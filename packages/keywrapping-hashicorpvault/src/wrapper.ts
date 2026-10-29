import { randomFillSync, randomInt } from 'node:crypto';
import { Agent as HttpAgent, request as httpRequest, STATUS_CODES, type ClientRequest, type IncomingMessage } from 'node:http';
import { Agent as HttpsAgent, request as httpsRequest } from 'node:https';
import { isIPv4 } from 'node:net';
import {
  ClosedError, HkdfGuardError, InvalidArgumentError, isWellFormed, MAX_WRAPPED_KEY_BYTES, wipe, type KeyWrapper,
} from '@runsecure/hkdfguard-abstractions';
import { KeyFileTrust, readTrustedKeyFile } from '@runsecure/hkdfguard-securefile';
import { decodeInto, encodedLength, encodeInto } from './base64.js';
import { HashiCorpVaultTransitError } from './errors.js';
import { JsonReader, JsonToken, MalformedJsonError } from './json.js';
import { HashiCorpVaultTransitKeyWrapperOptions, MAX_CONTEXT_LENGTH } from './options.js';
import { isValidToken, MAX_TOKEN_LENGTH, type VaultTokenSource } from './token.js';

export { MAX_CONTEXT_LENGTH } from './options.js';
export { MAX_TOKEN_LENGTH } from './token.js';

/** The length of the DEK {@link HashiCorpVaultTransitKeyWrapper.generateAndWrap} generates: 32 bytes (AES-256). */
export const GENERATED_KEY_LENGTH = 32;

/** The largest plaintext {@link HashiCorpVaultTransitKeyWrapper.wrap} accepts, in bytes: its ciphertext still fits MAX_WRAPPED_KEY_BYTES. */
export const MAX_PLAINTEXT_LENGTH = 256;

/** The longest key name. */
export const MAX_KEY_NAME_LENGTH = 128;

/**
 * The largest response read from Vault, in bytes; a transit answer is well under 1 KB. Exported for
 * the package's tests, never from the package index.
 */
export const MAX_RESPONSE_LENGTH = 16 * 1024;

const TOKEN_HEADER = 'X-Vault-Token';
const SEGMENT = /^[A-Za-z0-9._-]+$/;
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_RETRY_DELAY_MS = 200;
const Limits = HashiCorpVaultTransitKeyWrapperOptions;

const ascii = (text: string) => new Uint8Array(Buffer.from(text, 'latin1'));
// Asks for a 256-bit key: GENERATED_KEY_LENGTH bytes.
const DATA_KEY_BODY = ascii('{"bits":256}');
const PLAINTEXT_PREFIX = ascii('{"plaintext":"');
const CIPHERTEXT_PREFIX = ascii('{"ciphertext":"');
const VAULT_PREFIX = ascii('vault:v');

/**
 * A {@link KeyWrapper} that protects (encrypt) and reveals (decrypt) a DEK under one key in a
 * HashiCorp Vault transit secrets engine, and generates fresh DEKs with datakey/wrapped - so on that
 * path the plaintext DEK never leaves Vault. The KEK never enters this process; every call is a
 * request to Vault's HTTP API, authorized by the token's policy and recorded in Vault's audit log. A
 * wrapped DEK is Vault's ciphertext as it returns it, "vault:v{version}:{base64}", in ASCII - byte
 * for byte what the .NET, Go, Java and Python wrappers write, so a key file made by any of them is
 * read by the others, given the same key and context. The Node port of the .NET
 * HkdfGuard.KeyWrapping.HashiCorpVault library. HashiCorp ships no Node SDK, so the wrapper talks to
 * Vault through Node's own http and https clients, with no third-party dependency.
 *
 * The key is pinned by its path: every request names it, and a ciphertext carries only its key
 * version, never its key, so a key file wrapped under another transit key fails to authenticate
 * rather than being revealed. Vault's key rotation (transit/keys/{name}/rotate) keeps the name and is
 * transparent here: new DEKs are wrapped under the latest version, and older ones still reveal while
 * their version is at or above the key's min_decryption_version. The key must be an AEAD key that
 * isn't derived - aes256-gcm96 (Vault's default), aes128-gcm96 or chacha20-poly1305.
 *
 * The context, if any, is bound into every wrapped DEK as Vault's associated_data (AAD): decrypt
 * fails unless it is presented again exactly. datakey/wrapped ignores associated_data, so with a
 * context {@link generateAndWrap} generates the DEK here and wraps it with encrypt instead - the
 * plaintext DEK then does cross the network to Vault, as on {@link wrap}. A response whose warnings
 * say Vault ignored a parameter (a Vault too old for associated_data) is refused, so a context is
 * never silently dropped. Vault's audit log HMACs request fields by default, but the context isn't a
 * secret and must not hold one.
 *
 * Key files are read only from where an untrusted account can't have written or replaced them (see
 * {@link readKeyFile} and KeyFileTrust). Pinning the key stops a key file wrapped under another key;
 * this stops one wrapped under this key by anyone whose policy allows encrypt, which would otherwise
 * choose the DEK new data is encrypted under.
 *
 * Plaintext key bytes this class owns are zeroed once used, and never become a string: the request
 * body encrypt is sent - the DEK base64-encoded straight into a buffer of the wrapper's own
 * (Buffer.alloc, never the shared pool), written to the socket from that buffer and zeroed once the
 * call is done; the response decrypt answers with, streamed into another such buffer (each chunk
 * zeroed once copied); the value read out of it; and the DEK decoded out of that, into `result` -
 * which is itself zeroed whenever an unwrap fails. The token is copied by its
 * {@link VaultTokenSource} into a buffer the wrapper zeroes once the call is done. What can't be
 * zeroed: Node takes header values only as strings, which JavaScript can't erase, so each request
 * leaves the token in two strings - the header's value and the request head Node builds from it -
 * referenced by nothing once the request is sent, which stay in memory until the garbage collector
 * reuses it. So do the socket's and, over TLS, OpenSSL's buffers, which this class can't reach.
 *
 * Requests go to /v1/ under Vault's address, which must be https except on loopback, through Node's
 * own http and https clients: no proxy unless the agent given is one, and no redirect is ever
 * followed, which would carry the token elsewhere - Vault's standbys forward requests to the active
 * node themselves, so a redirect is answered as an error. A request that fails transiently - no
 * answer, a connection lost mid-response, a timed-out attempt, 429 or a 5xx other than 501 - is
 * retried (see HashiCorpVaultTransitKeyWrapperOptions.retryCount). Aborting a call's `signal`
 * abandons it at once - the token source's signal is aborted, or the request destroyed - and it
 * rejects with the signal's reason; no retry follows. {@link close} the wrapper to release its
 * connections, once nothing uses it - a key ring's background refresh included.
 *
 * Argument errors throw InvalidArgumentError. A Vault refusal, an unreachable Vault, or an answer
 * that isn't a usable one rejects with {@link HashiCorpVaultTransitError}, naming the operation, the
 * key, and Vault's status and errors (`Vault answered 400 BadRequest: cipher: message authentication
 * failed`). A token source's own failure propagates as it is; a token that isn't one rejects with an
 * HkdfGuardError (ERR_HKDFGUARD_INVALID_VAULT_TOKEN).
 */
export class HashiCorpVaultTransitKeyWrapper implements KeyWrapper {
  /** The transit key that wraps every DEK, as given. */
  readonly keyName: string;
  readonly #tokenSource: VaultTokenSource;
  readonly #https: boolean;
  readonly #hostname: string;
  readonly #port: number | undefined;
  readonly #agent: HttpAgent;
  readonly #ownAgent: boolean;
  readonly #encryptPath: string;
  readonly #decryptPath: string;
  readonly #dataKeyPath: string;
  readonly #hasContext: boolean;
  // Closes every encrypt and decrypt body: the closing quote of its value, the context if any, and
  // the closing brace.
  readonly #bodySuffix: Uint8Array;
  readonly #namespace: string | undefined;
  readonly #timeoutMs: number;
  readonly #retryCount: number;
  readonly #retryDelayMs: number;
  readonly #keyFileTrust: KeyFileTrust;
  #closed = false;

  /**
   * A wrapper over one transit key. No call is made until it is used.
   *
   * @param address Vault's address, e.g. https://vault.example.com:8200 - the same value as
   *   VAULT_ADDR. Must be https, except on a loopback address (a local Vault Agent or dev server). A
   *   path, if any, is kept as a prefix (Vault behind a reverse proxy).
   * @param keyName The transit key that wraps every DEK, e.g. "myapp-kek".
   * @param tokenSource Supplies the token every request is made with.
   * @param options The context, key file trust, the transit engine called and how to reach it;
   *   omitted for the engine at "transit", binding no context.
   * @throws InvalidArgumentError address isn't https (or http on loopback), or holds credentials, a
   *   query or a fragment (ERR_HKDFGUARD_INVALID_VAULT_ADDRESS); tokenSource isn't a
   *   VaultTokenSource; keyName isn't 1-MAX_KEY_NAME_LENGTH ASCII letters, digits, '-', '_' and '.'
   *   (and not "." or ".."); the context isn't a string, isn't well-formed text or is over
   *   MAX_CONTEXT_LENGTH bytes in UTF-8; keyFileTrust isn't a KeyFileTrust; the mount path or
   *   namespace isn't a Vault path; the timeout isn't positive, the retry count isn't 3-10 or the
   *   retry delay isn't zero to 10 seconds; or an option is of the wrong type.
   */
  constructor(address: string | URL, keyName: string, tokenSource: VaultTokenSource, options: HashiCorpVaultTransitKeyWrapperOptions = {}) {
    if (typeof tokenSource !== 'object' || tokenSource === null || typeof tokenSource.copyToken !== 'function') {
      throw new InvalidArgumentError('tokenSource must be a VaultTokenSource.');
    }
    if (typeof options !== 'object' || options === null) {
      throw new InvalidArgumentError('HashiCorpVaultTransitKeyWrapper options must be an object.');
    }
    const api = apiBase(address);
    if (typeof keyName !== 'string' || keyName.length > MAX_KEY_NAME_LENGTH || !isValidSegment(keyName)) {
      throw new InvalidArgumentError(`The key name ${JSON.stringify(keyName) ?? String(keyName)} isn't one: 1-${MAX_KEY_NAME_LENGTH} ASCII `
        + 'letters, digits, \'-\', \'_\' and \'.\', and not "." or "..".');
    }
    const settings = checked(options);
    const context = encodeContext(options.context);

    this.keyName = keyName;
    this.#tokenSource = tokenSource;
    this.#https = api.https;
    this.#hostname = api.hostname;
    this.#port = api.port;
    this.#ownAgent = !api.https || options.agent === undefined;
    // Keep-alive, so a call reuses a connection; a stale one is reset, and that attempt retried.
    this.#agent = !api.https ? new HttpAgent({ keepAlive: true }) : options.agent ?? new HttpsAgent({ keepAlive: true });
    this.#encryptPath = `${api.base}${settings.mountPath}/encrypt/${keyName}`;
    this.#decryptPath = `${api.base}${settings.mountPath}/decrypt/${keyName}`;
    this.#dataKeyPath = `${api.base}${settings.mountPath}/datakey/wrapped/${keyName}`;
    // Vault treats an empty associated_data as none, so an empty context is none too.
    this.#hasContext = context.length > 0;
    this.#bodySuffix = this.#hasContext ? ascii(`","associated_data":"${Buffer.from(context).toString('base64')}"}`) : ascii('"}');
    this.#namespace = settings.namespace;
    this.#timeoutMs = settings.timeoutMs;
    this.#retryCount = settings.retryCount;
    this.#retryDelayMs = settings.retryDelayMs;
    this.#keyFileTrust = settings.keyFileTrust;
  }

  /**
   * Protects a DEK with Vault's encrypt, writing the ciphertext ("vault:v{n}:...", ASCII) to
   * `result`. `plaintext` is not modified - it is the caller's to zero; it is encoded into the
   * request before this first awaits anything.
   *
   * @throws InvalidArgumentError `plaintext` is empty or over MAX_PLAINTEXT_LENGTH bytes, or `result`
   *   is too small for the wrapped DEK.
   * @throws HashiCorpVaultTransitError Vault refused the request or could not be reached, or returned
   *   no ciphertext, one over MAX_WRAPPED_KEY_BYTES, or one that ignored the context.
   */
  async wrap(plaintext: Uint8Array, result: Uint8Array, signal?: AbortSignal): Promise<number> {
    signal?.throwIfAborted();
    requireBytes(plaintext, 'plaintext');
    requireBytes(result, 'result');
    if (plaintext.length === 0 || plaintext.length > MAX_PLAINTEXT_LENGTH) {
      throw new InvalidArgumentError(`Vault transit wraps 1-${MAX_PLAINTEXT_LENGTH} bytes here; got ${plaintext.length}.`);
    }
    return this.#wrapKey(plaintext, result, signal);
  }

  /**
   * Reveals a DEK with Vault's decrypt, the key pinned, into `result`. On any failure `result` is
   * zeroed.
   *
   * @throws InvalidArgumentError `result` is too small for the revealed key.
   * @throws HashiCorpVaultTransitError `wrapped` is empty, over MAX_WRAPPED_KEY_BYTES or isn't a Vault
   *   ciphertext (refused without calling Vault); or Vault refused it - tampered with, wrapped under
   *   another key or under a different context, or its key version is below min_decryption_version -
   *   or could not be reached, or returned no plaintext or one that isn't base64.
   */
  async unwrap(wrapped: Uint8Array, result: Uint8Array, signal?: AbortSignal): Promise<number> {
    requireBytes(result, 'result');
    try {
      signal?.throwIfAborted();
      requireBytes(wrapped, 'wrapped');
      // Refused locally: no ciphertext Vault produces is outside these bounds, and one that is
      // Vault's ciphertext needs no escaping to go in the request body.
      if (wrapped.length === 0 || wrapped.length > MAX_WRAPPED_KEY_BYTES) {
        throw this.#error('unwrap', `A wrapped DEK is 1-${MAX_WRAPPED_KEY_BYTES} bytes; got ${wrapped.length}.`);
      }
      if (!isVaultCiphertext(wrapped)) {
        throw this.#error('unwrap', "A wrapped DEK is a Vault transit ciphertext, vault:v{version}:{base64}; this isn't one.");
      }

      // Not secret, but copied now, so what the caller does with `wrapped` meanwhile changes nothing.
      const body = this.#body(CIPHERTEXT_PREFIX, wrapped, false);
      const answer = await this.#post('unwrap', this.#decryptPath, body, signal);
      return this.#readAnswer(answer, 'unwrap', result, true);
    } catch (error) {
      // Whatever a failed call left in the DEK buffer is erased.
      wipe(result);
      throw error;
    }
  }

  /**
   * Generates a fresh GENERATED_KEY_LENGTH-byte DEK wrapped under the key. Without a context Vault
   * generates it and returns it wrapped only (datakey/wrapped), so the plaintext DEK never leaves
   * Vault on this call. With a context - which datakey/wrapped would ignore - it is generated here
   * and wrapped with encrypt, then zeroed.
   *
   * @throws InvalidArgumentError `result` is too small for the wrapped DEK.
   * @throws HashiCorpVaultTransitError as {@link wrap}.
   */
  async generateAndWrap(result: Uint8Array, signal?: AbortSignal): Promise<number> {
    signal?.throwIfAborted();
    requireBytes(result, 'result');
    if (this.#hasContext) {
      const dek = randomFillSync(new Uint8Array(GENERATED_KEY_LENGTH));
      try {
        return await this.#wrapKey(dek, result, signal);
      } finally {
        wipe(dek);
      }
    }

    const answer = await this.#post('generate-and-wrap', this.#dataKeyPath, Buffer.from(DATA_KEY_BODY), signal);
    return this.#readAnswer(answer, 'generate-and-wrap', result, false);
  }

  /**
   * Reads a key file this wrapper wrote, still wrapped, refusing one that an account other than the
   * operating system's administrators and the KeyFileTrust given at construction could have written
   * or replaced - the TypeScript equivalent of the native library's checks (readTrustedKeyFile in
   * @runsecure/hkdfguard-securefile). On Windows the file must be on a local fixed drive, reached
   * through real folders (no symbolic link, junction or substituted drive), and it and every folder
   * above it must be owned by, and modifiable only by, trusted principals. On Linux and macOS it and
   * every directory above it must be owned by root or a trusted user and writable by nobody else (by
   * its group only if that group is trusted), and only symbolic links a trusted user owns are
   * followed. It is also refused if it is empty, over MAX_WRAPPED_KEY_BYTES, or looks like an
   * unwrapped key. No Vault call is made.
   *
   * @throws KeyFileError (from @runsecure/hkdfguard-securefile) with `code` 'ENOENT', 'EACCES' (not
   *   readable, or not trusted), ERR_HKDFGUARD_INVALID_KEY_FILE, 'EBUSY' or another fs code.
   * @throws InvalidArgumentError the path is empty, or the KeyFileTrust names a Windows principal that can't be trusted.
   * @throws UnsupportedPlatformError not Windows, Linux or an Apple silicon Mac.
   */
  async readKeyFile(path: string, signal?: AbortSignal): Promise<Uint8Array> {
    return readTrustedKeyFile(path, this.#keyFileTrust, signal);
  }

  /**
   * Stops the wrapper calling Vault, and closes its connections (and its own agent; one given in the
   * options is the caller's). A call made afterwards rejects with ClosedError. Neither the token
   * source nor an agent given is closed. Safe to call more than once.
   */
  close(): void {
    this.#closed = true;
    if (this.#ownAgent) this.#agent.destroy();
  }

  // Encrypts `key` - read into the request body before anything is awaited - and checks the answer.
  async #wrapKey(key: Uint8Array, result: Uint8Array, signal: AbortSignal | undefined): Promise<number> {
    const body = this.#body(PLAINTEXT_PREFIX, key, true);
    try {
      const answer = await this.#post('wrap', this.#encryptPath, body, signal);
      return this.#readAnswer(answer, 'wrap', result, false);
    } finally {
      // Every attempt is over - answered, failed or abandoned - so nothing will send it again.
      wipe(body);
    }
  }

  // prefix, then value (base64-encoded if encode), then the suffix: a whole encrypt or decrypt body,
  // in a buffer of its own exactly that long. Request bodies are byte for byte .NET's.
  #body(prefix: Uint8Array, value: Uint8Array, encode: boolean): Buffer {
    const suffix = this.#bodySuffix;
    const body = Buffer.alloc(prefix.length + (encode ? encodedLength(value.length) : value.length) + suffix.length);
    body.set(prefix);
    let length = prefix.length;
    if (encode) {
      length = encodeInto(value, body, length);
    } else {
      body.set(value, length);
      length += value.length;
    }
    body.set(suffix, length);
    return body;
  }

  #ensureOpen(): void {
    if (this.#closed) throw new ClosedError('This HashiCorp Vault transit key wrapper has been closed.');
  }

  // Posts body to path and returns Vault's successful response, in a buffer the caller zeroes. The
  // token is asked for once; a request that fails transiently is retried. Vault's refusals, and
  // failures to reach it once the retries are spent, become HashiCorpVaultTransitError.
  async #post(operation: string, path: string, body: Buffer, signal: AbortSignal | undefined): Promise<Buffer> {
    this.#ensureOpen();
    signal?.throwIfAborted();
    const token = Buffer.alloc(MAX_TOKEN_LENGTH);
    try {
      // A source's failure is its own to retry, so isn't retried here, and propagates as it is.
      const tokenLength = await this.#copyToken(token, signal);

      for (let retry = 0; ; retry++) {
        this.#ensureOpen();
        try {
          return await this.#send(operation, path, body, token, tokenLength, signal);
        } catch (error) {
          if (signal?.aborted === true) throw signal.reason;
          if (!TRANSIENT.has(error as object)) throw this.#failure(operation, error);
          if (retry >= this.#retryCount || this.#closed) throw this.#failure(operation, error);
        }
        await delay(retryDelay(this.#retryDelayMs, retry, randomInt(0, 101)), signal);
      }
    } finally {
      wipe(token);
    }
  }

  // The token the source copies into `token`, waited for within the timeout; the source's signal is
  // aborted once it passes, or the call is aborted. Returns its length.
  async #copyToken(token: Buffer, signal: AbortSignal | undefined): Promise<number> {
    const timeout = new AbortController();
    const timer = setTimeout(() => timeout.abort(), this.#timeoutMs);
    const either = signal === undefined ? timeout.signal : AbortSignal.any([signal, timeout.signal]);
    let length: unknown;
    try {
      length = await untilAborted(Promise.resolve().then(() => this.#tokenSource.copyToken(token, either)), either);
    } catch (error) {
      if (signal?.aborted === true) throw signal.reason;
      if (timeout.signal.aborted) throw new DOMException(`The Vault token source supplied no token within ${this.#timeoutMs} ms.`, 'TimeoutError');
      throw error;
    } finally {
      clearTimeout(timer);
    }
    if (typeof length !== 'number' || !Number.isInteger(length) || length <= 0 || length > MAX_TOKEN_LENGTH
      || !isValidToken(token.subarray(0, length))) {
      throw new HkdfGuardError('ERR_HKDFGUARD_INVALID_VAULT_TOKEN',
        `The Vault token source supplied no token, or one that isn't a token: 1-${MAX_TOKEN_LENGTH} printable ASCII characters, with no spaces.`);
    }
    return length;
  }

  // One attempt: one request, and Vault's whole response, within the attempt's timeout. A successful
  // response is returned in a buffer of its own; any other is thrown as a VaultAnswer carrying
  // Vault's status and errors.
  async #send(operation: string, path: string, body: Buffer, token: Buffer, tokenLength: number, signal: AbortSignal | undefined): Promise<Buffer> {
    signal?.throwIfAborted();
    const attempt = new AbortController();
    const timer = setTimeout(() => attempt.abort(), this.#timeoutMs);
    const either = signal === undefined ? attempt.signal : AbortSignal.any([signal, attempt.signal]);
    let request: ClientRequest | undefined;
    let response: IncomingMessage | undefined;
    // Destroyed with an error, so whichever is being waited for fails at once; the catch below
    // replaces it with the abort's reason or the timeout.
    const abandon = () => {
      const abandoned = new Error('The call to Vault was abandoned.');
      request?.destroy(abandoned);
      response?.destroy(abandoned);
    };
    either.addEventListener('abort', abandon, { once: true });

    try {
      const sent = this.#request(path, body.length, token, tokenLength);
      request = sent;
      response = await new Promise<IncomingMessage>((resolve, reject) => {
        sent.on('response', resolve);
        // Kept for the request's life: an error after the response must find a listener.
        sent.on('error', (error) => reject(transient(error)));
        // Sent from body itself, not a copy: Node writes a Buffer to the socket as it is.
        sent.end(body);
      });
      // A body's errors reach the reader through its iterator; this one keeps a late one quiet.
      response.on('error', () => undefined);
      try {
        return await this.#readResponse(operation, response);
      } finally {
        if (!response.complete) response.destroy();
      }
    } catch (error) {
      if (signal?.aborted === true) throw signal.reason;
      if (attempt.signal.aborted) throw transient(new DOMException(`Vault's answer took longer than ${this.#timeoutMs} ms.`, 'TimeoutError'));
      throw error;
    } finally {
      clearTimeout(timer);
      either.removeEventListener('abort', abandon);
    }
  }

  // The request, with the token `token` holds. Node takes a header only as a string: that string,
  // and the request head built from it, are the copies of the token this class can't erase.
  #request(path: string, contentLength: number, token: Buffer, tokenLength: number): ClientRequest {
    const headers: Record<string, string | number> = {
      'Content-Type': 'application/json',
      'Content-Length': contentLength,
      'X-Vault-Request': 'true',
    };
    if (this.#namespace !== undefined) headers['X-Vault-Namespace'] = this.#namespace;
    // Checked by copyToken - printable ASCII - so latin1 is the token exactly.
    headers[TOKEN_HEADER] = token.toString('latin1', 0, tokenLength);
    return (this.#https ? httpsRequest : httpRequest)({
      hostname: this.#hostname, port: this.#port, path, method: 'POST', agent: this.#agent, headers,
    });
  }

  // Reads Vault's whole response into a buffer of the wrapper's own, at most MAX_RESPONSE_LENGTH
  // bytes, zeroing each chunk once copied. A success is returned in a copy just its size, for the
  // caller to zero; anything else is thrown with Vault's status and errors.
  async #readResponse(operation: string, response: IncomingMessage): Promise<Buffer> {
    // One byte over the limit, so a body that doesn't fit is noticed rather than truncated.
    const buffer = Buffer.alloc(MAX_RESPONSE_LENGTH + 1);
    try {
      let length = 0;
      try {
        for await (const chunk of response) {
          const bytes = chunk as Buffer;
          const take = Math.min(bytes.length, buffer.length - length);
          buffer.set(bytes.subarray(0, take), length);
          length += take;
          wipe(bytes);
          if (length > MAX_RESPONSE_LENGTH) break;
        }
      } catch (error) {
        // A connection lost mid-response.
        throw transient(error);
      }
      if (length > MAX_RESPONSE_LENGTH) {
        throw this.#error(operation, `Vault's answer for key '${this.keyName}' is over ${MAX_RESPONSE_LENGTH} bytes; a transit answer is far smaller.`);
      }

      const status = response.statusCode ?? 0;
      if (status >= 200 && status < 300) {
        const answer = Buffer.alloc(length);
        buffer.copy(answer, 0, 0, length);
        return answer;
      }

      const errors = readErrors(buffer.subarray(0, length));
      const detail = errors !== undefined && errors.length > 0 ? `: ${errors.join('; ')}` : '';
      const name = STATUS_CODES[status]?.replace(/[^A-Za-z0-9]/g, '');
      const answer = new VaultAnswer(`Vault answered ${status}${name ? ` ${name}` : ''}${detail}`, status);
      if (status === 429 || (status >= 500 && status !== 501)) TRANSIENT.add(answer);
      throw answer;
    } finally {
      wipe(buffer);
    }
  }

  // Takes data.plaintext (decoded) or data.ciphertext out of a successful answer into result, then
  // zeroes the answer and the copy of the value read out of it.
  #readAnswer(answer: Buffer, operation: string, result: Uint8Array, plaintext: boolean): number {
    // Never longer than the answer it is read out of.
    const value = Buffer.alloc(answer.length);
    try {
      const length = this.#readData(answer, plaintext ? 'plaintext' : 'ciphertext', operation, value);
      return plaintext ? this.#decodePlaintext(value.subarray(0, length), result) : this.#copyCiphertext(value.subarray(0, length), result, operation);
    } finally {
      wipe(value);
      wipe(answer);
    }
  }

  // Copies the string at data.{name} in a successful response into value, unescaped, and returns its
  // length. Refused if it is missing or repeated, isn't a string, or the response's warnings say
  // Vault ignored a parameter - as a Vault too old for associated_data does, leaving a DEK bound to
  // no context.
  #readData(json: Uint8Array, name: string, operation: string, value: Uint8Array): number {
    let length = 0;
    let found = false;
    let ignoredParameter = false;
    try {
      const reader = new JsonReader(json);
      reader.read();
      if (reader.token() !== JsonToken.StartObject) throw this.#malformed(operation);

      for (reader.read(); reader.token() === JsonToken.PropertyName; reader.read()) {
        if (reader.valueTextEquals('data')) {
          reader.read();
          if (reader.token() !== JsonToken.StartObject) {
            reader.skip();
            continue;
          }

          for (reader.read(); reader.token() === JsonToken.PropertyName; reader.read()) {
            const isValue = reader.valueTextEquals(name);
            reader.read();
            if (!isValue) {
              reader.skip();
              continue;
            }

            if (found || reader.token() !== JsonToken.String) throw this.#malformed(operation);
            // Vault doesn't escape base64 or its ciphertext, but a proxy re-encoding the answer might.
            length = reader.copyString(value);
            found = true;
          }
        } else if (reader.valueTextEquals('warnings')) {
          reader.read();
          if (reader.token() !== JsonToken.StartArray) {
            reader.skip();
            continue;
          }

          for (reader.read(); reader.token() !== JsonToken.EndArray; reader.read()) {
            // A warning holds no key material, so may be a string.
            if (reader.token() === JsonToken.String && reader.getString().toLowerCase().includes('unrecognized parameters')) ignoredParameter = true;
            reader.skip();
          }
        } else {
          reader.read();
          reader.skip();
        }
      }
    } catch (error) {
      if (error instanceof MalformedJsonError) throw this.#malformed(operation);
      throw error;
    }

    if (ignoredParameter) {
      throw this.#error(operation, `Vault transit ${operation} for key '${this.keyName}' ignored a parameter it was sent, so its answer can't be used: `
        + 'a context needs a Vault that supports associated_data.');
    }
    if (!found || length === 0) throw this.#error(operation, `Vault transit ${operation} for key '${this.keyName}' returned no ${name}.`);
    return length;
  }

  #copyCiphertext(ciphertext: Uint8Array, result: Uint8Array, operation: string): number {
    if (!isVaultCiphertext(ciphertext)) {
      throw this.#error(operation, `Vault transit ${operation} for key '${this.keyName}' returned something that isn't a ciphertext.`);
    }
    // A key file over the limit would be refused when read back, so refuse to produce one.
    if (ciphertext.length > MAX_WRAPPED_KEY_BYTES) {
      throw this.#error(operation,
        `Vault transit ${operation} for key '${this.keyName}' returned ${ciphertext.length} bytes; a wrapped DEK is at most ${MAX_WRAPPED_KEY_BYTES}.`);
    }
    if (ciphertext.length > result.length) {
      throw new InvalidArgumentError(`The wrapped DEK is ${ciphertext.length} bytes; result holds ${result.length}.`);
    }
    result.set(ciphertext);
    return ciphertext.length;
  }

  // Decodes the revealed key into result, through a buffer that is zeroed: decoded straight into
  // result, a key too long for it would be partly written before that was known.
  #decodePlaintext(base64: Uint8Array, result: Uint8Array): number {
    const decoded = Buffer.alloc(Math.ceil(base64.length / 4) * 3);
    try {
      const length = decodeInto(base64, decoded);
      if (length <= 0) throw this.#error('unwrap', `Vault transit unwrap for key '${this.keyName}' returned a plaintext that isn't base64.`);
      if (length > result.length) throw new InvalidArgumentError(`The revealed key is ${length} bytes; result holds ${result.length}.`);
      result.set(decoded.subarray(0, length));
      return length;
    } finally {
      wipe(decoded);
    }
  }

  // What a call that didn't succeed rejects with: Vault's answer, a failure to reach it (once the
  // retries are spent), or the attempt's timeout, as a HashiCorpVaultTransitError. Anything else -
  // already one, or not a failure of the call to Vault - is left as it is.
  #failure(operation: string, error: unknown): unknown {
    const prefix = `Vault transit ${operation} failed for key '${this.keyName}'`;
    if (error instanceof VaultAnswer) {
      return new HashiCorpVaultTransitError(operation, this.keyName, `${prefix}: ${error.message}`, { statusCode: error.statusCode });
    }
    if (!TRANSIENT.has(error as object)) return error;
    const reason = error instanceof DOMException && error.name === 'TimeoutError' ? `no answer within ${this.#timeoutMs} ms`
      : error instanceof Error ? error.message : String(error);
    return new HashiCorpVaultTransitError(operation, this.keyName, `${prefix}: ${reason}`, { cause: error });
  }

  #malformed(operation: string): HashiCorpVaultTransitError {
    return this.#error(operation, `Vault transit ${operation} for key '${this.keyName}' returned a response that isn't Vault's.`);
  }

  #error(operation: string, message: string): HashiCorpVaultTransitError {
    return new HashiCorpVaultTransitError(operation, this.keyName, message);
  }
}

/** Vault answered with a status other than success: its status, and the errors it listed. Never leaves the package. */
class VaultAnswer extends Error {
  constructor(message: string, readonly statusCode: number) {
    super(message);
  }
}

// Failures another attempt may not meet: no answer at all (connection refused or reset, DNS), a
// connection lost mid-response, the attempt's own timeout, or Vault busy or briefly unable to
// answer - 429, or a 5xx other than 501.
const TRANSIENT = new WeakSet<object>();

function transient<T>(error: T): T {
  if (typeof error === 'object' && error !== null) TRANSIENT.add(error);
  return error;
}

/**
 * Whether `value` is a transit ciphertext as Vault writes it: vault:v{version}:{base64}, the version
 * 1-10 digits. Exported for the package's tests, never from the package index.
 */
export function isVaultCiphertext(value: Uint8Array): boolean {
  if (value.length < VAULT_PREFIX.length) return false;
  for (let i = 0; i < VAULT_PREFIX.length; i++) if (value[i] !== VAULT_PREFIX[i]) return false;

  let i = VAULT_PREFIX.length;
  const digitsStart = i;
  while (i < value.length && value[i]! >= 0x30 && value[i]! <= 0x39) i++;
  const digits = i - digitsStart;
  if (digits < 1 || digits > 10 || i >= value.length || value[i] !== 0x3a || i + 1 >= value.length) return false; // :

  for (i++; i < value.length; i++) {
    const b = value[i]!;
    const isBase64 = (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || (b >= 0x30 && b <= 0x39) || b === 0x2b || b === 0x2f || b === 0x3d;
    if (!isBase64) return false;
  }
  return true;
}

/**
 * The wait before retry number `retry` (0 for the first), in milliseconds: `baseDelayMs`, doubled
 * for each retry before it, at most MAX_RETRY_DELAY_MS - plus `jitterMs`. Exported for the
 * package's tests, never from the package index.
 */
export function retryDelay(baseDelayMs: number, retry: number, jitterMs: number): number {
  const maximum = Limits.MAX_RETRY_DELAY_MS;
  const backoff = retry >= 30 ? maximum : baseDelayMs * 2 ** retry;
  return Math.min(backoff, maximum) + jitterMs;
}

// The errors Vault listed in an error response; undefined if it isn't Vault's JSON. An error
// response holds no key material, so is read as a string.
function readErrors(body: Uint8Array): string[] | undefined {
  let root: unknown;
  try {
    root = JSON.parse(new TextDecoder().decode(body));
  } catch {
    return undefined;
  }
  if (typeof root !== 'object' || root === null || Array.isArray(root)) return undefined;
  if (!Object.hasOwn(root, 'errors')) return [];
  const errors = (root as { errors: unknown }).errors;
  return Array.isArray(errors) ? errors.map((e: unknown) => (typeof e === 'string' ? e : JSON.stringify(e))) : undefined;
}

/** Resolves after `ms`, or rejects with `signal`'s reason once it is aborted. */
function delay(ms: number, signal: AbortSignal | undefined): Promise<void> {
  signal?.throwIfAborted();
  return new Promise<void>((resolve, reject) => {
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal!.reason);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/** `promise`, or `signal`'s reason once it is aborted, whichever comes first. */
function untilAborted<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (value) => { signal.removeEventListener('abort', onAbort); resolve(value); },
      (error: unknown) => { signal.removeEventListener('abort', onAbort); reject(error); });
  });
}

interface Settings {
  mountPath: string;
  namespace: string | undefined;
  timeoutMs: number;
  retryCount: number;
  retryDelayMs: number;
  keyFileTrust: KeyFileTrust;
}

function checked(options: HashiCorpVaultTransitKeyWrapperOptions): Settings {
  // Only an undefined member takes its default: null is a value of the wrong type.
  const or = <T>(value: T | undefined, fallback: T): T => (value === undefined ? fallback : value);
  const settings: Settings = {
    mountPath: or(options.mountPath, 'transit'),
    namespace: options.namespace,
    timeoutMs: or(options.timeoutMs, DEFAULT_TIMEOUT_MS),
    retryCount: or(options.retryCount, Limits.MIN_RETRY_COUNT),
    retryDelayMs: or(options.retryDelayMs, DEFAULT_RETRY_DELAY_MS),
    keyFileTrust: or(options.keyFileTrust, KeyFileTrust.administratorsOnly),
  };
  if (typeof settings.mountPath !== 'string') throw new InvalidArgumentError('mountPath must be a string.');
  if (settings.namespace !== undefined && typeof settings.namespace !== 'string') throw new InvalidArgumentError('namespace must be a string.');
  for (const [name, value] of [['timeoutMs', settings.timeoutMs], ['retryCount', settings.retryCount], ['retryDelayMs', settings.retryDelayMs]] as const) {
    if (typeof value !== 'number') throw new InvalidArgumentError(`${name} must be a number.`);
  }
  if (!(settings.keyFileTrust instanceof KeyFileTrust)) throw new InvalidArgumentError('keyFileTrust must be a KeyFileTrust.');
  if (options.agent !== undefined && !(options.agent instanceof HttpAgent)) throw new InvalidArgumentError('agent must be an https.Agent.');

  if (!isValidPath(settings.mountPath)) throw new InvalidArgumentError(`The mount path '${settings.mountPath}' isn't a Vault path.`);
  if (settings.namespace !== undefined && !isValidPath(settings.namespace)) {
    throw new InvalidArgumentError(`The namespace '${settings.namespace}' isn't a Vault path.`);
  }
  if (!(settings.timeoutMs > 0 && settings.timeoutMs <= Limits.MAX_TIMEOUT_MS)) {
    throw new InvalidArgumentError(`The timeout must be positive, at most ${Limits.MAX_TIMEOUT_MS} ms; it is ${settings.timeoutMs}.`);
  }
  if (!Number.isInteger(settings.retryCount) || settings.retryCount < Limits.MIN_RETRY_COUNT || settings.retryCount > Limits.MAX_RETRY_COUNT) {
    throw new InvalidArgumentError(`The retry count must be ${Limits.MIN_RETRY_COUNT}-${Limits.MAX_RETRY_COUNT}; it is ${settings.retryCount}.`);
  }
  if (!(settings.retryDelayMs >= 0 && settings.retryDelayMs <= Limits.MAX_RETRY_DELAY_MS)) {
    throw new InvalidArgumentError(`The retry delay must be zero to ${Limits.MAX_RETRY_DELAY_MS} ms; it is ${settings.retryDelayMs}.`);
  }
  return settings;
}

// The UTF-8 context, refusing a lone surrogate, which .NET would encode differently (as U+FFFD).
function encodeContext(context: unknown): Uint8Array {
  if (context === undefined || context === null) return new Uint8Array(0);
  if (typeof context !== 'string') throw new InvalidArgumentError('context must be a string.');
  if (!isWellFormed(context)) throw new InvalidArgumentError('The context isn\'t well-formed text: it holds a lone surrogate.');
  const encoded = new TextEncoder().encode(context);
  if (encoded.length > MAX_CONTEXT_LENGTH) {
    throw new InvalidArgumentError(`The context is ${encoded.length} bytes in UTF-8; at most ${MAX_CONTEXT_LENGTH} are allowed.`);
  }
  return encoded;
}

// Whether Vault's address is https, its host and port, and the path of /v1/ under it - refusing an
// address that would send tokens and DEKs in the clear (http anywhere but loopback) or that carries
// credentials, a query or a fragment.
function apiBase(address: string | URL): { https: boolean; hostname: string; port: number | undefined; base: string } {
  const text = address instanceof URL ? address.href : address;
  if (typeof text !== 'string') throw new InvalidArgumentError('address must be a string or a URL.');
  const invalid = (problem: string) => new InvalidArgumentError(`Vault's address '${text}' ${problem}`, 'ERR_HKDFGUARD_INVALID_VAULT_ADDRESS');

  // A scheme and a host, checked on the text: the URL parser would read "https:///host" as "https://host".
  let url: URL | undefined;
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#\\]/.test(text)) {
    try {
      url = new URL(text);
    } catch {
      url = undefined;
    }
  }
  if (url === undefined || url.hostname === '') throw invalid("isn't absolute, e.g. https://vault.example.com:8200.");

  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback(url.hostname))) {
    throw invalid('must be https; http is allowed only on a loopback address (a local Vault Agent or dev server), since every request carries a token and DEKs.');
  }
  const authority = text.slice(text.indexOf('//') + 2).split(/[/?#]/, 1)[0]!;
  if (authority.includes('@') || url.username !== '' || url.password !== '' || text.includes('?') || text.includes('#')) {
    throw invalid('must not hold credentials, a query or a fragment.');
  }

  let prefix = url.pathname;
  while (prefix.endsWith('/')) prefix = prefix.slice(0, -1);
  return {
    https: url.protocol === 'https:',
    hostname: url.hostname.startsWith('[') ? url.hostname.slice(1, -1) : url.hostname,
    port: url.port === '' ? undefined : Number(url.port),
    base: `${prefix}/v1/`,
  };
}

// localhost, or an IP literal on the loopback network - as the URL parser normalized it, so no name
// is ever resolved.
function isLoopback(hostname: string): boolean {
  return hostname === 'localhost' || (isIPv4(hostname) && hostname.startsWith('127.')) || hostname === '[::1]';
}

// '/'-separated segments, none empty, "." or "..": a path that stays where it's put.
function isValidPath(path: unknown): boolean {
  return typeof path === 'string' && path.split('/').every(isValidSegment);
}

function isValidSegment(segment: string): boolean {
  return SEGMENT.test(segment) && segment !== '.' && segment !== '..';
}

function requireBytes(value: unknown, name: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) throw new InvalidArgumentError(`${name} must be a Uint8Array.`);
}

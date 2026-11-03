import { randomFillSync } from 'node:crypto';
import type { ClientRequest, IncomingMessage } from 'node:http';
import {
  ClosedError, InvalidArgumentError, isWellFormed, MAX_WRAPPED_KEY_BYTES, wipe, type KeyWrapper,
} from '@runsecure/hkdfguard-abstractions';
import { JsonReader, JsonToken, MalformedJsonError } from '@runsecure/hkdfguard-abstractions/internal';
import {
  apiBase, checkConnectionOptions, chunksOf, copyTokenWithin, isTransient, isValidSegment, MAX_TOKEN_LENGTH, putToken, readBody, readVaultErrors,
  sendAttempt, vaultHeaders, VaultConnector, vaultRefusal, VaultRequestError, withRetries, type VaultTokenSource,
} from '@runsecure/hkdfguard-integration-hashicorpvault';
import { KeyFileTrust, readTrustedKeyFile } from '@runsecure/hkdfguard-securefile';
import { decodeInto, encodedLength, encodeInto } from './base64.js';
import { HashiCorpVaultTransitError } from './errors.js';
import { MAX_CONTEXT_LENGTH, type HashiCorpVaultTransitKeyWrapperOptions } from './options.js';

export { MAX_CONTEXT_LENGTH } from './options.js';

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

// The deepest nesting read from Vault's answer, as .NET's wrapper limits it: a transit answer nests three deep.
const MAX_JSON_DEPTH = 16;

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
 * retried (see VaultConnectionOptions.retryCount). Aborting a call's `signal`
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
  readonly #connector: VaultConnector;
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
    const text = address instanceof URL ? address.href : address;
    if (typeof text !== 'string') throw new InvalidArgumentError('address must be a string or a URL.');
    const api = apiBase(text, 'a token and DEKs');
    if (typeof keyName !== 'string' || keyName.length > MAX_KEY_NAME_LENGTH || !isValidSegment(keyName)) {
      throw new InvalidArgumentError(`The key name ${JSON.stringify(keyName) ?? String(keyName)} isn't one: 1-${MAX_KEY_NAME_LENGTH} ASCII `
        + 'letters, digits, \'-\', \'_\' and \'.\', and not "." or "..".');
    }
    const settings = checkConnectionOptions(options, 'transit');
    const keyFileTrust = checkedKeyFileTrust(options.keyFileTrust);
    const context = encodeContext(options.context);

    this.keyName = keyName;
    this.#tokenSource = tokenSource;
    this.#connector = new VaultConnector(api, options.agent, options.tls);
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
    this.#keyFileTrust = keyFileTrust;
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
    this.#connector.close();
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
      const tokenLength = await copyTokenWithin(this.#tokenSource, token, this.#timeoutMs, signal);
      try {
        return await withRetries(() => {
          this.#ensureOpen();
          // One attempt: one request, and Vault's whole response, within the attempt's timeout.
          return sendAttempt(() => this.#request(path, body.length, token, tokenLength), body,
            (response) => this.#readResponse(operation, response), this.#timeoutMs, signal, `Vault's answer took longer than ${this.#timeoutMs} ms.`);
        }, this.#retryCount, this.#retryDelayMs, signal, { stopped: () => this.#closed });
      } catch (error) {
        if (signal?.aborted === true) throw signal.reason;
        throw this.#failure(operation, error);
      }
    } finally {
      wipe(token);
    }
  }

  // The request, with the token `token` holds. Node takes a header only as a string: that string,
  // and the request head built from it, are the copies of the token this class can't erase.
  #request(path: string, contentLength: number, token: Buffer, tokenLength: number): ClientRequest {
    const headers = vaultHeaders(this.#namespace, { 'Content-Type': 'application/json', 'Content-Length': contentLength });
    // Checked by copyTokenWithin - printable ASCII - so latin1 is the token exactly.
    putToken(headers, token, tokenLength);
    return this.#connector.request('POST', path, headers);
  }

  // Reads Vault's whole response (readBody: each chunk zeroed once copied), at most
  // MAX_RESPONSE_LENGTH bytes. A success is returned in a copy just its size, for the caller to
  // zero; anything else is thrown with Vault's status and errors.
  async #readResponse(operation: string, response: IncomingMessage): Promise<Buffer> {
    // A connection lost mid-response is transient.
    const body = await readBody(chunksOf(response), MAX_RESPONSE_LENGTH);
    if (body === undefined) {
      throw this.#error(operation, `Vault's answer for key '${this.keyName}' is over ${MAX_RESPONSE_LENGTH} bytes; a transit answer is far smaller.`);
    }
    try {
      const status = response.statusCode ?? 0;
      // 429 and a 5xx other than 501 are transient, and retried.
      if (status < 200 || status >= 300) throw vaultRefusal(status, readVaultErrors(body.view()));
      // Buffer.alloc, never the shared pool Buffer.from copies into, so zeroing it reaches every copy.
      const answer = Buffer.alloc(body.length);
      answer.set(body.view());
      return answer;
    } finally {
      body.close();
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
      const reader = new JsonReader(json, json.length, MAX_JSON_DEPTH);
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
    if (error instanceof VaultRequestError) {
      return new HashiCorpVaultTransitError(operation, this.keyName, `${prefix}: ${error.message}`, { statusCode: error.statusCode });
    }
    if (!isTransient(error)) return error;
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

// Who may have written a key file, given or by default; refused unless a KeyFileTrust. Only an
// undefined member takes its default: null is a value of the wrong type.
function checkedKeyFileTrust(keyFileTrust: unknown): KeyFileTrust {
  if (keyFileTrust === undefined) return KeyFileTrust.administratorsOnly;
  if (!(keyFileTrust instanceof KeyFileTrust)) throw new InvalidArgumentError('keyFileTrust must be a KeyFileTrust.');
  return keyFileTrust;
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

function requireBytes(value: unknown, name: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) throw new InvalidArgumentError(`${name} must be a Uint8Array.`);
}

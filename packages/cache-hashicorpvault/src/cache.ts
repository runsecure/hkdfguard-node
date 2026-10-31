import { randomInt } from 'node:crypto';
import { Agent as HttpAgent, request as httpRequest, type ClientRequest, type IncomingMessage } from 'node:http';
import { Agent as HttpsAgent, request as httpsRequest } from 'node:https';
import {
  ClosedError, HkdfGuardError, InvalidArgumentError, wipe, type DataProtector, type KeyRing,
} from '@runsecure/hkdfguard-abstractions';
import { delay, isValidVaultPath, untilAborted, vaultApiBase } from '@runsecure/hkdfguard-abstractions/internal';
import { ErrorResponseBody, RemoteSecretCache, SecretJsonBody, SecretNameMatching, type SecretValueSink } from '@runsecure/hkdfguard-cache';
import { VaultRequestError } from './errors.js';
import { HashiCorpVaultSecretCacheOptions, VaultKvVersion } from './options.js';
import { isValidToken, type VaultTokenProvider } from './token.js';

const TOKEN_HEADER = 'X-Vault-Token';
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_RETRY_DELAY_MS = 200;
const Limits = HashiCorpVaultSecretCacheOptions;

/**
 * A ProtectedReadOnlyCache over the secrets in one HashiCorp Vault KV secrets engine. The first
 * lookup of a name that isn't cached yet reads that one secret (GET on its path; for KV version 2,
 * its latest version); fetching, encryption, caching and telemetry are RemoteSecretCache's. This
 * class never lists secrets, so the token's policy needs only `read` on the paths it reads, never
 * `list`.
 *
 * A name is a secret's path within the engine, with the key to read after '#': "myapp/db#password"
 * reads the password key of the secret at myapp/db, and "myapp/db" reads its
 * {@link HashiCorpVaultSecretCacheOptions.defaultKey}. One read caches every key the secret holds, so
 * the first lookup of any of them reads the secret once and the rest are already cached. A string is
 * cached as its UTF-8 bytes; a number, true or false as its JSON text; a null, object or array value
 * isn't cached. Paths are matched exactly, as Vault matches them, and so are keys. A path that isn't
 * one - segments of ASCII letters, digits, '-', '_' and '.', no segment "." or "..", at most
 * {@link MAX_SECRET_NAME_LENGTH} characters, such as the configuration path "ConnectionStrings:Admin"
 * - is reported missing without a call.
 *
 * A secret that doesn't exist (404 with no errors, as Vault answers), whose latest version is
 * deleted or destroyed, or that has no such key, or whose value there is empty or isn't cached, is
 * reported missing. Any other answer (403 for a token that is invalid or not allowed to read the
 * path, a 404 naming an error such as a mount that doesn't exist, a redirect, Vault sealed) rejects
 * with a {@link VaultRequestError} carrying Vault's status and errors. A request that fails
 * transiently - no answer, a connection lost mid-response, a timed-out attempt, 429 or a 5xx other
 * than 501 - is first retried {@link HashiCorpVaultSecretCacheOptions.retryCount} times (3-10),
 * waiting {@link HashiCorpVaultSecretCacheOptions.retryDelayMs} and doubling, up to 10 seconds, plus
 * a random 0-100 ms each time so clients reconnecting together spread out. Once the retries are
 * spent, a failure without an answer rejects with Node's own network error (ECONNREFUSED,
 * ECONNRESET, ENOTFOUND...), or a DOMException named TimeoutError for a timed-out attempt.
 *
 * Authentication isn't the cache's: every fetch asks its {@link VaultTokenProvider} for a token,
 * once, so a provider can log in, renew and replace tokens however it likes. A provider's failure
 * propagates as it is, and isn't retried; a provider that hasn't answered within the timeout fails
 * the fetch with a TimeoutError. The token is handed over protected - encrypted by the cache's token
 * protector, a protector on the key ring (`keyRing.createProtector(TOKEN_PURPOSE)`) - and a fetch
 * given one that isn't fails with an HkdfGuardError (ERR_HKDFGUARD_INVALID_VAULT_TOKEN), quoting and
 * chaining nothing. It is decrypted only as each request is built, into a buffer that is zeroed as
 * soon as the request has its headers. Node takes header values only as strings, though, which
 * JavaScript can't erase: each request leaves the token in two strings - the header's value and the
 * request head Node builds from it - referenced by nothing once the request is sent, which stay in
 * memory until the garbage collector reuses it. So do the socket's and, over TLS, OpenSSL's
 * buffers, which this class can't reach.
 *
 * Requests go to /v1/ under Vault's address, which must be https except on loopback, through Node's
 * own http and https clients: no proxy unless the agent given is one, and no redirect is ever
 * followed, which would carry the token elsewhere - Vault's standbys forward requests to the active
 * node themselves, so a redirect is answered as an error. Each attempt - one request and Vault's
 * whole response - must finish within {@link HashiCorpVaultSecretCacheOptions.timeoutMs}. Aborting
 * the lookup that started a fetch abandons it: the provider's signal is aborted, or the request is
 * destroyed, and no retry follows; nothing it read is kept.
 *
 * The secret never becomes a string. The response body is streamed into a buffer of the library's
 * own (each chunk zeroed once copied), and the value is unescaped into another and encrypted from
 * there (SecretJsonBody.captureKeysAsync); every buffer holding it is zeroed. What can't be zeroed
 * is below that: the socket's and OpenSSL's buffers. {@link close} the cache to release its
 * connections.
 */
export class HashiCorpVaultSecretCache extends RemoteSecretCache {
  /** The longest secret path looked up. */
  static readonly MAX_SECRET_NAME_LENGTH = 512;

  /**
   * The purpose to create the token protector with - `keyRing.createProtector(TOKEN_PURPOSE)` - so a
   * token protected for the cache can't be decrypted as anything else, nor anything else as it.
   */
  static readonly TOKEN_PURPOSE = 'HkdfGuard.Cache.HashiCorpVault.Token';

  readonly #tokenProvider: VaultTokenProvider;
  readonly #tokenProtector: DataProtector;
  readonly #https: boolean;
  readonly #hostname: string;
  readonly #port: number | undefined;
  readonly #agent: HttpAgent;
  readonly #ownAgent: boolean;
  readonly #readBase: string;
  readonly #dataPath: readonly string[];
  readonly #defaultKey: string;
  readonly #namespace: string | undefined;
  readonly #timeoutMs: number;
  readonly #retryCount: number;
  readonly #retryDelayMs: number;
  #closed = false;

  /**
   * @param address Vault's address, e.g. https://vault.example.com:8200 - the same value as
   *   VAULT_ADDR. Must be https, except on a loopback address (a local Vault Agent or dev server). A
   *   path, if any, is kept as a prefix (Vault behind a reverse proxy).
   * @param tokenProvider supplies the token every read is made with, protected by tokenProtector
   * @param tokenProtector decrypts the token tokenProvider supplies: a protector on the key ring,
   *   `keyRing.createProtector(TOKEN_PURPOSE)`
   * @param keyRing supplies the key every fetched secret is encrypted under; owned by the caller -
   *   the cache never closes keys
   * @param options the KV engine read and how to reach it; omitted for KV version 2 at "secret",
   *   reading the key "value"
   * @throws TypeError address, tokenProvider, tokenProtector or keyRing is missing, or an option is
   *   of the wrong type
   * @throws InvalidArgumentError address isn't https (or http on loopback), or holds credentials, a
   *   query or a fragment (ERR_HKDFGUARD_INVALID_VAULT_ADDRESS); or the mount path, default key or
   *   namespace isn't one, the KV version isn't, the timeout isn't positive, the retry count isn't
   *   3-10 or the retry delay isn't zero to 10 seconds
   */
  constructor(
    address: string | URL, tokenProvider: VaultTokenProvider, tokenProtector: DataProtector, keyRing: KeyRing,
    options: HashiCorpVaultSecretCacheOptions = {},
  ) {
    if (address === undefined || address === null) throw new TypeError('address must not be undefined.');
    if (tokenProvider === undefined || tokenProvider === null || typeof tokenProvider.getToken !== 'function') {
      throw new TypeError('tokenProvider must be a VaultTokenProvider.');
    }
    if (tokenProtector === undefined || tokenProtector === null) throw new TypeError('tokenProtector must not be undefined.');
    if (options === null || typeof options !== 'object') throw new TypeError('options must be a HashiCorpVaultSecretCacheOptions object.');
    super(keyRing, SecretNameMatching.exact, options.logger);

    const text = address instanceof URL ? address.href : address;
    if (typeof text !== 'string') throw new TypeError('address must be a string or a URL.');
    const api = vaultApiBase(text, 'a token');
    const settings = checked(options);
    this.#tokenProvider = tokenProvider;
    this.#tokenProtector = tokenProtector;
    this.#https = api.https;
    this.#hostname = api.hostname;
    this.#port = api.port;
    this.#ownAgent = !api.https || options.agent === undefined;
    // Keep-alive, so a fetch reuses a connection; a stale one is reset, and that attempt retried.
    this.#agent = !api.https ? new HttpAgent({ keepAlive: true }) : options.agent ?? new HttpsAgent({ keepAlive: true });
    this.#defaultKey = settings.defaultKey;
    this.#namespace = settings.namespace;
    this.#timeoutMs = settings.timeoutMs;
    this.#retryCount = settings.retryCount;
    this.#retryDelayMs = settings.retryDelayMs;
    if (settings.kvVersion === VaultKvVersion.v2) {
      this.#readBase = `${api.base}${settings.mountPath}/data/`;
      this.#dataPath = ['data', 'data'];
    } else {
      this.#readBase = `${api.base}${settings.mountPath}/`;
      this.#dataPath = ['data'];
    }
  }

  /**
   * Whether `name` is a secret's path: '/'-separated segments of ASCII letters, digits, '-', '_' and
   * '.', no segment "." or "..", at most {@link MAX_SECRET_NAME_LENGTH} characters. A key to read
   * follows it in a lookup, after '#' (see {@link RemoteSecretCache.isValidKey}).
   */
  static isValidSecretName(name: string | undefined | null): boolean {
    return typeof name === 'string' && name.length > 0 && name.length <= HashiCorpVaultSecretCache.MAX_SECRET_NAME_LENGTH
      && isValidVaultPath(name);
  }

  /**
   * Stops the cache reading Vault, and closes its connections (and its own agent; one given in the
   * options is the caller's). Cached secrets can still be read afterwards, but a lookup that would
   * read Vault rejects with ClosedError. Safe to call more than once.
   */
  close(): void {
    this.#closed = true;
    if (this.#ownAgent) this.#agent.destroy();
  }

  protected override defaultKey(): string {
    return this.#defaultKey;
  }

  protected override isValidName(name: string): boolean {
    return HashiCorpVaultSecretCache.isValidSecretName(name);
  }

  protected override async fetch(name: string, sink: SecretValueSink, signal?: AbortSignal): Promise<void> {
    this.#ensureOpen();
    // Asked for once per fetch; a provider's failure is its own to retry, so isn't retried here.
    const protectedToken = await this.#getToken(signal);

    for (let retry = 0; ; retry++) {
      this.#ensureOpen();
      try {
        await this.#read(name, protectedToken, sink, signal);
        return;
      } catch (error) {
        if (signal?.aborted === true || !TRANSIENT.has(error as object) || retry >= this.#retryCount || this.#closed) throw error;
      }
      // A failed attempt has handed nothing to sink: the body is read whole before anything is
      // parsed out of it, and a parse failure isn't transient.
      await delay(retryDelay(this.#retryDelayMs, retry, randomInt(0, 101)), signal);
    }
  }

  #ensureOpen(): void {
    if (this.#closed) throw new ClosedError('This HashiCorp Vault secret cache has been closed.');
  }

  // The protected token the provider returns, waited for within the timeout; the provider's signal
  // is aborted once it passes, or the lookup is aborted.
  async #getToken(signal: AbortSignal | undefined): Promise<string> {
    signal?.throwIfAborted();
    const timeout = new AbortController();
    const timer = setTimeout(() => timeout.abort(), this.#timeoutMs);
    const either = signal === undefined ? timeout.signal : AbortSignal.any([signal, timeout.signal]);
    let token: unknown;
    try {
      token = await untilAborted(Promise.resolve().then(() => this.#tokenProvider.getToken(either)), either);
    } catch (error) {
      if (signal?.aborted === true) throw signal.reason;
      if (timeout.signal.aborted) throw new DOMException(`The Vault token provider returned no token within ${this.#timeoutMs} ms.`, 'TimeoutError');
      throw error;
    } finally {
      clearTimeout(timer);
    }
    if (typeof token !== 'string' || token === '') throw invalidToken('The Vault token provider returned no token.');
    return token;
  }

  // One attempt: one request, and Vault's whole response, within the attempt's timeout.
  async #read(path: string, protectedToken: string, sink: SecretValueSink, signal: AbortSignal | undefined): Promise<void> {
    signal?.throwIfAborted();
    const attempt = new AbortController();
    const timer = setTimeout(() => attempt.abort(), this.#timeoutMs);
    const either = signal === undefined ? attempt.signal : AbortSignal.any([signal, attempt.signal]);
    let request: ClientRequest | undefined;
    let response: IncomingMessage | undefined;
    // Destroyed with an error, so whichever is being waited for fails at once; the catch below
    // replaces it with the abort's reason or the timeout.
    const abandon = () => {
      const abandoned = new Error('The read from Vault was abandoned.');
      request?.destroy(abandoned);
      response?.destroy(abandoned);
    };
    either.addEventListener('abort', abandon, { once: true });

    try {
      const sent = this.#send(path, protectedToken);
      request = sent;
      response = await new Promise<IncomingMessage>((resolve, reject) => {
        sent.on('response', resolve);
        // Kept for the request's life: an error after the response must find a listener.
        sent.on('error', (error) => reject(transient(error)));
        sent.end();
      });
      // A body's errors reach the reader through its iterator; this one keeps a late one quiet.
      response.on('error', () => undefined);
      try {
        await this.#readResponse(path, response.statusCode ?? 0, chunksOf(response), sink, either);
      } finally {
        if (!response.complete) response.destroy();
      }
    } catch (error) {
      if (signal?.aborted === true) throw signal.reason;
      if (attempt.signal.aborted) {
        throw transient(new DOMException(`Vault's response to the read of '${path}' took longer than ${this.#timeoutMs} ms.`, 'TimeoutError'));
      }
      throw error;
    } finally {
      clearTimeout(timer);
      either.removeEventListener('abort', abandon);
    }
  }

  // The request for path's secret, with the token protectedToken holds - decrypted into a buffer
  // zeroed once Node has the header's string.
  #send(path: string, protectedToken: string): ClientRequest {
    const { buffer, length } = this.#decryptToken(protectedToken);
    try {
      const headers: Record<string, string> = { 'X-Vault-Request': 'true' };
      if (this.#namespace !== undefined) headers['X-Vault-Namespace'] = this.#namespace;
      // Checked by decryptToken - printable ASCII - so latin1 is the token exactly.
      headers[TOKEN_HEADER] = Buffer.from(buffer.buffer, buffer.byteOffset, length).toString('latin1');
      return (this.#https ? httpsRequest : httpRequest)({
        hostname: this.#hostname, port: this.#port, path: this.#readBase + path, method: 'GET', agent: this.#agent, headers,
      });
    } finally {
      wipe(buffer);
    }
  }

  async #readResponse(path: string, status: number, body: AsyncIterable<Uint8Array>, sink: SecretValueSink, signal: AbortSignal): Promise<void> {
    if (status >= 200 && status < 300) {
      await SecretJsonBody.captureKeysAsync(body, sink, this.#dataPath, signal);
      return;
    }

    const errors = await ErrorResponseBody.readStringsAsync(body, 'errors', signal);

    // Nothing at the path: Vault answers 404 with an empty error list - or, for a KV version 2
    // secret whose latest version is deleted, with its metadata and none. A 404 naming an error (no
    // such mount) or that isn't Vault's JSON (a proxy's page) is a failure.
    if (status === 404 && errors !== undefined && errors.length === 0) return;

    const detail = errors !== undefined && errors.length > 0 ? `: ${errors.join('; ')}` : '';
    const error = new VaultRequestError(`Vault refused to read '${path}': HTTP ${status}${detail}`, status);
    if (error.isTransient) TRANSIENT.add(error);
    throw error;
  }

  // The token protectedToken holds, decrypted into a buffer the caller zeroes, and its length.
  // Refused unless it is protected by the token protector - it parses, its key version is on the
  // ring, and it authenticates under TOKEN_PURPOSE - and is a token. The protector's errors aren't
  // chained: a parser handed an unprotected token could quote it.
  #decryptToken(protectedToken: string): { buffer: Uint8Array; length: number } {
    let buffer: Uint8Array | undefined;
    let length = -1;
    try {
      const maxLength = this.#tokenProtector.maxDecryptedLength(protectedToken);
      if (Number.isSafeInteger(maxLength) && maxLength >= 0) {
        buffer = new Uint8Array(maxLength);
        length = this.#tokenProtector.decrypt(protectedToken, buffer);
      }
    } catch {
      length = -1;
    }
    if (buffer === undefined || !Number.isSafeInteger(length) || length < 0 || length > buffer.length) {
      wipe(buffer);
      throw invalidToken("The Vault token provider returned a token that isn't protected by the cache's token protector: "
        + 'hand over tokenProtector.encrypt(token), never the token itself.');
    }
    if (!isValidToken(buffer.subarray(0, length))) {
      wipe(buffer);
      throw invalidToken("The protected Vault token isn't a token: printable ASCII, with no spaces.");
    }
    return { buffer, length };
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

function invalidToken(message: string): HkdfGuardError {
  return new HkdfGuardError('ERR_HKDFGUARD_INVALID_VAULT_TOKEN', message);
}

// The response's chunks; an error reading them is a connection lost mid-response. Its partial
// bytes may hold the secret: the reader zeroes each chunk it copies.
async function* chunksOf(response: IncomingMessage): AsyncGenerator<Uint8Array> {
  try {
    for await (const chunk of response) yield chunk as Uint8Array;
  } catch (error) {
    throw transient(error);
  }
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

interface Settings {
  mountPath: string;
  kvVersion: VaultKvVersion;
  defaultKey: string;
  namespace: string | undefined;
  timeoutMs: number;
  retryCount: number;
  retryDelayMs: number;
}

function checked(options: HashiCorpVaultSecretCacheOptions): Settings {
  // Only an undefined member takes its default: null is a value of the wrong type.
  const or = <T>(value: T | undefined, fallback: T): T => (value === undefined ? fallback : value);
  const settings: Settings = {
    mountPath: or(options.mountPath, 'secret'),
    kvVersion: or(options.kvVersion, VaultKvVersion.v2),
    defaultKey: or(options.defaultKey, 'value'),
    namespace: options.namespace,
    timeoutMs: or(options.timeoutMs, DEFAULT_TIMEOUT_MS),
    retryCount: or(options.retryCount, Limits.MIN_RETRY_COUNT),
    retryDelayMs: or(options.retryDelayMs, DEFAULT_RETRY_DELAY_MS),
  };
  for (const [name, value] of [['mountPath', settings.mountPath], ['defaultKey', settings.defaultKey]] as const) {
    if (typeof value !== 'string') throw new TypeError(`${name} must be a string.`);
  }
  if (settings.namespace !== undefined && typeof settings.namespace !== 'string') throw new TypeError('namespace must be a string.');
  for (const [name, value] of [['kvVersion', settings.kvVersion], ['timeoutMs', settings.timeoutMs], ['retryCount', settings.retryCount],
    ['retryDelayMs', settings.retryDelayMs]] as const) {
    if (typeof value !== 'number') throw new TypeError(`${name} must be a number.`);
  }
  if (options.agent !== undefined && !(options.agent instanceof HttpAgent)) throw new TypeError('agent must be an https.Agent.');

  if (!isValidVaultPath(settings.mountPath)) throw new InvalidArgumentError(`The mount path '${settings.mountPath}' isn't a Vault path.`);
  if (!RemoteSecretCache.isValidKey(settings.defaultKey)) {
    throw new InvalidArgumentError(`The default key '${settings.defaultKey}' isn't a key: 1-${RemoteSecretCache.MAX_KEY_LENGTH} printable ASCII `
      + "characters other than space, '!' and '#'.");
  }
  if (settings.namespace !== undefined && !isValidVaultPath(settings.namespace)) {
    throw new InvalidArgumentError(`The namespace '${settings.namespace}' isn't a Vault path.`);
  }
  if (settings.kvVersion !== VaultKvVersion.v1 && settings.kvVersion !== VaultKvVersion.v2) {
    throw new InvalidArgumentError(`The KV version must be 1 or 2; it is ${settings.kvVersion}.`);
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

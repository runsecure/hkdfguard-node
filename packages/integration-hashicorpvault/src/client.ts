import { constants as bufferConstants } from 'node:buffer';
import { readFileSync } from 'node:fs';
import {
  Agent as HttpAgent, request as httpRequest, type IncomingMessage, type OutgoingHttpHeaders,
} from 'node:http';
import { request as httpsRequest } from 'node:https';
import { arch, release, type } from 'node:os';
import { join } from 'node:path';
import { ClosedError, InvalidArgumentError, type DataProtector } from '@runsecure/hkdfguard-abstractions';
import { delay, untilAborted } from '@runsecure/hkdfguard-abstractions/internal';
import { LogKeys, type Logger } from '@runsecure/hkdfguard-diagnostics';
import { readBody, SecureBuffer } from './body.js';
import { VaultRedirectError } from './client-errors.js';
import {
  checkMfaCredentials, copyHeaders, isValidNamespace, mergeHeaders, VaultClientOptions, VaultRequest, type HeaderMap, type VaultRequestCallback,
  type VaultRequestOptions, type VaultResponseCallback,
} from './client-options.js';
import { apiBase, isLoopback, MAX_TIMEOUT_MS, NAMESPACE_HEADER, REQUEST_HEADER } from './connection.js';
import { formatGoDuration } from './duration.js';
import { VaultRequestError } from './errors.js';
import { VaultApis } from './generated/apis.js';
import { checkProtectedToken, httpsAgentFor, putProtectedToken } from './http.js';
import { JsonValue, JsonWriter } from './json.js';
import { INDEX_HEADER, ReplicationForwardingMode, ReplicationStateCache } from './replication.js';
import { reasonPhrase, readResponse, responseError, VaultRawResponse, type VaultResponse } from './response.js';
import { defaultRetryPolicy, linearJitterBackoff, VaultRetryOptions, type Backoff, type RetryPolicy } from './retry.js';
import { queryParameters, queryString, SEND, v1Path, type Query } from './sender.js';
import { StaticVaultToken, TOKEN_PURPOSE, type VaultTokenProvider } from './token.js';

const HEALTH_PATH = '/v1/sys/health';
const WHOSE = "the client's token protector";

function packageVersion(): string {
  try {
    const version: unknown = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8')).version;
    return typeof version === 'string' ? version : '';
  } catch {
    return '';
  }
}

// library/version (OS; architecture; runtime), as vault-client-go's - only what a header can carry.
function userAgent(): string {
  const agent = `hkdfguard-integration-hashicorpvault/${packageVersion() || '0.0.0'} (${type()} ${release()}; ${arch()}; Node ${process.versions.node})`;
  return agent.replace(/[^\x20-\x7e]/g, ' ');
}

// The headers and callbacks a client adds to every request. Frozen: the client swaps in a new one
// when a setting changes, so a request in flight keeps the settings it started with.
interface Modifiers {
  readonly token: VaultTokenProvider | undefined;
  readonly namespace: string | undefined;
  readonly mfaCredentials: readonly string[];
  readonly responseWrappingTtlMs: number;
  readonly replicationForwardingMode: ReplicationForwardingMode;
  readonly customHeaders: HeaderMap;
  readonly requestCallbacks: readonly VaultRequestCallback[];
  readonly responseCallbacks: readonly VaultResponseCallback[];
}

// These with options' over them: options' single values win, its arrays are appended, and its
// headers replace these headers of the same name.
function merge(modifiers: Modifiers, options: VaultRequestOptions | undefined): Modifiers {
  if (options === undefined || options === null) return modifiers;
  if (typeof options !== 'object') throw new TypeError('options must be a VaultRequestOptions object.');
  const namespace = options.namespace;
  if (namespace !== undefined && namespace !== '' && !isValidNamespace(namespace)) {
    throw new RangeError(`The namespace '${String(namespace)}' contains non-printable characters.`);
  }
  const mfa = options.mfaCredentials ?? [];
  checkMfaCredentials(mfa);
  const headers = copyHeaders(options.customHeaders);
  const ttl = options.responseWrappingTtlMs;
  if (ttl !== undefined) checkTtl(ttl);
  const mode = options.replicationForwardingMode;
  if (mode !== undefined) checkMode(mode);
  return Object.freeze({
    token: options.token ?? modifiers.token,
    namespace: namespace || modifiers.namespace,
    mfaCredentials: [...modifiers.mfaCredentials, ...mfa],
    responseWrappingTtlMs: ttl || modifiers.responseWrappingTtlMs,
    replicationForwardingMode: mode !== undefined && mode !== ReplicationForwardingMode.none ? mode : modifiers.replicationForwardingMode,
    customHeaders: headers.size > 0 ? mergeHeaders(modifiers.customHeaders, headers) : modifiers.customHeaders,
    requestCallbacks: [...modifiers.requestCallbacks, ...checkCallbacks(options.requestCallbacks ?? [])],
    responseCallbacks: [...modifiers.responseCallbacks, ...checkCallbacks(options.responseCallbacks ?? [])],
  });
}

// Where a request goes: scheme, host and port, and the path with its query.
interface Target {
  readonly https: boolean;
  readonly hostname: string;
  readonly port: number | undefined;
  readonly path: string;
}

function urlOf(target: Target): string {
  const host = target.hostname.includes(':') ? `[${target.hostname}]` : target.hostname;
  return `${target.https ? 'https' : 'http'}://${host}${target.port === undefined ? '' : `:${target.port}`}${target.path}`;
}

interface Sent {
  readonly request: VaultRequest;
  readonly response: IncomingMessage;
  // Stops the request's signal destroying the response: for a raw response, whose body outlives it.
  readonly release: () => void;
}

// What every copy of a client shares.
interface Shared {
  readonly https: boolean;
  readonly hostname: string;
  readonly port: number | undefined;
  readonly prefix: string;
  readonly options: VaultClientOptions;
  readonly tokenProtector: DataProtector;
  readonly logger: Logger | undefined;
  readonly requestTimeoutMs: number;
  readonly maxResponseBytes: number;
  readonly retryWaitMinMs: number;
  readonly retryWaitMaxMs: number;
  readonly retryMax: number;
  readonly checkRetry: RetryPolicy;
  readonly backoff: Backoff;
  readonly httpsAgent: HttpAgent;
  readonly ownHttpsAgent: boolean;
  readonly httpAgent: HttpAgent;
  closed: boolean;
}

// The request's deadline passed: it fails with a TimeoutError naming it.
class DeadlineExceeded extends Error {}

// A request's deadline and abort: the caller's signal and the request timeout in one.
class Deadline {
  readonly signal: AbortSignal | undefined;
  readonly #caller: AbortSignal | undefined;
  readonly #timeout: AbortController | undefined;
  readonly #timer: NodeJS.Timeout | undefined;
  readonly #end: number;

  constructor(timeoutMs: number, caller: AbortSignal | undefined) {
    this.#caller = caller;
    this.#end = timeoutMs > 0 ? performance.now() + timeoutMs : Infinity;
    if (timeoutMs > 0) {
      this.#timeout = new AbortController();
      this.#timer = setTimeout(() => this.#timeout!.abort(new DeadlineExceeded()), timeoutMs);
    }
    this.signal = this.#timeout === undefined ? caller : caller === undefined ? this.#timeout.signal : AbortSignal.any([caller, this.#timeout.signal]);
  }

  get remainingMs(): number {
    return this.#end - performance.now();
  }

  // Throws the caller's reason once it has aborted, or DeadlineExceeded once the deadline has passed.
  check(): void {
    if (this.#caller?.aborted === true) throw this.#caller.reason;
    if (this.#timeout?.signal.aborted === true || this.remainingMs <= 0) throw new DeadlineExceeded();
  }

  // The error to fail with in place of `error`, now that the request has failed with it.
  failure(error: unknown): unknown {
    if (this.#caller?.aborted === true) return this.#caller.reason;
    if (this.#timeout?.signal.aborted === true || error instanceof DeadlineExceeded) return new DeadlineExceeded();
    return error;
  }

  dispose(): void {
    clearTimeout(this.#timer);
  }
}

/**
 * A HashiCorp Vault client: the Node port of vault-client-go, and of the .NET, Java and Python
 * HkdfGuard VaultClient. The generic {@link read}, {@link write}, {@link list} and {@link delete}
 * reach any path; the methods generated from Vault's OpenAPI spec reach the endpoints generator.json
 * names, typed, grouped as {@link auth}, {@link secrets} and {@link system}.
 *
 * Tokens are held only protected - encrypted by the client's token protector, a protector on a key
 * ring (`keyRing.createProtector(VaultClient.TOKEN_PURPOSE)`) - and supplied by a
 * {@link VaultTokenProvider}. A token is decrypted only as a request is sent, into a buffer zeroed
 * once Node has the header's string (Node takes headers only as strings, which JavaScript can't
 * erase; see @runsecure/hkdfguard-cache-hashicorpvault). A token Vault returns (a login's, a
 * wrapping token) is protected straight from the response's bytes, never a string. Request and
 * response bodies are held in buffers zeroed after use; what a generated model holds, though, is
 * ordinary strings.
 *
 * Defaults are stricter than vault-client-go's: Vault's address must be https except on loopback,
 * and redirects - which would carry the token wherever they point - fail with
 * {@link VaultRedirectError} unless {@link VaultClientOptions.followRedirects} is set. Failures are
 * retried as vault-client-go retries them ({@link VaultRetryOptions}).
 *
 * Every method returns a promise. A request rejects with {@link VaultResponseError} when Vault
 * refuses it, with {@link VaultRedirectError} for a redirect it won't follow, with Node's network
 * error (ECONNREFUSED, ENOTFOUND...) when Vault can't be reached, with a DOMException named
 * TimeoutError when it outlives {@link VaultClientOptions.requestTimeoutMs}, with the signal's reason
 * when {@link VaultRequestOptions.signal} aborts it, and with {@link VaultJsonError} when the answer
 * isn't the JSON expected.
 *
 * Settings changed with the set and clear methods apply to requests started afterwards. Requests
 * share keep-alive connections; {@link close} the client to release them.
 */
export class VaultClient extends VaultApis {
  /**
   * The purpose to create the token protector with - `keyRing.createProtector(TOKEN_PURPOSE)` - so a
   * token protected for the client can't be decrypted as anything else, nor anything else as it.
   */
  static readonly TOKEN_PURPOSE = TOKEN_PURPOSE;

  /** The User-Agent every request carries. */
  static readonly USER_AGENT = userAgent();

  // What copy hands the constructor: private fields can be set only there.
  static #copying: { shared: Shared; modifiers: Modifiers; replicationStates: ReplicationStateCache | undefined } | undefined;

  readonly #shared: Shared;
  readonly #owner: boolean;
  #modifiers: Modifiers;
  #replicationStates: ReplicationStateCache | undefined;

  /**
   * @param tokenProtector protects and decrypts tokens: a protector on the key ring,
   *   `keyRing.createProtector(TOKEN_PURPOSE)`. Every token the client is given must be protected by it.
   * @param options how to reach Vault; omitted for the defaults (https://127.0.0.1:8200)
   * @param logger where retries and followed redirects are logged (paths only, never a query); omitted for none
   * @throws TypeError tokenProtector is missing, or an option is of the wrong type
   * @throws InvalidArgumentError the address isn't https (or http on loopback, or with
   *   allowUnencryptedHttp), or holds credentials, a query or a fragment; the namespace can't be
   *   sent; the request timeout or a retry wait is negative; both agent and tls are given; or a
   *   certificate can't be read
   */
  constructor(tokenProtector: DataProtector, options: VaultClientOptions = {}, logger?: Logger) {
    super();
    const copying = VaultClient.#copying;
    if (copying !== undefined) {
      VaultClient.#copying = undefined;
      this.#shared = copying.shared;
      this.#owner = false;
      this.#modifiers = copying.modifiers;
      this.#replicationStates = copying.replicationStates;
      return;
    }
    if (tokenProtector === undefined || tokenProtector === null) throw new TypeError('tokenProtector must not be undefined.');
    if (options === null || typeof options !== 'object') throw new TypeError('options must be a VaultClientOptions object.');
    const address = options.address ?? VaultClientOptions.DEFAULT_ADDRESS;
    if (typeof address !== 'string') throw new TypeError('address must be a string.');
    const base = apiBase(address, 'a token', { allowUnencryptedHttp: options.allowUnencryptedHttp === true });
    const requestTimeoutMs = options.requestTimeoutMs ?? VaultClientOptions.DEFAULT_REQUEST_TIMEOUT_MS;
    // Node's timers hold at most MAX_TIMEOUT_MS; a longer one fires at once, timing out every request.
    if (typeof requestTimeoutMs !== 'number' || !(requestTimeoutMs >= 0 && requestTimeoutMs <= MAX_TIMEOUT_MS)) {
      throw new InvalidArgumentError(`The request timeout must be 0 (none) to ${MAX_TIMEOUT_MS} ms; it is ${requestTimeoutMs}.`);
    }
    const maxResponseBytes = options.maxResponseBytes ?? VaultClientOptions.DEFAULT_MAX_RESPONSE_BYTES;
    if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1 || maxResponseBytes >= bufferConstants.MAX_LENGTH) {
      throw new InvalidArgumentError(`The largest response must be a positive whole number of bytes below ${bufferConstants.MAX_LENGTH}; it is ${String(maxResponseBytes)}.`);
    }
    const retry = options.retry ?? {};
    const retryWaitMinMs = retry.retryWaitMinMs ?? VaultRetryOptions.DEFAULT_RETRY_WAIT_MIN_MS;
    const retryWaitMaxMs = retry.retryWaitMaxMs ?? VaultRetryOptions.DEFAULT_RETRY_WAIT_MAX_MS;
    if (!(retryWaitMinMs >= 0 && retryWaitMinMs <= MAX_TIMEOUT_MS) || !(retryWaitMaxMs >= 0 && retryWaitMaxMs <= MAX_TIMEOUT_MS)) {
      throw new InvalidArgumentError(`The retry waits must be 0 to ${MAX_TIMEOUT_MS} ms.`);
    }
    const namespace = options.namespace;
    if (namespace !== undefined && namespace !== '' && !isValidNamespace(namespace)) {
      throw new InvalidArgumentError(`The namespace '${String(namespace)}' contains non-printable characters.`);
    }
    // The TLS settings read once, here: a certificate that can't be read fails the constructor.
    const https = httpsAgentFor(options.agent, options.tls);

    this.#shared = {
      https: base.https, hostname: base.hostname, port: base.port, prefix: base.prefix,
      options, tokenProtector, logger, requestTimeoutMs, maxResponseBytes, retryWaitMinMs, retryWaitMaxMs,
      retryMax: retry.retryMax ?? VaultRetryOptions.DEFAULT_RETRY_MAX,
      checkRetry: retry.checkRetry ?? defaultRetryPolicy,
      backoff: retry.backoff ?? linearJitterBackoff,
      httpsAgent: https.agent, ownHttpsAgent: https.own, httpAgent: new HttpAgent({ keepAlive: true }), closed: false,
    };
    this.#owner = true;
    this.#replicationStates = options.enforceReadYourWritesConsistency === true ? new ReplicationStateCache() : undefined;
    this.#modifiers = Object.freeze({
      token: options.token, namespace: namespace || undefined, mfaCredentials: [], responseWrappingTtlMs: 0,
      replicationForwardingMode: ReplicationForwardingMode.none, customHeaders: new Map(), requestCallbacks: [], responseCallbacks: [],
    });
  }

  /** The options the client was created with. */
  get options(): VaultClientOptions {
    return this.#shared.options;
  }

  /**
   * A client with this one's options, settings (token, namespace, headers, callbacks...) and
   * replication states, which then change independently. It shares this client's connections:
   * closing it does nothing, and it can't be used once this client is closed.
   */
  copy(): VaultClient {
    VaultClient.#copying = { shared: this.#shared, modifiers: this.#modifiers, replicationStates: this.#replicationStates?.copy() };
    try {
      return new VaultClient(undefined as unknown as DataProtector);
    } finally {
      VaultClient.#copying = undefined;
    }
  }

  /**
   * Closes the client: a request started afterwards rejects with ClosedError, and the connections
   * are closed (its own agents; one given in the options is the caller's). A copy's close does
   * nothing. Safe to call more than once.
   */
  close(): void {
    if (!this.#owner) return;
    this.#shared.closed = true;
    this.#shared.httpAgent.destroy();
    if (this.#shared.ownHttpsAgent) this.#shared.httpsAgent.destroy();
  }

  // --- Settings ----------------------------------------------------------------------------------

  /**
   * `token`, protected by the client's token protector: for {@link setToken} or
   * {@link VaultRequestOptions.token}. A string can't be erased: keep no other reference to it - or
   * hand over its bytes, and zero them once this returns.
   * @throws InvalidArgumentError token is empty, or isn't printable ASCII without spaces
   */
  protectToken(token: string | Uint8Array): StaticVaultToken {
    return StaticVaultToken.protect(this.#shared.tokenProtector, token);
  }

  /**
   * Makes every later request with `token` - protected first if it is a string or bytes (see
   * {@link protectToken}) - unless the request sets its own; see
   * https://developer.hashicorp.com/vault/docs/concepts/tokens.
   */
  setToken(token: VaultTokenProvider | string | Uint8Array): void {
    const provider = typeof token === 'string' || token instanceof Uint8Array ? this.protectToken(token) : token;
    if (provider === undefined || provider === null || typeof provider.getToken !== 'function') {
      throw new TypeError('token must be a VaultTokenProvider, a string or a Uint8Array.');
    }
    this.#update({ token: provider });
  }

  /** Makes later requests without a token, unless they set their own. */
  clearToken(): void {
    this.#update({ token: undefined });
  }

  /**
   * Makes every later request in `namespace`, unless the request sets its own; empty for none. See
   * https://developer.hashicorp.com/vault/docs/enterprise/namespaces.
   * @throws RangeError namespace contains non-printable characters
   */
  setNamespace(namespace: string): void {
    if (typeof namespace !== 'string') throw new TypeError('namespace must be a string.');
    if (!isValidNamespace(namespace)) throw new RangeError(`The namespace '${namespace}' contains non-printable characters.`);
    this.#update({ namespace: namespace || undefined });
  }

  /** Makes later requests in no namespace, unless they set their own. */
  clearNamespace(): void {
    this.#update({ namespace: undefined });
  }

  /**
   * Sends `credentials` (X-Vault-MFA) with every later request; see
   * https://developer.hashicorp.com/vault/docs/auth/login-mfa.
   * @throws RangeError a credential is empty or not printable ASCII
   */
  setMfaCredentials(...credentials: string[]): void {
    checkMfaCredentials(credentials);
    this.#update({ mfaCredentials: [...credentials] });
  }

  /** Stops sending MFA credentials. */
  clearMfaCredentials(): void {
    this.#update({ mfaCredentials: [] });
  }

  /**
   * Asks Vault to wrap every later response for `ttlMs` milliseconds (X-Vault-Wrap-TTL); zero to
   * stop. See https://developer.hashicorp.com/vault/docs/concepts/response-wrapping.
   * @throws RangeError ttlMs is negative
   */
  setResponseWrapping(ttlMs: number): void {
    checkTtl(ttlMs);
    this.#update({ responseWrappingTtlMs: ttlMs });
  }

  /** Stops asking Vault to wrap responses. */
  clearResponseWrapping(): void {
    this.#update({ responseWrappingTtlMs: 0 });
  }

  /**
   * Adds `headers` to every later request, replacing those set before; names starting X-Vault- are refused.
   * @throws RangeError a header has no name, is named X-Vault-*, or can't be sent
   */
  setCustomHeaders(headers: Readonly<Record<string, readonly string[]>>): void {
    if (headers === undefined || headers === null) throw new TypeError('headers must not be undefined.');
    this.#update({ customHeaders: copyHeaders(headers) });
  }

  /** Stops adding custom headers. */
  clearCustomHeaders(): void {
    this.#update({ customHeaders: new Map() });
  }

  /** Calls `callbacks` with each attempt's request before it's sent (without its token), replacing those set before. */
  setRequestCallbacks(...callbacks: VaultRequestCallback[]): void {
    this.#update({ requestCallbacks: checkCallbacks(callbacks) });
  }

  /** Stops calling request callbacks. */
  clearRequestCallbacks(): void {
    this.#update({ requestCallbacks: [] });
  }

  /** Calls `callbacks` once Vault has answered each request, replacing those set before. */
  setResponseCallbacks(...callbacks: VaultResponseCallback[]): void {
    this.#update({ responseCallbacks: checkCallbacks(callbacks) });
  }

  /** Stops calling response callbacks. */
  clearResponseCallbacks(): void {
    this.#update({ responseCallbacks: [] });
  }

  /**
   * Sends a forwarding header with every later request (Vault Enterprise): X-Vault-Forward for
   * always, X-Vault-Inconsistent for inconsistent, none for none.
   */
  setReplicationForwardingMode(mode: ReplicationForwardingMode): void {
    checkMode(mode);
    this.#update({ replicationForwardingMode: mode });
  }

  /** Stops sending a forwarding header. */
  clearReplicationForwardingMode(): void {
    this.#update({ replicationForwardingMode: ReplicationForwardingMode.none });
  }

  /** Whether `error` - or the first {@link VaultRequestError} among its causes - is Vault answering with `status`. */
  static isErrorStatus(error: unknown, status: number): boolean {
    for (let current = error, depth = 0; typeof current === 'object' && current !== null && depth < 16; depth++) {
      if (current instanceof VaultRequestError) return current.statusCode === status;
      current = (current as { cause?: unknown }).cause;
    }
    return false;
  }

  // --- Generic requests ----------------------------------------------------------------------------

  /**
   * Reads the value at `path` (GET /v1/path).
   * @param path the path under /v1/, with or without that prefix
   * @returns Vault's response; undefined if it has no body
   */
  async read(path: string, options?: VaultRequestOptions): Promise<VaultResponse<Record<string, JsonValue>> | undefined> {
    return this[SEND]('GET', v1Path(path), undefined, queryParameters(options), options, readJsonRecord);
  }

  /**
   * Reads `path` (GET /v1/path) and returns Vault's response as it is: not parsed, not checked for
   * an error status, and its body not bound by {@link VaultClientOptions.requestTimeoutMs} - for a
   * large or streamed body. Close it once read.
   */
  async readRaw(path: string, options?: VaultRequestOptions): Promise<VaultRawResponse> {
    const v1 = v1Path(path);
    const modifiers = merge(this.#modifiers, options);
    const query = queryParameters(options);
    const deadline = new Deadline(this.#shared.requestTimeoutMs, options?.signal);
    try {
      const sent = await this.#sendCore('GET', v1, undefined, query, modifiers, deadline);
      // The body isn't bound by the timeout.
      sent.release();
      return new VaultRawResponse(sent.response);
    } catch (error) {
      throw this.#failure(deadline, error, 'GET', v1);
    } finally {
      deadline.dispose();
    }
  }

  /** Writes `body`, as a JSON object, to `path` (POST /v1/path). Its values are written as {@link JsonWriter.value} writes them. */
  async write(path: string, body: Readonly<Record<string, unknown>>, options?: VaultRequestOptions): Promise<VaultResponse<Record<string, JsonValue>> | undefined> {
    if (body === undefined || body === null || typeof body !== 'object' || Array.isArray(body)) throw new TypeError('body must be an object.');
    return this[SEND]('POST', v1Path(path), (writer) => writer.value(body), queryParameters(options), options, readJsonRecord);
  }

  /**
   * Writes `body` as it is to `path` (POST /v1/path). It is sent from the buffer itself, every
   * attempt: leave it unchanged until this settles, then clear it if it holds a secret.
   */
  async writeFromBytes(path: string, body: Uint8Array, options?: VaultRequestOptions): Promise<VaultResponse<Record<string, JsonValue>> | undefined> {
    if (!(body instanceof Uint8Array)) throw new TypeError('body must be a Uint8Array.');
    return this.#execute('POST', v1Path(path), body, queryParameters(options), options, readJsonRecord);
  }

  /**
   * Writes what `body` (a stream, or any async iterable of bytes) holds to `path` (POST /v1/path).
   * It's read whole first - into a buffer zeroed afterwards - so a retry can send it again. The
   * chunks themselves are the stream's, which this can't zero.
   */
  async writeFromStream(path: string, body: AsyncIterable<Uint8Array | string>, options?: VaultRequestOptions): Promise<VaultResponse<Record<string, JsonValue>> | undefined> {
    if (body === undefined || body === null || typeof (body as AsyncIterable<unknown>)[Symbol.asyncIterator] !== 'function') {
      throw new TypeError('body must be a stream or an async iterable of bytes.');
    }
    const v1 = v1Path(path);
    const buffer = new SecureBuffer();
    try {
      for await (const chunk of body) buffer.write(typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk);
      return await this.#execute('POST', v1, buffer.view(), queryParameters(options), options, readJsonRecord);
    } finally {
      buffer.close();
    }
  }

  /** Lists the keys at `path` (GET /v1/path?list=true). */
  async list(path: string, options?: VaultRequestOptions): Promise<VaultResponse<Record<string, JsonValue>> | undefined> {
    const query = queryParameters(options);
    query.push(['list', 'true']);
    return this[SEND]('GET', v1Path(path), undefined, query, options, readJsonRecord);
  }

  /** Deletes the value at `path` (DELETE /v1/path). */
  async delete(path: string, options?: VaultRequestOptions): Promise<VaultResponse<Record<string, JsonValue>> | undefined> {
    return this[SEND]('DELETE', v1Path(path), undefined, queryParameters(options), options, readJsonRecord);
  }

  /**
   * The response `wrappingToken` wraps (PUT /v1/sys/wrapping/unwrap, made with that token), its
   * data read with `reader` - the read of the model the wrapped method returns, e.g.
   * `KvV2ReadResponse.read`; JSON values by default. See
   * https://developer.hashicorp.com/vault/docs/concepts/response-wrapping.
   * @param wrappingToken the wrapping token - {@link VaultResponseWrapInfo.token}, or one protected with {@link protectToken}
   * @throws VaultResponseError Vault refuses the token: unknown, expired or already used
   */
  unwrap(wrappingToken: VaultTokenProvider, options?: VaultRequestOptions): Promise<VaultResponse<Record<string, JsonValue>> | undefined>;
  unwrap<T>(wrappingToken: VaultTokenProvider, reader: (json: JsonValue) => T | undefined, options?: VaultRequestOptions): Promise<VaultResponse<T> | undefined>;
  async unwrap<T>(
    wrappingToken: VaultTokenProvider, readerOrOptions?: ((json: JsonValue) => T | undefined) | VaultRequestOptions, options?: VaultRequestOptions,
  ): Promise<VaultResponse<unknown> | undefined> {
    if (wrappingToken === undefined || wrappingToken === null || typeof wrappingToken.getToken !== 'function') {
      throw new TypeError('wrappingToken must be a VaultTokenProvider.');
    }
    const reader: (json: JsonValue) => unknown = typeof readerOrOptions === 'function' ? readerOrOptions : readJsonRecord;
    const given = typeof readerOrOptions === 'function' ? options : readerOrOptions;
    return this[SEND]('PUT', '/v1/sys/wrapping/unwrap', undefined, [], { ...given, token: wrappingToken }, reader);
  }

  // --- Sending -------------------------------------------------------------------------------------

  /** Sends one request for the generated API and the generic methods; see {@link VaultSender}. */
  [SEND]<T>(
    method: string, path: string, body: ((writer: JsonWriter) => void) | undefined, query: Query, options: VaultRequestOptions | undefined,
    reader: (json: JsonValue) => T | undefined,
  ): Promise<VaultResponse<T> | undefined> {
    // Written before anything is awaited, so a model the caller changes afterwards isn't half-sent.
    let json: SecureBuffer | undefined;
    try {
      if (body !== undefined) {
        json = new SecureBuffer();
        body(new JsonWriter(json));
      }
    } catch (error) {
      json?.close();
      return Promise.reject(error);
    }
    return this.#execute(method, path, json?.view(), query, options, reader).finally(() => json?.close());
  }

  #update(changes: Partial<Modifiers>): void {
    this.#modifiers = Object.freeze({ ...this.#modifiers, ...changes });
  }

  // One request within the request timeout: sent, its whole body read, and parsed.
  async #execute<T>(
    method: string, path: string, body: Uint8Array | undefined, query: Query, options: VaultRequestOptions | undefined,
    reader: (json: JsonValue) => T | undefined,
  ): Promise<VaultResponse<T> | undefined> {
    const modifiers = merge(this.#modifiers, options);
    const deadline = new Deadline(this.#shared.requestTimeoutMs, options?.signal);
    try {
      const sent = await this.#sendCore(method, path, body, query, modifiers, deadline);
      let content: SecureBuffer | undefined;
      try {
        const limit = this.#shared.maxResponseBytes;
        const status = sent.response.statusCode ?? 0;
        try {
          // The first buffer is sized from Content-Length, which is only Vault's word: never past the limit.
          const declared = Number(sent.response.headers['content-length'] ?? 0) || 0;
          content = await readBody(sent.response, limit, Math.min(declared, limit));
        } catch (error) {
          deadline.check();
          // Its partial bytes may hold a secret: neither kept nor chained.
          throw Object.assign(new Error(`The connection was lost during Vault's response to ${method} ${withoutQuery(sent.request.url)}.`),
            { code: (error as { code?: unknown }).code ?? 'ECONNRESET' });
        }
        if (content === undefined) {
          // What was read is already zeroed; the rest is never read, and the connection is dropped below.
          throw new VaultRequestError(`Vault's response to ${method} ${withoutQuery(sent.request.url)} is longer than ${limit} bytes `
            + '(VaultClientOptions.maxResponseBytes); it was not read.', { statusCode: status });
        }
        // sys/health answers 429, 472, 473, 501 and 503 with the health status itself.
        if (!(status >= 200 && status <= 399) && path !== HEALTH_PATH) throw responseError(status, content.view(), sent.request.method, sent.request.url);
        return readResponse(content.view(), this.#shared.tokenProtector, reader);
      } finally {
        content?.close();
        sent.release();
        if (!sent.response.complete) sent.response.destroy();
      }
    } catch (error) {
      throw this.#failure(deadline, error, method, path);
    } finally {
      deadline.dispose();
    }
  }

  #failure(deadline: Deadline, error: unknown, method: string, path: string): unknown {
    const failure = deadline.failure(error);
    if (failure instanceof DeadlineExceeded) {
      return new DOMException(`Vault didn't answer ${method} ${withoutQuery(path)} within ${this.#shared.requestTimeoutMs} ms.`, 'TimeoutError');
    }
    return failure;
  }

  // Sends the request, retrying and following a redirect as configured, and calls the response
  // callbacks. The body of the response it returns is unread; the caller releases it.
  async #sendCore(method: string, path: string, body: Uint8Array | undefined, query: Query, modifiers: Modifiers, deadline: Deadline): Promise<Sent> {
    const shared = this.#shared;
    if (shared.closed) throw new ClosedError('This Vault client has been closed.');
    let target: Target = { https: shared.https, hostname: shared.hostname, port: shared.port, path: shared.prefix + path + queryString(query) };

    const limiter = shared.options.rateLimiter;
    if (limiter !== undefined && !(await limiter.acquire(deadline.remainingMs, deadline.signal))) throw new DeadlineExceeded();
    const states = this.#replicationStates?.snapshot() ?? [];

    // Asked for once per request; a provider's failure is its own to retry, so isn't retried here.
    const protectedToken = modifiers.token === undefined ? undefined : await this.#getToken(modifiers.token, deadline);

    for (let redirects = 1; ; redirects--) {
      const sent = await this.#sendWithRetries(method, target, path, body, modifiers, states, protectedToken, deadline);
      let location: Target | undefined;
      try {
        location = this.#redirectTarget(sent, redirects);
        if (location === undefined) {
          for (const callback of modifiers.responseCallbacks) callback(sent.request, sent.response.statusCode ?? 0, sent.response.headers);
          this.#replicationStates?.record(sent.response.headers);
          return sent;
        }
      } catch (error) {
        discard(sent);
        throw error;
      }
      shared.logger?.info?.(`Vault redirected ${method} ${withoutQuery(path)} to ${withoutQuery(urlOf(location))}; following it.`,
        { [LogKeys.eventId]: 2, [LogKeys.eventName]: 'VaultRedirectFollowed' });
      discard(sent);
      target = location;
    }
  }

  // Where a redirect response says to go, if following it is allowed; undefined if it isn't one.
  #redirectTarget(sent: Sent, redirects: number): Target | undefined {
    const status = sent.response.statusCode ?? 0;
    if (status !== 301 && status !== 302 && status !== 307) return undefined;

    const request = sent.request;
    const header = sent.response.headers.location;
    let location: URL | undefined;
    if (header) {
      try {
        location = new URL(header, request.url);
      } catch {
        location = undefined;
      }
    }
    if (location === undefined || location.hostname === '') throw new VaultRedirectError(status, 'could not read the redirect location', undefined, request.method, request.url);
    const text = location.href;
    if (this.#shared.options.followRedirects !== true) throw new VaultRedirectError(status, 'redirects are disabled', text, request.method, request.url);
    if (redirects <= 0) throw new VaultRedirectError(status, 'at most one redirect is allowed', text, request.method, request.url);

    const scheme = location.protocol;
    const hostname = location.hostname.startsWith('[') ? location.hostname.slice(1, -1) : location.hostname;
    if (request.url.toLowerCase().startsWith('https:') && scheme !== 'https:') {
      throw new VaultRedirectError(status, 'the redirect would cause a protocol downgrade', text, request.method, request.url);
    }
    if (scheme !== 'https:' && !(scheme === 'http:' && (isLoopback(location.hostname) || this.#shared.options.allowUnencryptedHttp === true))) {
      throw new VaultRedirectError(status, 'the redirect would send the token over unencrypted http', text, request.method, request.url);
    }
    return { https: scheme === 'https:', hostname, port: location.port === '' ? undefined : Number(location.port), path: location.pathname + location.search };
  }

  // One request, sent until it succeeds, fails in a way not worth retrying, or runs out of retries.
  async #sendWithRetries(
    method: string, target: Target, path: string, body: Uint8Array | undefined, modifiers: Modifiers, states: readonly string[],
    protectedToken: string | undefined, deadline: Deadline,
  ): Promise<Sent> {
    const shared = this.#shared;
    for (let attempt = 0; ; attempt++) {
      const request = createRequest(method, target, body, modifiers, states);
      for (const callback of modifiers.requestCallbacks) callback(request);

      let sent: Sent | undefined;
      let failure: unknown;
      try {
        sent = await this.#sendOnce(target, request, body, protectedToken, deadline);
      } catch (error) {
        deadline.check();
        if (error instanceof DeadlineExceeded || attempt >= shared.retryMax || !shared.checkRetry(0, error)) throw error;
        failure = error;
      }

      const status = sent?.response.statusCode ?? 0;
      if (sent !== undefined && (attempt >= shared.retryMax || !shared.checkRetry(status, undefined))) return sent;

      let delayMs = shared.backoff(shared.retryWaitMinMs, shared.retryWaitMaxMs, attempt, status);
      if (typeof delayMs !== 'number' || !(delayMs >= 0)) delayMs = 0;
      if (sent !== undefined) discard(sent);
      if (delayMs >= deadline.remainingMs) throw new DeadlineExceeded();

      const cause = failure === undefined ? `${status}${reasonPhrase(status)}` : String((failure as Error)?.message ?? failure);
      shared.logger?.warn?.(`Vault request ${method} ${withoutQuery(path)} failed (${cause}); retry ${attempt + 1} of ${shared.retryMax} in ${delayMs} ms.`,
        { [LogKeys.eventId]: 1, [LogKeys.eventName]: 'VaultRequestRetried' });
      await delay(delayMs, deadline.signal);
    }
  }

  // One attempt: the request with the token, if any, in its header - decrypted into a buffer zeroed
  // once Node has the header's string. Resolves once Vault's response has its headers.
  #sendOnce(target: Target, request: VaultRequest, body: Uint8Array | undefined, protectedToken: string | undefined, deadline: Deadline): Promise<Sent> {
    deadline.check();
    const headers: OutgoingHttpHeaders = {};
    for (const [name, value] of request.headers) {
      const existing = headers[name];
      headers[name] = existing === undefined ? value : [...(Array.isArray(existing) ? existing : [String(existing)]), value];
    }
    if (body !== undefined) headers['Content-Length'] = String(body.length);
    if (protectedToken !== undefined) putProtectedToken(headers, this.#shared.tokenProtector, protectedToken, WHOSE);

    const shared = this.#shared;
    const sent = (target.https ? httpsRequest : httpRequest)({
      hostname: target.hostname, port: target.port, path: target.path, method: request.method, headers,
      agent: target.https ? shared.httpsAgent : shared.httpAgent,
    });
    let response: IncomingMessage | undefined;
    // Destroyed with an error, so whatever is being waited for fails at once; the caller replaces
    // it with the abort's reason or the timeout.
    const abandon = () => {
      const abandoned = new Error('The Vault request was abandoned.');
      sent.destroy(abandoned);
      response?.destroy(abandoned);
    };
    const signal = deadline.signal;
    signal?.addEventListener('abort', abandon, { once: true });
    const release = () => signal?.removeEventListener('abort', abandon);
    return new Promise<Sent>((resolve, reject) => {
      sent.on('response', (answer: IncomingMessage) => {
        response = answer;
        // A body's errors reach the reader through its iterator; this one keeps a late one quiet.
        answer.on('error', () => undefined);
        resolve({ request, response: answer, release });
      });
      // Kept for the request's life: an error after the response must find a listener.
      sent.on('error', (error) => {
        release();
        reject(error);
      });
      sent.end(body === undefined ? undefined : Buffer.from(body.buffer, body.byteOffset, body.length));
    });
  }

  // The protected token the provider returns, waited for within the deadline.
  async #getToken(provider: VaultTokenProvider, deadline: Deadline): Promise<string> {
    deadline.check();
    const signal = deadline.signal ?? new AbortController().signal;
    return checkProtectedToken(await untilAborted(Promise.resolve().then(() => provider.getToken(signal)), deadline.signal));
  }
}

// --- Internals ---------------------------------------------------------------------------------------

function readJsonRecord(json: JsonValue): Record<string, JsonValue> | undefined {
  return json.readJsonRecord();
}

// A request carrying the client's headers, as vault-client-go's newRequest builds it; the token is
// added only as it's sent.
function createRequest(method: string, target: Target, body: Uint8Array | undefined, modifiers: Modifiers, states: readonly string[]): VaultRequest {
  const headers: [string, string][] = [[REQUEST_HEADER, 'true']];
  if (modifiers.namespace) headers.push([NAMESPACE_HEADER, modifiers.namespace]);
  let contentType = false;
  for (const [name, values] of modifiers.customHeaders) {
    contentType ||= name.toLowerCase() === 'content-type';
    for (const value of values) headers.push([name, value]);
  }
  if (body !== undefined && !contentType) headers.push(['Content-Type', 'application/json']);
  headers.push(['User-Agent', VaultClient.USER_AGENT]);
  for (const credential of modifiers.mfaCredentials) headers.push(['X-Vault-MFA', credential]);
  if (modifiers.responseWrappingTtlMs > 0) headers.push(['X-Vault-Wrap-TTL', formatGoDuration(modifiers.responseWrappingTtlMs)]);
  if (modifiers.replicationForwardingMode === ReplicationForwardingMode.always) headers.push(['X-Vault-Forward', 'active-node']);
  else if (modifiers.replicationForwardingMode === ReplicationForwardingMode.inconsistent) headers.push(['X-Vault-Inconsistent', 'forward-active-node']);
  for (const state of states) headers.push([INDEX_HEADER, state]);
  return new VaultRequest(method, urlOf(target), headers);
}

// A response not to be read: its connection freed for the next request.
function discard(sent: Sent): void {
  sent.release();
  sent.response.resume();
}

function checkTtl(ttlMs: unknown): void {
  if (typeof ttlMs !== 'number' || !(ttlMs >= 0) || !Number.isFinite(ttlMs)) throw new RangeError(`The wrapping TTL must not be negative; it is ${String(ttlMs)}.`);
}

function checkMode(mode: unknown): void {
  if (!Object.values(ReplicationForwardingMode).includes(mode as ReplicationForwardingMode)) {
    throw new TypeError('mode must be a ReplicationForwardingMode.');
  }
}

function checkCallbacks<T>(callbacks: readonly T[]): T[] {
  if (!Array.isArray(callbacks) || !callbacks.every((c) => typeof c === 'function')) throw new TypeError('A callback must be a function.');
  return [...callbacks];
}

function withoutQuery(url: string): string {
  return url.split('?', 1)[0]!;
}

// How a VaultClient reaches Vault, and what a request may set over the client's settings.
import type { Agent, IncomingHttpHeaders } from 'node:http';
import type { DataProtector } from '@runsecure/hkdfguard-abstractions';
import { parseGoDuration } from './duration.js';
import type { ReplicationForwardingMode } from './replication.js';
import { VaultRateLimiter, type VaultRetryOptions } from './retry.js';
import type { VaultTlsOptions } from './tls.js';
import { isValidToken, StaticVaultToken, type VaultTokenProvider } from './token.js';

// RFC 9110's token: what a header name may be.
const HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
// Headers Node writes itself, from the request.
const RESTRICTED_HEADERS = new Set(['host', 'content-length', 'transfer-encoding', 'connection']);

/**
 * An attempt's request as request callbacks see it, before it's sent: its method, its URL and the
 * headers the client has given it - never the token, which is added after every callback.
 */
export class VaultRequest {
  readonly #headers: [string, string][];

  /**
   * @param method the HTTP method
   * @param url the URL, its query included
   */
  constructor(readonly method: string, readonly url: string, headers: [string, string][]) {
    this.#headers = headers;
  }

  /** The headers, as name and value, in the order they are sent; a copy. */
  get headers(): [string, string][] {
    return this.#headers.map(([n, v]) => [n, v]);
  }

  /** The values of the header `name` (case ignored) joined with ","; undefined if it isn't set. */
  header(name: string): string | undefined {
    const values = this.#headers.filter(([n]) => n.toLowerCase() === name.toLowerCase()).map(([, v]) => v);
    return values.length > 0 ? values.join(',') : undefined;
  }

  /**
   * Adds a header; X-Vault-Token is refused.
   * @throws RangeError the header can't be sent, or is X-Vault-Token
   */
  addHeader(name: string, value: string): void {
    checkHeader(name, value, true);
    if (name.toLowerCase() === 'x-vault-token') throw new RangeError("A request callback can't set the token.");
    this.#headers.push([name, value]);
  }

  toString(): string {
    return `VaultRequest(${this.method} ${this.url})`;
  }
}

/**
 * Called with each attempt's request before a {@link VaultClient} sends it, to add headers to it -
 * {@link VaultReplication.requireReplicationStates}, say.
 */
export type VaultRequestCallback = (request: VaultRequest) => void;

/**
 * Called once Vault has answered a {@link VaultClient} request (after any retries and redirect),
 * before its body is read, with the request Vault answered (without its token), the status and the
 * response's headers - {@link VaultReplication.recordReplicationState}, say.
 */
export type VaultResponseCallback = (request: VaultRequest, statusCode: number, headers: IncomingHttpHeaders) => void;

/**
 * How a {@link VaultClient} reaches Vault: vault-client-go's ClientConfiguration. Every member is
 * optional; read the members from the environment with {@link VaultClientOptions.fromEnvironment}.
 * The values are checked by the client's constructor, not here.
 */
export interface VaultClientOptions {
  /**
   * Vault's address, scheme://host:port - VAULT_ADDR; default {@link VaultClientOptions.DEFAULT_ADDRESS}.
   * https; http only on a loopback address (a local agent or dev server) unless
   * {@link allowUnencryptedHttp} is set, since every request carries a token. A path, if any, is kept
   * as a prefix (Vault behind a reverse proxy). Unix domain sockets (unix://), which vault-client-go
   * also reaches, aren't.
   */
  readonly address?: string;
  /** Allows an http address that isn't loopback, and redirects to one. Off: the token would cross the network in the clear. */
  readonly allowUnencryptedHttp?: boolean;
  /**
   * The agent every https request is sent through, e.g. one of your own; can't be combined with
   * {@link tls}. Not destroyed by the client. Undefined for one {@link tls} makes - or the client's
   * own, verifying against Node's trust store.
   */
  readonly agent?: Agent;
  /** Which certificates to trust and to present; undefined for Node's trust store and no client certificate. */
  readonly tls?: VaultTlsOptions;
  /**
   * How long each request may take, in milliseconds, its token, retries and redirect included -
   * VAULT_CLIENT_TIMEOUT. Zero for none; default 60 seconds. Not applied to reading a
   * {@link VaultClient.readRaw} body.
   */
  readonly requestTimeoutMs?: number;
  /** When and how often a failed request is retried. */
  readonly retry?: VaultRetryOptions;
  /** Limits how often requests are sent - VAULT_RATE_LIMIT. Undefined for no limit. One limiter can be shared by several clients. */
  readonly rateLimiter?: VaultRateLimiter;
  /**
   * Sends the replication states seen in earlier responses with every request, so a performance
   * standby that hasn't caught up forwards it to the active node: read-your-writes consistency
   * across a cluster, at a cost on every request. Requires Vault Enterprise.
   */
  readonly enforceReadYourWritesConsistency?: boolean;
  /**
   * Follows one redirect (301, 302 or 307) per request, never from https to http. Off: a redirect
   * fails with {@link VaultRedirectError}, since it would carry the token wherever it points.
   */
  readonly followRedirects?: boolean;
  /** The token every request is made with unless the request sets its own; undefined for none until {@link VaultClient.setToken}. */
  readonly token?: VaultTokenProvider;
  /** The namespace every request is made in unless the request sets its own - VAULT_NAMESPACE. Vault Enterprise. */
  readonly namespace?: string;
}

/** The defaults of {@link VaultClientOptions}, and reading them from the environment. */
export const VaultClientOptions = {
  /** The address used when none is set: a local Vault server or agent. */
  DEFAULT_ADDRESS: 'https://127.0.0.1:8200',

  /** The request timeout used when none is set: 60 seconds. */
  DEFAULT_REQUEST_TIMEOUT_MS: 60_000,

  /**
   * Options from the environment variables vault-client-go reads:
   *
   *  - VAULT_ADDR, VAULT_AGENT_ADDR - address (VAULT_AGENT_ADDR wins if both are set)
   *  - VAULT_CLIENT_TIMEOUT - requestTimeoutMs, a Go duration such as 30s
   *  - VAULT_RATE_LIMIT - rateLimiter, rate[:burst] in requests per second
   *  - VAULT_DISABLE_REDIRECTS - true turns followRedirects off; false leaves it as it is
   *  - VAULT_TOKEN - token, protected with `tokenProtector`; ignored without one
   *  - VAULT_NAMESPACE - namespace
   *  - VAULT_SKIP_VERIFY, VAULT_CACERT, VAULT_CACERT_BYTES, VAULT_CAPATH, VAULT_CLIENT_CERT,
   *    VAULT_CLIENT_KEY, VAULT_TLS_SERVER_NAME - tls
   *  - VAULT_RETRY_WAIT_MIN, VAULT_RETRY_WAIT_MAX, VAULT_MAX_RETRIES - retry
   *
   * @param tokenProtector the protector the client will be given, to protect VAULT_TOKEN with;
   *   undefined to ignore VAULT_TOKEN
   * @param environment the variables; omitted for process.env
   * @throws RangeError a variable is set to a value that isn't one
   */
  fromEnvironment(tokenProtector?: DataProtector, environment: Readonly<Record<string, string | undefined>> = process.env): VaultClientOptions {
    // An unset variable and an empty one are the same, as in vault-client-go.
    const value = (name: string) => (environment[name] === '' ? undefined : environment[name]);
    const settings: { -readonly [K in keyof VaultClientOptions]: VaultClientOptions[K] } = {};
    // Later variables win, as in vault-client-go.
    for (const name of ['VAULT_ADDR', 'VAULT_AGENT_ADDR']) {
      const address = value(name);
      if (address !== undefined) settings.address = parse(name, address, parseAddress);
    }
    const timeout = value('VAULT_CLIENT_TIMEOUT');
    if (timeout !== undefined) settings.requestTimeoutMs = parse('VAULT_CLIENT_TIMEOUT', timeout, parseGoDuration);
    const rateLimit = value('VAULT_RATE_LIMIT');
    if (rateLimit !== undefined) settings.rateLimiter = parse('VAULT_RATE_LIMIT', rateLimit, parseRateLimit);
    const disableRedirects = value('VAULT_DISABLE_REDIRECTS');
    if (disableRedirects !== undefined && parse('VAULT_DISABLE_REDIRECTS', disableRedirects, parseGoBool)) settings.followRedirects = false;
    const namespace = value('VAULT_NAMESPACE');
    if (namespace !== undefined) {
      if (!isValidNamespace(namespace)) throw new RangeError('VAULT_NAMESPACE contains non-printable characters.');
      settings.namespace = namespace;
    }
    const token = tokenProtector === undefined ? undefined : value('VAULT_TOKEN');
    if (token !== undefined) {
      if (!isValidToken(token)) throw new RangeError("VAULT_TOKEN isn't a token: printable ASCII, with no spaces.");
      settings.token = StaticVaultToken.protect(tokenProtector!, token);
    }

    const tls: { -readonly [K in keyof VaultTlsOptions]: VaultTlsOptions[K] } = {};
    const skipVerify = value('VAULT_SKIP_VERIFY');
    if (skipVerify !== undefined) tls.insecureSkipVerify = parse('VAULT_SKIP_VERIFY', skipVerify, parseGoBool);
    const files = [['VAULT_CACERT', 'serverCertificateFile'], ['VAULT_CAPATH', 'serverCertificateDirectory'],
      ['VAULT_CLIENT_CERT', 'clientCertificateFile'], ['VAULT_CLIENT_KEY', 'clientCertificateKeyFile']] as const;
    for (const [variable, option] of files) {
      const path = value(variable);
      if (path !== undefined) tls[option] = path;
    }
    const caBytes = value('VAULT_CACERT_BYTES');
    if (caBytes !== undefined) tls.serverCertificatePem = caBytes;
    const serverName = value('VAULT_TLS_SERVER_NAME');
    if (serverName !== undefined) tls.serverName = serverName;
    if (Object.keys(tls).length > 0) settings.tls = tls;

    const retry: { -readonly [K in keyof VaultRetryOptions]: VaultRetryOptions[K] } = {};
    const waitMin = value('VAULT_RETRY_WAIT_MIN');
    if (waitMin !== undefined) retry.retryWaitMinMs = parse('VAULT_RETRY_WAIT_MIN', waitMin, parseGoDuration);
    const waitMax = value('VAULT_RETRY_WAIT_MAX');
    if (waitMax !== undefined) retry.retryWaitMaxMs = parse('VAULT_RETRY_WAIT_MAX', waitMax, parseGoDuration);
    const maxRetries = value('VAULT_MAX_RETRIES');
    if (maxRetries !== undefined) retry.retryMax = parse('VAULT_MAX_RETRIES', maxRetries, parseInteger);
    if (Object.keys(retry).length > 0) settings.retry = retry;
    return settings;
  },
} as const;

/**
 * Settings for one request, over the client's: its own token, namespace, headers, callbacks, the
 * mount a generated method calls, query parameters, and a signal to abort it with. Every member is
 * optional; a setting left unset is the client's.
 */
export interface VaultRequestOptions {
  /** The token to make this request with, instead of the client's. */
  readonly token?: VaultTokenProvider;
  /** The namespace to make this request in, instead of the client's; undefined or empty keeps the client's. */
  readonly namespace?: string;
  /** Multi-factor credentials (X-Vault-MFA), added to the client's; see https://developer.hashicorp.com/vault/docs/auth/login-mfa. */
  readonly mfaCredentials?: readonly string[];
  /**
   * Asks Vault to wrap the response for this many milliseconds (X-Vault-Wrap-TTL) instead of
   * returning it: the response holds only {@link VaultResponse.wrapInfo}, for {@link VaultClient.unwrap}.
   * Undefined or zero keeps the client's setting.
   */
  readonly responseWrappingTtlMs?: number;
  /** Headers to add, over the client's; names starting X-Vault- are the client's own and refused. */
  readonly customHeaders?: Readonly<Record<string, readonly string[]>>;
  /** Called with each attempt's request before it's sent, after the client's own callbacks. The token isn't on it yet. */
  readonly requestCallbacks?: readonly VaultRequestCallback[];
  /** Called once Vault has answered, after the client's own callbacks. */
  readonly responseCallbacks?: readonly VaultResponseCallback[];
  /**
   * Where the auth method or secrets engine is mounted, instead of its default - for the generated
   * methods; leading and trailing '/' are ignored.
   */
  readonly mountPath?: string;
  /** Query parameters to add to the request; meant for the generic read, readRaw, list and delete. */
  readonly queryParameters?: readonly (readonly [string, string])[];
  /** Whether a performance standby forwards this request to the active node; undefined or none keeps the client's. */
  readonly replicationForwardingMode?: ReplicationForwardingMode;
  /** Aborts the request - and the waits between its retries - rejecting with the signal's reason. */
  readonly signal?: AbortSignal;
}

/** Whether `value` can go in a header: printable ASCII, spaces allowed. */
export function isValidNamespace(value: unknown): value is string {
  return typeof value === 'string' && /^[\x20-\x7e]*$/.test(value);
}

/** @throws RangeError a credential can't go in a header */
export function checkMfaCredentials(credentials: readonly string[]): void {
  if (!Array.isArray(credentials)) throw new TypeError('MFA credentials are an array of strings.');
  for (const credential of credentials) {
    if (typeof credential !== 'string' || credential === '' || !isValidNamespace(credential)) {
      throw new RangeError('An MFA credential must be non-empty printable ASCII.');
    }
  }
}

/** The custom headers a client sends: name to values, names unique ignoring case. */
export type HeaderMap = ReadonlyMap<string, readonly string[]>;

/**
 * `headers` checked and copied, their names compared ignoring case (the last of two spellings winning).
 * @throws RangeError a header has no name, is named X-Vault-*, or can't be sent
 */
export function copyHeaders(headers: Readonly<Record<string, readonly string[]>> | undefined): HeaderMap {
  const copied = new Map<string, readonly string[]>();
  if (headers === undefined || headers === null) return copied;
  if (typeof headers !== 'object') throw new TypeError('headers must be an object of header names to arrays of values.');
  const byLower = new Map<string, string>();
  for (const [name, values] of Object.entries(headers)) {
    if (!Array.isArray(values)) throw new TypeError(`The custom header '${name}' must map to an array of values.`);
    const valuesCopy = Object.freeze([...values]);
    for (const one of valuesCopy) checkHeader(name, one, false);
    if (valuesCopy.length === 0) checkHeader(name, '', false);
    const previous = byLower.get(name.toLowerCase());
    if (previous !== undefined) copied.delete(previous);
    byLower.set(name.toLowerCase(), name);
    copied.set(name, valuesCopy);
  }
  return copied;
}

/** `base` with `over`'s headers replacing those of the same name, case ignored. */
export function mergeHeaders(base: HeaderMap, over: HeaderMap): HeaderMap {
  const overNames = new Set([...over.keys()].map((n) => n.toLowerCase()));
  const merged = new Map([...base].filter(([name]) => !overNames.has(name.toLowerCase())));
  for (const [name, values] of over) merged.set(name, values);
  return merged;
}

function checkHeader(name: unknown, value: unknown, allowVault: boolean): void {
  if (typeof name !== 'string' || name.trim() === '') throw new RangeError('A custom header must have a name.');
  if (!allowVault && name.toLowerCase().startsWith('x-vault-')) {
    throw new RangeError(`The custom header '${name}' isn't allowed: the 'X-Vault-' prefix is for the client's own use.`);
  }
  if (!HEADER_NAME.test(name) || RESTRICTED_HEADERS.has(name.toLowerCase())) {
    throw new RangeError(`The header '${name}' can't be sent: it isn't a header name, or is one the client sets itself.`);
  }
  if (typeof value !== 'string' || !/^[\x20-\x7e\t]*$/.test(value)) throw new RangeError(`The header '${name}' has a value that can't be sent.`);
}

function parse<T>(name: string, value: string, parser: (value: string) => T): T {
  try {
    return parser(value);
  } catch (error) {
    throw new RangeError(`Configuration error: could not convert the ${name} environment variable's value '${value}': ${(error as Error).message}`,
      { cause: error });
  }
}

function parseAddress(address: string): string {
  if (!address.includes('://')) throw new RangeError('Not an absolute URI.');
  return address;
}

function parseInteger(value: string): number {
  if (!/^[+-]?\d+$/.test(value)) throw new RangeError('Expected an integer.');
  return Number(value);
}

/** strconv.ParseBool's spellings. */
export function parseGoBool(value: string): boolean {
  if (['1', 't', 'T', 'TRUE', 'true', 'True'].includes(value)) return true;
  if (['0', 'f', 'F', 'FALSE', 'false', 'False'].includes(value)) return false;
  throw new RangeError('Expected a boolean: 1, t, T, TRUE, true, True, 0, f, F, FALSE, false or False.');
}

// "rate:burst", or "rate" with a burst of the rate rounded down (at least 1).
function parseRateLimit(value: string): VaultRateLimiter {
  const colon = value.indexOf(':');
  const number = (text: string) => {
    if (!/^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$/.test(text.trim())) throw new RangeError(`'${text}' isn't a number.`);
    return Number(text);
  };
  if (colon >= 0) return new VaultRateLimiter(number(value.slice(0, colon)), parseInteger(value.slice(colon + 1)));
  const rate = number(value);
  return new VaultRateLimiter(rate, Number.isFinite(rate) ? Math.max(1, Math.floor(Math.min(rate, 2 ** 31 - 1))) : 1);
}


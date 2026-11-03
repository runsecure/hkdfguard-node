// What every HkdfGuard Vault integration - the client, the transit key wrapper and the KV secret
// cache - checks about Vault's address, the paths under it and how it is reached.
import { Agent as HttpAgent } from 'node:http';
import { isIPv4 } from 'node:net';
import { InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';
import type { VaultTlsOptions } from './tls.js';

const PATH_SEGMENT = /^[A-Za-z0-9._-]+$/;

/** The header every request carries its token in. */
export const TOKEN_HEADER = 'X-Vault-Token';

/** The header naming the Vault Enterprise namespace a request is made in, as VAULT_NAMESPACE does. */
export const NAMESPACE_HEADER = 'X-Vault-Namespace';

/**
 * The header every request carries, `X-Vault-Request: true`, as Vault's own clients send it: a
 * browser can't send it cross-origin without a preflight Vault refuses.
 */
export const REQUEST_HEADER = 'X-Vault-Request';

/** The fewest retries of a request that failed transiently an integration allows. */
export const MIN_RETRY_COUNT = 3;

/** The most retries of a request that failed transiently an integration allows. */
export const MAX_RETRY_COUNT = 10;

/** The longest wait between retries, in milliseconds, before the random 0-100 ms each adds. */
export const MAX_RETRY_DELAY_MS = 10_000;

/** The longest timeout, in milliseconds: the longest delay a Node timer keeps. */
export const MAX_TIMEOUT_MS = 2_147_483_647;

/** The timeout an integration uses when none is given: 30 seconds. */
export const DEFAULT_TIMEOUT_MS = 30_000;

/** The wait before the first retry an integration uses when none is given: 200 ms. */
export const DEFAULT_RETRY_DELAY_MS = 200;

/**
 * Where Vault's API is: whether over https, its host and port, the address's path with no trailing
 * '/' (Vault behind a reverse proxy; "" for none), and the path of /v1/ under it.
 */
export interface VaultApiBase {
  readonly https: boolean;
  readonly hostname: string;
  readonly port: number | undefined;
  readonly prefix: string;
  readonly base: string;
}

/**
 * Vault's API under `address`, refusing a unix socket, an address that would send what every
 * request `carries` in the clear (http anywhere but loopback, unless `options.allowUnencryptedHttp`)
 * or one that holds credentials, a query or a fragment.
 * @param options VaultClient's: its allowUnencryptedHttp allows http anywhere. Omitted, http is
 *   allowed only on loopback.
 * @throws InvalidArgumentError ERR_HKDFGUARD_INVALID_VAULT_ADDRESS
 */
export function apiBase(address: string, carries: string, options?: { allowUnencryptedHttp?: boolean }): VaultApiBase {
  const invalid = (problem: string) => new InvalidArgumentError(`Vault's address '${address}' ${problem}`, 'ERR_HKDFGUARD_INVALID_VAULT_ADDRESS');
  if (/^unix:/i.test(address)) {
    throw invalid("is a unix socket, which can't be connected to here: reach Vault (or its agent) over https, or http on loopback.");
  }

  // A scheme and a host, checked on the text: the URL parser would read "https:///host" as "https://host".
  let url: URL | undefined;
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#\\]/.test(address)) {
    try {
      url = new URL(address);
    } catch {
      url = undefined;
    }
  }
  if (url === undefined || url.hostname === '') throw invalid("isn't absolute, e.g. https://vault.example.com:8200.");

  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && (isLoopback(url.hostname) || options?.allowUnencryptedHttp === true))) {
    const allowed = options === undefined ? '' : ', or with allowUnencryptedHttp';
    throw invalid(`must be https; http is allowed only on a loopback address (a local Vault Agent or dev server)${allowed}, `
      + `since every request carries ${carries}.`);
  }
  const authority = address.slice(address.indexOf('//') + 2).split(/[/?#]/, 1)[0]!;
  if (authority.includes('@') || url.username !== '' || url.password !== '' || address.includes('?') || address.includes('#')) {
    throw invalid('must not hold credentials, a query or a fragment.');
  }

  let prefix = url.pathname;
  while (prefix.endsWith('/')) prefix = prefix.slice(0, -1);
  return {
    https: url.protocol === 'https:',
    hostname: url.hostname.startsWith('[') ? url.hostname.slice(1, -1) : url.hostname,
    port: url.port === '' ? undefined : Number(url.port),
    prefix,
    base: `${prefix}/v1/`,
  };
}

/** '/'-separated segments, none empty, "." or "..": a path that stays where it's put. */
export function isValidPath(path: unknown): boolean {
  return typeof path === 'string' && path.split('/').every(isValidSegment);
}

/** One segment of a path: ASCII letters, digits, '-', '_' and '.', and not "." or "..". */
export function isValidSegment(segment: string): boolean {
  return PATH_SEGMENT.test(segment) && segment !== '.' && segment !== '..';
}

/**
 * The wait before retry number `retry` (0 for the first), in milliseconds: `baseDelayMs`, doubled
 * for each retry before it, at most {@link MAX_RETRY_DELAY_MS} - plus `jitterMs`.
 */
export function retryDelay(baseDelayMs: number, retry: number, jitterMs: number): number {
  const backoff = retry >= 30 ? MAX_RETRY_DELAY_MS : baseDelayMs * 2 ** retry;
  return Math.min(backoff, MAX_RETRY_DELAY_MS) + jitterMs;
}

/** How an integration reaches Vault, as its options name it, with every default applied. */
export interface VaultConnectionSettings {
  readonly mountPath: string;
  readonly namespace: string | undefined;
  readonly timeoutMs: number;
  readonly retryCount: number;
  readonly retryDelayMs: number;
}

/**
 * How the transit key wrapper and the KV secret cache reach Vault: what their options share, checked
 * by {@link checkConnectionOptions}. Every member is optional.
 */
export interface VaultConnectionOptions {
  /** Where the secrets engine is mounted, e.g. "transit" or "kv/team-a"; each integration has its own default. */
  readonly mountPath?: string;

  /**
   * The Vault Enterprise namespace every request is made in, e.g. "team-a/prod"; undefined (the
   * default) for the root namespace. Sent as X-Vault-Namespace, as VAULT_NAMESPACE is.
   */
  readonly namespace?: string;

  /**
   * How long one attempt may take, in milliseconds: getting the token, or one request and Vault's
   * whole response. Default {@link DEFAULT_TIMEOUT_MS} (30 seconds); at most {@link MAX_TIMEOUT_MS}.
   * A call that keeps failing transiently makes up to {@link retryCount} + 1 attempts, with the waits
   * between them.
   */
  readonly timeoutMs?: number;

  /**
   * How many times a request that failed transiently is retried: one that got no answer (connection
   * refused or reset, DNS), lost its connection mid-response, timed out, or was answered 429 or a 5xx
   * other than 501 (Vault answers 503 while sealed or electing a leader). Anything else - 403, 400, a
   * token source's or provider's failure, the caller's abort - isn't retried.
   * {@link MIN_RETRY_COUNT}-{@link MAX_RETRY_COUNT}; default MIN_RETRY_COUNT.
   */
  readonly retryCount?: number;

  /**
   * The wait before the first retry, in milliseconds, doubling before each retry after it, up to
   * {@link MAX_RETRY_DELAY_MS}. Every wait also adds a random 0-100 ms, so many clients reconnecting
   * at once - after a network outage, say - don't all retry together. Zero to MAX_RETRY_DELAY_MS;
   * default {@link DEFAULT_RETRY_DELAY_MS}.
   */
  readonly retryDelayMs?: number;

  /**
   * The agent every https request is sent through, e.g. `new https.Agent({ ca: readFileSync('vault-ca.pem') })`
   * trusting a private CA, or one presenting a client certificate (cert and key). Not destroyed by
   * the integration. Undefined (the default) for the integration's own keep-alive agent: built from
   * {@link tls}, or verifying Vault's certificate and host name against Node's trust store (plus
   * NODE_EXTRA_CA_CERTS). Unused for an http address. Node never follows a redirect, whatever the
   * agent; one that is a proxy sends the token, and everything else a request carries, through it.
   * Refused together with tls.
   */
  readonly agent?: HttpAgent;

  /**
   * The CA certificates Vault's must chain to and the client certificate presented - PEM, or
   * password-protected PKCS#12 key stores whose passwords are protected by the key ring - read once,
   * when the integration is created, into the keep-alive agent it builds. Refused together with
   * {@link agent}. Unused for an http address.
   */
  readonly tls?: VaultTlsOptions;
}

/**
 * `options`' connection settings, every default applied (the mount path `defaultMountPath`) and
 * checked: the agent and tls ({@link checkTlsOptions}), the types, then the values
 * ({@link checkConnectionSettings}). Only an undefined member takes its default: null is a value of
 * the wrong type.
 * @throws InvalidArgumentError a member is of the wrong type, or isn't a valid value
 */
export function checkConnectionOptions(options: VaultConnectionOptions, defaultMountPath: string): VaultConnectionSettings {
  const or = <T>(value: T | undefined, fallback: T): T => (value === undefined ? fallback : value);
  const settings: VaultConnectionSettings = {
    mountPath: or(options.mountPath, defaultMountPath),
    namespace: options.namespace,
    timeoutMs: or(options.timeoutMs, DEFAULT_TIMEOUT_MS),
    retryCount: or(options.retryCount, MIN_RETRY_COUNT),
    retryDelayMs: or(options.retryDelayMs, DEFAULT_RETRY_DELAY_MS),
  };
  if (typeof settings.mountPath !== 'string') throw new InvalidArgumentError('mountPath must be a string.');
  if (settings.namespace !== undefined && typeof settings.namespace !== 'string') throw new InvalidArgumentError('namespace must be a string.');
  for (const [name, value] of [['timeoutMs', settings.timeoutMs], ['retryCount', settings.retryCount], ['retryDelayMs', settings.retryDelayMs]] as const) {
    if (typeof value !== 'number') throw new InvalidArgumentError(`${name} must be a number.`);
  }
  checkTlsOptions(options.agent, options.tls);
  checkConnectionSettings(settings);
  return settings;
}

/**
 * Refuses `agent` and `tls` both set - each says how to connect - and checks their types.
 * @throws InvalidArgumentError agent isn't an http(s).Agent, tls isn't an object, or both are set
 */
export function checkTlsOptions(agent: unknown, tls: unknown): void {
  if (agent !== undefined && !(agent instanceof HttpAgent)) throw new InvalidArgumentError('agent must be an https.Agent.');
  if (tls !== undefined && (typeof tls !== 'object' || tls === null)) throw new InvalidArgumentError('tls must be a VaultTlsOptions object.');
  if (agent !== undefined && tls !== undefined) {
    throw new InvalidArgumentError('Set agent or tls, not both: an agent already says how to connect, and would ignore tls.');
  }
}

/**
 * Checks the values an integration's options share - already known to be of the right types.
 * @throws InvalidArgumentError the mount path or namespace isn't a Vault path, the timeout isn't
 *   positive or is over MAX_TIMEOUT_MS, the retry count isn't MIN_RETRY_COUNT-MAX_RETRY_COUNT or the
 *   retry delay isn't zero to MAX_RETRY_DELAY_MS
 */
export function checkConnectionSettings(settings: VaultConnectionSettings): void {
  if (!isValidPath(settings.mountPath)) throw new InvalidArgumentError(`The mount path '${settings.mountPath}' isn't a Vault path.`);
  if (settings.namespace !== undefined && !isValidPath(settings.namespace)) {
    throw new InvalidArgumentError(`The namespace '${settings.namespace}' isn't a Vault path.`);
  }
  if (!(settings.timeoutMs > 0 && settings.timeoutMs <= MAX_TIMEOUT_MS)) {
    throw new InvalidArgumentError(`The timeout must be positive, at most ${MAX_TIMEOUT_MS} ms; it is ${settings.timeoutMs}.`);
  }
  if (!Number.isInteger(settings.retryCount) || settings.retryCount < MIN_RETRY_COUNT || settings.retryCount > MAX_RETRY_COUNT) {
    throw new InvalidArgumentError(`The retry count must be ${MIN_RETRY_COUNT}-${MAX_RETRY_COUNT}; it is ${settings.retryCount}.`);
  }
  if (!(settings.retryDelayMs >= 0 && settings.retryDelayMs <= MAX_RETRY_DELAY_MS)) {
    throw new InvalidArgumentError(`The retry delay must be zero to ${MAX_RETRY_DELAY_MS} ms; it is ${settings.retryDelayMs}.`);
  }
}

/**
 * Whether `hostname` - as the URL parser normalized it, IPv6 with or without its brackets - is
 * localhost or an IP literal on the loopback network. No name is ever resolved.
 */
export function isLoopback(hostname: string): boolean {
  return hostname === 'localhost' || (isIPv4(hostname) && hostname.startsWith('127.')) || hostname === '[::1]' || hostname === '::1';
}

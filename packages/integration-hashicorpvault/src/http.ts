// How every HkdfGuard Vault integration talks to Vault: the connection (its agent, from the caller or
// built from VaultTlsOptions), the headers every request carries, the token put in them, one attempt
// within its timeout and the retries around it.
import { randomInt } from 'node:crypto';
import {
  Agent as HttpAgent, request as httpRequest, type ClientRequest, type IncomingMessage, type OutgoingHttpHeaders,
} from 'node:http';
import { Agent as HttpsAgent, request as httpsRequest, type AgentOptions } from 'node:https';
import { HkdfGuardError, InvalidArgumentError, wipe, type DataProtector } from '@runsecure/hkdfguard-abstractions';
import { delay, untilAborted } from '@runsecure/hkdfguard-abstractions/internal';
import { checkTlsOptions, NAMESPACE_HEADER, REQUEST_HEADER, retryDelay, TOKEN_HEADER, type VaultApiBase } from './connection.js';
import { VaultRequestError } from './errors.js';
import { createSecureContextOptions, type VaultTlsOptions } from './tls.js';
import { isValidToken, MAX_TOKEN_LENGTH, type VaultTokenProvider, type VaultTokenSource } from './token.js';

// Failures another attempt may not meet: no answer at all (connection refused or reset, DNS), a
// connection lost mid-response, the attempt's own timeout.
const TRANSIENT = new WeakSet<object>();

/** Marks `error` as one another attempt may not meet - no answer, a lost connection, a timeout - and returns it. */
export function markTransient<T>(error: T): T {
  if (typeof error === 'object' && error !== null) TRANSIENT.add(error);
  return error;
}

/**
 * Whether another attempt may not meet `error`: one {@link markTransient} marked, or a
 * {@link VaultRequestError} that {@link VaultRequestError.isTransient is transient}.
 */
export function isTransient(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) return false;
  return TRANSIENT.has(error) || (error instanceof VaultRequestError && error.isTransient);
}

/**
 * `attempt`'s result, retrying it while it fails transiently ({@link isTransient}, or
 * `options.isTransient`): up to `retryCount` times, waiting `baseDelayMs` and doubling (at most
 * MAX_RETRY_DELAY_MS) plus a random 0-100 ms before each. Rejects with the failure that ended the
 * retries - or `signal`'s reason once it is aborted, without retrying; or the last failure once
 * `options.stopped()` (the integration was closed) says so.
 * @param attempt makes one attempt; told which retry it is (0 for the first attempt)
 */
export async function withRetries<T>(
  attempt: (retry: number) => Promise<T>, retryCount: number, baseDelayMs: number, signal?: AbortSignal,
  options?: { stopped?: () => boolean; isTransient?: (error: unknown) => boolean },
): Promise<T> {
  const transient = options?.isTransient ?? isTransient;
  for (let retry = 0; ; retry++) {
    try {
      return await attempt(retry);
    } catch (error) {
      if (signal?.aborted === true) throw signal.reason;
      if (!transient(error) || retry >= retryCount || options?.stopped?.() === true) throw error;
    }
    await delay(retryDelay(baseDelayMs, retry, randomInt(0, 101)), signal);
  }
}

/**
 * What `action` returns, waited for at most `timeoutMs`: `action`'s signal is aborted once the
 * timeout passes, or `signal` is. Rejects with `signal`'s reason once it is aborted, a DOMException
 * named TimeoutError with `timeoutMessage` once the timeout passes, or `action`'s own failure.
 */
export async function runWithin<T>(
  action: (signal: AbortSignal) => Promise<T> | T, timeoutMs: number, signal: AbortSignal | undefined, timeoutMessage: string,
): Promise<T> {
  signal?.throwIfAborted();
  const timeout = new AbortController();
  const timer = setTimeout(() => timeout.abort(), timeoutMs);
  const either = signal === undefined ? timeout.signal : AbortSignal.any([signal, timeout.signal]);
  try {
    return await untilAborted(Promise.resolve().then(() => action(either)), either);
  } catch (error) {
    if (signal?.aborted === true) throw signal.reason;
    if (timeout.signal.aborted) throw new DOMException(timeoutMessage, 'TimeoutError');
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

/** What a call given something that isn't a token fails with: ERR_HKDFGUARD_INVALID_VAULT_TOKEN, quoting nothing. */
export function invalidTokenError(message: string): HkdfGuardError {
  return new HkdfGuardError('ERR_HKDFGUARD_INVALID_VAULT_TOKEN', message);
}

/**
 * Has `source` copy its token into `destination` (at least MAX_TOKEN_LENGTH bytes, zeroed by the
 * caller), within `timeoutMs`, and returns its length.
 * @throws HkdfGuardError ERR_HKDFGUARD_INVALID_VAULT_TOKEN: the source supplied no token, or one that isn't one
 */
export async function copyTokenWithin(source: VaultTokenSource, destination: Buffer, timeoutMs: number, signal?: AbortSignal): Promise<number> {
  const length: unknown = await runWithin((either) => source.copyToken(destination, either), timeoutMs, signal,
    `The Vault token source supplied no token within ${timeoutMs} ms.`);
  if (typeof length !== 'number' || !Number.isInteger(length) || length <= 0 || length > MAX_TOKEN_LENGTH || length > destination.length
    || !isValidToken(destination.subarray(0, length))) {
    throw invalidTokenError(
      `The Vault token source supplied no token, or one that isn't a token: 1-${MAX_TOKEN_LENGTH} printable ASCII characters, with no spaces.`);
  }
  return length;
}

/**
 * The protected token `provider` returns, within `timeoutMs`.
 * @throws HkdfGuardError ERR_HKDFGUARD_INVALID_VAULT_TOKEN: the provider returned no token
 */
export async function getTokenWithin(provider: VaultTokenProvider, timeoutMs: number, signal?: AbortSignal): Promise<string> {
  return checkProtectedToken(await runWithin((either) => provider.getToken(either), timeoutMs, signal,
    `The Vault token provider returned no token within ${timeoutMs} ms.`));
}

/**
 * What a {@link VaultTokenProvider} returned, if it is a protected token - a non-empty string; not
 * yet decrypted.
 * @throws HkdfGuardError ERR_HKDFGUARD_INVALID_VAULT_TOKEN: the provider returned no token
 */
export function checkProtectedToken(token: unknown): string {
  if (typeof token !== 'string' || token === '') throw invalidTokenError('The Vault token provider returned no token.');
  return token;
}

/**
 * The token `protectedToken` holds, decrypted into a buffer the caller zeroes, and its length.
 * Refused unless it is protected by `protector` - it parses, its key version is on the ring, and it
 * authenticates under the protector's purpose - and is a token. The protector's errors aren't
 * chained: a parser handed an unprotected token could quote it.
 * @param whose names the protector in the error, e.g. "the cache's token protector"
 * @throws HkdfGuardError ERR_HKDFGUARD_INVALID_VAULT_TOKEN
 */
export function decryptToken(protector: DataProtector, protectedToken: string, whose: string): { buffer: Uint8Array; length: number } {
  let buffer: Uint8Array | undefined;
  let length = -1;
  try {
    const maxLength = protector.maxDecryptedLength(protectedToken);
    if (Number.isSafeInteger(maxLength) && maxLength >= 0) {
      buffer = new Uint8Array(maxLength);
      length = protector.decrypt(protectedToken, buffer);
    }
  } catch {
    length = -1;
  }
  if (buffer === undefined || !Number.isSafeInteger(length) || length < 0 || length > buffer.length) {
    wipe(buffer);
    throw invalidTokenError(`The Vault token provider returned a token that isn't protected by ${whose}: `
      + 'hand over tokenProtector.encrypt(token), never the token itself.');
  }
  if (!isValidToken(buffer.subarray(0, length))) {
    wipe(buffer);
    throw invalidTokenError("The protected Vault token isn't a token: printable ASCII, with no spaces.");
  }
  return { buffer, length };
}

/**
 * The headers every request carries - `X-Vault-Request: true`, and X-Vault-Namespace when
 * `namespace` is given - added to `headers`.
 */
export function vaultHeaders(namespace: string | undefined, headers: OutgoingHttpHeaders = {}): OutgoingHttpHeaders {
  headers[REQUEST_HEADER] = 'true';
  if (namespace !== undefined) headers[NAMESPACE_HEADER] = namespace;
  return headers;
}

/**
 * Puts the token in `token`'s first `length` bytes - printable ASCII, checked already - in
 * `headers`. Node takes a header only as a string: that string, and the request head Node builds
 * from it, are the copies of the token no integration can erase.
 */
export function putToken(headers: OutgoingHttpHeaders, token: Uint8Array, length: number): void {
  headers[TOKEN_HEADER] = Buffer.from(token.buffer, token.byteOffset, length).toString('latin1');
}

/**
 * Puts the token `protectedToken` holds in `headers`, decrypted by `protector` into a buffer zeroed
 * once Node has the header's string.
 * @throws HkdfGuardError ERR_HKDFGUARD_INVALID_VAULT_TOKEN: see {@link decryptToken}
 */
export function putProtectedToken(headers: OutgoingHttpHeaders, protector: DataProtector, protectedToken: string, whose: string): void {
  const { buffer, length } = decryptToken(protector, protectedToken, whose);
  try {
    putToken(headers, buffer, length);
  } finally {
    wipe(buffer);
  }
}

/**
 * Makes one attempt within `timeoutMs`: sends the request `send` builds, with `body` if any, and
 * hands Vault's response to `read`. `signal` aborting, or the timeout passing, destroys the request
 * and response, so whatever is being waited for fails at once. A request that fails, or a timeout,
 * is marked transient; `read` marks its own failures ({@link chunksOf} does for a lost connection).
 * Rejects with `signal`'s reason once it is aborted.
 */
export async function sendAttempt<T>(
  send: () => ClientRequest, body: Uint8Array | undefined, read: (response: IncomingMessage, signal: AbortSignal) => Promise<T>,
  timeoutMs: number, signal: AbortSignal | undefined, timeoutMessage: string,
): Promise<T> {
  signal?.throwIfAborted();
  const attempt = new AbortController();
  const timer = setTimeout(() => attempt.abort(), timeoutMs);
  const either = signal === undefined ? attempt.signal : AbortSignal.any([signal, attempt.signal]);
  let request: ClientRequest | undefined;
  let response: IncomingMessage | undefined;
  // Destroyed with an error, so whichever is being waited for fails at once; the catch below
  // replaces it with the abort's reason or the timeout.
  const abandon = () => {
    const abandoned = new Error('The request to Vault was abandoned.');
    request?.destroy(abandoned);
    response?.destroy(abandoned);
  };
  either.addEventListener('abort', abandon, { once: true });

  try {
    const sent = send();
    request = sent;
    response = await new Promise<IncomingMessage>((resolve, reject) => {
      sent.on('response', resolve);
      // Kept for the request's life: an error after the response must find a listener.
      sent.on('error', (error) => reject(markTransient(error)));
      // Sent from body itself, not a copy: Node writes a Buffer to the socket as it is.
      if (body === undefined) sent.end();
      else sent.end(body);
    });
    // A body's errors reach the reader through its iterator; this one keeps a late one quiet.
    response.on('error', () => undefined);
    try {
      return await read(response, either);
    } finally {
      if (!response.complete) response.destroy();
    }
  } catch (error) {
    if (signal?.aborted === true) throw signal.reason;
    if (attempt.signal.aborted) throw markTransient(new DOMException(timeoutMessage, 'TimeoutError'));
    throw error;
  } finally {
    clearTimeout(timer);
    either.removeEventListener('abort', abandon);
  }
}

/**
 * The response's chunks; an error reading them is a connection lost mid-response, marked transient.
 * Its partial bytes may hold a secret: the reader zeroes each chunk it copies.
 */
export async function* chunksOf(response: IncomingMessage): AsyncGenerator<Uint8Array> {
  try {
    for await (const chunk of response) yield chunk as Uint8Array;
  } catch (error) {
    throw markTransient(error);
  }
}

/**
 * A keep-alive https agent built from `tls`: its files and key stores read, and their passwords
 * decrypted, now - each password into a buffer zeroed before this returns. The agent's connections
 * all share one secure context, so nothing is read again.
 * @throws InvalidArgumentError tls isn't consistent, a file can't be read or a key store opened (see VaultTlsOptions)
 */
export function createVaultAgent(tls: VaultTlsOptions, options: AgentOptions = {}): HttpsAgent {
  return new HttpsAgent({ keepAlive: true, ...options, ...createSecureContextOptions(tls) });
}

/**
 * The agent https requests go through: the caller's `agent` (`own` false: the caller destroys it),
 * else one built from `tls` ({@link createVaultAgent}), else a keep-alive agent verifying against
 * Node's trust store (`own` true: destroyed when the integration closes).
 * @throws InvalidArgumentError see checkTlsOptions and {@link createVaultAgent}
 */
export function httpsAgentFor(agent: HttpAgent | undefined, tls: VaultTlsOptions | undefined): { agent: HttpAgent; own: boolean } {
  checkTlsOptions(agent, tls);
  if (agent !== undefined) return { agent, own: false };
  return { agent: tls !== undefined ? createVaultAgent(tls) : new HttpsAgent({ keepAlive: true }), own: true };
}

/**
 * How an integration reaches Vault: over http on loopback, or https through the caller's agent, one
 * built from VaultTlsOptions, or its own verifying against Node's trust store - keep-alive either
 * way, so a call reuses a connection (a stale one is reset, and that attempt retried). Node never
 * follows a redirect, whatever the agent.
 */
export class VaultConnector {
  readonly https: boolean;
  readonly hostname: string;
  readonly port: number | undefined;
  readonly agent: HttpAgent;
  readonly #ownAgent: boolean;

  /**
   * @param api where Vault's API is
   * @param agent the caller's agent, not destroyed by {@link close}; unused for http
   * @param tls the TLS to build an agent from, in place of agent; unused for http
   * @throws InvalidArgumentError see {@link checkTlsOptions} and {@link createVaultAgent}
   */
  constructor(api: VaultApiBase, agent?: HttpAgent, tls?: VaultTlsOptions) {
    checkTlsOptions(agent, tls);
    this.https = api.https;
    this.hostname = api.hostname;
    this.port = api.port;
    const chosen = api.https ? httpsAgentFor(agent, tls) : { agent: new HttpAgent({ keepAlive: true }), own: true };
    this.agent = chosen.agent;
    this.#ownAgent = chosen.own;
  }

  /** A request to `path` on Vault, through the connector's agent; sent once the caller ends it. */
  request(method: string, path: string, headers: OutgoingHttpHeaders): ClientRequest {
    return (this.https ? httpsRequest : httpRequest)({ hostname: this.hostname, port: this.port, path, method, agent: this.agent, headers });
  }

  /** Closes the connections, destroying the connector's own agent (one given is the caller's). Safe to call more than once. */
  close(): void {
    if (this.#ownAgent) this.agent.destroy();
  }
}

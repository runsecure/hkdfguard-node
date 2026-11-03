// When and how often a VaultClient retries, and how fast it may send: vault-client-go's
// RetryConfiguration and rate limiter.
import { randomInt } from 'node:crypto';
import { delay } from '@runsecure/hkdfguard-abstractions/internal';

/**
 * Whether to retry an attempt: called with the status Vault answered with (0 if no answer came)
 * and what the attempt failed with when no answer came (undefined otherwise).
 */
export type RetryPolicy = (statusCode: number, failure: unknown) => boolean;

/**
 * How long to wait before a retry, in milliseconds: called with
 * {@link VaultRetryOptions.retryWaitMinMs} and {@link VaultRetryOptions.retryWaitMaxMs}, the attempt
 * that failed (0 for the first) and the status it was answered with (0 if none).
 */
export type Backoff = (minimumMs: number, maximumMs: number, attempt: number, statusCode: number) => number;

// The codes Node's TLS gives a server certificate it refuses.
const CERTIFICATE_FAILURE = /^(ERR_TLS_CERT_ALTNAME_INVALID|DEPTH_ZERO_SELF_SIGNED_CERT|SELF_SIGNED_CERT_IN_CHAIN|UNABLE_TO_(GET_ISSUER_CERT(_LOCALLY)?|VERIFY_LEAF_SIGNATURE|DECRYPT_CERT_SIGNATURE)|CERT_[A-Z_]+|ERR_TLS_CERT_[A-Z_]+|HOSTNAME_MISMATCH)$/;

/**
 * go-retryablehttp's default policy, plus 412 (which Vault answers when an X-Vault-Index state
 * isn't there yet): retry when no answer came - unless the server's certificate was refused, which
 * another attempt would meet again - and on 412, 429, and any 5xx but 501.
 */
export function defaultRetryPolicy(statusCode: number, failure: unknown): boolean {
  if (failure !== undefined) return !isCertificateFailure(failure);
  return statusCode === 0 || statusCode === 412 || statusCode === 429 || (statusCode >= 500 && statusCode !== 501);
}

/**
 * go-retryablehttp's LinearJitterBackoff: a random wait between `minimumMs` and `maximumMs`, times
 * the number of attempts made so far - spread out so clients retrying together don't all arrive
 * together.
 */
export function linearJitterBackoff(minimumMs: number, maximumMs: number, attempt: number, _statusCode: number): number {
  const attempts = attempt + 1;
  if (maximumMs <= minimumMs) return minimumMs * attempts;
  const span = Math.min(Math.floor(maximumMs - minimumMs), 2 ** 47);
  return (minimumMs + (span > 0 ? randomInt(0, span) : 0)) * attempts;
}

/**
 * When and how often a {@link VaultClient} retries a failed request: vault-client-go's
 * RetryConfiguration (its go-retryablehttp client). Retries happen within the request's timeout,
 * and the request is sent whole each time - its body is held in memory for that. Every member is
 * optional.
 */
export interface VaultRetryOptions {
  /** The least time to wait before a retry, in milliseconds - VAULT_RETRY_WAIT_MIN. Default 1000. */
  readonly retryWaitMinMs?: number;
  /** The most time to wait before a retry, in milliseconds - VAULT_RETRY_WAIT_MAX. Default 1500. */
  readonly retryWaitMaxMs?: number;
  /** How many times to retry - VAULT_MAX_RETRIES. Zero or less for none. Default 2: three tries in all. */
  readonly retryMax?: number;
  /** Whether to retry; omitted for {@link defaultRetryPolicy}. */
  readonly checkRetry?: RetryPolicy;
  /** How long to wait before a retry; omitted for {@link linearJitterBackoff}. */
  readonly backoff?: Backoff;
}

/** The defaults of {@link VaultRetryOptions}. */
export const VaultRetryOptions = {
  DEFAULT_RETRY_WAIT_MIN_MS: 1000,
  DEFAULT_RETRY_WAIT_MAX_MS: 1500,
  DEFAULT_RETRY_MAX: 2,
} as const;

/**
 * A token bucket, as Go's rate.Limiter: up to {@link burst} requests at once, then
 * {@link requestsPerSecond}. A request waits for its turn rather than failing. Several clients may
 * share one.
 */
export class VaultRateLimiter {
  readonly #requestsPerSecond: number;
  readonly #burst: number;
  #tokens: number;
  #updated: number;

  /**
   * @param requestsPerSecond how many requests a second, once the burst is spent; may be fractional
   * @param burst how many requests may go at once
   * @throws RangeError requestsPerSecond isn't a positive number, or burst isn't a positive integer
   */
  constructor(requestsPerSecond: number, burst: number) {
    if (typeof requestsPerSecond !== 'number' || !Number.isFinite(requestsPerSecond) || requestsPerSecond <= 0) {
      throw new RangeError(`The rate must be a positive number; it is ${requestsPerSecond}.`);
    }
    if (!Number.isInteger(burst) || burst < 1) throw new RangeError(`The burst must be at least 1; it is ${burst}.`);
    this.#requestsPerSecond = requestsPerSecond;
    this.#burst = burst;
    this.#tokens = burst;
    this.#updated = performance.now();
  }

  /** Requests a second, once the burst is spent. */
  get requestsPerSecond(): number {
    return this.#requestsPerSecond;
  }

  /** Requests that may go at once. */
  get burst(): number {
    return this.#burst;
  }

  /**
   * Waits until a request may be sent, and counts it - unless the wait would take longer than
   * `maxWaitMs`, when it resolves false at once without counting it. Rejects with `signal`'s reason
   * if it is aborted meanwhile, giving the turn back.
   */
  async acquire(maxWaitMs: number, signal?: AbortSignal): Promise<boolean> {
    const now = performance.now();
    this.#tokens = Math.min(this.#burst, this.#tokens + ((now - this.#updated) / 1000) * this.#requestsPerSecond);
    this.#updated = now;
    const waitMs = this.#tokens >= 1 ? 0 : ((1 - this.#tokens) / this.#requestsPerSecond) * 1000;
    if (waitMs > maxWaitMs) return false;
    // Reserved now, waited for after: a request behind it waits for its own turn as well.
    this.#tokens -= 1;
    if (waitMs <= 0) return true;
    try {
      await delay(waitMs, signal);
    } catch (error) {
      // The request won't be sent: give its turn back.
      this.#tokens = Math.min(this.#burst, this.#tokens + 1);
      throw error;
    }
    return true;
  }
}

function isCertificateFailure(failure: unknown): boolean {
  for (let error = failure, depth = 0; typeof error === 'object' && error !== null && depth < 16; depth++) {
    const code = (error as { code?: unknown }).code;
    if (typeof code === 'string' && CERTIFICATE_FAILURE.test(code)) return true;
    error = (error as { cause?: unknown }).cause;
  }
  return false;
}

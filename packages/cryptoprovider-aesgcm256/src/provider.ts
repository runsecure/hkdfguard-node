import {
  ClosedError, InvalidArgumentError, KeyAccessSuspendedError, MAX_WRAPPED_KEY_BYTES, RefreshFailurePolicy, wipe,
  type CryptoProvider, type CryptoProviderFactory, type CryptoProviderOptions, type KeyWrapper,
} from '@runsecure/hkdfguard-abstractions';
import { AttributeNames, EventNames, HkdfGuardLog, HkdfGuardTelemetry, recordException, SpanNames, type Logger } from '@runsecure/hkdfguard-diagnostics';
import { AesGcmSession, budgetFor, KEY_SIZE, OVERHEAD, type EncryptionBudget } from './session.js';

/** The refresh interval range every provider accepts, in seconds. */
export const MIN_EXPIRY_SECONDS = 1;
export const MAX_EXPIRY_SECONDS = 300;

/** Options for {@link AesGcmCryptoProvider.create} beyond the cross-cipher {@link CryptoProviderOptions}. */
export interface AesGcmProviderOptions extends CryptoProviderOptions {
  /**
   * Receives an error for every failed background refresh, a critical entry when key access is
   * suspended, an informational one when it resumes, and a warning when the key nears its
   * encryption limit. Optional, but strongly recommended: under fail-open, the log is the only sign
   * a KEK has been revoked.
   */
  logger?: Logger;
}

/** @internal Test hooks: a budget of the test's own, and refreshes the test drives itself. */
export interface ProviderInternals {
  budget?: EncryptionBudget;
  manualRefresh?: boolean;
}

function validate(expirySeconds: number): void {
  if (!Number.isInteger(expirySeconds) || expirySeconds < MIN_EXPIRY_SECONDS || expirySeconds > MAX_EXPIRY_SECONDS) {
    throw new InvalidArgumentError(`ExpirySeconds must be between ${MIN_EXPIRY_SECONDS} and ${MAX_EXPIRY_SECONDS}, got ${expirySeconds}.`, 'ERR_HKDFGUARD_INVALID_EXPIRY');
  }
}

/** Reveals the DEK through the key wrapper and builds a session around it. */
async function reveal(wrapper: KeyWrapper, wrapped: Uint8Array, budget: EncryptionBudget | undefined,
  logger: Logger | undefined, signal: AbortSignal | undefined): Promise<AesGcmSession> {
  const key = new Uint8Array(KEY_SIZE);
  try {
    const written = await wrapper.unwrap(wrapped, key, signal);
    // A wrapper that reveals fewer bytes (a misconfigured KMS returning a 128-bit data key) would
    // otherwise leave the rest of the key zero and silently weaken every session.
    if (written !== KEY_SIZE) {
      throw new InvalidArgumentError(`Key wrapper revealed ${written} bytes; a ${KEY_SIZE}-byte DEK is required.`, 'ERR_HKDFGUARD_INVALID_LENGTH');
    }
    return new AesGcmSession(key, budget ?? budgetFor(key), logger);
  } catch (error) {
    wipe(key);
    throw error;
  }
}

/**
 * An AES-256-GCM {@link CryptoProvider} bound to one wrapped DEK. A background timer, ticking every
 * expiry, reveals the DEK fresh through the key wrapper and swaps in a new session, so encrypt and
 * decrypt never pay the unwrap cost; only create does, once.
 *
 * A refresh re-reveals the same DEK, so it checks the KEK is still accessible rather than bounding
 * how long the DEK is in memory. When refreshes fail, the {@link RefreshFailurePolicy} applies:
 * failing closed (the default) zeroes the key after that many consecutive failures and suspends
 * encrypt/decrypt - they throw KeyAccessSuspendedError - until a refresh succeeds; failing open
 * keeps the last good key in use.
 *
 * The timer is unref'd, so a provider never keeps the process alive; close() stops it.
 */
export class AesGcmCryptoProvider implements CryptoProvider {
  #current: AesGcmSession | undefined;
  #closed = false;
  #consecutiveFailures = 0;
  #timer: NodeJS.Timeout | undefined;
  #inFlight: Promise<void> | undefined;
  readonly #shutdown = new AbortController();

  private constructor(
    private readonly wrapper: KeyWrapper,
    private readonly wrapped: Uint8Array,
    readonly refreshFailurePolicy: RefreshFailurePolicy,
    private readonly budget: EncryptionBudget,
    private readonly logger: Logger | undefined,
    first: AesGcmSession,
  ) {
    this.#current = first;
  }

  /**
   * Creates a provider: reveals the DEK in `wrapped` through `wrapper` and starts the background
   * refresh. The provider owns `wrapped` and zeroes it on close. Bad arguments, or an aborted
   * signal, are reported before the key wrapper is called.
   */
  static async create(wrapper: KeyWrapper, wrapped: Uint8Array, options: AesGcmProviderOptions, internals: ProviderInternals = {}): Promise<AesGcmCryptoProvider> {
    validate(options.expirySeconds);
    // Don't rely on the key wrapper to honor a signal that's already aborted.
    options.signal?.throwIfAborted();

    const first = await reveal(wrapper, wrapped, internals.budget, options.logger, options.signal);
    const provider = new AesGcmCryptoProvider(wrapper, wrapped, options.refreshFailurePolicy ?? RefreshFailurePolicy.default,
      first.budget, options.logger, first);
    if (!internals.manualRefresh) {
      // A refresh records its own failures; this only keeps a throwing logger from becoming an
      // unhandled rejection.
      provider.#timer = setInterval(() => provider.refresh().catch(() => undefined), options.expirySeconds * 1000).unref();
    }
    return provider;
  }

  /** True while this provider has failed closed: its key is zeroed and every operation fails until a refresh succeeds. */
  get keyAccessSuspended(): boolean {
    return this.#current === undefined && !this.#closed;
  }

  /** Encryptions performed under this provider's key so far, across every provider revealing it. */
  get encryptionCount(): number {
    return this.budget.count;
  }

  encrypt(plaintext: Uint8Array, result: Uint8Array, aad?: Uint8Array): number {
    const session = this.#current;
    if (session === undefined) {
      // Suspended or closed: no session will run its own zeroing, so honor the contract here.
      wipe(plaintext);
      throw this.#unavailable();
    }
    return session.encrypt(plaintext, result, aad);
  }

  decrypt(ciphertext: Uint8Array, result: Uint8Array, aad?: Uint8Array): number {
    const session = this.#current;
    if (session === undefined) {
      throw this.#unavailable();
    }
    return session.decrypt(ciphertext, result, aad);
  }

  encryptedAllocationLength(plaintextLength: number): number {
    return plaintextLength + OVERHEAD;
  }

  decryptedAllocationLength(ciphertextLength: number): number {
    return Math.max(0, ciphertextLength - OVERHEAD);
  }

  #unavailable(): Error {
    return this.#closed
      ? new ClosedError('This crypto provider has been closed.')
      : new KeyAccessSuspendedError(`Key access is suspended: ${this.refreshFailurePolicy.maxFailures} consecutive attempts to re-reveal the key through the key wrapper failed. Operations resume once a refresh succeeds.`);
  }

  /**
   * One background refresh. A refresh still running when the next tick comes is not doubled up.
   * @internal Called by the timer, and by tests driving refreshes themselves.
   */
  refresh(): Promise<void> {
    if (this.#closed) {
      return Promise.resolve();
    }
    this.#inFlight ??= this.#refreshOnce().finally(() => { this.#inFlight = undefined; });
    return this.#inFlight;
  }

  async #refreshOnce(): Promise<void> {
    const telemetry = HkdfGuardTelemetry.cryptoProviderAesGcm256;
    const span = telemetry.tracer.startSpan(SpanNames.cryptoProviderAesGcm256.backgroundRefresh);
    try {
      let fresh: AesGcmSession;
      try {
        fresh = await reveal(this.wrapper, this.wrapped, this.budget, this.logger, this.#shutdown.signal);
      } catch (error) {
        if (this.#closed) {
          return; // shutdown: whatever the in-flight refresh failed with is moot
        }
        recordException(span, error);
        this.#consecutiveFailures++;
        const failures = this.#consecutiveFailures;
        // Logged on every failure, whatever the policy: under fail-open it is the only sign the KEK is gone.
        HkdfGuardLog.keyRefreshFailed(this.logger, failures, this.refreshFailurePolicy.toString(), error);
        if (failures === this.refreshFailurePolicy.maxFailures) {
          // Fail closed: zero the revealed DEK and refuse operations until a refresh succeeds.
          this.#swap(undefined);
          span.addEvent(EventNames.keyAccessSuspended, { [AttributeNames.consecutiveFailures]: failures });
          HkdfGuardLog.keyAccessSuspended(this.logger, failures);
        }
        return;
      }

      if (this.#closed) {
        fresh.close();
        return;
      }
      this.#swap(fresh);
      const previousFailures = this.#consecutiveFailures;
      this.#consecutiveFailures = 0;
      const limit = this.refreshFailurePolicy.maxFailures;
      if (limit !== undefined && previousFailures >= limit) {
        HkdfGuardLog.keyAccessResumed(this.logger, previousFailures);
      }
    } finally {
      span.end();
    }
  }

  /** Makes `next` current and zeroes the session it replaces - nothing can still be using it, since operations are synchronous. */
  #swap(next: AesGcmSession | undefined): void {
    const previous = this.#current;
    this.#current = next;
    previous?.close();
  }

  /**
   * Stops the background refresh - cancelling and awaiting one in flight - then zeroes the wrapped
   * payload and the revealed key. Every later operation throws ClosedError. Safe to call more than once.
   */
  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    clearInterval(this.#timer);
    this.#shutdown.abort();
    await this.#inFlight;
    wipe(this.wrapped);
    this.#swap(undefined);
  }
}

/**
 * Mints {@link AesGcmCryptoProvider}s for a key ring - the {@link CryptoProviderFactory} for this
 * cipher. Its logger is handed to every provider it creates.
 */
export class AesGcmCryptoProviderFactory implements CryptoProviderFactory {
  constructor(private readonly options: { logger?: Logger } = {}) {}

  create(wrapper: KeyWrapper, wrapped: Uint8Array, options: CryptoProviderOptions): Promise<CryptoProvider> {
    return AesGcmCryptoProvider.create(wrapper, wrapped, { ...options, logger: this.options.logger });
  }

  /** Has `wrapper` generate and wrap a fresh DEK, then builds a provider revealing it. Bad arguments fail before anything is generated. */
  async createEphemeral(wrapper: KeyWrapper, options: CryptoProviderOptions): Promise<CryptoProvider> {
    validate(options.expirySeconds);
    options.signal?.throwIfAborted();

    // Sized to the same limit a key file is held to; trimmed to what generateAndWrap wrote.
    const buffer = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await wrapper.generateAndWrap(buffer, options.signal);
    if (!Number.isInteger(length) || length <= 0 || length > buffer.length) {
      throw new InvalidArgumentError(`Key wrapper reported a ${length}-byte wrapped key in a ${buffer.length}-byte buffer.`, 'ERR_HKDFGUARD_INVALID_LENGTH');
    }
    return this.create(wrapper, buffer.slice(0, length), options);
  }
}

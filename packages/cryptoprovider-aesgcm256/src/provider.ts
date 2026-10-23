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
  /** How long a refresh waits for the key wrapper; the refresh interval unless a test shortens it. */
  refreshTimeoutMs?: number;
}

type RevealOutcome = { kind: 'revealed'; session: AesGcmSession } | { kind: 'timedOut' } | { kind: 'shutdown' };

/** Runs application code (its logger, its tracer) so that an exception from it can never decide whether the key stays in use. */
function quietly(action: () => void): void {
  try {
    action();
  } catch {
    // Deliberately ignored: see above.
  }
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
 * A refresh that takes longer than one refresh interval counts as failed, so a key wrapper that hangs
 * instead of failing still suspends key access on schedule.
 *
 * The timer is unref'd, so a provider never keeps the process alive; close() stops it.
 */
export class AesGcmCryptoProvider implements CryptoProvider {
  #current: AesGcmSession | undefined;
  #closed = false;
  #consecutiveFailures = 0;
  #timer: NodeJS.Timeout | undefined;
  #inFlight: Promise<void> | undefined;
  // A reveal a refresh stopped waiting for, while it is still running. See #refreshOnce.
  #abandoned: Promise<AesGcmSession> | undefined;
  readonly #shutdown = new AbortController();

  private constructor(
    private readonly wrapper: KeyWrapper,
    private readonly wrapped: Uint8Array,
    readonly refreshFailurePolicy: RefreshFailurePolicy,
    private readonly budget: EncryptionBudget,
    private readonly logger: Logger | undefined,
    private readonly refreshTimeoutMs: number,
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
      first.budget, options.logger, internals.refreshTimeoutMs ?? options.expirySeconds * 1000, first);
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

  /**
   * Re-reveals the key, waiting at most one refresh interval for the key wrapper. A wrapper that
   * hangs rather than failing (a busy TPM resource manager, a keychain prompt nobody can answer, a
   * KMS endpoint that never replies) must still count towards the refresh-failure policy, or a
   * revoked KEK would never suspend key access. A reveal that misses its deadline is abandoned, not
   * cancelled - a native call can't be - and until it settles no new one starts, so a stuck wrapper
   * never accumulates calls; each tick in the meantime is a failed refresh.
   */
  async #refreshOnce(): Promise<void> {
    const telemetry = HkdfGuardTelemetry.cryptoProviderAesGcm256;
    const span = telemetry.tracer.startSpan(SpanNames.cryptoProviderAesGcm256.backgroundRefresh);
    try {
      if (this.#abandoned !== undefined) {
        this.#refreshFailed(span, new Error('The key wrapper has still not returned from a refresh that timed out; no new refresh starts until it does.'));
        return;
      }

      let outcome: RevealOutcome;
      try {
        outcome = await this.#revealWithDeadline();
      } catch (error) {
        if (this.#closed) {
          return; // shutdown: whatever the in-flight refresh failed with is moot
        }
        this.#refreshFailed(span, error);
        return;
      }

      if (outcome.kind === 'shutdown') {
        return;
      }
      if (outcome.kind === 'timedOut') {
        this.#refreshFailed(span, new Error(`The key wrapper did not reveal the key within ${this.refreshTimeoutMs} ms.`));
        return;
      }
      if (this.#closed) {
        outcome.session.close();
        return;
      }
      this.#swap(outcome.session);
      const previousFailures = this.#consecutiveFailures;
      this.#consecutiveFailures = 0;
      const limit = this.refreshFailurePolicy.maxFailures;
      if (limit !== undefined && previousFailures >= limit) {
        quietly(() => HkdfGuardLog.keyAccessResumed(this.logger, previousFailures));
      }
    } finally {
      quietly(() => span.end());
    }
  }

  /** Reveals the key, unless the deadline or shutdown comes first; then the reveal is abandoned. */
  async #revealWithDeadline(): Promise<RevealOutcome> {
    const pending = reveal(this.wrapper, this.wrapped, this.budget, this.logger, this.#shutdown.signal);
    let timer: NodeJS.Timeout | undefined;
    let onShutdown: (() => void) | undefined;
    const deadline = new Promise<RevealOutcome>((resolve) => {
      timer = setTimeout(() => resolve({ kind: 'timedOut' }), this.refreshTimeoutMs).unref();
      onShutdown = () => resolve({ kind: 'shutdown' });
      this.#shutdown.signal.addEventListener('abort', onShutdown, { once: true });
    });
    try {
      const outcome = await Promise.race([pending.then((session): RevealOutcome => ({ kind: 'revealed', session })), deadline]);
      if (outcome.kind !== 'revealed') {
        this.#abandon(pending);
      }
      return outcome;
    } finally {
      clearTimeout(timer);
      this.#shutdown.signal.removeEventListener('abort', onShutdown!);
    }
  }

  /** Remembers a reveal nobody waits for any more, and zeroes whatever key it eventually reveals. */
  #abandon(pending: Promise<AesGcmSession>): void {
    this.#abandoned = pending;
    pending.then((late) => late.close(), () => undefined).finally(() => {
      if (this.#abandoned === pending) {
        this.#abandoned = undefined;
      }
    });
  }

  #refreshFailed(span: ReturnType<typeof HkdfGuardTelemetry.cryptoProviderAesGcm256.tracer.startSpan>, error: unknown): void {
    this.#consecutiveFailures++;
    const failures = this.#consecutiveFailures;

    // Enforce the policy before anything that runs application code (telemetry, the logger), so an
    // exception there can't leave the key in use past the limit. >= rather than ===, and a suspend
    // that is a no-op once suspended, so no tick can step over it.
    const limit = this.refreshFailurePolicy.maxFailures;
    const suspendedNow = limit !== undefined && failures >= limit && this.#current !== undefined;
    if (suspendedNow) {
      // Fail closed: zero the revealed DEK and refuse operations until a refresh succeeds.
      this.#swap(undefined);
    }

    quietly(() => recordException(span, error));
    // Logged on every failure, whatever the policy: under fail-open it is the only sign the KEK is gone.
    quietly(() => HkdfGuardLog.keyRefreshFailed(this.logger, failures, this.refreshFailurePolicy.toString(), error));
    if (suspendedNow) {
      quietly(() => span.addEvent(EventNames.keyAccessSuspended, { [AttributeNames.consecutiveFailures]: failures }));
      quietly(() => HkdfGuardLog.keyAccessSuspended(this.logger, failures));
    }
  }

  /** Makes `next` current and zeroes the session it replaces - nothing can still be using it, since operations are synchronous. */
  #swap(next: AesGcmSession | undefined): void {
    const previous = this.#current;
    this.#current = next;
    previous?.close();
  }

  /**
   * Stops the background refresh - cancelling one in flight, and not waiting for a key wrapper that
   * doesn't return; whatever key it later reveals is zeroed when it arrives - then zeroes the wrapped
   * payload and the revealed key. Every later operation throws ClosedError. Safe to call more than once.
   */
  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    clearInterval(this.#timer);
    this.#shutdown.abort();
    await this.#inFlight?.catch(() => undefined);
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

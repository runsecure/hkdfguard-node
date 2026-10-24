import { InvalidArgumentError } from './errors.js';
import { DEFAULT_MAX_REFRESH_FAILURES, MAX_ALLOWED_REFRESH_FAILURES } from './rules.js';

/**
 * What a crypto provider does when re-revealing its key through the KEK keeps failing. Failing
 * closed after n consecutive failures zeroes the key and refuses every operation until a refresh
 * succeeds, so revoking the KEK reaches a running process; failing open keeps serving on the last
 * good key however many refreshes fail. Omitting a policy means {@link RefreshFailurePolicy.default}
 * - failing closed - so the safe choice is the one made by doing nothing.
 */
export class RefreshFailurePolicy {
  private constructor(
    /** Consecutive failures tolerated before failing closed; undefined when the policy fails open. */
    readonly maxFailures: number | undefined,
  ) {}

  /** Fails closed after {@link DEFAULT_MAX_REFRESH_FAILURES} consecutive failures. */
  static readonly default = new RefreshFailurePolicy(DEFAULT_MAX_REFRESH_FAILURES);

  /**
   * Fails closed once `maxFailures` consecutive refreshes have failed.
   *
   * @throws InvalidArgumentError maxFailures is not an integer from 1 to {@link MAX_ALLOWED_REFRESH_FAILURES}.
   */
  static failClosedAfter(maxFailures: number): RefreshFailurePolicy {
    if (!Number.isInteger(maxFailures) || maxFailures < 1 || maxFailures > MAX_ALLOWED_REFRESH_FAILURES) {
      throw new InvalidArgumentError(`MaxRefreshFailures must be between 1 and ${MAX_ALLOWED_REFRESH_FAILURES}, got ${maxFailures}.`, 'ERR_HKDFGUARD_INVALID_REFRESH_FAILURE_POLICY');
    }
    return new RefreshFailurePolicy(maxFailures);
  }

  /** Keeps serving on the last good key however many refreshes fail. */
  static failOpen(): RefreshFailurePolicy {
    return new RefreshFailurePolicy(undefined);
  }

  /** True when the policy fails closed. */
  get failsClosed(): boolean {
    return this.maxFailures !== undefined;
  }

  /** The policy as the other ports describe it in logs. */
  toString(): string {
    return this.maxFailures === undefined
      ? 'fail open (the last good key stays in use)'
      : `fail closed after ${this.maxFailures} consecutive failures`;
  }
}

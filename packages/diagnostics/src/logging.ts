import { AttributeNames } from './names.js';

/**
 * Where HkdfGuard writes log entries. `console` satisfies it, and so does any logger with
 * level-named methods taking a message and an attributes object (wrap loggers whose argument order
 * differs, such as pino's). Every method is optional; a missing level is simply not logged.
 */
export interface Logger {
  debug?(message: string, attributes: Record<string, unknown>): void;
  info?(message: string, attributes: Record<string, unknown>): void;
  warn?(message: string, attributes: Record<string, unknown>): void;
  error?(message: string, attributes: Record<string, unknown>): void;
}

/** Log entry attribute keys. Event ids and names match the other ports'. */
export const LogKeys = {
  eventId: 'event.id',
  eventName: 'event.name',
  error: 'error',
  level: 'log.level',
  refreshFailurePolicy: 'hkdfguard.refresh_failure_policy',
} as const;

type Level = 'debug' | 'info' | 'warn' | 'error' | 'critical';

/**
 * Writes one entry. The message is built only when `logger` has the level, so an absent logger
 * or level costs nothing. Critical entries go to `error`, marked with {@link LogKeys.level}.
 */
function logEvent(
  logger: Logger | undefined,
  level: Level,
  eventId: number,
  eventName: string,
  message: () => string,
  attributes: Record<string, unknown>,
  error?: unknown,
): void {
  const method = logger?.[level === 'critical' ? 'error' : level];
  if (method === undefined) {
    return;
  }
  const entry: Record<string, unknown> = { [LogKeys.eventId]: eventId, [LogKeys.eventName]: eventName, ...attributes };
  if (level === 'critical') {
    entry[LogKeys.level] = 'critical';
  }
  if (error !== undefined) {
    entry[LogKeys.error] = error;
  }
  method.call(logger, message(), entry);
}

/**
 * Structured-log helpers shared by every component that accepts an optional {@link Logger}.
 * `sensitiveOperationLogged` is only worth calling when sensitive logging is enabled, while
 * `operationFailed` is unconditional - failures are always worth logging.
 */
export const HkdfGuardLog = {
  /** Debug: `operationName` completed for `name`. */
  sensitiveOperationLogged(logger: Logger | undefined, operationName: string, name: string): void {
    logEvent(logger, 'debug', 1, 'SensitiveOperationLogged', () => `${operationName} completed for ${name}.`, {
      [AttributeNames.operationName]: operationName,
      [AttributeNames.name]: name,
    });
  },

  /** Error: `operationName` failed with `error`. */
  operationFailed(logger: Logger | undefined, operationName: string, error: unknown): void {
    logEvent(logger, 'error', 2, 'OperationFailed', () => `${operationName} failed.`, {
      [AttributeNames.operationName]: operationName,
    }, error);
  },

  /**
   * Error: a background attempt to re-reveal a key through its key wrapper failed - the KEK may
   * have been revoked or become unreachable. Log it on every failure, whatever the policy: under
   * fail-open it is the only sign the KEK is gone.
   */
  keyRefreshFailed(logger: Logger | undefined, consecutiveFailures: number, refreshFailurePolicy: string, error: unknown): void {
    logEvent(logger, 'error', 3, 'KeyRefreshFailed',
      () => `Background key refresh failed (${consecutiveFailures} consecutive). Policy: ${refreshFailurePolicy}.`, {
        [AttributeNames.consecutiveFailures]: consecutiveFailures,
        [LogKeys.refreshFailurePolicy]: refreshFailurePolicy,
      }, error);
  },

  /** Critical: the refresh-failure limit was reached; the key is zeroed and every operation fails until a refresh succeeds. */
  keyAccessSuspended(logger: Logger | undefined, consecutiveFailures: number): void {
    logEvent(logger, 'critical', 4, 'KeyAccessSuspended',
      () => `Key access suspended after ${consecutiveFailures} consecutive failed refreshes; the key has been zeroed and every operation under it fails until a refresh succeeds.`,
      { [AttributeNames.consecutiveFailures]: consecutiveFailures });
  },

  /** Info: a refresh succeeded after key access had been suspended; operations resume. */
  keyAccessResumed(logger: Logger | undefined, consecutiveFailures: number): void {
    logEvent(logger, 'info', 5, 'KeyAccessResumed',
      () => `Key access resumed: a background refresh succeeded after ${consecutiveFailures} consecutive failures.`,
      { [AttributeNames.consecutiveFailures]: consecutiveFailures });
  },

  /** Info: a scheduled rotation added a fresh ephemeral key, which is now current. */
  ephemeralKeyRotated(logger: Logger | undefined, keyVersion: number): void {
    logEvent(logger, 'info', 6, 'EphemeralKeyRotated',
      () => `Ephemeral key rotated: version ${keyVersion} is now current.`,
      { [AttributeNames.keyVersion]: keyVersion });
  },

  /** Error: a scheduled rotation could not add a key; the current version stays in use. */
  ephemeralKeyRotationFailed(logger: Logger | undefined, keyVersion: number, error: unknown): void {
    logEvent(logger, 'error', 7, 'EphemeralKeyRotationFailed',
      () => `Ephemeral key rotation failed; version ${keyVersion} stays current until the next attempt.`,
      { [AttributeNames.keyVersion]: keyVersion }, error);
  },

  /** Info: a superseded ephemeral key's retention ran out; it was removed and zeroed. */
  ephemeralKeyRetired(logger: Logger | undefined, keyVersion: number): void {
    logEvent(logger, 'info', 8, 'EphemeralKeyRetired',
      () => `Ephemeral key retired: version ${keyVersion} has been removed and its key zeroed; values encrypted under it no longer decrypt.`,
      { [AttributeNames.keyVersion]: keyVersion });
  },

  /** Error: a retired ephemeral key was removed from the ring but closing it failed. */
  ephemeralKeyRetirementFailed(logger: Logger | undefined, keyVersion: number, error: unknown): void {
    logEvent(logger, 'error', 9, 'EphemeralKeyRetirementFailed',
      () => `Ephemeral key version ${keyVersion} was removed from the ring, but disposing it failed.`,
      { [AttributeNames.keyVersion]: keyVersion }, error);
  },

  /** Warning: a key crossed the warning threshold of its encryption budget; rotate it before the limit. */
  encryptionBudgetWarning(logger: Logger | undefined, encryptionCount: number, encryptionLimit: number): void {
    logEvent(logger, 'warn', 10, 'EncryptionBudgetWarning',
      () => `This key has performed ${encryptionCount} encryptions of its ${encryptionLimit} AES-GCM limit; rotate it before the limit, when it stops encrypting.`,
      { [AttributeNames.encryptionCount]: encryptionCount, [AttributeNames.encryptionLimit]: encryptionLimit });
  },
};

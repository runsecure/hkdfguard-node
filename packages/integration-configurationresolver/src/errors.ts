import { HkdfGuardError, InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';

/**
 * Why a configuration item could not be resolved - the port of ConfigurationResolver's
 * ConfigurationKeyError enum. Each value is its .NET name, which is what messages show.
 */
export const ConfigurationKeyErrorCode = {
  /** The key was not read by the configuration item reader, so no value provider was asked for it. */
  notAllowed: 'NotAllowed',
  /** The key was allowed, but no value provider has a value for it. */
  notFound: 'NotFound',
  /** The value kept changing size while it was read, such as a secret being replaced. */
  valueUnstable: 'ValueUnstable',
  /** The key's value, resolved through the items in it, leads back to the same key. */
  cycle: 'Cycle',
} as const;

/** A {@link ConfigurationKeyErrorCode} value. */
export type ConfigurationKeyErrorCode = (typeof ConfigurationKeyErrorCode)[keyof typeof ConfigurationKeyErrorCode];

/**
 * The value for a configuration key could not be resolved - the port of ConfigurationKeyException.
 * `code` is 'ERR_HKDFGUARD_CONFIGURATION_KEY', and {@link error} says why.
 *
 * The message holds only the item's position and the reason, so it is safe to log. The key is
 * available from {@link key}; it may come from the source text, which may be untrusted, so treat it
 * as untrusted input before logging or displaying it.
 */
export class ConfigurationKeyError extends HkdfGuardError {
  /** The configuration key. When thrown by a resolver it comes from the source text and may be untrusted. */
  readonly key: string;

  /** Why the value could not be resolved. */
  readonly error: ConfigurationKeyErrorCode;

  /**
   * The index in the UTF-8 source where the item's start sequence begins, or undefined when thrown
   * outside a resolver, such as by a value provider called directly.
   */
  readonly sourceIndex: number | undefined;

  /**
   * @param key the configuration key; for an item in a source, its trimmed key
   * @param error why the value could not be resolved
   * @param sourceIndex the byte index in the source where the item's start sequence begins, or
   *   undefined when it isn't known
   */
  constructor(key: string, error: ConfigurationKeyErrorCode, sourceIndex?: number, options?: { cause?: unknown }) {
    super(
      'ERR_HKDFGUARD_CONFIGURATION_KEY',
      sourceIndex === undefined
        ? `The value for a configuration key could not be resolved (${error}).`
        : `The configuration item at index ${sourceIndex} could not be resolved (${error}).`,
      options,
    );
    this.key = key;
    this.error = error;
    this.sourceIndex = sourceIndex;
  }
}

/**
 * The destination is too small for the resolved text - the port of the ArgumentException a .NET
 * resolver throws for its destination. Its `code` is 'ERR_HKDFGUARD_DESTINATION_TOO_SMALL'.
 */
export class DestinationTooSmallError extends InvalidArgumentError {
  constructor() {
    super('The destination is too small for the resolved text.', 'ERR_HKDFGUARD_DESTINATION_TOO_SMALL');
  }
}

/**
 * ProtectedCacheValueProvider.tryGetValue was called without allowStringValues set - the port of the
 * InvalidOperationException .NET throws. Its `code` is 'ERR_HKDFGUARD_STRING_VALUES_NOT_ALLOWED'.
 */
export class StringValuesNotAllowedError extends HkdfGuardError {
  constructor() {
    super(
      'ERR_HKDFGUARD_STRING_VALUES_NOT_ALLOWED',
      "ProtectedCacheValueProvider doesn't return values as strings unless allowStringValues is set.",
    );
  }
}

/**
 * A template resolves to more than a ResolvingProtectedCacheCollection's maxResolvedLength bytes -
 * the port of the InvalidOperationException .NET throws. Its `code` is
 * 'ERR_HKDFGUARD_RESOLVED_VALUE_TOO_LONG'.
 */
export class ResolvedValueTooLongError extends HkdfGuardError {
  constructor(maxResolvedLength: number, options?: { cause?: unknown }) {
    super('ERR_HKDFGUARD_RESOLVED_VALUE_TOO_LONG', `The value resolves to more than maxResolvedLength (${maxResolvedLength}) bytes.`, options);
  }
}

/**
 * An operation called before the object was ready for it, such as building a resolver with no reader
 * - the port of .NET's InvalidOperationException. Its `code` is 'ERR_HKDFGUARD_INVALID_OPERATION'.
 */
export class InvalidOperationError extends HkdfGuardError {
  constructor(message: string) {
    super('ERR_HKDFGUARD_INVALID_OPERATION', message);
  }
}

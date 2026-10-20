/**
 * Errors shared across implementations. Each has a stable `code` (Node convention), so callers can
 * test `error instanceof KeyNotFoundError` or `error.code === 'ERR_HKDFGUARD_KEY_NOT_FOUND'` - the
 * latter also works across duplicate copies of this package. Every cipher, key wrapper and cache
 * reports the same errors for the same situations, so callers handle them the same way whichever
 * implementation is plugged in.
 */
export class HkdfGuardError extends Error {
  constructor(
    readonly code: string,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** No key is registered for a requested key version. */
export class KeyNotFoundError extends HkdfGuardError {
  constructor(message = 'No key is registered for this version.', options?: { cause?: unknown }) {
    super('ERR_HKDFGUARD_KEY_NOT_FOUND', message, options);
  }
}

/** A key ring has no key registered yet. */
export class NoCurrentKeyError extends HkdfGuardError {
  constructor(message = 'No current version has been set. Add a key first.') {
    super('ERR_HKDFGUARD_NO_CURRENT_KEY', message);
  }
}

/** A protected cache already holds a value under a name. */
export class AlreadyExistsError extends HkdfGuardError {
  constructor(message: string) {
    super('ERR_HKDFGUARD_ALREADY_EXISTS', message);
  }
}

/** An argument breaks a rule: an invalid configuration key, service name, cache name, policy, length or setting. */
export class InvalidArgumentError extends HkdfGuardError {
  constructor(message: string, code = 'ERR_HKDFGUARD_INVALID_ARGUMENT') {
    super(code, message);
  }
}

/** A configuration key that is empty or not valid UTF-16. */
export class InvalidConfigurationKeyError extends InvalidArgumentError {
  constructor(message: string) {
    super(message, 'ERR_HKDFGUARD_INVALID_CONFIGURATION_KEY');
  }
}

/** A service name that breaks a {@link validateServiceName} rule. */
export class InvalidServiceNameError extends InvalidArgumentError {
  constructor(message: string) {
    super(message, 'ERR_HKDFGUARD_INVALID_SERVICE_NAME');
  }
}

/** A cache entry name that is not valid UTF-16. */
export class InvalidCacheNameError extends InvalidArgumentError {
  constructor(message: string) {
    super(message, 'ERR_HKDFGUARD_INVALID_CACHE_NAME');
  }
}

/**
 * Ciphertext failed AEAD authentication: it was altered, or is being decrypted with a different
 * key or Additional Authenticated Data than it was encrypted with.
 */
export class AuthenticationFailedError extends HkdfGuardError {
  constructor(message = 'Message authentication failed.', options?: { cause?: unknown }) {
    super('ERR_HKDFGUARD_AUTHENTICATION_FAILED', message, options);
  }
}

/**
 * A crypto provider has failed closed under its refresh-failure policy: its key is zeroed and every
 * operation fails until a background refresh succeeds again.
 */
export class KeyAccessSuspendedError extends HkdfGuardError {
  constructor(message: string) {
    super('ERR_HKDFGUARD_KEY_ACCESS_SUSPENDED', message);
  }
}

/** A key has performed as many encryptions as its cipher safely allows; rotate it. Decryption still works. */
export class EncryptionLimitReachedError extends HkdfGuardError {
  constructor(message: string) {
    super('ERR_HKDFGUARD_ENCRYPTION_LIMIT_REACHED', message);
  }
}

/** An operation on a provider, key, ring, protector or cache that has been closed. */
export class ClosedError extends HkdfGuardError {
  constructor(message = 'This object has been closed.') {
    super('ERR_HKDFGUARD_CLOSED', message);
  }
}

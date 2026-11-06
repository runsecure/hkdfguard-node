import { HkdfGuardError } from '@runsecure/hkdfguard-abstractions';

/**
 * The code a key file that is not a wrapped key is refused with - the same code the native key
 * wrapper's KeyFileRefusedError and the dek package's InvalidKeyFileError carry, so a caller handles
 * every key wrapper's refusal alike.
 */
export const INVALID_KEY_FILE = 'ERR_HKDFGUARD_INVALID_KEY_FILE';

/**
 * The code a file {@link readTrustedFile} reads is refused with when it is longer than the caller's
 * limit - read no more than one byte past it.
 */
export const FILE_TOO_LARGE = 'ERR_HKDFGUARD_FILE_TOO_LARGE';

/**
 * A file {@link readTrustedKeyFile} or {@link readTrustedFile} refused or could not read - a key
 * file, or any other file read from a trusted location. `code` follows Node's fs errors, as
 * KeyWrapper.readKeyFile documents:
 *
 * - 'ENOENT': the file, or a folder on its path, doesn't exist.
 * - 'EACCES': this account may not read it, or its location is not trusted - another account could
 *   have written or replaced it (the message says "is not trusted" and names what).
 * - ERR_HKDFGUARD_INVALID_KEY_FILE (readTrustedKeyFile): it is empty, larger than
 *   MAX_WRAPPED_KEY_BYTES, or holds what looks like an unwrapped key.
 * - ERR_HKDFGUARD_FILE_TOO_LARGE (readTrustedFile): it is longer than the limit the caller gave.
 * - 'EBUSY': another process has it open for writing (Windows).
 * - anything else: what the system reported ('EIO' when it reported nothing more specific).
 */
export class KeyFileError extends HkdfGuardError {
  constructor(
    code: string,
    /** The file's path, as given or as resolved - whichever the message names. */
    readonly path: string,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(code, message, options);
  }
}

/** Not Windows, Linux or an Apple silicon Mac - or, on Windows, the add-on was never built. */
export class UnsupportedPlatformError extends HkdfGuardError {
  constructor(message: string, options?: { cause?: unknown }) {
    super('ERR_HKDFGUARD_UNSUPPORTED_PLATFORM', message, options);
  }
}

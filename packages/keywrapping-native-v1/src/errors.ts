import { HkdfGuardError } from '@runsecure/hkdfguard-abstractions';
import { Status } from './status.js';

/** The native KMS library is not installed at any location it is loaded from. */
export class NotInstalledError extends HkdfGuardError {
  constructor(message: string) {
    super('ERR_HKDFGUARD_NATIVE_NOT_INSTALLED', message);
  }
}

/**
 * The installed library, its location, its dependencies, or the process environment failed
 * verification, so the library was not loaded.
 */
export class UntrustedError extends HkdfGuardError {
  constructor(message: string, options?: { cause?: unknown }) {
    super('ERR_HKDFGUARD_NATIVE_UNTRUSTED', message, options);
  }
}

/**
 * A platform (OS, architecture or OS version, or a missing native add-on build) the native library
 * can't be used on, or an operation it doesn't offer.
 */
export class UnsupportedPlatformError extends HkdfGuardError {
  constructor(message: string, options?: { cause?: unknown }) {
    super('ERR_HKDFGUARD_NATIVE_UNSUPPORTED_PLATFORM', message, options);
  }
}

/**
 * A native call that returned a non-zero status. Every platform shares one status table (see
 * Status); `description` is what `status` means here, or undefined when unknown.
 */
export class StatusError extends HkdfGuardError {
  constructor(
    /** "wrap", "unwrap", "generate-and-wrap", or "process hardening". */
    readonly operation: string,
    /** The service name the operation ran under; undefined for process hardening. */
    readonly service: string | undefined,
    readonly status: number,
    readonly description: string | undefined,
  ) {
    const meaning = description === undefined ? '' : ` (${description})`;
    super('ERR_HKDFGUARD_NATIVE_STATUS', service === undefined
      ? `Native ${operation} failed with status ${status}${meaning}.`
      : `Native KMS ${operation} failed for service '${service}' with status ${status}${meaning}.`);
  }
}

/**
 * The `code` a key-file refusal carries, chosen as Node's fs errors would report the same problem,
 * and as KeyWrapper.readKeyFile documents: 'ENOENT' for a missing
 * file or folder, 'EACCES' for a file this account may not read or whose path is not trusted,
 * ERR_HKDFGUARD_INVALID_KEY_FILE for a file of the wrong size, one holding what looks like an
 * unwrapped key, or one that is not a wrapped DEK, ERR_HKDFGUARD_INVALID_ARGUMENT for a path the
 * library rejects as an argument, and 'EIO' for anything else.
 */
export function keyFileErrorCode(status: number): string {
  switch (status) {
    case Status.fileNotFound: return 'ENOENT';
    case Status.fileAccessDenied:
    case Status.fileUntrusted: return 'EACCES';
    case Status.fileTooShort:
    case Status.fileTooLong:
    case Status.filePlaintextKey:
    case Status.fileMalformed: return INVALID_KEY_FILE;
    case Status.invalidArgument: return 'ERR_HKDFGUARD_INVALID_ARGUMENT';
    default: return 'EIO';
  }
}

/** The code the managed key-file read gives an empty or oversized file; shared so both reads agree. */
export const INVALID_KEY_FILE = 'ERR_HKDFGUARD_INVALID_KEY_FILE';

/**
 * A key file the native library's hkdfguard_open_file refused. `code` follows Node's fs errors (see
 * {@link keyFileErrorCode}); `status` and `description` are the native status and its meaning.
 */
export class KeyFileRefusedError extends HkdfGuardError {
  constructor(
    /** The key file's path, as given. */
    readonly path: string,
    readonly status: number,
    readonly description: string | undefined,
  ) {
    super(keyFileErrorCode(status),
      `Key file '${path}' was refused by the native library with status ${status} (${description ?? 'unknown status'}).`);
  }
}

/**
 * `error` unchanged if it is already one of this package's loader errors, otherwise wrapped in an
 * {@link UntrustedError}: any failure while verifying the library - a path that couldn't be
 * examined, say - is a reason not to load it.
 */
export function classify(error: unknown): Error {
  if (error instanceof NotInstalledError || error instanceof UntrustedError || error instanceof UnsupportedPlatformError) {
    return error;
  }
  const message = error instanceof Error ? error.message : String(error);
  return new UntrustedError(message, { cause: error });
}

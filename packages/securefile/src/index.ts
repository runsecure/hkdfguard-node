/**
 * Reads a wrapped-key file only from where no untrusted account could have written or replaced it -
 * the native library's hkdfguard_open_file checks, made in TypeScript - for a key wrapper with no
 * native library to read through, such as @runsecure/hkdfguard-keywrapping-awskms. The Node port of
 * the .NET HkdfGuard.SecureFile library.
 *
 * {@link readTrustedKeyFile} reads; {@link KeyFileTrust} says who, besides the operating system's
 * administrators, may have written the file. It runs on Windows, Linux and Apple silicon Macs with
 * no native HkdfGuard library installed: on Linux and macOS the checks are Node's own fs calls
 * (lstat, readlink, open with O_NOFOLLOW, fstat); on Windows they are Win32 calls - owner and DACL,
 * reparse points, final path, drive type - made through this package's own small add-on
 * (native/hkdfguard_securefile.c), compiled by node-gyp when the package is installed on Windows.
 * Nothing is compiled on Linux or macOS.
 *
 * This package is standalone: it does not depend on, or load, the native KMS library or its loader.
 */
export { readTrustedKeyFile, PLAINTEXT_KEY_LENGTH } from './trustedkeyfile.js';
export { KeyFileTrust, type KeyFileTrustOptions } from './trust.js';
export { INVALID_KEY_FILE, KeyFileError, UnsupportedPlatformError } from './errors.js';

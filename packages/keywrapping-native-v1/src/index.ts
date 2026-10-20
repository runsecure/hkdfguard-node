/**
 * A KeyWrapper over the operating system's native HkdfGuard KMS library - the Node port of the .NET
 * HkdfGuard.KeyWrapping.V1 library. The KEK is a TPM2, Secure Enclave, or Platform Crypto Provider
 * key held entirely outside this process, identified only by a service name.
 *
 * The native library receives every plaintext DEK on unwrap and chooses every DEK on
 * generate-and-wrap, so it is never found by a search: it is loaded only from its fixed install
 * location, after verifying path ownership and permissions, the platform code signature
 * (Authenticode on Windows, Developer ID on macOS), the dynamic linker's environment and - after
 * loading - which file was actually mapped. On Linux, which has no platform code signature, a
 * release's authenticity is verified with Sigstore/cosign when the package is installed. Any failed
 * check throws UntrustedError; there is no fallback and no override.
 *
 * Key files are read through the native library too (NativeKeyWrapperV1.readKeyFile, which
 * buildKeyRing uses), so its checks on who could have written a key file, and on what it holds,
 * apply before any of it is unwrapped.
 *
 * The library is called through this package's own native add-on (native/hkdfguard_native.c),
 * compiled by node-gyp at install.
 */
export { NativeKeyWrapperV1, DEK_LENGTH, hardenProcess, type ProcessHardeningOptions } from './wrapper.js';
export { KeyFileRefusedError, NotInstalledError, StatusError, UnsupportedPlatformError, UntrustedError } from './errors.js';
export { Status, WRAPPED_DEK_LENGTHS } from './status.js';

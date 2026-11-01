/**
 * The native status codes and what they mean - plain data, so it can be tested anywhere. Every
 * platform's hkdfguard.h defines the same HKDFGUARD_ERR_* table, number for number, so the codes and
 * their meanings live here once. A platform's table adds what to do about a code there (which group
 * grants access to a KEK, where the policy lives) and falls back to the shared meaning for the rest.
 * A code missing from a table (reserved or unknown) has no description.
 */

/** HKDFGUARD_OK and HKDFGUARD_ERR_*, exactly as every platform's hkdfguard.h defines them. */
export const Status = {
  ok: 0,

  // General (-1..-7; -7 is reserved)
  invalidArgument: -1,
  bufferTooSmall: -2,
  providerUnavailable: -3,
  providerError: -4,
  cryptoError: -5,
  internalError: -6,

  // Service name and policy (-8..-9)
  invalidServiceName: -8,
  policyInvalid: -9,

  // Wrapped payload (-10..-15; -14..-15 are reserved)
  payloadMalformed: -10,
  payloadAuthFailed: -11,
  payloadUnsupported: -12,
  payloadVersionRefused: -13,

  // KEK and process (-16..-31; -21..-31 are reserved)
  kekFingerprintMismatch: -16,
  kekNotFound: -17,
  kekAccessDenied: -18,
  kekInvalid: -19,
  processHardeningFailed: -20,

  // Key file, hkdfguard_open_file (-32..-63; -40..-63 are reserved)
  fileNotFound: -32,
  fileAccessDenied: -33,
  fileIo: -34,
  fileTooShort: -35,
  fileTooLong: -36,
  filePlaintextKey: -37,
  fileMalformed: -38,
  fileUntrusted: -39,

  // Windows-specific (-64..-79), refining policyInvalid
  winGroupInvalid: -64,

  // macOS-specific (-96..-111), each refining providerError
  macAccessControlCreationFailed: -96,
  macKeyGenerationFailed: -97,
  macKeychainWriteFailed: -98,
  macKekVerificationFailed: -99,
  macKeychainReadFailed: -100,
} as const;

/**
 * HKDFGUARD_WRAPPED_MAX_LEN on each platform: the length of every wrapped DEK, and so of every key
 * file hkdfguard_open_file accepts. Each fits in MAX_WRAPPED_KEY_BYTES.
 */
export const WRAPPED_DEK_LENGTHS: Readonly<Record<'win32' | 'linux' | 'darwin', number>> = {
  win32: 132,
  linux: 276,
  darwin: 125,
};

/** What each code means on every platform. */
export const sharedStatusDescriptions: ReadonlyMap<number, string> = new Map([
  [Status.invalidArgument, 'invalid argument: a null pointer, wrong DEK length, negative buffer capacity, or bad path'],
  [Status.bufferTooSmall, 'the output buffer is too small for the result'],
  [Status.providerUnavailable, 'no key storage provider could be used at all'],
  [Status.providerError, 'the KEK provider or key could not be opened or created'],
  [Status.cryptoError, 'an ECDH, HKDF, AES or random number operation failed'],
  [Status.internalError, 'an unexpected internal failure in the native library'],
  [Status.invalidServiceName, "the service name is null, empty, too long, or has a character other than an ASCII letter, digit or '.'"],
  [Status.policyInvalid, "the machine's HkdfGuard policy is invalid"],
  [Status.payloadMalformed, 'the wrapped payload is not a valid wrapped DEK'],
  [Status.payloadAuthFailed, 'AES-GCM authentication failed: the wrapped payload was altered'],
  [Status.payloadUnsupported, "the wrapped payload's version or suite is not one this native library understands"],
  [Status.payloadVersionRefused, "the wrapped payload's version is one this native library understands, but this host's policy does not use"],
  [Status.kekFingerprintMismatch, "the payload was wrapped under a different KEK than this service's current one"],
  [Status.kekNotFound, 'no KEK is provisioned for this service; run hkdfguard provision'],
  [Status.kekAccessDenied, 'the KEK exists, but this account is not authorized to use it'],
  [Status.kekInvalid, 'the existing KEK is unusable as found'],
  [Status.processHardeningFailed, 'process hardening failed'],
  [Status.fileNotFound, 'the key file, or a folder in its path, does not exist'],
  [Status.fileAccessDenied, 'this account may not read the key file'],
  [Status.fileIo, 'the key file is not a regular file, is in use by a writer, or could not be read'],
  [Status.fileTooShort, 'the key file is shorter than a wrapped DEK'],
  [Status.fileTooLong, 'the key file is longer than a wrapped DEK'],
  [Status.filePlaintextKey, 'the key file holds what looks like an UNWRAPPED key (32 raw bytes, or its hex or base64): treat it as a key exposure'],
  [Status.fileMalformed, 'the key file is the right size, but is not a valid wrapped DEK'],
  [Status.fileUntrusted, "the key file's path is not trusted: a link or reparse point, a short or network path, or a file or folder another account could replace"],
  [Status.winGroupInvalid, 'an HKLM\\Software\\Policies\\HkdfGuard\\KeyUseGroups entry is unresolvable, not a group, not host-local, or over-broad'],
  [Status.macAccessControlCreationFailed, 'the access policy for a new KEK could not be created'],
  [Status.macKeyGenerationFailed, 'the Secure Enclave refused to generate a key'],
  [Status.macKeychainWriteFailed, 'the new KEK could not be stored in the keychain'],
  [Status.macKekVerificationFailed, 'the new KEK could not be reloaded after it was stored'],
  [Status.macKeychainReadFailed, 'the keychain could not be read'],
]);

/** The shared descriptions with a platform's own hints in place of some. */
function withHints(hints: [number, string][]): ReadonlyMap<number, string> {
  return new Map([...sharedStatusDescriptions, ...hints]);
}

/** Windows HkdfGuard.dll. */
export const windowsStatusDescriptions: ReadonlyMap<number, string> = withHints([
  [Status.providerUnavailable, "payload version 2 is unavailable on this host: the TPM can't be used for it and KeyStoragePolicy, or an existing TPM KEK, rules out the software key store (event 2008 names the reason); set HKLM\\Software\\Policies\\HkdfGuard\\ClassicalMode to 1 to keep using version 1"],
  [Status.providerError, 'the KEK\'s key storage provider (Platform Crypto Provider or Software KSP) could not open or create the key'],
  [Status.policyInvalid, 'a machine policy value under HKLM\\Software\\Policies\\HkdfGuard is invalid'],
  [Status.payloadVersionRefused, 'the wrapped payload is the other payload version from the one HKLM\\Software\\Policies\\HkdfGuard\\ClassicalMode selects (absent or 0: version 2; 1: version 1); a host unwraps only its own version'],
  [Status.kekNotFound, 'no KEK is provisioned for this service; run hkdfguard provision from an elevated prompt'],
  [Status.kekAccessDenied, 'the KEK exists, but this account is not authorized to use it (or, for a new KEK, the process is not elevated); add it to the HkdfGuardUsers group or a KeyUseGroups group'],
  [Status.kekInvalid, "the existing KEK's ACL is missing, lacks SYSTEM/Administrators, or grants an over-broad principal"],
  [Status.processHardeningFailed, 'process hardening failed: the crash-report heap exclusion or the process and thread access lists could not be set, or (with requireProtectedSignature) the process could not be closed to its own user'],
]);

/** Linux libhkdfguard.so.1. */
export const linuxStatusDescriptions: ReadonlyMap<number, string> = withHints([
  [Status.providerUnavailable, 'no KEK provider could be reached: no usable TPM, PKCS#11 token or external secret under /etc/hkdfguard/policy.toml'],
  [Status.providerError, "a KEK provider was reached but failed (policy file, secret file permissions, TPM or token error); the native library's log names the reason"],
  [Status.policyInvalid, "/etc/hkdfguard/policy.toml can't be used: unparsable, an invalid or contradictory setting, insecure ownership or permissions, or a provider this build lacks"],
  [Status.kekNotFound, 'no KEK is provisioned for this service; run hkdfguard provision'],
  [Status.kekFingerprintMismatch, "the payload was wrapped under a different KEK than this service's current one: another service, or the KEK or TPM derivation secret has changed"],
  [Status.processHardeningFailed, 'process hardening failed: core dumps or ptrace access could not be disabled'],
]);

/** macOS libhkdfguard.dylib. */
export const macStatusDescriptions: ReadonlyMap<number, string> = withHints([
  [Status.providerUnavailable, 'this Mac has no Secure Enclave'],
  [Status.payloadAuthFailed, 'AES-GCM authentication failed: the payload was altered, or wrapped for another service under this KEK'],
  [Status.kekNotFound, 'no KEK is provisioned for this service in this keychain mode; run hkdfguard provision'],
  [Status.kekAccessDenied, "the keychain denied access: it is locked, there is no session to prompt in, or this process isn't allowed"],
  [Status.kekInvalid, "the keychain item for this service can't be reconstructed into a key"],
  [Status.processHardeningFailed, "process hardening failed: core dumps or debugger attachment could not be denied, or (with requireProtectedSignature) the host executable's code signature still allows it - it needs the Hardened Runtime, without get-task-allow or DYLD_* entitlements"],
]);

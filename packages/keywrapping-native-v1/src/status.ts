/**
 * Each platform's native status codes, exactly as its header defines them, and what they mean -
 * plain data, so it can be tested anywhere. A code missing from a table (reserved, unassigned or
 * unknown) has no description.
 */

/** macOS libhkdfguard_v1.dylib (hkdfguard.h). -3 and -4 are reserved and never returned. */
export const macStatusDescriptions: ReadonlyMap<number, string> = new Map([
  [-1, 'invalid input length, or a null buffer'],
  [-2, 'the output buffer is too small for the result'],
  [-5, 'encryption failed'],
  [-6, 'AES-GCM authentication failed: the payload was altered, or wrapped for another service under this KEK'],
  [-7, 'the native library produced an unexpected output length'],
  [-8, "the service name is null, empty, too long, or has a character other than an ASCII letter, digit or '.'"],
  [-9, 'this Mac has no Secure Enclave'],
  [-10, 'no KEK is provisioned for this service in this keychain mode; run hkdfguard-v1-initialize provision'],
  [-11, "the keychain item for this service can't be reconstructed into a key"],
  [-12, 'the access policy for a new KEK could not be created'],
  [-13, 'the Secure Enclave refused to generate a key'],
  [-14, 'the new KEK could not be stored in the keychain'],
  [-15, 'the new KEK could not be reloaded after it was stored'],
  [-16, "the payload was wrapped under a different KEK than this service's"],
  [-17, "the keychain denied access: it is locked, there is no session to prompt in, or this process isn't allowed"],
  [-18, 'the keychain could not be read'],
]);

/** Linux libhkdfguard.so.1. -7 is reserved; -10..-15 are unassigned on Linux. */
export const linuxStatusDescriptions: ReadonlyMap<number, string> = new Map([
  [-1, 'invalid argument: a null pointer, wrong DEK length, or negative buffer capacity'],
  [-2, 'the output buffer is too small for the result'],
  [-3, 'no KEK provider could be reached: no usable TPM, PKCS#11 token or external secret under /etc/hkdfguard/policy.toml'],
  [-4, "a KEK provider was reached but failed (policy file, secret file permissions, TPM or token error); the native library's log names the reason"],
  [-5, 'the wrapped payload is malformed or failed AES-GCM authentication'],
  [-6, 'an unexpected internal failure in the native library'],
  [-8, 'the service name is malformed or invalid'],
  [-9, 'no KEK is provisioned for this service; run hkdfguard-v1-initialize provision'],
  [-16, "the payload was wrapped under a different KEK than this service's current one: another service, or the KEK or TPM derivation secret has changed"],
  [-17, 'process hardening failed: core dumps or ptrace access could not be disabled'],
]);

/** Windows HkdfGuardV1.dll (HKDFGUARD_ERR_*). */
export const windowsStatusDescriptions: ReadonlyMap<number, string> = new Map([
  [-1, 'invalid argument: a null pointer, wrong DEK length, or bad service'],
  [-2, 'the output buffer is too small for the result'],
  [-3, 'the KEK provider or key could not be opened or created'],
  [-4, 'an ECDH, HKDF or AES operation failed'],
  [-5, 'AES-GCM authentication failed: the wrapped payload was altered'],
  [-6, 'the wrapped payload is not a valid WrappedDekV1'],
  [-7, 'an unexpected internal failure in the native library'],
  [-8, 'the service name is malformed or invalid'],
  [-9, 'HKLM\\Software\\Policies\\HkdfGuard\\KeyStoragePolicy is invalid'],
  [-10, 'an HKLM\\Software\\Policies\\HkdfGuard\\KeyUseGroups entry is unresolvable, not a group, or over-broad'],
  [-11, "the payload was wrapped under a different KEK than this service's"],
  [-12, 'no KEK is provisioned for this service; run hkdfguard-v1-initialize provision'],
  [-13, 'the KEK exists, but this account is not authorized to use it; add it to the HkdfGuardUsers group or a KeyUseGroups group'],
  [-14, "the existing KEK's ACL is missing, lacks SYSTEM/Administrators, or grants an over-broad principal"],
]);

/** Status codes the tests and loaders refer to by name. */
export const Status = {
  ok: 0,
  linuxProcessHardeningFailed: -17,
  windowsKekNotFound: -12,
  windowsAccessDenied: -13,
} as const;

/**
 * The data-encryption-key layer every HkdfGuard store sits on - the Node port of the .NET
 * HkdfGuard.DataEncryptionKey library: DataEncryptionKey (one DEK over a crypto provider), KeyRing
 * (keys by version, with ephemeral-key rotation), its data protectors, DefaultFormatProvider (the
 * enc::v<version>::<base64> wire format), and buildKeyRing.
 *
 * It depends only on the abstractions: the cipher (a CryptoProviderFactory) and the KEK (a
 * KeyWrapper) are supplied by the caller, so either can be swapped without touching this package.
 */
export { DataEncryptionKey } from './key.js';
export { DEFAULT_MAX_ENCRYPTED_LENGTH, DefaultFormatProvider, InvalidFormatError } from './format.js';
export { DuplicateVersionError, KeyRing } from './keyring.js';
export {
  buildKeyRing, DEFAULT_EPHEMERAL_KEY_RETENTION_HOURS, DEFAULT_EPHEMERAL_KEY_ROTATION_HOURS, InvalidKeyFileError,
  MAX_EPHEMERAL_KEY_ROTATION_HOURS, MIN_EPHEMERAL_KEY_RETENTION_MINUTES, MIN_EPHEMERAL_KEY_ROTATION_HOURS, readKeyFile, type KeyRingConfig,
} from './build.js';
export {
  InvalidOptionsError, keyRingConfigFromOptions, keyRingOptionsFromJson, validateKeyRingOptions, type KeyFileOptions, type KeyRingOptions,
} from './options.js';

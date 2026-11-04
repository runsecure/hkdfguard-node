/**
 * One X.509 certificate, and its private key, opened from where configuration says it is - the Node
 * port of the .NET HkdfGuard.Options.Certificate: {@link CertificateOptions} names exactly one source
 * (a Windows certificate store, a macOS keychain, an OpenSSL 3 provider on Linux, or a
 * password-protected PKCS#12 or PEM file), {@link CertificateOptionsValidator} checks it, and
 * {@link CertificateOptionsLoader} opens it as a {@link LoadedCertificate}.
 *
 * A key an operating system store holds is never exported: every signature and decryption is a call
 * into the store, through this package's own native add-on (native/hkdfguard_certificate.c), compiled
 * by node-gyp at install on Windows and macOS. A provider key is the provider's own object in Node's
 * OpenSSL. A file's password is read from a protected secret source into a buffer zeroed at once, and
 * never becomes a string; its key is held sealed and wiped on close.
 */
export {
  CertificateFileFormat, certificateOptionsFromJson, certificateOptionsFromObject, StoreLocation, StoreName,
  type CertificateFileOptions, type CertificateOptions, type CertificateStoreOptions, type LinuxOpenSslProviderOptions,
} from './options.js';
export { CertificateOptionsValidator, currentPlatform, validateCertificateOptions, type CertificatePlatform } from './validator.js';
export { CertificateOptionsLoader, readOperatingSystemStore, type CertificateOptionsLoaderConfig } from './loader.js';
export { LoadedCertificate } from './loaded.js';
export type { DecryptOptions, HashAlgorithm, SignOptions } from './keys.js';
export type { StoreCertificate, StoreKey, StoreReader } from './store.js';
export { DistinguishedName } from './dn.js';
export {
  CertificateError, CertificateNotFoundError, CertificateNotValidNowError, CertificateStoreError, InvalidCertificateFileError,
  InvalidCertificateOptionsError, NativeProviderRequiredError, NoPasswordSourceError, NoPrivateKeyError, OpenSslProviderUnavailableError,
  PasswordNotFoundError, UnsupportedCertificateError, WrongPasswordError,
} from './errors.js';

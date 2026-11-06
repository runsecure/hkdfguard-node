import { HkdfGuardError, KeyNotFoundError } from '@runsecure/hkdfguard-abstractions';

/**
 * {@link CertificateOptions} the validator refuses - .NET's OptionsValidationException. `failures`
 * lists every rule broken, so they can all be fixed at once; `name` is the options' name, for named
 * options (undefined for the default). Its `code` is 'ERR_HKDFGUARD_INVALID_CERTIFICATE_OPTIONS'.
 */
export class InvalidCertificateOptionsError extends HkdfGuardError {
  constructor(readonly failures: readonly string[], readonly optionsName?: string) {
    super('ERR_HKDFGUARD_INVALID_CERTIFICATE_OPTIONS',
      `${optionsName === undefined ? 'The certificate options are invalid' : `The certificate options '${optionsName}' are invalid`}:\n  ${failures.join('\n  ')}`);
  }
}

/**
 * The base of every failure to open or use a certificate, but invalid options
 * ({@link InvalidCertificateOptionsError}), a missing password ({@link PasswordNotFoundError}), a
 * closed certificate (ClosedError) and the operating system's own errors for a file that can't be
 * read (ENOENT, EACCES...).
 */
export class CertificateError extends HkdfGuardError {
  constructor(code: string, message: string, options?: { cause?: unknown }) {
    super(code, message, options);
  }
}

/**
 * A store holds no certificate with the subject named that is valid now (and has its private key,
 * when one is required) - .NET's InvalidOperationException from a store. 'ERR_HKDFGUARD_CERTIFICATE_NOT_FOUND'.
 */
export class CertificateNotFoundError extends CertificateError {
  constructor(message: string) {
    super('ERR_HKDFGUARD_CERTIFICATE_NOT_FOUND', message);
  }
}

/** The certificate is expired or not yet valid. 'ERR_HKDFGUARD_CERTIFICATE_NOT_VALID_NOW'. */
export class CertificateNotValidNowError extends CertificateError {
  constructor(message: string) {
    super('ERR_HKDFGUARD_CERTIFICATE_NOT_VALID_NOW', message);
  }
}

/**
 * The certificate has no private key, or the store won't open it, and one is required - or a key
 * operation was asked of a certificate loaded without one. 'ERR_HKDFGUARD_CERTIFICATE_NO_PRIVATE_KEY'.
 */
export class NoPrivateKeyError extends CertificateError {
  constructor(message: string, options?: { cause?: unknown }) {
    super('ERR_HKDFGUARD_CERTIFICATE_NO_PRIVATE_KEY', message, options);
  }
}

/** A key file has a password to read, but the loader was given no password source. 'ERR_HKDFGUARD_CERTIFICATE_NO_PASSWORD_SOURCE'. */
export class NoPasswordSourceError extends CertificateError {
  constructor(message: string) {
    super('ERR_HKDFGUARD_CERTIFICATE_NO_PASSWORD_SOURCE', message);
  }
}

/**
 * The password source holds no secret by the name `passwordSecretName` gives - .NET's
 * KeyNotFoundException, so it is a KeyNotFoundError, with its code 'ERR_HKDFGUARD_KEY_NOT_FOUND'.
 */
export class PasswordNotFoundError extends KeyNotFoundError {
  constructor(readonly passwordSecretName: string) {
    super(`The password source holds no secret named '${passwordSecretName}'.`);
  }
}

/** A file isn't a certificate or key in the format named - .NET's CryptographicException. 'ERR_HKDFGUARD_INVALID_CERTIFICATE_FILE'. */
export class InvalidCertificateFileError extends CertificateError {
  constructor(message: string, options?: { cause?: unknown }) {
    super('ERR_HKDFGUARD_INVALID_CERTIFICATE_FILE', message, options);
  }
}

/**
 * A key file the password doesn't open: a PKCS#12 file whose integrity check fails, or a key that
 * doesn't decrypt - .NET's CryptographicException. 'ERR_HKDFGUARD_CERTIFICATE_WRONG_PASSWORD'.
 */
export class WrongPasswordError extends CertificateError {
  constructor(message: string) {
    super('ERR_HKDFGUARD_CERTIFICATE_WRONG_PASSWORD', message);
  }
}

/**
 * What this port can't open or do: a legacy RC2 or RC4 PKCS#12 file, a store or key the platform has
 * no way to reach, an algorithm the key or the store doesn't support. 'ERR_HKDFGUARD_UNSUPPORTED_CERTIFICATE',
 * unless a subclass says otherwise.
 */
export class UnsupportedCertificateError extends CertificateError {
  constructor(message: string, options?: { cause?: unknown; code?: string }) {
    super(options?.code ?? 'ERR_HKDFGUARD_UNSUPPORTED_CERTIFICATE', message, options);
  }
}

/**
 * A TLS context was asked for a certificate whose private key an operating system store holds
 * (Windows, macOS): Node's TLS is OpenSSL's, which takes a key only as PEM or through a provider
 * loaded into it, and a store's key is never exported to make one, nor is there a provider for the
 * store. Use {@link LoadedCertificate.sign} and {@link LoadedCertificate.decrypt}, which call the
 * store, or a File or Linux source for TLS. 'ERR_HKDFGUARD_CERTIFICATE_NATIVE_PROVIDER_REQUIRED'.
 */
export class NativeProviderRequiredError extends UnsupportedCertificateError {
  constructor(message: string) {
    super(message, { code: 'ERR_HKDFGUARD_CERTIFICATE_NATIVE_PROVIDER_REQUIRED' });
  }
}

/**
 * A Linux key whose OpenSSL provider isn't loaded into this Node's OpenSSL: no decoder took the key.
 * Node loads providers only from an OpenSSL configuration file, at startup - `--openssl-config=<file>`
 * (its `nodejs_conf` section), or `--openssl-shared-config` with `OPENSSL_CONF`. 'ERR_HKDFGUARD_OPENSSL_PROVIDER_UNAVAILABLE'.
 */
export class OpenSslProviderUnavailableError extends UnsupportedCertificateError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, { ...options, code: 'ERR_HKDFGUARD_OPENSSL_PROVIDER_UNAVAILABLE' });
  }
}

/**
 * An operating system store call failed: reading the store, or a signature or decryption with its
 * key. `status` is the call's status (an NTSTATUS/HRESULT/Win32 error on Windows, an OSStatus or
 * CFError code on macOS; -1 when there is none). 'ERR_HKDFGUARD_CERTIFICATE_STORE'.
 */
export class CertificateStoreError extends CertificateError {
  constructor(message: string, readonly status: number, options?: { cause?: unknown }) {
    super('ERR_HKDFGUARD_CERTIFICATE_STORE', message, options);
  }
}

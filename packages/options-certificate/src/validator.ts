import { isAbsolute as isPosixAbsolute } from 'node:path/posix';
import { isAbsolute as isWindowsAbsolute } from 'node:path/win32';
import { DistinguishedName } from './dn.js';
import { InvalidCertificateOptionsError } from './errors.js';
import {
  CertificateFileFormat, DEFAULTS, StoreLocation, StoreName, type CertificateFileOptions, type CertificateOptions, type CertificateStoreOptions,
  type LinuxOpenSslProviderOptions,
} from './options.js';

/** The platform a validator judges for: 'windows', 'macos', 'linux', or another `process.platform`, which has no native source. */
export type CertificatePlatform = 'windows' | 'macos' | 'linux' | (string & {});

/** The platform the process runs on, as the validator names it. */
export function currentPlatform(): CertificatePlatform {
  return process.platform === 'win32' ? 'windows' : process.platform === 'darwin' ? 'macos' : process.platform;
}

function describePlatform(platform: CertificatePlatform): string {
  return platform === 'windows' ? 'Windows' : platform === 'macos' ? 'macOS' : platform === 'linux' ? 'Linux' : platform;
}

const LOCATIONS: readonly string[] = Object.values(StoreLocation);
const NAMES: readonly string[] = Object.values(StoreName);
const FORMATS: readonly string[] = Object.values(CertificateFileFormat);

/**
 * Checks a {@link CertificateOptions} before anything is opened: exactly one source set, and one this
 * operating system has - the Windows store on Windows, a keychain on macOS, an OpenSSL provider on
 * Linux, a file anywhere - with a store, subject, provider, key or path that is one. A file holding a
 * private key must be protected by a password, named by its secret, unless an unprotected key is
 * explicitly allowed.
 *
 * Beyond .NET's rules, it refuses what this port can't open on the platform it runs on, where the
 * source is otherwise usable: a macOS store other than My, and a Linux provider key that is neither a
 * `pkcs11:` URI nor the absolute path of a key file (a `handle:` TPM handle).
 */
export class CertificateOptionsValidator {
  /** @param platform the platform to judge for, for tests; the one the process runs on by default */
  constructor(readonly platform: CertificatePlatform = currentPlatform()) {}

  /** Every failure, or an empty array if `options` is valid. */
  validate(options: CertificateOptions): string[] {
    if (options === null || typeof options !== 'object') throw new TypeError('options must be CertificateOptions.');
    const failures: string[] = [];
    const sources: [string, unknown, CertificatePlatform | undefined][] = [
      ['Windows', options.windows, 'windows'], ['MacOS', options.macOS, 'macos'], ['Linux', options.linux, 'linux'], ['File', options.file, undefined],
    ];
    const chosen = sources.filter(([, value]) => value !== undefined && value !== null).map(([name]) => name);
    if (chosen.length === 0) failures.push('One certificate source is required: Windows, MacOS, Linux or File.');
    else if (chosen.length > 1) failures.push(`Only one certificate source can be set, but ${chosen.join(', ')} are.`);
    for (const [name, value, platform] of sources) {
      if (value !== undefined && value !== null && platform !== undefined && platform !== this.platform) {
        failures.push(`The ${name} certificate source can only be used on ${name}; this is ${describePlatform(this.platform)}.`);
      }
    }
    if (options.requirePrivateKey !== undefined && typeof options.requirePrivateKey !== 'boolean') failures.push('RequirePrivateKey must be true or false.');
    const requirePrivateKey = options.requirePrivateKey !== false;

    if (options.windows) validateStore('Windows', options.windows, failures);
    if (options.macOS) {
      validateStore('MacOS', options.macOS, failures);
      // Only where the source is otherwise usable: elsewhere the platform failure says enough.
      const name = options.macOS.storeName ?? DEFAULTS.storeName;
      if (this.platform === 'macos' && NAMES.includes(name) && name !== StoreName.my) {
        failures.push(`MacOS.StoreName must be My - the keychain itself, the only store this port reads on macOS - not ${name}.`);
      }
    }
    if (options.linux) this.#validateLinux(options.linux, requirePrivateKey, failures);
    if (options.file) this.#validateFile(options.file, requirePrivateKey, failures);
    return failures;
  }

  /**
   * `options`, if valid.
   * @param name the options' name, for named options; only reported in the error
   * @throws InvalidCertificateOptionsError any rule is broken; it lists every failure
   */
  requireValid(options: CertificateOptions, name?: string): CertificateOptions {
    const failures = this.validate(options);
    if (failures.length > 0) throw new InvalidCertificateOptionsError(failures, name);
    return options;
  }

  #validateLinux(linux: LinuxOpenSslProviderOptions, requirePrivateKey: boolean, failures: string[]): void {
    const provider = linux.provider ?? DEFAULTS.provider;
    if (typeof provider !== 'string' || !/^[A-Za-z0-9_-]+$/.test(provider)) {
      failures.push(`Linux.Provider must be an OpenSSL provider's name - "tpm2" or "pkcs11" - not '${String(provider)}'.`);
    }
    if (requirePrivateKey) {
      if (typeof linux.keyUri !== 'string' || linux.keyUri.trim() === '') {
        failures.push('Linux.KeyUri is required: the key as the provider names it, e.g. "pkcs11:token=...;object=..." or a TSS2 key file\'s path.');
      } else if (this.platform === 'linux') {
        const problem = providerKeyProblem(linux.keyUri);
        if (problem !== undefined) failures.push(problem);
      }
    }
    validatePath('Linux.CertificateFile', linux.certificateFile, failures);
  }

  #validateFile(file: CertificateFileOptions, requirePrivateKey: boolean, failures: string[]): void {
    validatePath('File.Path', file.path, failures);
    const format = file.format ?? DEFAULTS.format;
    if (!FORMATS.includes(format)) failures.push(`File.Format must be Pkcs12 or Pem, not ${format}.`);
    else if (format === CertificateFileFormat.pem && requirePrivateKey) validatePath('File.KeyPath', file.keyPath, failures);

    if (file.allowUnprotectedPrivateKey !== undefined && typeof file.allowUnprotectedPrivateKey !== 'boolean') {
      failures.push('File.AllowUnprotectedPrivateKey must be true or false.');
    }
    if (file.passwordSecretName !== undefined && (typeof file.passwordSecretName !== 'string' || file.passwordSecretName.trim() === '')) {
      failures.push("File.PasswordSecretName can't be empty: name the secret holding the key's password, or leave it unset.");
    } else if (requirePrivateKey && file.passwordSecretName === undefined && file.allowUnprotectedPrivateKey !== true) {
      failures.push('File.PasswordSecretName is required: a private key file must be protected by a password, read from a protected secret. '
        + 'Set File.AllowUnprotectedPrivateKey to accept a plaintext key, for development only.');
    }
  }
}

/** Every failure in `options` for the platform the process runs on; empty when they are valid. */
export function validateCertificateOptions(options: CertificateOptions): string[] {
  return new CertificateOptionsValidator().validate(options);
}

function validateStore(source: string, store: CertificateStoreOptions, failures: string[]): void {
  const location = store.storeLocation ?? DEFAULTS.storeLocation;
  const name = store.storeName ?? DEFAULTS.storeName;
  if (!LOCATIONS.includes(location)) failures.push(`${source}.StoreLocation must be CurrentUser or LocalMachine, not ${location}.`);
  if (!NAMES.includes(name)) failures.push(`${source}.StoreName must be a store's name - My, Root, CertificateAuthority, TrustedPeople... - not ${name}.`);
  if (typeof store.subject !== 'string' || store.subject.trim() === '') {
    failures.push(`${source}.Subject is required: the certificate's subject distinguished name, e.g. "CN=api.example.com".`);
    return;
  }
  try {
    DistinguishedName.parse(store.subject);
  } catch {
    failures.push(`${source}.Subject must be a distinguished name, e.g. "CN=api.example.com, O=Contoso", not '${store.subject}'.`);
  }
}

/**
 * Why a Linux KeyUri can't be given to Node's OpenSSL through a provider's decoder; undefined for one
 * that can: a `pkcs11:` URI, or an absolute path (optionally `file:`-prefixed), by the host's rules.
 */
export function providerKeyProblem(keyUri: string): string | undefined {
  if (keyUri.startsWith('pkcs11:')) return undefined;
  if (keyUri.startsWith('handle:')) {
    return `Linux.KeyUri '${keyUri}' is a persistent TPM handle, which Node can't open: node:crypto and node:tls read a key only from PEM, `
      + "through the provider's decoder, and have no OSSL_STORE API. Give the path of the key's TSS2 PRIVATE KEY PEM file instead "
      + "(tpm2-openssl writes one with 'openssl genpkey -provider tpm2 ... -out key.pem').";
  }
  const path = keyUri.startsWith('file:') ? keyUri.slice('file:'.length) : keyUri;
  if (!isHostAbsolute(path)) {
    return `Linux.KeyUri must be a "pkcs11:" URI or the absolute path of a key file the provider decodes (a TSS2 PRIVATE KEY PEM, for tpm2), not '${keyUri}'.`;
  }
  return undefined;
}

// A path is judged by the rules of the host it will be opened on, as .NET's Path.IsPathFullyQualified is.
function validatePath(what: string, path: unknown, failures: string[]): void {
  if (typeof path !== 'string' || path.trim() === '') {
    failures.push(`${what} is required.`);
  } else if (!isHostAbsolute(path)) {
    failures.push(`${what} must be an absolute path, not '${path}'.`);
  }
}

function isHostAbsolute(path: string): boolean {
  return process.platform === 'win32' ? isFullyQualifiedWindowsPath(path) : isPosixAbsolute(path);
}

// .NET's Path.IsPathFullyQualified: a drive and a root ("C:\x"), or a UNC or device path ("\\server\share", "\\?\C:\x") - not "\x" or "C:x",
// which path.win32.isAbsolute accepts for the first.
function isFullyQualifiedWindowsPath(path: string): boolean {
  if (/^[A-Za-z]:[\\/]/.test(path)) return true;
  return /^[\\/]{2}/.test(path) && isWindowsAbsolute(path);
}

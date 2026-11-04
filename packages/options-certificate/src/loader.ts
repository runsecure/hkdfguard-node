import { createPublicKey, type KeyObject } from 'node:crypto';
import { wipe, type ProtectedReadOnlyCache } from '@runsecure/hkdfguard-abstractions';
import { DistinguishedName } from './dn.js';
import {
  CertificateError, CertificateNotFoundError, CertificateNotValidNowError, InvalidCertificateFileError, InvalidCertificateOptionsError,
  NoPasswordSourceError, NoPrivateKeyError, PasswordNotFoundError, UnsupportedCertificateError,
} from './errors.js';
import { decryptPemKey, parseCertificates, plainPemKey, publicKeyOf, readWholeFile } from './files.js';
import { FileKeySource, LoadedCertificate, ProviderKeySource, StoreKeySource, type KeySource } from './loaded.js';
import { readMacKeychain } from './macos.js';
import {
  CertificateFileFormat, DEFAULTS, type CertificateFileOptions, type CertificateOptions, type CertificateStoreOptions, type LinuxOpenSslProviderOptions,
  type StoreLocation, type StoreName,
} from './options.js';
import { decodePkcs12 } from './pkcs12.js';
import { checkProviderKeyFile, openProviderKey, pkcs11UriPem } from './provider.js';
import type { StoreCertificate, StoreReader } from './store.js';
import { CertificateOptionsValidator } from './validator.js';
import { readWindowsStore } from './windows.js';
import { describe, leafFirst, parseCertificate, spki, universal, type ParsedCertificate } from './x509.js';

/** What a {@link CertificateOptionsLoader} is made with. */
export interface CertificateOptionsLoaderConfig {
  /**
   * Where a file's password is read from, by passwordSecretName - a FilePerSecretCache, a remote
   * secret cache. Needed only for a file with a password.
   */
  passwords?: ProtectedReadOnlyCache;
  /** The clock a certificate's validity is judged by; the system's by default. */
  now?: () => Date;
  /** The validator, for tests; this platform's by default. */
  validator?: CertificateOptionsValidator;
  /** Reads a store's certificates, for tests; the operating system's own by default. */
  storeReader?: StoreReader;
}

/** The operating system's own store: Windows' certificate stores, or macOS' keychains. */
export function readOperatingSystemStore(location: StoreLocation, name: StoreName): StoreCertificate[] {
  if (process.platform === 'win32') return readWindowsStore(location, name);
  if (process.platform === 'darwin') return readMacKeychain(location, name);
  throw new UnsupportedCertificateError(`There is no certificate store to read on ${process.platform}.`);
}

/**
 * Opens the certificate a validated {@link CertificateOptions} describes, as a
 * {@link LoadedCertificate} the caller owns, and closes.
 *
 * - A store (windows, macOS) is opened read-only, and of the certificates whose subject is the one
 *   named, the one valid now - with its private key, when one is required - that expires last is
 *   returned; every other is released. The key stays where the store keeps it, and every use of it is
 *   a call into the store.
 * - A Linux OpenSSL provider key (linux) is decoded through the provider - which must be loaded into
 *   Node's OpenSSL by its configuration - and checked to be the certificate's; it never enters the process.
 * - A file (file) is read with its password, which is decrypted from the password source into a
 *   buffer only while the key is read, and zeroed at once; it is never a string. The key is decrypted
 *   into a buffer of its own, sealed under a random key at once, and that buffer zeroed.
 *
 * Whatever the source, a certificate that isn't valid now, or that has no private key when one is
 * required, is refused.
 */
export class CertificateOptionsLoader {
  readonly #passwords: ProtectedReadOnlyCache | undefined;
  readonly #now: () => Date;
  readonly #validator: CertificateOptionsValidator;
  readonly #readStore: StoreReader;

  constructor(config: CertificateOptionsLoaderConfig = {}) {
    this.#passwords = config.passwords;
    this.#now = config.now ?? (() => new Date());
    this.#validator = config.validator ?? new CertificateOptionsValidator();
    this.#readStore = config.storeReader ?? readOperatingSystemStore;
  }

  /**
   * Opens the certificate `options` describes.
   * @param name the options' name, for named options; only reported in a validation failure
   * @param signal cancels reading the password
   * @throws InvalidCertificateOptionsError the options aren't valid on this operating system
   * @throws CertificateNotFoundError a store holds no certificate valid now (with its key, when required)
   * @throws CertificateNotValidNowError a file's certificate isn't valid now
   * @throws NoPrivateKeyError the certificate has no private key, or it can't be opened, and one is required
   * @throws NoPasswordSourceError a password is needed and the loader has no password source
   * @throws PasswordNotFoundError the password source holds no secret by the name given
   * @throws InvalidCertificateFileError a file isn't a certificate or key
   * @throws WrongPasswordError the password doesn't open the key file
   * @throws OpenSslProviderUnavailableError a Linux key's provider isn't loaded into Node's OpenSSL
   * @throws UnsupportedCertificateError what this port can't open
   * @throws the operating system's error (ENOENT, EACCES...) for a file that can't be read
   */
  async load(options: CertificateOptions, name?: string, signal?: AbortSignal): Promise<LoadedCertificate> {
    const failures = this.#validator.validate(options);
    if (failures.length > 0) throw new InvalidCertificateOptionsError(failures, name);
    const passwordName = passwordNameOf(options);
    if (passwordName === undefined) return this.#open(options, undefined);

    if (this.#passwords === undefined) {
      throw new NoPasswordSourceError("The certificate's key file has a password, but the loader was given no password source to read it from.");
    }
    const length = await this.#passwords.maxDecryptedLength(passwordName, signal);
    if (length === undefined || length === 0) throw new PasswordNotFoundError(passwordName);
    const password = Buffer.alloc(length);
    try {
      const written = await this.#passwords.decrypt(passwordName, password, signal);
      if (written === 0) throw new PasswordNotFoundError(passwordName);
      return await this.#open(options, password.subarray(0, written));
    } finally {
      wipe(password);
    }
  }

  async #open(options: CertificateOptions, password: Buffer | undefined): Promise<LoadedCertificate> {
    const requirePrivateKey = options.requirePrivateKey !== false;
    const loaded = options.windows ? await this.#fromStore(options.windows, requirePrivateKey, 'the Windows certificate store')
      : options.macOS ? await this.#fromStore(options.macOS, requirePrivateKey, 'the macOS keychain')
        : options.linux ? await fromProvider(options.linux, requirePrivateKey)
          : await fromFile(options.file!, requirePrivateKey, password);
    try {
      if (requirePrivateKey && !loaded.hasPrivateKey) throw new NoPrivateKeyError(`The certificate '${loaded.subject}' has no private key.`);
      if (!this.#isValidNow(loaded.notBefore, loaded.notAfter)) {
        throw new CertificateNotValidNowError(`The certificate '${loaded.subject}' is valid from ${universal(loaded.notBefore)} to ${universal(loaded.notAfter)}, not now.`);
      }
      return loaded;
    } catch (error) {
      await loaded.close();
      throw error;
    }
  }

  #isValidNow(notBefore: Date, notAfter: Date): boolean {
    const now = this.#now().getTime();
    return notBefore.getTime() <= now && now <= notAfter.getTime();
  }

  async #fromStore(store: CertificateStoreOptions, requirePrivateKey: boolean, description: string): Promise<LoadedCertificate> {
    const location = (store.storeLocation ?? DEFAULTS.storeLocation) as StoreLocation;
    const storeName = (store.storeName ?? DEFAULTS.storeName) as StoreName;
    const subject = DistinguishedName.parse(store.subject!);
    const found = [...await this.#readStore(location, storeName)];
    let kept: StoreCertificate | undefined; // the one returned: every other is released
    try {
      let chosen: { entry: StoreCertificate; certificate: ParsedCertificate } | undefined;
      let named = 0;
      for (const entry of found) {
        let certificate: ParsedCertificate;
        try {
          certificate = parseCertificate(entry.der, 'A store certificate');
        } catch {
          continue; // a certificate that can't be parsed can't be the one named
        }
        // Compared decoded, as each certificate states its subject, so how either side spells its
        // string types doesn't matter; ignoring case, as distinguished names compare.
        if (!certificate.subject.matches(subject)) continue;
        named++;
        if (!this.#isValidNow(certificate.notBefore, certificate.notAfter) || (requirePrivateKey && !entry.hasPrivateKey)) continue;
        if (chosen === undefined || certificate.notAfter.getTime() > chosen.certificate.notAfter.getTime()) chosen = { entry, certificate };
      }
      if (chosen === undefined) {
        if (named === 0) throw new CertificateNotFoundError(`The ${location} ${storeName} store holds no certificate whose subject is '${store.subject}'.`);
        throw new CertificateNotFoundError(`The ${location} ${storeName} store's ${named} certificate(s) whose subject is '${store.subject}' are all `
          + `${requirePrivateKey ? 'expired, not yet valid, or without a private key' : 'expired or not yet valid'}.`);
      }
      let key: KeySource | undefined;
      if (requirePrivateKey) {
        try {
          key = new StoreKeySource(chosen.entry.openPrivateKey(), description);
        } catch (error) {
          if (error instanceof NoPrivateKeyError) {
            throw new NoPrivateKeyError(`The certificate '${describe(chosen.certificate)}' in the ${location} ${storeName} store: ${error.message}`, { cause: error });
          }
          if (error instanceof UnsupportedCertificateError) {
            throw new UnsupportedCertificateError(`The certificate '${describe(chosen.certificate)}' in the ${location} ${storeName} store: ${error.message}`,
              { cause: error, code: error.code });
          }
          throw error;
        }
      }
      kept = chosen.entry;
      return new LoadedCertificate([chosen.certificate], key, [chosen.entry]);
    } finally {
      for (const entry of found) if (entry !== kept) entry.close();
    }
  }
}

// The secret a file's password is in; undefined when it has none to read. A PKCS#12 file needs its
// password even for the certificate alone; a PEM certificate without its key needs none.
function passwordNameOf(options: CertificateOptions): string | undefined {
  const file = options.file;
  if (!file) return undefined;
  const format = file.format ?? DEFAULTS.format;
  if (format !== CertificateFileFormat.pkcs12 && options.requirePrivateKey === false) return undefined;
  return file.passwordSecretName;
}

async function readCertificates(path: string): Promise<ParsedCertificate[]> {
  const data = await readWholeFile(path);
  try {
    return parseCertificates(data, path);
  } finally {
    wipe(data);
  }
}

async function fromProvider(linux: LinuxOpenSslProviderOptions, requirePrivateKey: boolean): Promise<LoadedCertificate> {
  const certificates = await readCertificates(linux.certificateFile!);
  if (!requirePrivateKey) return new LoadedCertificate(certificates, undefined);
  const provider = linux.provider ?? DEFAULTS.provider;
  const keyUri = linux.keyUri!;
  let pem: Buffer;
  if (keyUri.startsWith('pkcs11:')) {
    pem = pkcs11UriPem(keyUri);
  } else {
    const path = keyUri.startsWith('file:') ? keyUri.slice('file:'.length) : keyUri;
    pem = await readWholeFile(path);
    try {
      checkProviderKeyFile(pem, path);
    } catch (error) {
      wipe(pem);
      throw error;
    }
  }
  try {
    const key = openProviderKey(provider, pem);
    if (key.asymmetricKeyType !== 'rsa' && key.asymmetricKeyType !== 'ec') {
      throw new UnsupportedCertificateError(`The provider's key is ${key.asymmetricKeyType ?? 'of an unknown type'}, not RSA or ECDSA.`);
    }
    // The provider's key, checked to be the certificate's now, rather than at the first handshake.
    const ordered = leafFirst(certificates, createPublicKey(key));
    if (ordered === undefined) {
      throw new InvalidCertificateFileError(`The key the OpenSSL provider '${provider}' gives isn't the key of any certificate in '${linux.certificateFile}'.`);
    }
    return new LoadedCertificate(ordered, new ProviderKeySource(provider, key, pem));
  } catch (error) {
    wipe(pem);
    throw error;
  }
}

async function fromFile(file: CertificateFileOptions, requirePrivateKey: boolean, password: Buffer | undefined): Promise<LoadedCertificate> {
  const format = file.format ?? DEFAULTS.format;
  if (format === CertificateFileFormat.pkcs12) return fromPkcs12(file.path!, password);
  const certificates = await readCertificates(file.path!);
  if (!requirePrivateKey) return new LoadedCertificate(certificates, undefined);
  const data = await readWholeFile(file.keyPath!);
  let privateKeyInfo: Buffer;
  try {
    privateKeyInfo = password === undefined ? plainPemKey(data, file.keyPath!) : decryptPemKey(data, password, file.keyPath!);
  } finally {
    wipe(data);
  }
  try {
    return withKey(certificates, privateKeyInfo, password === undefined ? 'an unprotected key file' : 'a key file', `No certificate in '${file.path}' is the key's.`);
  } finally {
    wipe(privateKeyInfo);
  }
}

/** The certificates, the key's first, with the key sealed. */
function withKey(certificates: ParsedCertificate[], privateKeyInfo: Buffer, description: string, mismatch: string): LoadedCertificate {
  const ordered = leafFirst(certificates, publicKeyOf(privateKeyInfo));
  if (ordered === undefined) throw new InvalidCertificateFileError(mismatch);
  return new LoadedCertificate(ordered, new FileKeySource(privateKeyInfo, description));
}

async function fromPkcs12(path: string, password: Buffer | undefined): Promise<LoadedCertificate> {
  const data = await readWholeFile(path);
  try {
    const contents = decodePkcs12(data, password);
    try {
      if (contents.certificates.length === 0) throw new InvalidCertificateFileError(`The PKCS#12 file '${path}' holds no certificate.`);
      const certificates = contents.certificates.map((der) => parseCertificate(der, `A certificate in '${path}'`));
      // The certificate is the first that has its key, as .NET chooses it, or else the first; the rest
      // are its chain. Any other key is wiped.
      for (const key of contents.keys) {
        let publicKey: KeyObject;
        try {
          publicKey = publicKeyOf(key);
        } catch (error) {
          if (error instanceof CertificateError) continue;
          throw error;
        }
        const wanted = spki(publicKey);
        if (certificates.some((certificate) => spki(certificate.x509.publicKey).equals(wanted))) {
          return withKey(certificates, key, password === undefined ? 'an unprotected key file' : 'a key file', '');
        }
      }
      return new LoadedCertificate(certificates, undefined);
    } finally {
      contents.wipe();
    }
  } finally {
    wipe(data);
  }
}

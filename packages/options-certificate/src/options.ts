import { InvalidArgumentError, jsonErrorLocation, jsonKind } from '@runsecure/hkdfguard-abstractions';

/** Which certificate store location a {@link CertificateStoreOptions} opens, as .NET names them. */
export const StoreLocation = {
  /** The store of the account the process runs as: on macOS, its login keychain. */
  currentUser: 'CurrentUser',
  /** The machine's store, the default: on macOS, the System keychain. */
  localMachine: 'LocalMachine',
} as const;

/** A {@link StoreLocation} value. */
export type StoreLocation = (typeof StoreLocation)[keyof typeof StoreLocation];

/**
 * Which store at a {@link StoreLocation} a {@link CertificateStoreOptions} opens - every name of
 * .NET's StoreName, so the same configuration binds. On macOS only My - the keychain itself - is read.
 */
export const StoreName = {
  /** Other users' certificates. */
  addressBook: 'AddressBook',
  /** Third-party certification authorities. */
  authRoot: 'AuthRoot',
  /** Intermediate certification authorities (the Windows system store "CA"). */
  certificateAuthority: 'CertificateAuthority',
  /** Revoked certificates. */
  disallowed: 'Disallowed',
  /** Personal certificates, with their private keys; the default. */
  my: 'My',
  /** Trusted root certification authorities. */
  root: 'Root',
  /** Directly trusted people and resources. */
  trustedPeople: 'TrustedPeople',
  /** Directly trusted publishers. */
  trustedPublisher: 'TrustedPublisher',
} as const;

/** A {@link StoreName} value. */
export type StoreName = (typeof StoreName)[keyof typeof StoreName];

/** The format of a certificate file. */
export const CertificateFileFormat = {
  /** A PKCS#12 (.pfx/.p12) file holding the certificate and its key; the default. */
  pkcs12: 'Pkcs12',
  /** A PEM certificate, with its key in {@link CertificateFileOptions.keyPath} as encrypted PKCS#8. */
  pem: 'Pem',
} as const;

/** A {@link CertificateFileFormat} value. */
export type CertificateFileFormat = (typeof CertificateFileFormat)[keyof typeof CertificateFileFormat];

/**
 * A certificate in an operating system certificate store, found by its subject, so a renewed
 * certificate an administrator adds under the same subject is picked up with no change to
 * configuration. Of the certificates with that subject, the one opened is the one valid now - and with
 * its private key, when one is required - that expires last; an expired or not-yet-valid one is never
 * chosen. Its private key stays in the store: CNG (or the TPM) on Windows, the keychain on macOS,
 * where CurrentUser is the login keychain and LocalMachine the System keychain.
 *
 * Matching by subject trusts whoever can add a certificate to the store to choose it: keep it to a
 * store only administrators can write, such as LocalMachine's My.
 */
export interface CertificateStoreOptions {
  /** Which store location to open; LocalMachine when unset. A string that isn't one is kept for the validator to refuse. */
  storeLocation?: StoreLocation | string;
  /** Which store to open; My (Personal) when unset. On macOS only My - the keychain itself - can be read. */
  storeName?: StoreName | string;
  /**
   * The certificate's subject distinguished name, as the certificate states it:
   * "CN=api.example.com, O=Contoso". Compared to each certificate's whole subject, decoded, ignoring
   * case - never as a substring, so "CN=api" doesn't match "CN=api.example.com".
   */
  subject?: string;
}

/**
 * A certificate on Linux whose private key is opened through an OpenSSL 3 provider - tpm2 for a key in
 * the TPM, or pkcs11 for a hardware token - so the key never leaves it, beside the certificate itself
 * as a PEM file, which holds nothing secret.
 *
 * Node reads the key through the provider's own decoder, which takes a key file, not a store URI:
 * `keyUri` is a `pkcs11:` URI (given to pkcs11-provider in memory as a `PKCS#11 PROVIDER URI` PEM) or
 * the absolute path of a PEM key file the provider decodes - a `TSS2 PRIVATE KEY` for tpm2. A
 * persistent TPM handle (`handle:0x81000001`) has no such file, and is refused. The provider must be
 * loaded into Node's OpenSSL by its configuration (`--openssl-config`); see the README.
 */
export interface LinuxOpenSslProviderOptions {
  /** The OpenSSL provider that holds the key: "tpm2" (the default) or "pkcs11". */
  provider?: string;
  /** The key, as the provider names it: a `pkcs11:` URI, or the path to a TPM key blob. */
  keyUri?: string;
  /** The certificate, PEM- or DER-encoded, without its key; absolute. */
  certificateFile?: string;
}

/**
 * A certificate and its key read from files, by absolute paths. The key must be protected by a
 * password - a password-protected PKCS#12 file, or an encrypted PKCS#8 PEM key - and the password
 * comes from the secret {@link passwordSecretName} names, never from configuration. An unprotected
 * key file is refused unless {@link allowUnprotectedPrivateKey} is set.
 */
export interface CertificateFileOptions {
  /** The certificate file - PKCS#12, or a PEM certificate. */
  path?: string;
  /** The file's format; Pkcs12 when unset. */
  format?: CertificateFileFormat | string;
  /** The PEM private key file, for Pem; ignored for Pkcs12. */
  keyPath?: string;
  /**
   * The name of the secret holding the key's password, as a protected secret source (a
   * FilePerSecretCache, a remote secret cache) is asked for it. The password is decrypted only while
   * the key is read, into a buffer zeroed straight after.
   */
  passwordSecretName?: string;
  /**
   * Accepts a key file with no password - a PKCS#12 file without one, or a plain PEM key - whose
   * private key is then plaintext on disk, protected only by file permissions. Set it only for development.
   */
  allowUnprotectedPrivateKey?: boolean;
}

/**
 * Plain-data description of where one certificate - with its private key - is opened from: exactly
 * one of the operating system's own protected key storage ({@link windows}, {@link macOS},
 * {@link linux}) or a key file on the filesystem ({@link file}). It carries no behavior and never a
 * password: a file's password is named here, and read at load time from a protected secret source,
 * so it is never plaintext on disk or in configuration.
 *
 * The configuration keys are the .NET port's, so the same appsettings.json section binds through
 * {@link certificateOptionsFromJson}:
 *
 * ```json
 * "Certificate": { "Windows": { "StoreLocation": "LocalMachine", "StoreName": "My", "Subject": "CN=api.example.com" } }
 * "Certificate": { "MacOS": { "StoreLocation": "LocalMachine", "Subject": "CN=api.example.com" } }
 * "Certificate": { "Linux": { "Provider": "pkcs11", "KeyUri": "pkcs11:token=tls;object=api;type=private", "CertificateFile": "/etc/myapp/tls.crt" } }
 * "Certificate": { "File": { "Path": "/etc/myapp/tls.pfx", "PasswordSecretName": "tls-pfx-password" } }
 * ```
 */
export interface CertificateOptions {
  /** A certificate in a Windows certificate store, its key held by CNG. */
  windows?: CertificateStoreOptions;
  /** A certificate in a macOS keychain, its key held by the keychain. */
  macOS?: CertificateStoreOptions;
  /** A certificate whose key an OpenSSL 3 provider holds on Linux - the TPM, say. */
  linux?: LinuxOpenSslProviderOptions;
  /** A certificate and key read from files, the key protected by a password. */
  file?: CertificateFileOptions;
  /**
   * Whether the certificate must come with its private key: true (the default) for one presented as a
   * TLS server or client certificate, or used to sign; false for one only to be trusted.
   */
  requirePrivateKey?: boolean;
}

// .NET's enum values, as configuration may give them by number.
const STORE_LOCATION_NUMBERS: Record<number, StoreLocation> = { 1: 'CurrentUser', 2: 'LocalMachine' };
const STORE_NAME_NUMBERS: Record<number, StoreName> = {
  1: 'AddressBook', 2: 'AuthRoot', 3: 'CertificateAuthority', 4: 'Disallowed', 5: 'My', 6: 'Root', 7: 'TrustedPeople', 8: 'TrustedPublisher',
};
const FORMAT_NUMBERS: Record<number, CertificateFileFormat> = { 0: 'Pkcs12', 1: 'Pem' };

const fail = (message: string) => new InvalidArgumentError(message, 'ERR_HKDFGUARD_INVALID_OPTIONS_JSON');

/**
 * Reads {@link CertificateOptions} from a parsed configuration section - an object from JSON, YAML or
 * an environment mapping. Keys match a field ignoring case, so a .NET appsettings.json section
 * ("MacOS", "StoreLocation", "KeyUri", "PasswordSecretName") and camelCase ("macOS", "keyUri") both
 * read. An enum is matched by name ignoring case, or by .NET's number for it; one that is neither is
 * kept as given, for the validator to report. Booleans may be given as strings ("true"), as an
 * environment variable supplies them. A null value leaves its field unset. The result is not
 * validated: the validator, or the loader, does that.
 *
 * Unlike .NET's binder, an unknown key is an error, never silently ignored: it is most likely a typo
 * that would otherwise leave a safe default in place of what was meant.
 *
 * @param where names the section in messages, e.g. "Certificate"
 * @throws InvalidArgumentError ('ERR_HKDFGUARD_INVALID_OPTIONS_JSON') a section that isn't an object,
 * an unknown key, a key given twice (differing only in case), or a value of the wrong type. Messages
 * name the key and the kind of value found, never the value.
 */
export function certificateOptionsFromObject(settings: unknown, where = 'Certificate'): CertificateOptions {
  const reader = new SectionReader(settings, where, ['windows', 'macOS', 'linux', 'file', 'requirePrivateKey']);
  const options: CertificateOptions = {};
  const windows = reader.read('windows', store);
  if (windows !== undefined) options.windows = windows;
  const macOS = reader.read('macOS', store);
  if (macOS !== undefined) options.macOS = macOS;
  const linux = reader.read('linux', linuxProvider);
  if (linux !== undefined) options.linux = linux;
  const file = reader.read('file', certificateFile);
  if (file !== undefined) options.file = file;
  const requirePrivateKey = reader.read('requirePrivateKey', boolean);
  if (requirePrivateKey !== undefined) options.requirePrivateKey = requirePrivateKey;
  return options;
}

/**
 * Reads {@link CertificateOptions} from `section` of a JSON document - the "Certificate" section of an
 * appsettings.json, or a nested path such as "Kestrel:Certificate"; "" reads the whole document.
 * Section names match ignoring case; the section itself is read as {@link certificateOptionsFromObject} reads it.
 *
 * @throws InvalidArgumentError ('ERR_HKDFGUARD_INVALID_OPTIONS_JSON') bad JSON, a missing section, or
 * anything certificateOptionsFromObject refuses
 */
export function certificateOptionsFromJson(document: string, section = 'Certificate'): CertificateOptions {
  let node: unknown;
  try {
    node = JSON.parse(document);
  } catch (error) {
    throw fail(`Reading certificate options section '${section}': invalid JSON${jsonErrorLocation(error)}.`);
  }
  for (const name of section === '' ? [] : section.split(':')) {
    const child = isObject(node) ? memberIgnoringCase(node, name) : undefined;
    if (child === undefined) throw fail(`The JSON document has no '${section}' section.`);
    node = child;
  }
  return certificateOptionsFromObject(node, section === '' ? 'Certificate' : section);
}

/** A configuration section's values by field name, matched ignoring case; an unknown key is refused. */
class SectionReader {
  readonly #values = new Map<string, unknown>();

  constructor(settings: unknown, readonly where: string, fields: readonly string[]) {
    if (!isObject(settings)) throw fail(`'${where}' must be an object, got ${jsonKind(settings)}.`);
    const known = new Map(fields.map((field) => [field.toLowerCase(), field]));
    for (const [key, value] of Object.entries(settings)) {
      const field = known.get(key.toLowerCase());
      if (field === undefined) throw fail(`'${where}' has an unknown key '${key}'. Known keys: ${fields.map(pascal).join(', ')}.`);
      if (this.#values.has(field)) throw fail(`'${where}' gives '${pascal(field)}' more than once.`);
      this.#values.set(field, value);
    }
  }

  read<T>(field: string, convert: (value: unknown, where: string) => T): T | undefined {
    const value = this.#values.get(field);
    return value === undefined || value === null ? undefined : convert(value, `${this.where}:${pascal(field)}`);
  }
}

function pascal(field: string): string {
  return field === 'macOS' ? 'MacOS' : field.charAt(0).toUpperCase() + field.slice(1);
}

function string(value: unknown, where: string): string {
  if (typeof value !== 'string') throw fail(`'${where}' must be a string, got ${jsonKind(value)}.`);
  return value;
}

function boolean(value: unknown, where: string): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string' && /^(true|false)$/i.test(value.trim())) return value.trim().toLowerCase() === 'true';
  throw fail(`'${where}' must be true or false, got ${jsonKind(value)}.`);
}

function enumeration<E extends string>(names: readonly E[], numbers: Record<number, E>): (value: unknown, where: string) => E | string {
  return (value, where) => {
    if (typeof value === 'number' && Number.isInteger(value)) return numbers[value] ?? String(value);
    if (typeof value !== 'string') throw fail(`'${where}' must be a string, got ${jsonKind(value)}.`);
    const text = value.trim();
    if (/^[+-]?\d+$/.test(text)) return numbers[Number(text)] ?? value;
    return names.find((name) => name.toLowerCase() === text.toLowerCase()) ?? value; // not one: the validator says so
  };
}

const storeLocation = enumeration(Object.values(StoreLocation), STORE_LOCATION_NUMBERS);
const storeName = enumeration(Object.values(StoreName), STORE_NAME_NUMBERS);
const fileFormat = enumeration(Object.values(CertificateFileFormat), FORMAT_NUMBERS);

function store(value: unknown, where: string): CertificateStoreOptions {
  const reader = new SectionReader(value, where, ['storeLocation', 'storeName', 'subject']);
  const options: CertificateStoreOptions = {};
  const location = reader.read('storeLocation', storeLocation);
  if (location !== undefined) options.storeLocation = location;
  const name = reader.read('storeName', storeName);
  if (name !== undefined) options.storeName = name;
  const subject = reader.read('subject', string);
  if (subject !== undefined) options.subject = subject;
  return options;
}

function linuxProvider(value: unknown, where: string): LinuxOpenSslProviderOptions {
  const reader = new SectionReader(value, where, ['provider', 'keyUri', 'certificateFile']);
  const options: LinuxOpenSslProviderOptions = {};
  const provider = reader.read('provider', string);
  if (provider !== undefined) options.provider = provider;
  const keyUri = reader.read('keyUri', string);
  if (keyUri !== undefined) options.keyUri = keyUri;
  const certificateFile = reader.read('certificateFile', string);
  if (certificateFile !== undefined) options.certificateFile = certificateFile;
  return options;
}

function certificateFile(value: unknown, where: string): CertificateFileOptions {
  const reader = new SectionReader(value, where, ['path', 'format', 'keyPath', 'passwordSecretName', 'allowUnprotectedPrivateKey']);
  const options: CertificateFileOptions = {};
  const path = reader.read('path', string);
  if (path !== undefined) options.path = path;
  const format = reader.read('format', fileFormat);
  if (format !== undefined) options.format = format;
  const keyPath = reader.read('keyPath', string);
  if (keyPath !== undefined) options.keyPath = keyPath;
  const passwordSecretName = reader.read('passwordSecretName', string);
  if (passwordSecretName !== undefined) options.passwordSecretName = passwordSecretName;
  const allow = reader.read('allowUnprotectedPrivateKey', boolean);
  if (allow !== undefined) options.allowUnprotectedPrivateKey = allow;
  return options;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function memberIgnoringCase(object: Record<string, unknown>, name: string): unknown {
  const lower = name.toLowerCase();
  const key = Object.keys(object).find((k) => k.toLowerCase() === lower);
  return key === undefined ? undefined : object[key];
}

/** The store location, name and format these options give, with .NET's defaults filled in. */
export const DEFAULTS = {
  storeLocation: StoreLocation.localMachine as StoreLocation | string,
  storeName: StoreName.my as StoreName | string,
  format: CertificateFileFormat.pkcs12 as CertificateFileFormat | string,
  provider: 'tpm2',
} as const;

import { createPrivateKey, createPublicKey, X509Certificate } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { createSecureContext, type SecureContext } from 'node:tls';
import { InvalidArgumentError, wipe, type DataProtector } from '@runsecure/hkdfguard-abstractions';
import { MAX_KEY_STORE_LENGTH, readPkcs12, type Pkcs12Certificate, type Pkcs12Key } from './pkcs12.js';

/**
 * The purpose of the protector a key store's password is protected by:
 * `keyRing.createProtector(PASSWORD_PURPOSE)`.
 */
const PASSWORD_PURPOSE = 'HkdfGuard.Integration.HashiCorpVault.KeyStorePassword';

// The first four bytes of a JKS and a JCEKS key store, neither of which Node can read.
const JAVA_KEY_STORE_MAGIC = [Buffer.from('feedfeed', 'hex'), Buffer.from('cececece', 'hex')];
const MAX_CHAIN_LENGTH = 10;
const MAX_PEM_LENGTH = 1024 * 1024;

/**
 * Which certificates a Vault client - or the HashiCorp Vault transit key wrapper or secret cache -
 * trusts Vault's to be signed by, and which it presents for the cert auth method or a Vault
 * requiring mutual TLS: the Node counterpart of the .NET, Java and Python VaultTlsOptions. All unset,
 * Node's trust store (plus NODE_EXTRA_CA_CERTS) decides. Files are read, and passwords decrypted,
 * once, when the integration is created; every connection shares the secure context built then.
 *
 * Certificates are PEM ("CERTIFICATE" blocks). A client key is a PEM "PRIVATE KEY" (PKCS#8), "RSA
 * PRIVATE KEY" (PKCS#1) or "EC PRIVATE KEY" (SEC1) - unencrypted, as vault-client-go reads it.
 *
 * Either can instead come from a password-protected PKCS#12 key store: a trust store
 * ({@link trustStoreFile}) in place of the PEM CA certificates, a client key store
 * ({@link clientKeyStoreFile}) in place of the PEM client certificate and key. JKS and JCEKS stores
 * are refused - Node can't read them; convert one with `keytool -importkeystore -deststoretype
 * PKCS12`. A store's password is held only protected, by a protector on the key ring
 * (`keyRing.createProtector(VaultTlsOptions.PASSWORD_PURPOSE)`, set as {@link passwordProtector}):
 * it is decrypted into a buffer only while the store is read, and zeroed at once - never a string,
 * so not Node's own `pfx` and `passphrase`, which take the password only as one. Stores are read by
 * HkdfGuard's own PKCS#12 reader: PBES2 (PBKDF2 with AES-CBC, what OpenSSL 3 and Java 11.0.12+
 * write) or PKCS#12's triple-DES encryption, under an HMAC; legacy RC2 and RC4 are refused. The
 * client key goes to OpenSSL as PEM from a buffer zeroed once the secure context holds it.
 */
export interface VaultTlsOptions {
  /** A PEM file of the CA certificates Vault's certificate must chain to (VAULT_CACERT), in place of Node's trust store. */
  readonly serverCertificateFile?: string;

  /** {@link serverCertificateFile}'s content, in memory (VAULT_CACERT_BYTES). */
  readonly serverCertificatePem?: string | Uint8Array;

  /** A directory of PEM files of CA certificates (VAULT_CAPATH); every regular file is read. */
  readonly serverCertificateDirectory?: string;

  /** A PEM file of the certificate, and any intermediates, presented to Vault (VAULT_CLIENT_CERT). */
  readonly clientCertificateFile?: string;

  /** {@link clientCertificateFile}'s content, in memory. */
  readonly clientCertificatePem?: string | Uint8Array;

  /** A PEM file of the client certificate's private key (VAULT_CLIENT_KEY), unencrypted. */
  readonly clientCertificateKeyFile?: string;

  /**
   * {@link clientCertificateKeyFile}'s content, in memory. A Uint8Array is the caller's: zero it once
   * the integration is created. A string can't be erased.
   */
  readonly clientCertificateKeyPem?: string | Uint8Array;

  /**
   * The name Vault's certificate must be issued to, and sent as SNI, in place of the address's host
   * (VAULT_TLS_SERVER_NAME).
   */
  readonly serverName?: string;

  /**
   * Trusts any certificate Vault presents (VAULT_SKIP_VERIFY). For development only: anyone on the
   * network path can then read every token and secret.
   */
  readonly insecureSkipVerify?: boolean;

  /** A PKCS#12 store of the CA certificates Vault's certificate must chain to, in place of the PEM ones. Needs {@link trustStorePassword}. */
  readonly trustStoreFile?: string;

  /** {@link trustStoreFile}'s password, protected: {@link VaultTlsOptions.protectPassword}. */
  readonly trustStorePassword?: string;

  /**
   * A PKCS#12 store of the private key and certificate chain presented to Vault, in place of the PEM
   * ones. Needs {@link clientKeyStorePassword}.
   */
  readonly clientKeyStoreFile?: string;

  /** {@link clientKeyStoreFile}'s password, protected: {@link VaultTlsOptions.protectPassword}. It unlocks the key too, as PKCS#12 requires. */
  readonly clientKeyStorePassword?: string;

  /**
   * The friendly name (alias) of the key in {@link clientKeyStoreFile} to present, ignoring case as
   * Java's PKCS#12 key store does; undefined when the store holds only one private key.
   */
  readonly clientKeyStoreAlias?: string;

  /** The protector the key store passwords were protected by: `keyRing.createProtector(VaultTlsOptions.PASSWORD_PURPOSE)`. */
  readonly passwordProtector?: DataProtector;
}

/** The purpose key store passwords are protected under, and how to protect one. */
export const VaultTlsOptions = {
  /**
   * The purpose of the protector a key store's password is protected by:
   * `keyRing.createProtector(VaultTlsOptions.PASSWORD_PURPOSE)`.
   */
  PASSWORD_PURPOSE,

  /**
   * Protects a key store's password with `passwordProtector` - a protector on the key ring,
   * `keyRing.createProtector(VaultTlsOptions.PASSWORD_PURPOSE)` - for
   * {@link VaultTlsOptions.trustStorePassword} or {@link VaultTlsOptions.clientKeyStorePassword}. A
   * string can't be erased: read it once, here, and keep no other reference to it - or hand over its
   * UTF-8 bytes, and zero them once this returns.
   * @throws TypeError passwordProtector or password is missing, or password isn't a string or a Uint8Array
   * @throws InvalidArgumentError password is empty
   */
  protectPassword(passwordProtector: DataProtector, password: string | Uint8Array): string {
    if (passwordProtector === undefined || passwordProtector === null) throw new TypeError('passwordProtector must not be undefined.');
    if (typeof password !== 'string' && !(password instanceof Uint8Array)) throw new TypeError('password must be a string or a Uint8Array.');
    if (password.length === 0) throw new InvalidArgumentError("A key store password can't be empty.");
    return passwordProtector.encrypt(password);
  },
} as const;

/** What an https agent is given to connect as `tls` says. */
export interface VaultTlsAgentOptions {
  secureContext?: SecureContext;
  rejectUnauthorized?: boolean;
  servername?: string;
}

/**
 * The agent options `tls` comes to: one secure context holding its CA certificates and client
 * identity, read now; whether to verify Vault's certificate; and the server name.
 * @throws InvalidArgumentError tls isn't consistent, a file can't be read, a key store can't be
 *   opened or holds no usable key or certificate, or OpenSSL refuses the certificates or key
 */
export function createSecureContextOptions(tls: VaultTlsOptions): VaultTlsAgentOptions {
  check(tls);
  const result: VaultTlsAgentOptions = {};
  if (tls.serverName !== undefined) result.servername = tls.serverName;
  if (tls.insecureSkipVerify === true) result.rejectUnauthorized = false;

  const ca = serverCertificates(tls);
  const identity = clientIdentity(tls);
  if (ca === undefined && identity === undefined) return result;
  try {
    const details: { ca?: string[]; cert?: string; key?: Buffer } = {};
    if (ca !== undefined) details.ca = ca;
    if (identity !== undefined) {
      details.cert = identity.chain;
      details.key = identity.key;
    }
    try {
      result.secureContext = createSecureContext(details);
    } catch (error) {
      // OpenSSL's reasons - a key that doesn't match the certificate, say - quote no key material.
      throw new InvalidArgumentError(`The Vault TLS certificates or key can't be used: ${(error as Error).message}`);
    }
  } finally {
    wipe(identity?.key);
  }
  return result;
}

function check(tls: VaultTlsOptions): void {
  const set = (name: keyof VaultTlsOptions) => tls[name] !== undefined && tls[name] !== null;
  const strings: (keyof VaultTlsOptions)[] = ['serverCertificateFile', 'serverCertificateDirectory', 'clientCertificateFile',
    'clientCertificateKeyFile', 'serverName', 'trustStoreFile', 'trustStorePassword', 'clientKeyStoreFile', 'clientKeyStorePassword',
    'clientKeyStoreAlias'];
  for (const name of strings) {
    if (set(name) && (typeof tls[name] !== 'string' || tls[name] === '')) throw new InvalidArgumentError(`tls.${name} must be a non-empty string.`);
  }
  for (const name of ['serverCertificatePem', 'clientCertificatePem', 'clientCertificateKeyPem'] as const) {
    if (set(name) && typeof tls[name] !== 'string' && !(tls[name] instanceof Uint8Array)) {
      throw new InvalidArgumentError(`tls.${name} must be a string or a Uint8Array.`);
    }
  }
  if (set('insecureSkipVerify') && typeof tls.insecureSkipVerify !== 'boolean') throw new InvalidArgumentError('tls.insecureSkipVerify must be a boolean.');
  if (set('passwordProtector') && typeof tls.passwordProtector?.decrypt !== 'function') {
    throw new InvalidArgumentError('tls.passwordProtector must be a DataProtector.');
  }

  const trusted = (['serverCertificateFile', 'serverCertificatePem', 'serverCertificateDirectory', 'trustStoreFile'] as const).filter(set);
  if (trusted.length > 1) throw new InvalidArgumentError(`Set at most one of tls.${trusted.join(', tls.')}: each names the CA certificates to trust.`);
  const exclusive = (a: keyof VaultTlsOptions, b: keyof VaultTlsOptions) => {
    if (set(a) && set(b)) throw new InvalidArgumentError(`Set tls.${a} or tls.${b}, not both.`);
  };
  exclusive('clientCertificateFile', 'clientCertificatePem');
  exclusive('clientCertificateKeyFile', 'clientCertificateKeyPem');
  const hasCertificate = set('clientCertificateFile') || set('clientCertificatePem');
  const hasKey = set('clientCertificateKeyFile') || set('clientCertificateKeyPem');
  if (hasCertificate !== hasKey) throw new InvalidArgumentError('A client certificate needs its key, and a key its certificate.');
  if (set('clientKeyStoreFile') && hasCertificate) {
    throw new InvalidArgumentError('Set tls.clientKeyStoreFile or the PEM client certificate and key, not both.');
  }
  if (set('trustStoreFile') !== set('trustStorePassword')) throw new InvalidArgumentError('tls.trustStoreFile and tls.trustStorePassword go together.');
  if (set('clientKeyStoreFile') !== set('clientKeyStorePassword')) {
    throw new InvalidArgumentError('tls.clientKeyStoreFile and tls.clientKeyStorePassword go together.');
  }
  if (set('clientKeyStoreAlias') && !set('clientKeyStoreFile')) throw new InvalidArgumentError('tls.clientKeyStoreAlias needs tls.clientKeyStoreFile.');
  if ((set('trustStorePassword') || set('clientKeyStorePassword')) && !set('passwordProtector')) {
    throw new InvalidArgumentError('A key store password is protected: set tls.passwordProtector, '
      + 'keyRing.createProtector(VaultTlsOptions.PASSWORD_PURPOSE), the protector it was protected by.');
  }
}

// The CA certificates to trust, as PEM, or undefined for Node's trust store.
function serverCertificates(tls: VaultTlsOptions): string[] | undefined {
  if (tls.serverCertificateFile !== undefined) return pemCertificates(readFile(tls.serverCertificateFile, 'server CA certificate file', MAX_PEM_LENGTH), `server CA certificate file '${tls.serverCertificateFile}'`);
  if (tls.serverCertificatePem !== undefined) return pemCertificates(Buffer.from(tls.serverCertificatePem), 'tls.serverCertificatePem');
  if (tls.serverCertificateDirectory !== undefined) {
    const directory = tls.serverCertificateDirectory;
    let names: string[];
    try {
      names = readdirSync(directory).sort(byCodeUnits);
    } catch (error) {
      throw new InvalidArgumentError(`The server CA certificate directory '${directory}' can't be read: ${(error as NodeJS.ErrnoException).code ?? error}.`);
    }
    const certificates: string[] = [];
    for (const name of names) {
      const path = join(directory, name);
      if (!statSync(path, { throwIfNoEntry: false })?.isFile()) continue;
      certificates.push(...pemCertificates(readFile(path, 'server CA certificate file', MAX_PEM_LENGTH), `server CA certificate file '${path}'`));
    }
    if (certificates.length === 0) throw new InvalidArgumentError(`The server CA certificate directory '${directory}' holds no certificates.`);
    return certificates;
  }
  if (tls.trustStoreFile !== undefined) {
    const what = `trust store '${tls.trustStoreFile}'`;
    const { certificates } = openStore(tls.trustStoreFile, tls.trustStorePassword!, tls.passwordProtector!, false, what);
    if (certificates.length === 0) throw new InvalidArgumentError(`The ${what} holds no certificates.`);
    return certificates.map((certificate) => toCertificate(certificate.der, what).toString());
  }
  return undefined;
}

// The client certificate chain, as PEM, and its key, as PEM in a buffer the caller zeroes.
function clientIdentity(tls: VaultTlsOptions): { chain: string; key: Buffer } | undefined {
  if (tls.clientKeyStoreFile !== undefined) return keyStoreIdentity(tls);
  if (tls.clientCertificateFile === undefined && tls.clientCertificatePem === undefined) return undefined;

  const certificateWhat = tls.clientCertificateFile !== undefined ? `client certificate file '${tls.clientCertificateFile}'` : 'tls.clientCertificatePem';
  const chain = pemCertificates(tls.clientCertificateFile !== undefined
    ? readFile(tls.clientCertificateFile, 'client certificate file', MAX_PEM_LENGTH) : Buffer.from(tls.clientCertificatePem!), certificateWhat);
  // Copied, so zeroing it never touches the caller's buffer, which is theirs to zero.
  const key = tls.clientCertificateKeyFile !== undefined
    ? readFile(tls.clientCertificateKeyFile, 'client certificate key file', MAX_PEM_LENGTH) : Buffer.from(tls.clientCertificateKeyPem!);
  return { chain: chain.join(''), key };
}

function keyStoreIdentity(tls: VaultTlsOptions): { chain: string; key: Buffer } {
  const what = `client key store '${tls.clientKeyStoreFile}'`;
  const { keys, certificates } = openStore(tls.clientKeyStoreFile!, tls.clientKeyStorePassword!, tls.passwordProtector!, true, what);
  try {
    const key = chooseKey(keys, tls.clientKeyStoreAlias, what);
    const leaf = chooseCertificate(key, certificates, what);
    const chain = [leaf];
    for (let current = leaf; chain.length < MAX_CHAIN_LENGTH && !current.checkIssued(current);) {
      const issuer = certificates.map((c) => toCertificate(c.der, what))
        .find((candidate) => !chain.some((c) => c.raw.equals(candidate.raw)) && current.checkIssued(candidate) && current.verify(candidate.publicKey));
      // The root, self-signed, is the server's to have; it isn't presented.
      if (issuer === undefined || issuer.checkIssued(issuer)) break;
      chain.push(issuer);
      current = issuer;
    }
    return { chain: chain.map((c) => c.toString()).join(''), key: pemFromPkcs8(key.pkcs8) };
  } finally {
    for (const key of keys) wipe(key.pkcs8);
  }
}

// The key the alias names, or the store's only key.
function chooseKey(keys: Pkcs12Key[], alias: string | undefined, what: string): Pkcs12Key {
  const names = keys.map((key) => (key.friendlyName === undefined ? '(unnamed)' : `'${key.friendlyName}'`)).join(', ');
  if (keys.length === 0) throw new InvalidArgumentError(`The ${what} holds no private key.`);
  if (alias === undefined) {
    if (keys.length > 1) throw new InvalidArgumentError(`The ${what} holds ${keys.length} private keys (${names}): set tls.clientKeyStoreAlias to the one to present.`);
    return keys[0]!;
  }
  const matches = keys.filter((key) => key.friendlyName?.toLowerCase() === alias.toLowerCase());
  if (matches.length !== 1) {
    throw new InvalidArgumentError(`The ${what} holds ${matches.length === 0 ? 'no' : 'more than one'} private key named '${alias}'; its keys are ${names}.`);
  }
  return matches[0]!;
}

// The certificate holding `key`'s public key, preferring the one its local key ID names.
function chooseCertificate(key: Pkcs12Key, certificates: Pkcs12Certificate[], what: string): X509Certificate {
  let publicKey;
  try {
    publicKey = createPublicKey(createPrivateKey({ key: key.pkcs8, format: 'der', type: 'pkcs8' }));
  } catch {
    throw new InvalidArgumentError(`The ${what} holds a private key Node can't read.`);
  }
  const matching = certificates.filter((c) => toCertificate(c.der, what).publicKey.equals(publicKey));
  const chosen = matching.find((c) => key.localKeyId !== undefined && c.localKeyId?.equals(key.localKeyId) === true) ?? matching[0];
  if (chosen === undefined) throw new InvalidArgumentError(`The ${what} holds no certificate for its private key${key.friendlyName === undefined ? '' : ` '${key.friendlyName}'`}.`);
  return toCertificate(chosen.der, what);
}

// The store at `path`, read with the password `protectedPassword` holds - decrypted into a buffer
// zeroed before this returns.
function openStore(path: string, protectedPassword: string, protector: DataProtector, readKeys: boolean, what: string) {
  const store = readFile(path, what.split(' \'')[0]!, MAX_KEY_STORE_LENGTH + 1);
  if (store.length >= 4 && JAVA_KEY_STORE_MAGIC.some((magic) => store.subarray(0, 4).equals(magic))) {
    throw new InvalidArgumentError(`The ${what} is a JKS or JCEKS store, which Node can't read; convert it to PKCS#12: `
      + 'keytool -importkeystore -srckeystore <store> -destkeystore <store>.p12 -deststoretype PKCS12.');
  }
  if (store.subarray(0, 64).toString('latin1').includes('-----BEGIN')) {
    throw new InvalidArgumentError(`The ${what} is PEM, not PKCS#12: set it as the PEM certificates (and key) instead.`);
  }
  const password = decryptPassword(protector, protectedPassword, what);
  try {
    return readPkcs12(store, password, readKeys, what);
  } finally {
    wipe(password);
  }
}

// The password, decrypted into a buffer the caller zeroes. The protector's errors aren't chained: a
// parser handed an unprotected password could quote it.
function decryptPassword(protector: DataProtector, protectedPassword: string, what: string): Uint8Array {
  let buffer: Uint8Array | undefined;
  let length = -1;
  try {
    const maxLength = protector.maxDecryptedLength(protectedPassword);
    if (Number.isSafeInteger(maxLength) && maxLength >= 0) {
      buffer = new Uint8Array(maxLength);
      length = protector.decrypt(protectedPassword, buffer);
    }
  } catch {
    length = -1;
  }
  if (buffer === undefined || !Number.isSafeInteger(length) || length <= 0 || length > buffer.length) {
    wipe(buffer);
    throw new InvalidArgumentError(`The ${what}'s password isn't protected by tls.passwordProtector: `
      + 'set VaultTlsOptions.protectPassword(passwordProtector, password), never the password itself.');
  }
  const password = buffer.slice(0, length);
  wipe(buffer);
  return password;
}

function readFile(path: string, what: string, maxLength: number): Buffer {
  let data: Buffer;
  try {
    data = readFileSync(path);
  } catch (error) {
    throw new InvalidArgumentError(`The ${what} '${path}' can't be read: ${(error as NodeJS.ErrnoException).code ?? error}.`);
  }
  if (data.length > maxLength) {
    wipe(data);
    throw new InvalidArgumentError(`The ${what} '${path}' is over ${maxLength} bytes.`);
  }
  return data;
}

// The certificates in PEM text, each checked, as PEM.
function pemCertificates(pem: Buffer, what: string): string[] {
  const text = pem.toString('latin1');
  const blocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
  if (blocks.length === 0) throw new InvalidArgumentError(`The ${what} holds no PEM certificate.`);
  return blocks.map((block) => {
    try {
      return new X509Certificate(block).toString();
    } catch {
      throw new InvalidArgumentError(`The ${what} holds a certificate that can't be parsed.`);
    }
  });
}

function toCertificate(der: Buffer, what: string): X509Certificate {
  try {
    return new X509Certificate(der);
  } catch {
    throw new InvalidArgumentError(`The ${what} holds a certificate that can't be parsed.`);
  }
}

const BASE64 = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', 'latin1');

// PKCS#8 DER as a PEM "PRIVATE KEY", written straight into a buffer the caller zeroes: never a string.
function pemFromPkcs8(der: Buffer): Buffer {
  const header = Buffer.from('-----BEGIN PRIVATE KEY-----\n', 'latin1');
  const footer = Buffer.from('-----END PRIVATE KEY-----\n', 'latin1');
  const encoded = Math.ceil(der.length / 3) * 4;
  const out = Buffer.alloc(header.length + encoded + Math.ceil(encoded / 64) + footer.length);
  let position = header.copy(out, 0);
  let column = 0;
  const put = (byte: number) => {
    out[position++] = byte;
    if (++column === 64) {
      out[position++] = 0x0a;
      column = 0;
    }
  };
  for (let i = 0; i < der.length; i += 3) {
    const a = der[i]!;
    const b = i + 1 < der.length ? der[i + 1]! : 0;
    const c = i + 2 < der.length ? der[i + 2]! : 0;
    put(BASE64[a >> 2]!);
    put(BASE64[((a & 0x03) << 4) | (b >> 4)]!);
    put(i + 1 < der.length ? BASE64[((b & 0x0f) << 2) | (c >> 6)]! : 0x3d);
    put(i + 2 < der.length ? BASE64[c & 0x3f]! : 0x3d);
  }
  if (column !== 0) out[position++] = 0x0a;
  position += footer.copy(out, position);
  return out.subarray(0, position);
}

// Ordinal order, UTF-16 code unit by code unit: the same on every machine, unlike localeCompare.
function byCodeUnits(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

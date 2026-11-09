// What the certificate tests share: certificates and keys they make (node:crypto has no certificate
// builder, so TBSCertificates are written here and signed with node:crypto), a PKCS#12 writer, a
// store and a password source they hand the loader, the fixtures other tools wrote, and a TLS
// handshake over a local server.
import {
  createCipheriv, createHash, createHmac, generateKeyPairSync, pbkdf2Sync, randomBytes, sign, type KeyObject,
} from 'node:crypto';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect, createServer, type SecureContext, type Server } from 'node:tls';
import type { ProtectedReadOnlyCache } from '@runsecure/hkdfguard-abstractions';
import { KeyFileTrust } from '@runsecure/hkdfguard-securefile';
import { linuxKeyFileRoot, trustedFixtureCopy, windowsCurrentUserSid } from '@runsecure/hkdfguard-test-support';
import * as der from './der.js';
import { CertificateOptionsLoader } from './loader.js';
import type { CertificateOptions } from './options.js';
import { pkcs12 as sharedPkcs12 } from '@runsecure/hkdfguard-abstractions/internal';
const { bmpPassword, pkcs12Kdf } = sharedPkcs12;
import { encodePem } from './pem.js';
import type { StoreCertificate, StoreKey, StoreReader } from './store.js';
import { CertificateOptionsValidator, type CertificatePlatform } from './validator.js';

// A private copy: the checkout's folder may not pass the trusted-file checks (see trustedFixtureCopy).
export const TESTDATA = trustedFixtureCopy(join(__dirname, '..', 'testdata'), 'hkdfguard-testdata-');
export const SUBJECT = 'CN=api.example.com, O=Contoso';

/**
 * The trust the tests' loaders read files with: this account, besides administrators, so the files
 * the tests write - and the fixtures, in this checkout - pass readTrustedFile's checks.
 */
export const FILE_TRUST: KeyFileTrust = process.platform === 'win32'
  ? new KeyFileTrust({ windowsPrincipals: [windowsCurrentUserSid()] })
  : new KeyFileTrust({ unixUserIds: [process.geteuid!()], unixGroupIds: [process.getegid!()] });

/**
 * A fresh folder, by its long path, that readTrustedFile accepts under {@link FILE_TRUST} for the
 * files a test file writes; `cleanUp` removes it (call it from after()). On Linux the temp folder is
 * world-writable, so the folder is made under $XDG_RUNTIME_DIR or ~/.cache instead (see
 * test-support's keyFileDirectory); when this host has neither, `directory` is undefined and
 * `skip` says why, for the describe blocks that write files.
 */
export function trustedDirectory(prefix: string): { directory?: string; skip: string | false; cleanUp(): void } {
  let root = tmpdir();
  if (process.platform === 'linux') {
    const linux = linuxKeyFileRoot();
    if (linux.root === undefined) return { skip: linux.skipReason!, cleanUp() {} };
    root = linux.root;
  }
  const directory = realpathSync.native(mkdtempSync(join(root, prefix)));
  return { directory, skip: false, cleanUp: () => rmSync(directory, { recursive: true, force: true }) };
}
export const PASSWORD = 'pässwörd-123'; // NOSONAR: protects only the throwaway stores these tests make
/** The tests' clock: the time they started, so the fixtures (made by OpenSSL and .NET, valid for ten years) are valid now too. */
export const NOW = new Date(Math.floor(Date.now() / 1000) * 1000);
const DAY = 24 * 60 * 60 * 1000;

export interface KeyPair {
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
}

const rsaKeys = new Map<number, KeyPair>();
/** An RSA key, made once per index: generating one per certificate would make the suite slow. */
export function rsaKey(index = 0): KeyPair {
  let key = rsaKeys.get(index);
  if (key === undefined) {
    key = generateKeyPairSync('rsa', { modulusLength: 2048 });
    rsaKeys.set(index, key);
  }
  return key;
}

let ec: KeyPair | undefined;
export function ecKey(): KeyPair {
  ec ??= generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return ec;
}

const ATTRIBUTE_OIDS: Record<string, string> = { CN: '2.5.4.3', O: '2.5.4.10', OU: '2.5.4.11', C: '2.5.4.6', DC: '0.9.2342.19200300.100.1.25', E: '1.2.840.113549.1.9.1' };

/** A subject written as configuration writes it, most specific first, encoded as a certificate encodes it: reversed, each value a UTF8String (or `stringTag`). */
export function nameDer(subject: string, stringTag = der.UTF8_STRING): Buffer {
  const rdns = subject.split(',').map((part) => {
    const [keyword, ...value] = part.trim().split('=');
    const oid = ATTRIBUTE_OIDS[keyword!.trim()]!;
    const text = value.join('=');
    const encoded = stringTag === 0x1e ? Buffer.from(text, 'utf16le').swap16() : Buffer.from(text, stringTag === der.UTF8_STRING ? 'utf8' : 'latin1');
    return der.encode(der.SET, der.encode(der.SEQUENCE, der.encodeOid(oid), der.encode(stringTag, encoded)));
  });
  return der.encode(der.SEQUENCE, ...rdns.reverse());
}

function time(moment: Date): Buffer {
  const iso = moment.toISOString().replace(/[-:T]/g, '').replace(/\.\d{3}Z$/, 'Z');
  return moment.getUTCFullYear() < 2050 ? der.encode(0x17, Buffer.from(iso.slice(2), 'latin1')) : der.encode(0x18, Buffer.from(iso, 'latin1'));
}

export interface CertificateSpec {
  readonly subject?: string | Buffer;
  readonly notBeforeDays?: number;
  readonly notAfterDays?: number;
  readonly now?: Date;
  /** The key that signs it, and the issuer's name; self-signed by default. */
  readonly issuer?: { key: KeyPair; name: string };
  readonly ca?: boolean;
}

/** A certificate for `key`, DER, valid from notBeforeDays to notAfterDays after now, for api.example.com. */
export function certificate(key: KeyPair, spec: CertificateSpec = {}): Buffer {
  const now = spec.now ?? NOW;
  const subject = Buffer.isBuffer(spec.subject) ? spec.subject : nameDer(spec.subject ?? SUBJECT);
  const signer = spec.issuer?.key ?? key;
  const issuer = spec.issuer === undefined ? subject : nameDer(spec.issuer.name);
  const rsa = signer.privateKey.asymmetricKeyType === 'rsa';
  const signatureAlgorithm = rsa
    ? der.encode(der.SEQUENCE, der.encodeOid('1.2.840.113549.1.1.11'), der.encode(der.NULL))
    : der.encode(der.SEQUENCE, der.encodeOid('1.2.840.10045.4.3.2'));
  const san = der.encode(der.SEQUENCE, der.encode(0x82, Buffer.from('api.example.com', 'latin1')));
  const extensions = der.encode(0xa3, der.encode(der.SEQUENCE,
    der.encode(der.SEQUENCE, der.encodeOid('2.5.29.19'), der.encode(0x01, Buffer.from([0xff])),
      der.encode(der.OCTET_STRING, der.encode(der.SEQUENCE, ...(spec.ca === false ? [] : [der.encode(0x01, Buffer.from([0xff]))])))),
    der.encode(der.SEQUENCE, der.encodeOid('2.5.29.17'), der.encode(der.OCTET_STRING, san))));
  const tbs = der.encode(der.SEQUENCE,
    der.encode(der.CONTEXT_0, der.encodeInteger(2)),
    der.encodeInteger(BigInt(`0x${randomBytes(8).toString('hex')}`)),
    signatureAlgorithm,
    issuer,
    der.encode(der.SEQUENCE, time(new Date(now.getTime() + (spec.notBeforeDays ?? -1) * DAY)), time(new Date(now.getTime() + (spec.notAfterDays ?? 30) * DAY))),
    subject,
    key.publicKey.export({ format: 'der', type: 'spki' }),
    extensions);
  const signature = sign('sha256', tbs, signer.privateKey);
  return der.encode(der.SEQUENCE, tbs, signatureAlgorithm, der.encode(der.BIT_STRING, Buffer.from([0]), signature));
}

/** Certificates as one PEM file. */
export function pem(...certificates: Buffer[]): Buffer {
  return Buffer.concat(certificates.map((c) => encodePem('CERTIFICATE', c)));
}

export function fixture(name: string): string {
  return join(TESTDATA, name);
}

export function fixtureCertificateDer(name: string): Buffer {
  const text = readFileSync(fixture(name), 'latin1');
  return Buffer.from(text.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''), 'base64');
}

export function utf8(text = PASSWORD): Buffer {
  return Buffer.from(text, 'utf8');
}

// --- A PKCS#12 writer -----------------------------------------------------------------------

const DATA = '1.2.840.113549.1.7.1';
const ENCRYPTED_DATA = '1.2.840.113549.1.7.6';

function pbes2Encrypt(plaintext: Buffer, password: Buffer, iterations: number): { algorithm: Buffer; ciphertext: Buffer } {
  const salt = randomBytes(16);
  const iv = randomBytes(16);
  const key = pbkdf2Sync(password, salt, iterations, 32, 'sha256');
  const cipher = createCipheriv('aes-256-cbc', key, iv); // NOSONAR: PBES2's AES-256-CBC, as OpenSSL 3 writes PKCS#12
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const algorithm = der.encode(der.SEQUENCE, der.encodeOid('1.2.840.113549.1.5.13'), der.encode(der.SEQUENCE,
    der.encode(der.SEQUENCE, der.encodeOid('1.2.840.113549.1.5.12'), der.encode(der.SEQUENCE, der.encode(der.OCTET_STRING, salt), der.encodeInteger(iterations),
      der.encode(der.SEQUENCE, der.encodeOid('1.2.840.113549.2.9'), der.encode(der.NULL)))),
    der.encode(der.SEQUENCE, der.encodeOid('2.16.840.1.101.3.4.1.42'), der.encode(der.OCTET_STRING, iv))));
  return { algorithm, ciphertext };
}

function pkcs12TripleDesEncrypt(plaintext: Buffer, password: Buffer | undefined, iterations: number): { algorithm: Buffer; ciphertext: Buffer } {
  const salt = randomBytes(8);
  const bmp = bmpPassword(password);
  const key = pkcs12Kdf('sha1', bmp, salt, iterations, 1, 24);
  const iv = pkcs12Kdf('sha1', bmp, salt, iterations, 2, 8);
  const cipher = createCipheriv('des-ede3-cbc', key, iv); // NOSONAR: the legacy PKCS#12 encryption the loader is tested against
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const algorithm = der.encode(der.SEQUENCE, der.encodeOid('1.2.840.113549.1.12.1.3'),
    der.encode(der.SEQUENCE, der.encode(der.OCTET_STRING, salt), der.encodeInteger(iterations)));
  return { algorithm, ciphertext };
}

export interface Pkcs12Spec {
  readonly keys?: KeyObject[];
  readonly certificates: Buffer[];
  /** The password's UTF-8 bytes; undefined for none. */
  readonly password?: Buffer;
  readonly keyEncryption?: 'pbes2' | '3des' | 'none';
  readonly certificateEncryption?: 'pbes2' | '3des' | 'none';
  readonly mac?: 'sha1' | 'sha256' | 'sha512' | 'none' | 'pbmac1';
  readonly iterations?: number;
  readonly macIterations?: number;
}

function bag(type: string, value: Buffer): Buffer {
  return der.encode(der.SEQUENCE, der.encodeOid(type), der.encode(der.CONTEXT_0, value));
}

function encrypt(how: 'pbes2' | '3des', plaintext: Buffer, password: Buffer | undefined, iterations: number) {
  return how === 'pbes2' ? pbes2Encrypt(plaintext, password ?? Buffer.alloc(0), iterations) : pkcs12TripleDesEncrypt(plaintext, password, iterations);
}

/** A PKCS#12 file of `spec.keys` and `spec.certificates`, as OpenSSL and Windows write one. */
export function pkcs12(spec: Pkcs12Spec): Buffer {
  const iterations = spec.iterations ?? 2048;
  const keyEncryption = spec.keyEncryption ?? 'pbes2';
  const certificateEncryption = spec.certificateEncryption ?? 'pbes2';
  const keyBags = (spec.keys ?? []).map((key) => {
    const info = key.export({ format: 'der', type: 'pkcs8' });
    if (keyEncryption === 'none') return bag('1.2.840.113549.1.12.10.1.1', info);
    const { algorithm, ciphertext } = encrypt(keyEncryption, info, spec.password, iterations);
    return bag('1.2.840.113549.1.12.10.1.2', der.encode(der.SEQUENCE, algorithm, der.encode(der.OCTET_STRING, ciphertext)));
  });
  const certificateBags = spec.certificates.map((c) => bag('1.2.840.113549.1.12.10.1.3',
    der.encode(der.SEQUENCE, der.encodeOid('1.2.840.113549.1.9.22.1'), der.encode(der.CONTEXT_0, der.encode(der.OCTET_STRING, c)))));
  const data = (contents: Buffer) => der.encode(der.SEQUENCE, der.encodeOid(DATA), der.encode(der.CONTEXT_0, der.encode(der.OCTET_STRING, contents)));
  const infos: Buffer[] = [];
  const certificateSafe = der.encode(der.SEQUENCE, ...certificateBags);
  if (certificateEncryption === 'none') {
    infos.push(data(certificateSafe));
  } else {
    const { algorithm, ciphertext } = encrypt(certificateEncryption, certificateSafe, spec.password, iterations);
    infos.push(der.encode(der.SEQUENCE, der.encodeOid(ENCRYPTED_DATA), der.encode(der.CONTEXT_0, der.encode(der.SEQUENCE, der.encodeInteger(0),
      der.encode(der.SEQUENCE, der.encodeOid(DATA), algorithm, der.encode(0x80, ciphertext))))));
  }
  if (keyBags.length > 0) infos.push(data(der.encode(der.SEQUENCE, ...keyBags)));
  const authSafe = der.encode(der.SEQUENCE, ...infos);
  const parts = [der.encodeInteger(3), data(authSafe)];
  const mac = spec.mac ?? 'sha256';
  if (mac === 'pbmac1') {
    parts.push(der.encode(der.SEQUENCE, der.encode(der.SEQUENCE, der.encode(der.SEQUENCE, der.encodeOid('1.2.840.113549.1.5.14')), der.encode(der.OCTET_STRING, Buffer.alloc(32))),
      der.encode(der.OCTET_STRING, randomBytes(8)), der.encodeInteger(1)));
  } else if (mac !== 'none') {
    const salt = randomBytes(8);
    const macIterations = spec.macIterations ?? iterations;
    const length = createHash(mac).digest().length;
    const key = pkcs12Kdf(mac, bmpPassword(spec.password), salt, macIterations, 3, length);
    const digest = createHmac(mac, key).update(authSafe).digest();
    const oid = { sha1: '1.3.14.3.2.26', sha256: '2.16.840.1.101.3.4.2.1', sha512: '2.16.840.1.101.3.4.2.3' }[mac];
    parts.push(der.encode(der.SEQUENCE, der.encode(der.SEQUENCE, der.encode(der.SEQUENCE, der.encodeOid(oid), der.encode(der.NULL)), der.encode(der.OCTET_STRING, digest)),
      der.encode(der.OCTET_STRING, salt), der.encodeInteger(macIterations)));
  }
  return der.encode(der.SEQUENCE, ...parts);
}

// --- Fakes ----------------------------------------------------------------------------------------

const DEFAULT_PASSWORDS: Readonly<Record<string, string>> = { 'tls-password': PASSWORD };

/** A password source holding plaintext passwords, recording every buffer it decrypts into so a test can check the loader zeroes it. */
export class FakePasswords implements ProtectedReadOnlyCache {
  readonly passwords: Map<string, Buffer>;
  readonly buffers: Uint8Array[] = [];
  failure: Error | undefined;

  constructor(passwords: Readonly<Record<string, string>> = DEFAULT_PASSWORDS) {
    this.passwords = new Map(Object.entries(passwords).map(([name, value]) => [name, utf8(value)]));
  }

  async decrypt(name: string, result: Uint8Array): Promise<number> {
    if (this.failure !== undefined) throw this.failure;
    const value = this.passwords.get(name);
    if (value === undefined) return 0;
    this.buffers.push(result);
    result.set(value);
    return value.length;
  }

  async maxDecryptedLength(name: string): Promise<number | undefined> {
    if (this.failure !== undefined) throw this.failure;
    const value = this.passwords.get(name);
    return value === undefined ? undefined : value.length + 7; // an upper bound, as a real cache's is
  }
}

/** A store's key, as a StoreKey: signs and decrypts with a node:crypto key, from the digest and scheme the loader resolved, as CNG and the keychain are handed them. */
export class FakeStoreKey implements StoreKey {
  closed = false;
  readonly digests: Buffer[] = [];

  constructor(private readonly key: KeyPair) {}

  async signDigest(digest: Buffer, hash: string, scheme: 'pkcs1' | 'pss' | 'ecdsa', saltLength: number): Promise<Buffer> {
    if (this.closed) throw new Error('closed');
    this.digests.push(digest);
    const { constants, privateEncrypt } = await import('node:crypto');
    if (scheme === 'ecdsa') return ecdsaSignDigest(this.key.privateKey, digest); // as CNG and the keychain sign a digest
    if (scheme === 'pkcs1') {
      const prefixes: Record<string, string> = {
        sha256: '3031300d060960864801650304020105000420', sha384: '3041300d060960864801650304020205000430',
        sha512: '3051300d060960864801650304020305000440', sha1: '3021300906052b0e03021a05000414',
      };
      return privateEncrypt({ key: this.key.privateKey, padding: constants.RSA_PKCS1_PADDING }, Buffer.concat([Buffer.from(prefixes[hash]!, 'hex'), digest]));
    }
    throw new Error(`the fake signs PSS only through the file path, not ${scheme} (salt ${saltLength})`);
  }

  /** Every decryption the store was asked for, by scheme. */
  readonly decryptions: ('pkcs1' | 'oaep')[] = [];

  async decrypt(ciphertext: Buffer, scheme: 'pkcs1' | 'oaep', hash: string, label: Buffer): Promise<Buffer> {
    this.decryptions.push(scheme);
    const { constants, privateDecrypt } = await import('node:crypto');
    return privateDecrypt(scheme === 'oaep' ? { key: this.key.privateKey, oaepHash: hash, oaepLabel: label } : { key: this.key.privateKey, padding: constants.RSA_PKCS1_PADDING },
      ciphertext);
  }

  close(): void {
    this.closed = true;
  }
}

// P-256, for signing a digest as it is - which node:crypto can't: its sign() always hashes for ECDSA.
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const A = P - 3n;
const G: [bigint, bigint] = [0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n];

function modulo(a: bigint, m: bigint): bigint {
  return ((a % m) + m) % m;
}

function inverse(a: bigint, m: bigint): bigint {
  let [r0, r1, s0, s1] = [modulo(a, m), m, 1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  return modulo(s0, m);
}

function add(p: [bigint, bigint] | undefined, q: [bigint, bigint] | undefined): [bigint, bigint] | undefined {
  if (p === undefined) return q;
  if (q === undefined) return p;
  if (p[0] === q[0] && modulo(p[1] + q[1], P) === 0n) return undefined;
  const lambda = p[0] === q[0] && p[1] === q[1]
    ? modulo((3n * p[0] * p[0] + A) * inverse(2n * p[1], P), P)
    : modulo((q[1] - p[1]) * inverse(q[0] - p[0], P), P);
  const x = modulo(lambda * lambda - p[0] - q[0], P);
  return [x, modulo(lambda * (p[0] - x) - p[1], P)];
}

function multiply(k: bigint, point: [bigint, bigint]): [bigint, bigint] | undefined {
  let result: [bigint, bigint] | undefined;
  let addend: [bigint, bigint] | undefined = point;
  for (let n = k; n > 0n; n >>= 1n) {
    if (n & 1n) result = add(result, addend);
    addend = add(addend, addend);
  }
  return result;
}

/** An ECDSA P-256 signature of `digest` as it is, DER - what a store's key gives for a digest. */
export function ecdsaSignDigest(privateKey: KeyObject, digest: Buffer): Buffer {
  const jwk = privateKey.export({ format: 'jwk' });
  if (jwk.crv !== 'P-256' || jwk.d === undefined) throw new Error('the fake signs with P-256 keys only');
  const d = BigInt(`0x${Buffer.from(jwk.d, 'base64url').toString('hex')}`);
  const e = BigInt(`0x${digest.subarray(0, 32).toString('hex')}`);
  for (;;) {
    const k = modulo(BigInt(`0x${randomBytes(40).toString('hex')}`), N - 1n) + 1n;
    const r = modulo(multiply(k, G)![0], N);
    const s = modulo(inverse(k, N) * (e + r * d), N);
    if (r === 0n || s === 0n) continue;
    const integer = (value: bigint) => {
      let hex = value.toString(16);
      if (hex.length % 2 !== 0) hex = `0${hex}`;
      if (Number.parseInt(hex.slice(0, 2), 16) >= 0x80) hex = `00${hex}`;
      return der.encode(der.INTEGER, Buffer.from(hex, 'hex'));
    };
    return der.encode(der.SEQUENCE, integer(r), integer(s));
  }
}

/** One certificate in a FakeStore. */
export class FakeStoreCertificate implements StoreCertificate {
  readonly hasPrivateKey: boolean;
  closed = false;
  opened: FakeStoreKey | undefined;

  constructor(readonly der: Buffer, private readonly key: KeyPair | undefined, readonly keyFails?: Error) {
    this.hasPrivateKey = key !== undefined;
  }

  openPrivateKey(): FakeStoreKey {
    if (this.keyFails !== undefined) throw this.keyFails;
    this.opened = new FakeStoreKey(this.key!);
    return this.opened;
  }

  close(): void {
    this.closed = true;
  }
}

/** A store the loader reads instead of the operating system's. */
export class FakeStore {
  readonly reads: [string, string][] = [];

  constructor(readonly certificates: FakeStoreCertificate[], readonly failure?: Error) {}

  readonly read: StoreReader = (location, name) => {
    this.reads.push([location, name]);
    if (this.failure !== undefined) throw this.failure;
    return [...this.certificates];
  };
}

export function entry(notBeforeDays: number, notAfterDays: number, options: { withKey?: boolean; subject?: string; key?: KeyPair } = {}): FakeStoreCertificate {
  const key = options.key ?? rsaKey();
  return new FakeStoreCertificate(certificate(key, { subject: options.subject ?? SUBJECT, notBeforeDays, notAfterDays }), options.withKey === false ? undefined : key);
}

export function loader(
  options: { passwords?: ProtectedReadOnlyCache; platform?: CertificatePlatform; store?: FakeStore; now?: Date; fileTrust?: KeyFileTrust } = {},
): CertificateOptionsLoader {
  const now = options.now ?? NOW;
  return new CertificateOptionsLoader({
    ...(options.passwords === undefined ? {} : { passwords: options.passwords }),
    fileTrust: options.fileTrust ?? FILE_TRUST,
    now: () => now,
    validator: new CertificateOptionsValidator(options.platform ?? (process.platform === 'win32' ? 'windows' : process.platform === 'darwin' ? 'macos' : 'linux')),
    ...(options.store === undefined ? {} : { storeReader: options.store.read }),
  });
}

export function pfxOptions(path: string, passwordSecretName: string | null = 'tls-password', extra: { allowUnprotected?: boolean; requirePrivateKey?: boolean } = {}): CertificateOptions {
  return {
    file: { path, ...(passwordSecretName === null ? {} : { passwordSecretName }), ...(extra.allowUnprotected ? { allowUnprotectedPrivateKey: true } : {}) },
    ...(extra.requirePrivateKey === false ? { requirePrivateKey: false } : {}),
  };
}

export function pemOptions(path: string, keyPath: string | undefined, passwordSecretName: string | null = 'tls-password',
  extra: { allowUnprotected?: boolean; requirePrivateKey?: boolean } = {}): CertificateOptions {
  return {
    file: {
      path, format: 'Pem', ...(keyPath === undefined ? {} : { keyPath }), ...(passwordSecretName === null ? {} : { passwordSecretName }),
      ...(extra.allowUnprotected ? { allowUnprotectedPrivateKey: true } : {}),
    },
    ...(extra.requirePrivateKey === false ? { requirePrivateKey: false } : {}),
  };
}

/**
 * A TLS handshake between a local server - a new one `configure` sets up, or `configure` itself, kept
 * listening for the next - and a client, and a message from server to
 * client through it; resolves to the DER of the certificate the client was shown (and the one the
 * server was, for client authentication).
 */
export async function handshake(configure: ((server: Server) => void) | Server, client: SecureContext,
  options: { clientCertificate?: boolean; servername?: string; sni?: SecureContext; checkHostname?: boolean } = {}):
Promise<{ serverCertificate: Buffer; clientCertificate: Buffer | undefined }> {
  let clientCertificate: Buffer | undefined;
  const sni = options.sni;
  const reused = typeof configure !== 'function';
  const tlsServer = reused ? configure : createServer({
    requestCert: options.clientCertificate === true, rejectUnauthorized: options.clientCertificate === true,
    ...(sni === undefined ? {} : { SNICallback: (_name: string, callback: (error: Error | null, context?: SecureContext) => void) => callback(null, sni) }),
  }, (socket) => {
    const peer = socket.getPeerX509Certificate();
    clientCertificate = peer?.raw;
    socket.end('hello');
  });
  if (reused) {
    tlsServer.removeAllListeners('secureConnection');
    tlsServer.on('secureConnection', (socket) => {
      clientCertificate = socket.getPeerX509Certificate()?.raw;
      socket.end('hello');
    });
  } else {
    configure(tlsServer);
  }
  const serverErrors: Error[] = [];
  tlsServer.removeAllListeners('tlsClientError');
  tlsServer.on('tlsClientError', (error) => serverErrors.push(error));
  if (!tlsServer.listening) {
    tlsServer.listen(0, '127.0.0.1');
    await once(tlsServer, 'listening');
  }
  try {
    const address = tlsServer.address();
    if (address === null || typeof address === 'string') throw new Error('no address');
    const socket = connect({
      host: '127.0.0.1', port: address.port, secureContext: client, servername: options.servername ?? 'api.example.com',
      ...(options.checkHostname === false ? { checkServerIdentity: () => undefined } : {}),
    });
    try {
      await once(socket, 'secureConnect');
      const peer = socket.getPeerX509Certificate();
      if (peer === undefined) throw new Error('no peer certificate');
      let received = '';
      socket.setEncoding('utf8');
      socket.on('data', (chunk: string) => {
        received += chunk;
      });
      await once(socket, 'end');
      if (received !== 'hello') throw new Error(`the server said '${received}'`);
      return { serverCertificate: peer.raw, clientCertificate };
    } catch (error) {
      if (serverErrors.length > 0) throw new Error(`${(error as Error).message}; the server: ${serverErrors.map((e) => e.message).join('; ')}`);
      throw error;
    } finally {
      socket.destroy();
    }
  } finally {
    if (!reused) await new Promise((resolve) => tlsServer.close(resolve));
  }
}

/** Loads `options` with the fixtures' password source. */
export function loadWithPassword(options: CertificateOptions, passwords = new FakePasswords()) {
  return loader({ passwords }).load(options);
}

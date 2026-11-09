// The one PKCS#12 (RFC 7292) and encrypted PKCS#8 reader HkdfGuard's packages share - the
// certificate package's file loader and the Vault client's trust and key stores - as the Go and
// Python ports read them: password-integrity MACs with HMAC-SHA-1/224/256/384/512; unencrypted and
// password-encrypted contents; key bags, shrouded key bags, certificate bags and nested safe
// contents; BER as well as DER. Encryption is PBES2 (PBKDF2 with HMAC-SHA-1/2, AES-CBC or 3DES-CBC)
// or PKCS#12's own 3DES; legacy RC2 and RC4, public-key (enveloped or signed) contents and the
// PBMAC1 MAC are refused, saying how to re-export the file.
//
// Written here rather than left to Node's tls `pfx` option, which takes the password only as a
// string, reads the first key it finds, and can't read a trust store of certificates alone. The
// password is always a Uint8Array, never a string. Every private key comes out as its PKCS#8
// PrivateKeyInfo in a Buffer the caller wipes; every buffer that held the password, a derived key or
// plaintext on the way is wiped here. What is beyond reach: the copies node:crypto makes inside
// OpenSSL (the PBKDF2 password, the cipher key schedule, the hash and HMAC state), which OpenSSL
// cleanses as it frees them.
//
// With `requireIntegrity`, a file must carry its MAC and every key it gives must be encrypted. RFC
// 7292 makes the MAC optional, but it is the only thing that ties a file to its password: without
// one, a file of anyone's plaintext key and certificate - or a trust store of anyone's CA - reads
// under any password at all. OpenSSL, keytool and Windows always write one unless told not to.
//
// Every failure is a Pkcs12Error whose `kind` the package maps to its own error, and whose message
// is a predicate for it to put a subject before: "The client key store 'x.p12' " + message. Exported
// from the internal index as `pkcs12`, never from the package index.
import { createDecipheriv, createHash, createHmac, pbkdf2Sync, timingSafeEqual } from 'node:crypto';
import { wipe } from '../rules.js';
import * as der from './der.js';
import { DerError, type Element } from './der.js';

/**
 * The most iterations one key derivation may ask for, and a whole file all of its derivations: a file
 * can't make reading it take minutes, which it would on the calling thread. Generous beside what tools
 * write (OpenSSL 2048, keytool 10000, Windows 2000-10000, .NET's PBES2 default 100000 and its loader's
 * 600000 cap). As the Go and Python ports.
 */
export const MAX_ITERATIONS = 1_000_000;
export const MAX_TOTAL_ITERATIONS = 4_000_000;

/** Why a file was refused, for the package to choose its own error by. */
export type Pkcs12ErrorKind =
  /** Not PKCS#12 (or PKCS#8) this can follow; an iteration count out of range. */
  | 'malformed'
  /** The password doesn't open it: its MAC fails, or its contents don't decrypt (or the password isn't UTF-8). */
  | 'wrongPassword'
  /** Legacy RC2 or RC4, PBMAC1, public-key contents, or an algorithm this doesn't know. */
  | 'unsupported'
  /** With requireIntegrity: there is no MAC. */
  | 'noMac'
  /** With requireIntegrity: a key the caller reads isn't encrypted. */
  | 'unencryptedKey';

/** A file refused. `message` is a predicate: put the file's description before it. */
export class Pkcs12Error extends Error {
  constructor(readonly kind: Pkcs12ErrorKind, message: string) {
    super(message);
    this.name = 'Pkcs12Error';
  }
}

/** One certificate or private key: its DER (a key's PKCS#8 PrivateKeyInfo, which {@link Pkcs12Contents.wipe} zeroes) and its bag's attributes. */
export interface Pkcs12Entry {
  readonly der: Buffer;
  readonly friendlyName: string | undefined;
  readonly localKeyId: Buffer | undefined;
}

/** What a PKCS#12 file holds, each in file order. */
export class Pkcs12Contents {
  readonly certificates: Pkcs12Entry[] = [];
  readonly keys: Pkcs12Entry[] = [];

  /** Zeroes every key. */
  wipe(): void {
    for (const key of this.keys) wipe(key.der);
    this.keys.length = 0;
  }
}

/** How {@link readPkcs12} reads a file. */
export interface Pkcs12ReadOptions {
  /**
   * Requires the integrity MAC, and refuses a key in a plaintext key bag outside encrypted contents:
   * for a file whose password is meant to protect it. Without it, a file with no MAC is read, and a
   * plaintext key given as it is.
   */
  readonly requireIntegrity: boolean;
  /** Whether keys are read at all; false for a trust store, whose keys are neither decrypted nor checked. True by default. */
  readonly readKeys?: boolean;
  /** What the messages call the file: "file" (the default) or "store". */
  readonly noun?: string;
}

const DATA = '1.2.840.113549.1.7.1';
const SIGNED_DATA = '1.2.840.113549.1.7.2';
const ENVELOPED_DATA = '1.2.840.113549.1.7.3';
const ENCRYPTED_DATA = '1.2.840.113549.1.7.6';
const KEY_BAG = '1.2.840.113549.1.12.10.1.1';
const SHROUDED_KEY_BAG = '1.2.840.113549.1.12.10.1.2';
const CERT_BAG = '1.2.840.113549.1.12.10.1.3';
const SAFE_CONTENTS_BAG = '1.2.840.113549.1.12.10.1.6';
const X509_CERTIFICATE = '1.2.840.113549.1.9.22.1';
const FRIENDLY_NAME = '1.2.840.113549.1.9.20';
const LOCAL_KEY_ID = '1.2.840.113549.1.9.21';
const BMP_STRING = 0x1e;
const MAX_SAFE_DEPTH = 4;

export const PBES2 = '1.2.840.113549.1.5.13';
export const PBKDF2 = '1.2.840.113549.1.5.12';
export const PBMAC1 = '1.2.840.113549.1.5.14';
const PBE_SHA_3DES = '1.2.840.113549.1.12.1.3';
const PBE_SHA_2DES = '1.2.840.113549.1.12.1.4';
const LEGACY: Record<string, string> = {
  '1.2.840.113549.1.12.1.1': 'RC4-128',
  '1.2.840.113549.1.12.1.2': 'RC4-40',
  '1.2.840.113549.1.12.1.5': 'RC2-128',
  '1.2.840.113549.1.12.1.6': 'RC2-40',
  '1.2.840.113549.3.2': 'RC2-CBC', // a PBES2 scheme
};
const PRFS: Record<string, string> = {
  '1.2.840.113549.2.7': 'sha1',
  '1.2.840.113549.2.8': 'sha224',
  '1.2.840.113549.2.9': 'sha256',
  '1.2.840.113549.2.10': 'sha384',
  '1.2.840.113549.2.11': 'sha512',
};
/** The digests a PKCS#12 MAC names, by OID, as node:crypto names them. */
export const DIGESTS: Record<string, string> = {
  '1.3.14.3.2.26': 'sha1',
  '2.16.840.1.101.3.4.2.4': 'sha224',
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
};
const CIPHERS: Record<string, { cipher: string; keyLength: number; blockLength: number }> = {
  '2.16.840.1.101.3.4.1.2': { cipher: 'aes-128-cbc', keyLength: 16, blockLength: 16 },
  '2.16.840.1.101.3.4.1.22': { cipher: 'aes-192-cbc', keyLength: 24, blockLength: 16 },
  '2.16.840.1.101.3.4.1.42': { cipher: 'aes-256-cbc', keyLength: 32, blockLength: 16 },
  '1.2.840.113549.3.7': { cipher: 'des-ede3-cbc', keyLength: 24, blockLength: 8 },
};

export const PKCS12_KEY_ID = 1;
export const PKCS12_IV_ID = 2;
export const PKCS12_MAC_ID = 3;

/** The key-derivation iterations one file has spent, against {@link MAX_ITERATIONS} and {@link MAX_TOTAL_ITERATIONS}. */
export class IterationBudget {
  spent = 0;

  /** @throws Pkcs12Error ('malformed') one count, or the file's total, is out of range */
  spend(iterations: number): void {
    if (!Number.isSafeInteger(iterations) || iterations < 1 || iterations > MAX_ITERATIONS || this.spent + iterations > MAX_TOTAL_ITERATIONS) {
      throw new Pkcs12Error('malformed', `asks for an iteration count out of range: at most ${MAX_ITERATIONS} a derivation and ${MAX_TOTAL_ITERATIONS} a file are read.`);
    }
    this.spent += iterations;
  }
}

/**
 * Reads a PKCS#12 file with a UTF-8 password - undefined (or empty) for a file without one, which is
 * tried as both the empty password and no password, as tools write either.
 * @throws Pkcs12Error what is wrong, by its kind
 */
export function readPkcs12(data: Uint8Array, password: Uint8Array | undefined, options: Pkcs12ReadOptions): Pkcs12Contents {
  const noun = options.noun ?? 'file';
  const readKeys = options.readKeys !== false;
  let authSafe: Buffer;
  let macData: Element | undefined;
  try {
    const pfx = der.sequence(der.read(data), 'A PKCS#12 file', 2, 3);
    const version = der.integer(pfx[0], 'The PKCS#12 version');
    if (version !== 3) throw new Pkcs12Error('unsupported', `is PKCS#12 version ${version}; only version 3 is read.`);
    const { type, content } = contentInfo(pfx[1]);
    if (type === SIGNED_DATA) {
      throw new Pkcs12Error('unsupported', `is protected by a public key, not a password; only a password-protected PKCS#12 ${noun} is read.`);
    }
    if (type !== DATA || content === undefined) throw new DerError('The authenticated safe is neither data nor signed data.');
    authSafe = der.octets(content, 'The PKCS#12 contents');
    macData = pfx[2];
  } catch (error) {
    throw malformed(error, noun);
  }

  try {
    if (options.requireIntegrity && macData === undefined) {
      throw new Pkcs12Error('noMac', `has no integrity MAC, so nothing shows it is the ${noun} its password was set on: export it with one `
        + '(OpenSSL, keytool and Windows write one unless told not to, as by -nomac).');
    }
    const budget = new IterationBudget();
    // The passwords to try: the one given; for none, the empty BMPString (00 00) and no bytes at all.
    let candidates: (Uint8Array | undefined)[] = password !== undefined && password.length > 0 ? [password] : [undefined, new Uint8Array(0)];
    if (macData !== undefined) candidates = [verifyMac(macData, authSafe, candidates, budget, noun)];
    let failure: Pkcs12Error | undefined;
    for (const candidate of candidates) {
      try {
        return readAuthenticatedSafe(authSafe, candidate, budget, { refusePlaintextKeys: options.requireIntegrity, readKeys, noun });
      } catch (error) {
        if (!(error instanceof Pkcs12Error) || error.kind !== 'wrongPassword') throw error;
        failure = error;
      }
    }
    throw failure!;
  } finally {
    wipe(authSafe);
  }
}

/**
 * Decrypts an EncryptedPrivateKeyInfo (a PKCS#8 key, encrypted) with a UTF-8 password: its
 * PrivateKeyInfo, in a new buffer the caller wipes.
 * @throws Pkcs12Error what is wrong, by its kind; 'wrongPassword' when the password doesn't decrypt it to a key
 */
export function decryptPrivateKeyInfo(encrypted: Uint8Array, password: Uint8Array | undefined, budget = new IterationBudget(), noun = 'key'): Buffer {
  let items: Element[];
  let ciphertext: Buffer;
  try {
    items = der.sequence(der.read(encrypted), 'An encrypted private key', 2, 2);
    ciphertext = der.octets(items[1], 'The encrypted key');
  } catch (error) {
    throw malformed(error, noun);
  }
  try {
    const plaintext = decrypt(items[0], password, ciphertext, budget, noun);
    try {
      const key = der.sequence(der.read(plaintext), 'A private key', 3);
      der.integer(key[0], "A private key's version");
    } catch (error) {
      wipe(plaintext);
      // A key that decrypted to nonsense was decrypted with the wrong password.
      if (error instanceof DerError) throw new Pkcs12Error('wrongPassword', "can't be opened: its password doesn't decrypt the key to one.");
      throw error;
    }
    return plaintext;
  } finally {
    wipe(ciphertext);
  }
}

/**
 * A UTF-8 password as PKCS#12's key derivation takes it: a BMPString - big-endian UTF-16 - with a
 * two-byte terminator, decoded byte by byte, never through a string. undefined is the empty password,
 * the terminator alone; an empty array is no password at all, no bytes - the two ways tools write a
 * file without one. A new buffer the caller wipes.
 * @throws Pkcs12Error ('wrongPassword') the password isn't UTF-8
 */
export function bmpPassword(password: Uint8Array | undefined): Buffer {
  if (password !== undefined && password.length === 0) return Buffer.alloc(0);
  const source = password ?? new Uint8Array(0);
  const out = Buffer.alloc(source.length * 2 + 2); // every UTF-8 sequence is at least half its UTF-16BE length
  let written = 0;
  const notUtf8 = () => {
    wipe(out);
    return new Pkcs12Error('wrongPassword', "can't be opened: its password isn't UTF-8.");
  };
  for (let i = 0; i < source.length;) {
    const lead = source[i]!;
    const extra = lead < 0x80 ? 0 : lead >= 0xc2 && lead <= 0xdf ? 1 : lead >= 0xe0 && lead <= 0xef ? 2 : lead >= 0xf0 && lead <= 0xf4 ? 3 : -1;
    if (extra < 0 || i + extra >= source.length) throw notUtf8();
    let code = extra === 0 ? lead : lead & (0x3f >> extra);
    for (let k = 1; k <= extra; k++) {
      const octet = source[i + k]!;
      if ((octet & 0xc0) !== 0x80) throw notUtf8();
      code = (code << 6) | (octet & 0x3f);
    }
    if ((extra === 2 && (code < 0x800 || (code >= 0xd800 && code <= 0xdfff))) || (extra === 3 && (code < 0x10000 || code > 0x10ffff))) {
      throw notUtf8();
    }
    if (code > 0xffff) {
      const high = 0xd800 | ((code - 0x10000) >> 10);
      const low = 0xdc00 | ((code - 0x10000) & 0x3ff);
      out[written++] = high >> 8;
      out[written++] = high & 0xff;
      out[written++] = low >> 8;
      out[written++] = low & 0xff;
    } else {
      out[written++] = code >> 8;
      out[written++] = code & 0xff;
    }
    i += extra + 1;
  }
  written += 2; // the terminator: already zero
  const result = Buffer.alloc(written);
  out.copy(result, 0, 0, written);
  wipe(out);
  return result;
}

/**
 * RFC 7292 B.2: `length` bytes for `purpose` (1 key, 2 IV, 3 MAC key) from a BMPString password and a
 * salt, in a new buffer the caller wipes. Every intermediate digest is a Buffer wiped once used.
 */
export function pkcs12Kdf(hash: string, password: Uint8Array, salt: Uint8Array, iterations: number, purpose: number, length: number): Buffer {
  const u = createHash(hash).digest().length;
  const v = hash === 'sha384' || hash === 'sha512' ? 128 : 64;
  const fill = (data: Uint8Array) => {
    const out = Buffer.alloc(data.length === 0 ? 0 : v * Math.ceil(data.length / v));
    for (let i = 0; i < out.length; i++) out[i] = data[i % data.length]!;
    return out;
  };
  const d = Buffer.alloc(v, purpose);
  const s = fill(salt);
  const p = fill(password);
  const input = Buffer.alloc(s.length + p.length);
  s.copy(input, 0);
  p.copy(input, s.length);
  wipe(p);
  const out = Buffer.alloc(length);
  const b = Buffer.alloc(v);
  try {
    for (let position = 0; ;) {
      let a = createHash(hash).update(d).update(input).digest();
      for (let i = 1; i < iterations; i++) {
        const next = createHash(hash).update(a).digest();
        wipe(a);
        a = next;
      }
      a.copy(out, position, 0, Math.min(u, length - position));
      position += u;
      if (position >= length) {
        wipe(a);
        return out;
      }
      for (let i = 0; i < v; i++) b[i] = a[i % u]!;
      wipe(a);
      // Each v-byte block of the input becomes (block + B + 1) mod 2^(8v).
      for (let j = 0; j < input.length; j += v) {
        let carry = 1;
        for (let k = v - 1; k >= 0; k--) {
          const sum = input[j + k]! + b[k]! + carry;
          input[j + k] = sum & 0xff;
          carry = sum >> 8;
        }
      }
    }
  } catch (error) {
    wipe(out);
    throw error;
  } finally {
    wipe(input);
    wipe(b);
  }
}

// --- Reading a file ------------------------------------------------------------------------------

// A DerError as the file being malformed; anything else as it is.
function malformed(error: unknown, noun: string): unknown {
  return error instanceof DerError ? new Pkcs12Error('malformed', `isn't a PKCS#12 ${noun} this can read: ${error.message}`) : error;
}

function contentInfo(element: Element | undefined): { type: string; content: Element | undefined } {
  const items = der.sequence(element, 'A ContentInfo', 1, 2);
  return { type: der.oid(items[0]), content: items[1] === undefined ? undefined : der.only(items[1], der.CONTEXT_0, "A ContentInfo's content") };
}

// The candidate password the file's integrity MAC verifies under.
function verifyMac(macData: Element, authSafe: Buffer, candidates: (Uint8Array | undefined)[], budget: IterationBudget, noun: string): Uint8Array | undefined {
  let algorithm: string;
  let expected: Buffer;
  let salt: Buffer;
  let iterations: number;
  try {
    const items = der.sequence(macData, 'The PKCS#12 MAC', 2, 3);
    const digestInfo = der.sequence(items[0], "The MAC's digest", 2, 2);
    algorithm = der.algorithm(digestInfo[0], 'The MAC algorithm').oid;
    expected = der.octets(digestInfo[1], 'The MAC');
    salt = der.octets(items[1], 'The MAC salt');
    iterations = items[2] === undefined ? 1 : der.integer(items[2], 'The MAC iteration count');
  } catch (error) {
    throw malformed(error, noun);
  }
  if (algorithm === PBMAC1) {
    throw new Pkcs12Error('unsupported', "is protected by a PBMAC1 integrity check (OpenSSL 3.4's -pbmac1_pbkdf2), which isn't supported: export it with the default HMAC.");
  }
  const hash = DIGESTS[algorithm];
  if (hash === undefined) throw new Pkcs12Error('unsupported', `has a MAC of digest ${algorithm}, which isn't supported.`);
  const size = createHash(hash).digest().length;
  for (const candidate of candidates) {
    budget.spend(iterations);
    const bmp = bmpPassword(candidate);
    let key: Buffer | undefined;
    let actual: Buffer | undefined;
    try {
      key = pkcs12Kdf(hash, bmp, salt, iterations, PKCS12_MAC_ID, size);
      actual = createHmac(hash, key).update(authSafe).digest();
      if (actual.length === expected.length && timingSafeEqual(actual, expected)) return candidate;
    } finally {
      wipe(bmp);
      wipe(key);
      wipe(actual);
    }
  }
  throw new Pkcs12Error('wrongPassword', `can't be opened: its password is wrong, or the ${noun} was altered.`);
}

interface SafeOptions {
  readonly refusePlaintextKeys: boolean;
  readonly readKeys: boolean;
  readonly noun: string;
}

function readAuthenticatedSafe(authSafe: Buffer, password: Uint8Array | undefined, budget: IterationBudget, options: SafeOptions): Pkcs12Contents {
  const contents = new Pkcs12Contents();
  try {
    let infos: Element[];
    try {
      infos = der.sequence(der.read(authSafe), 'The PKCS#12 authenticated safe');
    } catch (error) {
      throw malformed(error, options.noun);
    }
    for (const info of infos) {
      let type: string;
      let content: Element;
      try {
        const read = contentInfo(info);
        if (read.content === undefined) throw new DerError('A safe has no content.');
        type = read.type;
        content = read.content;
      } catch (error) {
        throw malformed(error, options.noun);
      }
      if (type === DATA) {
        let safe: Buffer | undefined;
        try {
          safe = der.octets(content, 'PKCS#12 data');
          readSafeContents(contents, safe, password, budget, 0, options.refusePlaintextKeys, options);
        } catch (error) {
          throw malformed(error, options.noun);
        } finally {
          wipe(safe);
        }
      } else if (type === ENCRYPTED_DATA) {
        const { algorithm, ciphertext } = encryptedData(content, options.noun);
        if (ciphertext === undefined) continue; // nothing was encrypted
        const plaintext = decrypt(algorithm, password, ciphertext, budget, options.noun);
        try {
          // Encrypted contents: a key bag inside them is encrypted with them.
          readSafeContents(contents, plaintext, password, budget, 0, false, options);
        } catch (error) {
          // Contents that decrypted to nonsense were decrypted with the wrong password. (An iteration
          // count out of range inside them is still that, not a password problem.)
          if (error instanceof DerError) {
            throw new Pkcs12Error('wrongPassword', `can't be opened: its password doesn't decrypt its contents (${error.message}).`);
          }
          throw error;
        } finally {
          wipe(plaintext);
          wipe(ciphertext);
        }
      } else if (type === ENVELOPED_DATA) {
        throw new Pkcs12Error('unsupported', `holds contents encrypted to a public key (enveloped data); only a password-protected PKCS#12 ${options.noun} is read.`);
      } else {
        throw new Pkcs12Error('unsupported', `holds contents of type ${type}, which aren't supported.`);
      }
    }
    return contents;
  } catch (error) {
    contents.wipe();
    throw error;
  }
}

function encryptedData(content: Element, noun: string): { algorithm: Element; ciphertext: Buffer | undefined } {
  try {
    const items = der.sequence(content, 'PKCS#12 encrypted data', 2, 3);
    const info = der.sequence(items[1], 'The encrypted content info', 2, 3);
    // [0] IMPLICIT OCTET STRING, primitive (0x80) or - BER - constructed (0xA0); absent when nothing was encrypted.
    return { algorithm: info[1]!, ciphertext: info[2] === undefined ? undefined : der.octets(info[2], 'The encrypted content', 0x80) };
  } catch (error) {
    throw malformed(error, noun);
  }
}

function readSafeContents(contents: Pkcs12Contents, safe: Buffer, password: Uint8Array | undefined, budget: IterationBudget, depth: number,
  refusePlaintextKeys: boolean, options: SafeOptions): void {
  if (depth > MAX_SAFE_DEPTH) throw new DerError('The PKCS#12 safe contents are nested too deep.');
  for (const bag of der.sequence(der.read(safe), 'PKCS#12 safe contents')) {
    const items = der.sequence(bag, 'A PKCS#12 bag', 2, 3);
    const type = der.oid(items[0]);
    const value = der.only(items[1], der.CONTEXT_0, "A bag's value");
    if (type === CERT_BAG) {
      const certificate = certificateOf(value);
      if (certificate !== undefined) contents.certificates.push({ der: certificate, ...attributesOf(items[2]) });
    } else if (type === KEY_BAG) {
      if (!options.readKeys) continue;
      if (refusePlaintextKeys) {
        throw new Pkcs12Error('unencryptedKey', "holds a private key that isn't encrypted: export it with the key encrypted (not -keypbe NONE).");
      }
      const key = Buffer.alloc(value.encoding.length);
      value.encoding.copy(key);
      contents.keys.push({ der: key, ...attributesOf(items[2]) });
    } else if (type === SHROUDED_KEY_BAG) {
      if (!options.readKeys) continue;
      contents.keys.push({ der: decryptPrivateKeyInfo(value.encoding, password, budget, options.noun), ...attributesOf(items[2]) });
    } else if (type === SAFE_CONTENTS_BAG) {
      readSafeContents(contents, value.encoding, password, budget, depth + 1, refusePlaintextKeys, options);
    }
    // CRL and secret bags hold nothing a certificate or TLS needs.
  }
}

// An X.509 certificate's DER, in a new buffer; undefined for another kind (an SDSI certificate).
function certificateOf(value: Element): Buffer | undefined {
  const items = der.sequence(value, 'A certificate bag', 2, 2);
  if (der.oid(items[0]) !== X509_CERTIFICATE) return undefined;
  return der.octets(der.only(items[1], der.CONTEXT_0, "A certificate bag's value"), 'A certificate');
}

// The friendly name (an alias) and local key ID among a bag's attributes; anything else is ignored.
function attributesOf(attributes: Element | undefined): { friendlyName: string | undefined; localKeyId: Buffer | undefined } {
  let friendlyName: string | undefined;
  let localKeyId: Buffer | undefined;
  if (attributes?.tag === der.SET) {
    for (const attribute of der.children(attributes)) {
      const [type, values] = attribute.tag === der.SEQUENCE ? der.children(attribute) : [];
      if (type?.tag !== der.OBJECT_IDENTIFIER || values?.tag !== der.SET) continue;
      const value = der.children(values)[0];
      const kind = der.oid(type);
      if (kind === FRIENDLY_NAME && value?.tag === BMP_STRING && !value.constructed) friendlyName = utf16be(value.contents);
      else if (kind === LOCAL_KEY_ID && value?.tag === der.OCTET_STRING && !value.constructed) localKeyId = Buffer.from(value.contents);
    }
  }
  return { friendlyName, localKeyId };
}

function utf16be(bytes: Buffer): string {
  let text = '';
  for (let i = 0; i + 1 < bytes.length; i += 2) text += String.fromCharCode((bytes[i]! << 8) | bytes[i + 1]!);
  return text;
}

// --- Password-based decryption -------------------------------------------------------------------

/**
 * Decrypts `ciphertext` under a password-based encryption algorithm: PBES2 (PBKDF2 with
 * HMAC-SHA-1/224/256/384/512, and AES-128/192/256-CBC or 3DES-CBC), or PKCS#12's
 * pbeWithSHAAnd3-KeyTripleDES-CBC or 2-KeyTripleDES. `password` is UTF-8: PBES2 uses it as it is, as
 * OpenSSL and .NET do, and PKCS#12's own PBE as a BMPString. The plaintext is a new buffer the caller
 * wipes. A wrong password shows as bad padding: 'wrongPassword'.
 */
function decrypt(algorithm: Element | undefined, password: Uint8Array | undefined, ciphertext: Buffer, budget: IterationBudget, noun: string): Buffer {
  let key: Buffer | undefined;
  let iv: Buffer | undefined;
  try {
    const { oid, parameters } = der.algorithm(algorithm, 'An encryption algorithm');
    let cipher: { cipher: string; blockLength: number };
    if (oid === PBES2) {
      ({ key, iv, cipher } = pbes2Key(parameters, password, budget));
    } else if (oid === PBE_SHA_3DES || oid === PBE_SHA_2DES) {
      const items = der.sequence(parameters, 'PKCS#12 PBE parameters', 2, 2);
      const salt = der.octets(items[0], 'A salt');
      const iterations = der.integer(items[1], 'An iteration count');
      // The key and the IV are each a derivation of their own.
      budget.spend(iterations);
      budget.spend(iterations);
      const bmp = bmpPassword(password);
      try {
        const threeKey = oid === PBE_SHA_3DES;
        key = pkcs12Kdf('sha1', bmp, salt, iterations, PKCS12_KEY_ID, threeKey ? 24 : 16);
        iv = pkcs12Kdf('sha1', bmp, salt, iterations, PKCS12_IV_ID, 8);
        cipher = { cipher: threeKey ? 'des-ede3-cbc' : 'des-ede-cbc', blockLength: 8 };
      } finally {
        wipe(bmp);
      }
    } else if (LEGACY[oid] !== undefined) {
      throw legacy(LEGACY[oid], oid);
    } else {
      throw new Pkcs12Error('unsupported', `is encrypted with algorithm ${oid}, which isn't supported.`);
    }
    return cbcDecrypt(cipher.cipher, cipher.blockLength, key, iv, ciphertext, noun);
  } catch (error) {
    if (error instanceof DerError) throw new Pkcs12Error('malformed', `has malformed encryption parameters: ${error.message}`);
    throw error;
  } finally {
    wipe(key);
    wipe(iv);
  }
}

// The refusal of a legacy RC2 or RC4 encryption, saying how to re-export the file.
function legacy(name: string, oid: string): Pkcs12Error {
  return new Pkcs12Error('unsupported',
    `is encrypted with legacy ${name} (${oid}), which OpenSSL 3 - and so Node - provides only through its legacy provider: `
    + "re-export it with AES (AES-256-CBC): 'openssl pkcs12 -export' from OpenSSL 3 without -legacy, keytool from Java 11.0.12 or later, "
    + "or .NET's ExportPkcs12 with Pkcs12ExportPbeParameters.Pbes2Aes256Sha256.");
}

function pbes2Key(parameters: Element | undefined, password: Uint8Array | undefined, budget: IterationBudget):
{ key: Buffer; iv: Buffer; cipher: { cipher: string; blockLength: number } } {
  const [kdf, scheme] = der.sequence(parameters, 'PBES2 parameters', 2, 2);
  const derivation = der.algorithm(kdf, 'A key derivation');
  if (derivation.oid !== PBKDF2) throw new Pkcs12Error('unsupported', `is encrypted with PBES2 key derivation ${derivation.oid}, which isn't supported.`);
  const items = der.sequence(derivation.parameters, 'PBKDF2 parameters', 2, 4);
  const salt = der.octets(items[0], 'A PBKDF2 salt');
  const iterations = der.integer(items[1], 'A PBKDF2 iteration count');
  let rest = items.slice(2);
  let keyLength: number | undefined;
  if (rest[0]?.tag === der.INTEGER) {
    keyLength = der.integer(rest[0], 'A PBKDF2 key length');
    rest = rest.slice(1);
  }
  let prf = 'sha1';
  if (rest[0] !== undefined) {
    const named = der.algorithm(rest[0], 'A PBKDF2 PRF').oid;
    const chosen = PRFS[named];
    if (chosen === undefined) throw new Pkcs12Error('unsupported', `is encrypted with PBKDF2 PRF ${named}, which isn't supported.`);
    prf = chosen;
  }
  budget.spend(iterations);
  const encryption = der.algorithm(scheme, 'A PBES2 cipher');
  if (LEGACY[encryption.oid] !== undefined) throw legacy(LEGACY[encryption.oid]!, encryption.oid);
  const cipher = CIPHERS[encryption.oid];
  if (cipher === undefined) throw new Pkcs12Error('unsupported', `is encrypted with PBES2 cipher ${encryption.oid}, which isn't supported: AES-CBC or 3DES-CBC are.`);
  if (keyLength !== undefined && keyLength !== cipher.keyLength) throw new DerError("PBKDF2's key length doesn't fit its cipher.");
  const iv = der.octets(encryption.parameters, 'An IV');
  if (iv.length !== cipher.blockLength) throw new DerError("The cipher's IV isn't one block.");
  const key = pbkdf2Sync(password ?? new Uint8Array(0), salt, iterations, cipher.keyLength, prf);
  return { key, iv, cipher };
}

function cbcDecrypt(cipher: string, blockLength: number, key: Buffer, iv: Buffer, ciphertext: Buffer, noun: string): Buffer {
  if (ciphertext.length === 0 || ciphertext.length % blockLength !== 0) throw new DerError("The encrypted data isn't whole cipher blocks.");
  let first: Buffer | undefined;
  let last: Buffer | undefined;
  try {
    const decipher = createDecipheriv(cipher, key, iv);
    first = decipher.update(ciphertext);
    try {
      last = decipher.final(); // checks the PKCS#7 padding
    } catch {
      throw new Pkcs12Error('wrongPassword', `can't be opened: its password is wrong, or the ${noun} was altered.`);
    }
    const plaintext = Buffer.alloc(first.length + last.length);
    first.copy(plaintext, 0);
    last.copy(plaintext, first.length);
    return plaintext;
  } finally {
    wipe(first);
    wipe(last);
  }
}

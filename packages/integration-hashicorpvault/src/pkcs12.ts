// A reader of password-protected PKCS#12 key stores (RFC 7292), written against node:crypto alone:
// Node's TLS reads a PKCS#12 only as a whole client identity - the first key it finds, with a string
// passphrase - so it can neither pick a key by alias nor read a trust store of certificates only.
// Reads what OpenSSL 3 and Java's keytool write - PBES2 (PBKDF2, AES-CBC) or PKCS#12's own
// triple-DES PBE, under an HMAC - and refuses RC2 and RC4, which OpenSSL 3 left to its legacy
// provider. The HMAC is required, though RFC 7292 makes it optional: it is the only thing that ties
// a store to its password, and without it a trust store of anyone's CA in plain contents reads under
// any password. A private key must be encrypted, as the password was set to protect it. Never
// exported from the package index.
import { createDecipheriv, createHash, createHmac, pbkdf2Sync, timingSafeEqual } from 'node:crypto';
import { InvalidArgumentError, wipe } from '@runsecure/hkdfguard-abstractions';

/** The largest key store read, in bytes: a store of a key and its chain is a few KB. */
export const MAX_KEY_STORE_LENGTH = 1024 * 1024;

// More iterations than this would hang the caller; OpenSSL defaults to 2048, Java to 10000.
const MAX_ITERATIONS = 10_000_000;
const MAX_DEPTH = 32;

// Object identifiers, as their DER content in hex.
const OID = {
  data: '2a864886f70d010701', // 1.2.840.113549.1.7.1
  signedData: '2a864886f70d010702', // 1.2.840.113549.1.7.2
  envelopedData: '2a864886f70d010703', // 1.2.840.113549.1.7.3
  encryptedData: '2a864886f70d010706', // 1.2.840.113549.1.7.6
  keyBag: '2a864886f70d010c0a0101', // 1.2.840.113549.1.12.10.1.1
  shroudedKeyBag: '2a864886f70d010c0a0102', // 1.2.840.113549.1.12.10.1.2
  certBag: '2a864886f70d010c0a0103', // 1.2.840.113549.1.12.10.1.3
  safeContentsBag: '2a864886f70d010c0a0106', // 1.2.840.113549.1.12.10.1.6
  x509Certificate: '2a864886f70d01091601', // 1.2.840.113549.1.9.22.1
  friendlyName: '2a864886f70d010914', // 1.2.840.113549.1.9.20
  localKeyId: '2a864886f70d010915', // 1.2.840.113549.1.9.21
  pbes2: '2a864886f70d01050d', // 1.2.840.113549.1.5.13
  pbkdf2: '2a864886f70d01050c', // 1.2.840.113549.1.5.12
  pbmac1: '2a864886f70d01050e', // 1.2.840.113549.1.5.14
} as const;

// PKCS#12's own password-based encryption (RFC 7292 appendix C): the key and IV derived with SHA-1.
const PKCS12_PBE: Record<string, { cipher: string; keyLength: number } | string> = {
  '2a864886f70d010c0103': { cipher: 'des-ede3-cbc', keyLength: 24 }, // pbeWithSHAAnd3-KeyTripleDES-CBC
  '2a864886f70d010c0104': { cipher: 'des-ede-cbc', keyLength: 16 }, // pbeWithSHAAnd2-KeyTripleDES-CBC
  '2a864886f70d010c0101': 'RC4', // pbeWithSHAAnd128BitRC4
  '2a864886f70d010c0102': 'RC4', // pbeWithSHAAnd40BitRC4
  '2a864886f70d010c0105': 'RC2', // pbeWithSHAAnd128BitRC2-CBC
  '2a864886f70d010c0106': 'RC2', // pbewithSHAAnd40BitRC2-CBC
};

// PBES2's ciphers, and their key lengths.
const PBES2_CIPHERS: Record<string, { cipher: string; keyLength: number }> = {
  '608648016503040102': { cipher: 'aes-128-cbc', keyLength: 16 }, // 2.16.840.1.101.3.4.1.2
  '608648016503040116': { cipher: 'aes-192-cbc', keyLength: 24 }, // 2.16.840.1.101.3.4.1.22
  '60864801650304012a': { cipher: 'aes-256-cbc', keyLength: 32 }, // 2.16.840.1.101.3.4.1.42
  '2a864886f70d0307': { cipher: 'des-ede3-cbc', keyLength: 24 }, // 1.2.840.113549.3.7
};

// PBKDF2's pseudo-random functions.
const PRFS: Record<string, string> = {
  '2a864886f70d0207': 'sha1', // hmacWithSHA1, the default
  '2a864886f70d0208': 'sha224',
  '2a864886f70d0209': 'sha256',
  '2a864886f70d020a': 'sha384',
  '2a864886f70d020b': 'sha512',
};

// The MAC's digests.
const DIGESTS: Record<string, string> = {
  '2b0e03021a': 'sha1', // 1.3.14.3.2.26
  '608648016503040204': 'sha224',
  '608648016503040201': 'sha256',
  '608648016503040202': 'sha384',
  '608648016503040203': 'sha512',
};

/** A private key in a key store: its PKCS#8 DER, which the caller zeroes, and its attributes. */
export interface Pkcs12Key {
  readonly friendlyName: string | undefined;
  readonly localKeyId: Buffer | undefined;
  readonly pkcs8: Buffer;
}

/** An X.509 certificate in a key store: its DER, and its attributes. */
export interface Pkcs12Certificate {
  readonly friendlyName: string | undefined;
  readonly localKeyId: Buffer | undefined;
  readonly der: Buffer;
}

/** What a key store holds. */
export interface Pkcs12Contents {
  readonly keys: Pkcs12Key[];
  readonly certificates: Pkcs12Certificate[];
}

/**
 * The keys (if `readKeys`) and certificates in the PKCS#12 store `store`, its integrity checked and
 * its contents decrypted under `password` - the password's UTF-8 bytes, which the caller zeroes.
 * Every buffer this makes from the password is zeroed before it returns.
 * @param what names the store in errors, e.g. "client key store 'client.p12'"
 * @throws InvalidArgumentError the store isn't a PKCS#12 store this can read, has no integrity MAC,
 *   holds a key (when `readKeys`) that isn't encrypted, or the password is wrong
 */
export function readPkcs12(store: Uint8Array, password: Uint8Array, readKeys: boolean, what: string): Pkcs12Contents {
  const fail = (problem: string) => new InvalidArgumentError(`The ${what} ${problem}`);
  if (store.length > MAX_KEY_STORE_LENGTH) throw fail(`is over ${MAX_KEY_STORE_LENGTH} bytes; a key store is far smaller.`);
  const bmpPassword = bmpString(password, fail);
  const contents: Pkcs12Contents = { keys: [], certificates: [] };
  try {
    const reader = new Pkcs12Reader(Buffer.from(store.buffer, store.byteOffset, store.length), password, bmpPassword, readKeys, fail);
    reader.read(contents);
    return contents;
  } catch (error) {
    for (const key of contents.keys) wipe(key.pkcs8);
    if (error instanceof InvalidArgumentError) throw error;
    if (error instanceof DerError) throw fail(`isn't a PKCS#12 store: ${error.message}`);
    throw error;
  } finally {
    wipe(bmpPassword);
  }
}

class Pkcs12Reader {
  constructor(
    private readonly store: Buffer,
    private readonly password: Uint8Array,
    private readonly bmpPassword: Buffer,
    private readonly readKeys: boolean,
    private readonly fail: (problem: string) => InvalidArgumentError,
  ) {}

  read(contents: Pkcs12Contents): void {
    const pfx = readOne(this.store, 0x30);
    const [version, authSafe, macData] = children(pfx);
    if (version?.tag !== 0x02 || integer(version) !== 3 || authSafe?.tag !== 0x30) throw new DerError('no version 3 PFX');
    const [contentType, content] = children(authSafe);
    if (contentType === undefined || content?.tag !== 0xa0) throw new DerError('no authenticated safe');
    const type = oid(contentType);
    if (type === OID.signedData) throw this.fail("is protected by a public key, not a password; only password-protected stores can be read.");
    if (type !== OID.data) throw new DerError('an authenticated safe that is neither data nor signed');
    const safe = octets(only(content));

    // Before anything in the store is read: a store without its MAC could be anyone's.
    if (macData === undefined) {
      throw this.fail('has no integrity MAC, so nothing shows it is the store its password was set on: export it with one - '
        + 'OpenSSL and keytool write one unless told not to (-nomac).');
    }
    this.#verifyMac(macData, safe);

    for (const info of children(readOne(safe, 0x30))) {
      const [infoType, infoContent] = children(info);
      if (infoType === undefined || infoContent?.tag !== 0xa0) throw new DerError('a content info without content');
      const kind = oid(infoType);
      if (kind === OID.data) {
        this.#readSafeContents(octets(only(infoContent)), contents, 0, false);
      } else if (kind === OID.encryptedData) {
        const [, encryptedContentInfo] = children(only(infoContent));
        if (encryptedContentInfo?.tag !== 0x30) throw new DerError('encrypted data without content');
        const [, algorithm, encrypted] = children(encryptedContentInfo);
        // Absent: nothing was encrypted. [0] IMPLICIT OCTET STRING, primitive or (BER) constructed.
        if (encrypted === undefined) continue;
        if (algorithm?.tag !== 0x30 || (encrypted.tag !== 0x80 && encrypted.tag !== 0xa0)) throw new DerError('malformed encrypted data');
        const plain = this.#decrypt(algorithm, octets(encrypted));
        try {
          this.#readSafeContents(plain, contents, 0, true);
        } finally {
          wipe(plain);
        }
      } else if (kind === OID.envelopedData) {
        throw this.fail('holds content encrypted to a public key; only password-protected stores can be read.');
      } else {
        throw new DerError('content of an unknown type');
      }
    }
  }

  // The MAC over the authenticated safe, keyed from the password: a wrong password fails here,
  // before anything is decrypted.
  #verifyMac(macData: Tlv, safe: Buffer): void {
    const [digestInfo, saltTlv, iterationsTlv] = children(macData);
    const [algorithm, digest] = children(digestInfo ?? fault('no MAC'));
    const [algorithmOid] = children(algorithm ?? fault('no MAC algorithm'));
    const algorithmId = oid(algorithmOid ?? fault('no MAC algorithm'));
    if (algorithmId === OID.pbmac1) {
      throw this.fail('is protected by a PBMAC1 MAC (OpenSSL 3.4+ -pbmac1_pbkdf2), which this reader does not support; '
        + 'export it with the default HMAC.');
    }
    const hash = DIGESTS[algorithmId] ?? fault('a MAC of an unknown digest');
    const iterations = iterationsTlv === undefined ? 1 : checkedIterations(integer(iterationsTlv));
    const expected = octets(digest ?? fault('no MAC digest'));
    const key = pkcs12Kdf(hash, this.bmpPassword, octets(saltTlv ?? fault('no MAC salt')), iterations, 3, createHash(hash).digest().length);
    try {
      const actual = createHmac(hash, key).update(safe).digest();
      if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
        throw this.fail("can't be opened: its password is wrong, or the store was altered.");
      }
    } finally {
      wipe(key);
    }
  }

  // `encrypted`: these safe contents came out of encrypted data, so a key bag in them was encrypted
  // with them; outside it, only a shrouded key bag is.
  #readSafeContents(der: Buffer, contents: Pkcs12Contents, depth: number, encrypted: boolean): void {
    if (depth > 4) throw new DerError('safe contents nested too deep');
    for (const bag of children(readOne(der, 0x30))) {
      const [bagId, value, attributes] = children(bag);
      if (bagId === undefined || value?.tag !== 0xa0) throw new DerError('a safe bag without a value');
      const kind = oid(bagId);
      const { friendlyName, localKeyId } = readAttributes(attributes);
      if (kind === OID.certBag) {
        const [certId, certValue] = children(only(value));
        if (certId === undefined || certValue?.tag !== 0xa0) throw new DerError('a certificate bag without a certificate');
        if (oid(certId) !== OID.x509Certificate) continue; // an SDSI certificate: nothing TLS can use
        contents.certificates.push({ friendlyName, localKeyId, der: Buffer.from(octets(only(certValue))) });
      } else if (kind === OID.keyBag) {
        if (!this.readKeys) continue;
        if (!encrypted) {
          throw this.fail("holds a private key that isn't encrypted: export it with the key encrypted (not -keypbe NONE), as its password "
            + 'is set to protect it.');
        }
        contents.keys.push({ friendlyName, localKeyId, pkcs8: Buffer.from(only(value).raw) });
      } else if (kind === OID.shroudedKeyBag) {
        if (!this.readKeys) continue;
        const [algorithm, encrypted] = children(only(value));
        if (algorithm?.tag !== 0x30 || encrypted === undefined) throw new DerError('a malformed shrouded key bag');
        contents.keys.push({ friendlyName, localKeyId, pkcs8: this.#decrypt(algorithm, octets(encrypted)) });
      } else if (kind === OID.safeContentsBag) {
        this.#readSafeContents(only(value).raw, contents, depth + 1, encrypted);
      }
      // A CRL or secret bag holds nothing TLS uses.
    }
  }

  // `encrypted` decrypted under the password, as `algorithm` says, into a buffer the caller zeroes.
  #decrypt(algorithm: Tlv, encrypted: Buffer): Buffer {
    const [algorithmOid, parameters] = children(algorithm);
    const id = oid(algorithmOid ?? fault('no encryption algorithm'));
    let cipher: string;
    let key: Buffer;
    let iv: Buffer;
    if (id === OID.pbes2) {
      const [kdf, scheme] = children(parameters ?? fault('no PBES2 parameters'));
      const [kdfOid, kdfParameters] = children(kdf ?? fault('no PBES2 key derivation'));
      if (oid(kdfOid ?? fault('no PBES2 key derivation')) !== OID.pbkdf2) throw this.fail('is encrypted with a key derivation other than PBKDF2.');
      const [saltTlv, iterationsTlv, ...rest] = children(kdfParameters ?? fault('no PBKDF2 parameters'));
      if (saltTlv?.tag !== 0x04 || iterationsTlv === undefined) throw new DerError('malformed PBKDF2 parameters');
      let keyLength: number | undefined;
      let prf = 'sha1';
      for (const optional of rest) {
        if (optional.tag === 0x02) keyLength = integer(optional);
        else if (optional.tag === 0x30) prf = PRFS[oid(children(optional)[0] ?? fault('no PRF'))] ?? fault('a PBKDF2 PRF of an unknown digest');
      }
      const [schemeOid, ivTlv] = children(scheme ?? fault('no PBES2 encryption scheme'));
      const chosen = PBES2_CIPHERS[oid(schemeOid ?? fault('no PBES2 encryption scheme'))];
      if (chosen === undefined) throw this.fail('is encrypted with a cipher other than AES-CBC or triple DES, which this reader does not support.');
      if (keyLength !== undefined && keyLength !== chosen.keyLength) throw new DerError('a PBKDF2 key length that does not fit its cipher');
      cipher = chosen.cipher;
      iv = Buffer.from(octets(ivTlv ?? fault('no IV')));
      key = pbkdf2Sync(this.password, octets(saltTlv), checkedIterations(integer(iterationsTlv)), chosen.keyLength, prf);
    } else {
      const chosen = PKCS12_PBE[id];
      if (chosen === undefined) throw this.fail('is encrypted with an algorithm this reader does not know.');
      if (typeof chosen === 'string') {
        throw this.fail(`is encrypted with legacy ${chosen}, which OpenSSL 3 - and so Node - no longer provides by default. Re-export it with AES: `
          + '`openssl pkcs12 -export` from OpenSSL 3, or keytool from Java 11.0.12 or later, encrypt with AES-256-CBC by default.');
      }
      const [saltTlv, iterationsTlv] = children(parameters ?? fault('no PBE parameters'));
      const salt = octets(saltTlv ?? fault('no PBE salt'));
      const iterations = checkedIterations(integer(iterationsTlv ?? fault('no PBE iterations')));
      cipher = chosen.cipher;
      key = pkcs12Kdf('sha1', this.bmpPassword, salt, iterations, 1, chosen.keyLength);
      iv = pkcs12Kdf('sha1', this.bmpPassword, salt, iterations, 2, 8);
    }

    let first: Buffer | undefined;
    let last: Buffer | undefined;
    try {
      const decipher = createDecipheriv(cipher, key, iv);
      first = decipher.update(encrypted);
      last = decipher.final();
      return Buffer.concat([first, last]);
    } catch (error) {
      if (error instanceof InvalidArgumentError) throw error;
      // Bad padding: the MAC passed, so the password opens the MAC but not this.
      throw this.fail("can't be opened: its password is wrong, or the store was altered.");
    } finally {
      wipe(first);
      wipe(last);
      wipe(key);
      wipe(iv);
    }
  }
}

// The friendly name and local key ID among a bag's attributes.
function readAttributes(attributes: Tlv | undefined): { friendlyName: string | undefined; localKeyId: Buffer | undefined } {
  let friendlyName: string | undefined;
  let localKeyId: Buffer | undefined;
  if (attributes?.tag === 0x31) {
    for (const attribute of children(attributes)) {
      const [attributeId, values] = children(attribute);
      if (attributeId === undefined || values?.tag !== 0x31) continue;
      const value = children(values)[0];
      if (value === undefined) continue;
      const kind = oid(attributeId);
      if (kind === OID.friendlyName && value.tag === 0x1e) friendlyName = utf16be(value.value);
      else if (kind === OID.localKeyId && value.tag === 0x04) localKeyId = Buffer.from(value.value);
    }
  }
  return { friendlyName, localKeyId };
}

/**
 * PKCS#12's key derivation (RFC 7292 appendix B.2): `length` bytes of key (`id` 1), IV (2) or MAC
 * key (3) from the BMP password, in a buffer the caller zeroes.
 */
export function pkcs12Kdf(hash: string, bmpPassword: Buffer, salt: Buffer, iterations: number, id: number, length: number): Buffer {
  const u = createHash(hash).digest().length;
  const v = hash === 'sha384' || hash === 'sha512' ? 128 : 64;
  const d = Buffer.alloc(v, id);
  const repeat = (source: Buffer) => {
    const out = Buffer.alloc(v * Math.ceil(source.length / v));
    for (let i = 0; i < out.length; i++) out[i] = source[i % source.length]!;
    return out;
  };
  const s = repeat(salt);
  const p = repeat(bmpPassword);
  const input = Buffer.concat([s, p]);
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
      // Each v-byte block of the input becomes (block + b + 1) mod 2^(8v).
      for (let j = 0; j < input.length; j += v) {
        let carry = 1;
        for (let k = v - 1; k >= 0; k--) {
          const sum = input[j + k]! + b[k]! + carry;
          input[j + k] = sum & 0xff;
          carry = sum >> 8;
        }
      }
    }
  } finally {
    wipe(input);
    wipe(b);
  }
}

// The password's UTF-8 bytes as a BMPString - UTF-16BE, with a two-byte terminator - as PKCS#12's
// key derivation takes it, in a buffer the caller zeroes.
function bmpString(utf8: Uint8Array, fail: (problem: string) => InvalidArgumentError): Buffer {
  const out = Buffer.alloc(utf8.length * 2 + 2);
  let length = 0;
  const put = (unit: number) => {
    out[length++] = unit >> 8;
    out[length++] = unit & 0xff;
  };
  for (let i = 0; i < utf8.length;) {
    const b = utf8[i]!;
    const extra = b < 0x80 ? 0 : b >= 0xc2 && b < 0xe0 ? 1 : b >= 0xe0 && b < 0xf0 ? 2 : b >= 0xf0 && b < 0xf5 ? 3 : -1;
    if (extra < 0 || i + extra >= utf8.length) {
      wipe(out);
      throw fail("password isn't UTF-8.");
    }
    let code = extra === 0 ? b : b & (0x3f >> extra);
    for (let k = 1; k <= extra; k++) {
      const c = utf8[i + k]!;
      if ((c & 0xc0) !== 0x80) {
        wipe(out);
        throw fail("password isn't UTF-8.");
      }
      code = (code << 6) | (c & 0x3f);
    }
    if ((extra === 2 && (code < 0x800 || (code >= 0xd800 && code < 0xe000))) || (extra === 3 && (code < 0x10000 || code > 0x10ffff))) {
      wipe(out);
      throw fail("password isn't UTF-8.");
    }
    if (code >= 0x10000) {
      put(0xd800 + ((code - 0x10000) >> 10));
      put(0xdc00 + ((code - 0x10000) & 0x3ff));
    } else {
      put(code);
    }
    i += extra + 1;
  }
  // The terminator: already zero.
  const result = Buffer.alloc(length + 2);
  out.copy(result, 0, 0, length);
  wipe(out);
  return result;
}

function checkedIterations(iterations: number): number {
  if (iterations < 1 || iterations > MAX_ITERATIONS) throw new DerError(`an iteration count of ${iterations}`);
  return iterations;
}

function utf16be(bytes: Buffer): string {
  let text = '';
  for (let i = 0; i + 1 < bytes.length; i += 2) text += String.fromCharCode((bytes[i]! << 8) | bytes[i + 1]!);
  return text;
}

// --- A minimal DER (and BER, for constructed and indefinite-length encodings) reader. ---

/** A key store that isn't DER this reader can follow. */
class DerError extends Error {}

function fault(problem: string): never {
  throw new DerError(problem);
}

interface Tlv {
  readonly tag: number;
  /** The contents; for an indefinite-length encoding, without the end-of-contents octets. */
  readonly value: Buffer;
  /** The whole encoding, tag to end. */
  readonly raw: Buffer;
  readonly depth: number;
}

function readTlv(buffer: Buffer, offset: number, depth: number): { tlv: Tlv; next: number } {
  if (depth > MAX_DEPTH) throw new DerError('nested too deep');
  if (offset + 2 > buffer.length) throw new DerError('truncated');
  const tag = buffer[offset]!;
  if ((tag & 0x1f) === 0x1f) throw new DerError('a multi-byte tag');
  let position = offset + 1;
  const first = buffer[position++]!;
  if (first === 0x80) {
    // Indefinite length (BER): constructed only, ended by two zero octets.
    if ((tag & 0x20) === 0) throw new DerError('a primitive value of indefinite length');
    let cursor = position;
    for (;;) {
      if (cursor + 2 > buffer.length) throw new DerError('truncated');
      if (buffer[cursor] === 0 && buffer[cursor + 1] === 0) break;
      cursor = readTlv(buffer, cursor, depth + 1).next;
    }
    return { tlv: { tag, value: buffer.subarray(position, cursor), raw: buffer.subarray(offset, cursor + 2), depth }, next: cursor + 2 };
  }
  let length = first;
  if (first > 0x80) {
    const count = first & 0x7f;
    if (count > 4 || position + count > buffer.length) throw new DerError('a length that does not fit');
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + buffer[position++]!;
  }
  const end = position + length;
  if (end > buffer.length) throw new DerError('truncated');
  return { tlv: { tag, value: buffer.subarray(position, end), raw: buffer.subarray(offset, end), depth }, next: end };
}

// The one value `buffer` holds, of `tag`.
function readOne(buffer: Buffer, tag: number): Tlv {
  const { tlv } = readTlv(buffer, 0, 0);
  if (tlv.tag !== tag) throw new DerError(`0x${tlv.tag.toString(16)} where 0x${tag.toString(16)} belongs`);
  return tlv;
}

function children(tlv: Tlv): Tlv[] {
  if ((tlv.tag & 0x20) === 0) throw new DerError('a primitive value where a constructed one belongs');
  const result: Tlv[] = [];
  for (let offset = 0; offset < tlv.value.length;) {
    const { tlv: child, next } = readTlv(tlv.value, offset, tlv.depth + 1);
    result.push(child);
    offset = next;
  }
  return result;
}

// An explicitly tagged value's one child.
function only(tlv: Tlv): Tlv {
  const [child, extra] = children(tlv);
  if (child === undefined || extra !== undefined) throw new DerError('an explicit tag without exactly one value');
  return child;
}

// An OCTET STRING's (or an implicitly tagged one's) bytes; a constructed one's pieces joined.
function octets(tlv: Tlv): Buffer {
  if ((tlv.tag & 0x20) === 0) return tlv.value;
  return Buffer.concat(children(tlv).map(octets));
}

function oid(tlv: Tlv): string {
  if (tlv.tag !== 0x06) throw new DerError('a value where an object identifier belongs');
  return tlv.value.toString('hex');
}

function integer(tlv: Tlv): number {
  if (tlv.tag !== 0x02 || tlv.value.length === 0 || tlv.value.length > 6) throw new DerError('a value where a small integer belongs');
  if ((tlv.value[0]! & 0x80) !== 0) throw new DerError('a negative integer');
  return tlv.value.readUIntBE(0, tlv.value.length);
}

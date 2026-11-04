// Password-based encryption for PKCS#12 files and encrypted PKCS#8 keys, decryption only: PBES2
// (PBKDF2 with HMAC-SHA-1/2, AES-CBC or 3DES-CBC), and PKCS#12's own 3DES key derivation, as the Go
// and Python ports read them.
//
// The password is always a Uint8Array, never a string. PBKDF2 runs in node:crypto's pbkdf2Sync, whose
// derived key is a Buffer zeroed here; PKCS#12's key derivation (RFC 7292 B.2) hashes with
// createHash, and every digest it produces is a Buffer zeroed as soon as it is used; every plaintext
// buffer the decipher gives is zeroed once copied into the one returned. What is beyond reach: the
// copies node:crypto makes inside OpenSSL (the PBKDF2 password, the cipher key schedule, the hash
// state), which OpenSSL cleanses as it frees them - for a Cipher or Hash object, when it is collected.
// Never exported from the package index.
import { createDecipheriv, createHash, pbkdf2Sync } from 'node:crypto';
import { wipe } from '@runsecure/hkdfguard-abstractions';
import * as der from './der.js';
import { DerError, type Element } from './der.js';
import { InvalidCertificateFileError, UnsupportedCertificateError, WrongPasswordError } from './errors.js';

/**
 * The most iterations one key derivation may ask for, and a whole file all of its derivations: a file
 * can't make loading it take minutes. Generous beside what tools write (OpenSSL 2048, Windows
 * 2000-10000, .NET's PBES2 default 100000 and its loader's 600000 cap). As the Go and Python ports.
 */
export const MAX_ITERATIONS = 1_000_000;
export const MAX_TOTAL_ITERATIONS = 4_000_000;

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

/** The key-derivation iterations one file has spent. */
export class IterationBudget {
  spent = 0;

  spend(iterations: number): void {
    if (!Number.isSafeInteger(iterations) || iterations < 1 || iterations > MAX_ITERATIONS || this.spent + iterations > MAX_TOTAL_ITERATIONS) {
      throw new InvalidCertificateFileError('An iteration count in the file is out of range.');
    }
    this.spent += iterations;
  }
}

/**
 * A UTF-8 password as PKCS#12's key derivation takes it: a BMPString - big-endian UTF-16 - with a
 * two-byte terminator, decoded byte by byte, never through a string. undefined is the empty password,
 * the terminator alone; an empty array is no password at all, no bytes - the two ways tools write a
 * file without one. A new buffer the caller wipes.
 * @throws WrongPasswordError the password isn't UTF-8
 */
export function bmpPassword(password: Uint8Array | undefined): Buffer {
  if (password !== undefined && password.length === 0) return Buffer.alloc(0);
  const source = password ?? new Uint8Array(0);
  const out = Buffer.alloc(source.length * 2 + 2); // every UTF-8 sequence is at least half its UTF-16BE length
  let written = 0;
  const notUtf8 = () => {
    wipe(out);
    return new WrongPasswordError("The password isn't UTF-8.");
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
    code = 0;
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

/**
 * Decrypts `ciphertext` under a password-based encryption algorithm: PBES2 (PBKDF2 with
 * HMAC-SHA-1/224/256/384/512, and AES-128/192/256-CBC or 3DES-CBC), or PKCS#12's
 * pbeWithSHAAnd3-KeyTripleDES-CBC or 2-KeyTripleDES. `password` is UTF-8: PBES2 uses it as it is, as
 * OpenSSL and .NET do, and PKCS#12's own PBE as a BMPString. The plaintext is a new buffer the caller
 * wipes. A wrong password shows as bad padding: WrongPasswordError.
 * @throws UnsupportedCertificateError legacy RC2 or RC4, or an algorithm this doesn't know
 */
export function decrypt(algorithm: Element | undefined, password: Uint8Array | undefined, ciphertext: Buffer, budget: IterationBudget): Buffer {
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
      throw new UnsupportedCertificateError(`The encryption algorithm ${oid} isn't supported.`);
    }
    return cbcDecrypt(cipher.cipher, cipher.blockLength, key, iv, ciphertext);
  } catch (error) {
    if (error instanceof DerError) throw new InvalidCertificateFileError(`The file's encryption parameters are malformed: ${error.message}`);
    throw error;
  } finally {
    wipe(key);
    wipe(iv);
  }
}

/** The refusal of a legacy RC2 or RC4 encryption, saying how to re-export the file. */
export function legacy(name: string, oid: string): UnsupportedCertificateError {
  return new UnsupportedCertificateError(
    `The file is encrypted with legacy ${name} (${oid}), which is refused: re-export it with AES - for instance with `
    + "'openssl pkcs12 -export' from OpenSSL 3 without -legacy, or .NET's ExportPkcs12 with Pkcs12ExportPbeParameters.Pbes2Aes256Sha256.");
}

function pbes2Key(parameters: Element | undefined, password: Uint8Array | undefined, budget: IterationBudget):
{ key: Buffer; iv: Buffer; cipher: { cipher: string; blockLength: number } } {
  const [kdf, scheme] = der.sequence(parameters, 'PBES2 parameters', 2, 2);
  const derivation = der.algorithm(kdf, 'A key derivation');
  if (derivation.oid !== PBKDF2) throw new UnsupportedCertificateError(`The PBES2 key derivation ${derivation.oid} isn't supported.`);
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
    if (chosen === undefined) throw new UnsupportedCertificateError(`The PBKDF2 PRF ${named} isn't supported.`);
    prf = chosen;
  }
  budget.spend(iterations);
  const encryption = der.algorithm(scheme, 'A PBES2 cipher');
  if (LEGACY[encryption.oid] !== undefined) throw legacy(LEGACY[encryption.oid]!, encryption.oid);
  const cipher = CIPHERS[encryption.oid];
  if (cipher === undefined) throw new UnsupportedCertificateError(`The PBES2 cipher ${encryption.oid} isn't supported.`);
  if (keyLength !== undefined && keyLength !== cipher.keyLength) throw new DerError("PBKDF2's key length doesn't fit its cipher.");
  const iv = der.octets(encryption.parameters, 'An IV');
  if (iv.length !== cipher.blockLength) throw new DerError("The cipher's IV isn't one block.");
  const key = pbkdf2Sync(password ?? new Uint8Array(0), salt, iterations, cipher.keyLength, prf);
  return { key, iv, cipher };
}

function cbcDecrypt(cipher: string, blockLength: number, key: Buffer, iv: Buffer, ciphertext: Buffer): Buffer {
  if (ciphertext.length === 0 || ciphertext.length % blockLength !== 0) throw new InvalidCertificateFileError("The encrypted data isn't whole cipher blocks.");
  let first: Buffer | undefined;
  let last: Buffer | undefined;
  try {
    const decipher = createDecipheriv(cipher, key, iv);
    first = decipher.update(ciphertext);
    try {
      last = decipher.final(); // checks the PKCS#7 padding
    } catch {
      throw new WrongPasswordError("The password doesn't decrypt the file's key or contents.");
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

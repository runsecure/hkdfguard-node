// A minimal PKCS#12 (RFC 7292) reader, as the Go and Python ports': password-integrity MACs with
// HMAC-SHA-1/224/256/384/512; unencrypted and password-encrypted contents; key bags, shrouded key
// bags, certificate bags and nested safe contents. Encryption is PBES2 (AES-CBC or 3DES-CBC under
// PBKDF2) or PKCS#12's own 3DES; legacy RC2 and RC4, public-key (enveloped or signed) contents and
// the PBMAC1 MAC are refused. Every private key comes out as its PKCS#8 PrivateKeyInfo in a Buffer
// the caller wipes; every buffer that held the password or the plaintext on the way is wiped here.
//
// Written here rather than given to Node's tls `pfx` option, which takes the password only as a
// string, reads the first key it finds, and can't say which certificate is the key's. Never exported
// from the package index.
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { wipe } from '@runsecure/hkdfguard-abstractions';
import * as der from './der.js';
import { DerError, type Element } from './der.js';
import { InvalidCertificateFileError, UnsupportedCertificateError, WrongPasswordError } from './errors.js';
import * as pbe from './pbe.js';

const DATA = '1.2.840.113549.1.7.1';
const SIGNED_DATA = '1.2.840.113549.1.7.2';
const ENVELOPED_DATA = '1.2.840.113549.1.7.3';
const ENCRYPTED_DATA = '1.2.840.113549.1.7.6';
const KEY_BAG = '1.2.840.113549.1.12.10.1.1';
const SHROUDED_KEY_BAG = '1.2.840.113549.1.12.10.1.2';
const CERT_BAG = '1.2.840.113549.1.12.10.1.3';
const SAFE_CONTENTS_BAG = '1.2.840.113549.1.12.10.1.6';
const X509_CERTIFICATE = '1.2.840.113549.1.9.22.1';
const MAX_SAFE_DEPTH = 4;

/** The largest PKCS#12 or key file read, in bytes: far beyond any certificate, chain or key. */
export const MAX_FILE_LENGTH = 4 * 1024 * 1024;

/** What a PKCS#12 file holds: its certificates' DER, in file order, and its private keys, each a PKCS#8 PrivateKeyInfo in a buffer {@link wipe} zeroes. */
export class Pkcs12Contents {
  readonly certificates: Buffer[] = [];
  readonly keys: Buffer[] = [];

  wipe(): void {
    for (const key of this.keys) wipe(key);
    this.keys.length = 0;
  }
}

/**
 * Reads a PKCS#12 file with a UTF-8 password - undefined for a file without one, which is tried as
 * both the empty password and no password, as tools write either.
 * @throws WrongPasswordError the file's MAC doesn't verify, or its contents don't decrypt
 * @throws InvalidCertificateFileError it isn't a PKCS#12 file
 * @throws UnsupportedCertificateError legacy RC2/RC4, PBMAC1, or public-key (enveloped or signed) contents
 */
export function decodePkcs12(data: Buffer, password: Uint8Array | undefined): Pkcs12Contents {
  let authSafe: Buffer;
  let macData: Element | undefined;
  try {
    const pfx = der.sequence(der.read(data), 'A PKCS#12 file', 2, 3);
    if (der.integer(pfx[0], 'The PKCS#12 version') !== 3) throw new UnsupportedCertificateError('Only PKCS#12 version 3 files are supported.');
    const { type, content } = contentInfo(pfx[1]);
    if (type === SIGNED_DATA) throw new UnsupportedCertificateError('A PKCS#12 file protected by a public key, not a password, isn\'t supported.');
    if (type !== DATA || content === undefined) throw new DerError('The authenticated safe is neither data nor signed data.');
    authSafe = der.octets(content, 'The PKCS#12 contents');
    macData = pfx[2];
  } catch (error) {
    if (error instanceof DerError) throw new InvalidCertificateFileError(`Not a PKCS#12 file: ${error.message}`);
    throw error;
  }

  try {
    const budget = new pbe.IterationBudget();
    // The passwords to try: the one given; for none, the empty BMPString (00 00) and no bytes at all.
    let candidates: (Uint8Array | undefined)[] = password !== undefined && password.length > 0 ? [password] : [undefined, new Uint8Array(0)];
    if (macData !== undefined) candidates = [verifyMac(macData, authSafe, candidates, budget)];
    let failure: WrongPasswordError | undefined;
    for (const candidate of candidates) {
      try {
        return readAuthenticatedSafe(authSafe, candidate, budget);
      } catch (error) {
        if (!(error instanceof WrongPasswordError)) throw error;
        failure = error;
      }
    }
    throw failure!;
  } finally {
    wipe(authSafe);
  }
}

function contentInfo(element: Element | undefined): { type: string; content: Element | undefined } {
  const items = der.sequence(element, 'A ContentInfo', 1, 2);
  return { type: der.oid(items[0]), content: items[1] === undefined ? undefined : der.only(items[1], der.CONTEXT_0, "A ContentInfo's content") };
}

/** The candidate password the file's integrity MAC verifies under. */
function verifyMac(macData: Element, authSafe: Buffer, candidates: (Uint8Array | undefined)[], budget: pbe.IterationBudget): Uint8Array | undefined {
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
    if (error instanceof DerError) throw new InvalidCertificateFileError(`The PKCS#12 MAC is malformed: ${error.message}`);
    throw error;
  }
  if (algorithm === pbe.PBMAC1) {
    throw new UnsupportedCertificateError("The PKCS#12 file's PBMAC1 integrity check (OpenSSL 3.4's -pbmac1_pbkdf2) isn't supported: export it with the default HMAC.");
  }
  const hash = pbe.DIGESTS[algorithm];
  if (hash === undefined) throw new UnsupportedCertificateError(`The PKCS#12 MAC algorithm ${algorithm} isn't supported.`);
  const size = createHash(hash).digest().length;
  for (const candidate of candidates) {
    budget.spend(iterations);
    const bmp = pbe.bmpPassword(candidate);
    let key: Buffer | undefined;
    let actual: Buffer | undefined;
    try {
      key = pbe.pkcs12Kdf(hash, bmp, salt, iterations, pbe.PKCS12_MAC_ID, size);
      actual = createHmac(hash, key).update(authSafe).digest();
      if (actual.length === expected.length && timingSafeEqual(actual, expected)) return candidate;
    } finally {
      wipe(bmp);
      wipe(key);
      wipe(actual);
    }
  }
  throw new WrongPasswordError("The PKCS#12 file's integrity check fails: the password is wrong, or the file is corrupt.");
}

function readAuthenticatedSafe(authSafe: Buffer, password: Uint8Array | undefined, budget: pbe.IterationBudget): Pkcs12Contents {
  const contents = new Pkcs12Contents();
  try {
    let infos: Element[];
    try {
      infos = der.sequence(der.read(authSafe), 'The PKCS#12 authenticated safe');
    } catch (error) {
      if (error instanceof DerError) throw new InvalidCertificateFileError(`The PKCS#12 authenticated safe is malformed: ${error.message}`);
      throw error;
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
        if (error instanceof DerError) throw new InvalidCertificateFileError(`The PKCS#12 contents are malformed: ${error.message}`);
        throw error;
      }
      if (type === DATA) {
        let safe: Buffer | undefined;
        try {
          safe = der.octets(content, 'PKCS#12 data');
          readSafeContents(contents, safe, password, budget, 0);
        } catch (error) {
          if (error instanceof DerError) throw new InvalidCertificateFileError(`The PKCS#12 data is malformed: ${error.message}`);
          throw error;
        } finally {
          wipe(safe);
        }
      } else if (type === ENCRYPTED_DATA) {
        const { algorithm, ciphertext } = encryptedData(content);
        if (ciphertext === undefined) continue; // nothing was encrypted
        const plaintext = pbe.decrypt(algorithm, password, ciphertext, budget);
        try {
          readSafeContents(contents, plaintext, password, budget, 0);
        } catch (error) {
          // Contents that decrypted to nonsense were decrypted with the wrong password.
          if (error instanceof DerError || error instanceof InvalidCertificateFileError) {
            throw new WrongPasswordError(`The password doesn't decrypt the file's contents (${error.message}).`);
          }
          throw error;
        } finally {
          wipe(plaintext);
        }
      } else if (type === ENVELOPED_DATA) {
        throw new UnsupportedCertificateError('PKCS#12 contents encrypted to a public key (enveloped data) aren\'t supported.');
      } else {
        throw new UnsupportedCertificateError(`PKCS#12 contents of type ${type} aren't supported.`);
      }
    }
    return contents;
  } catch (error) {
    contents.wipe();
    throw error;
  }
}

function encryptedData(content: Element): { algorithm: Element; ciphertext: Buffer | undefined } {
  try {
    const items = der.sequence(content, 'PKCS#12 encrypted data', 2, 3);
    const info = der.sequence(items[1], 'The encrypted content info', 2, 3);
    // [0] IMPLICIT OCTET STRING, primitive (0x80) or - BER - constructed (0xA0); absent when nothing was encrypted.
    return { algorithm: info[1]!, ciphertext: info[2] === undefined ? undefined : der.octets(info[2], 'The encrypted content', 0x80) };
  } catch (error) {
    if (error instanceof DerError) throw new InvalidCertificateFileError(`The PKCS#12 encrypted data is malformed: ${error.message}`);
    throw error;
  }
}

function readSafeContents(contents: Pkcs12Contents, safe: Buffer, password: Uint8Array | undefined, budget: pbe.IterationBudget, depth: number): void {
  if (depth > MAX_SAFE_DEPTH) throw new InvalidCertificateFileError('The PKCS#12 safe contents are nested too deep.');
  let bags: Element[];
  try {
    bags = der.sequence(der.read(safe), 'PKCS#12 safe contents');
  } catch (error) {
    if (error instanceof DerError) throw new InvalidCertificateFileError(`The PKCS#12 safe contents are malformed: ${error.message}`);
    throw error;
  }
  for (const bag of bags) {
    let type: string;
    let value: Element;
    try {
      const items = der.sequence(bag, 'A PKCS#12 bag', 2, 3);
      type = der.oid(items[0]);
      value = der.only(items[1], der.CONTEXT_0, "A bag's value");
    } catch (error) {
      if (error instanceof DerError) throw new InvalidCertificateFileError(`A PKCS#12 bag is malformed: ${error.message}`);
      throw error;
    }
    if (type === CERT_BAG) {
      const certificate = certificateOf(value);
      if (certificate !== undefined) contents.certificates.push(certificate);
    } else if (type === KEY_BAG) {
      const key = Buffer.alloc(value.encoding.length);
      value.encoding.copy(key);
      contents.keys.push(key);
    } else if (type === SHROUDED_KEY_BAG) {
      contents.keys.push(decryptPkcs8(value.encoding, password, budget));
    } else if (type === SAFE_CONTENTS_BAG) {
      readSafeContents(contents, value.encoding, password, budget, depth + 1);
    }
    // CRL and secret bags hold nothing a certificate needs.
  }
}

function certificateOf(value: Element): Buffer | undefined {
  try {
    const items = der.sequence(value, 'A certificate bag', 2, 2);
    if (der.oid(items[0]) !== X509_CERTIFICATE) return undefined; // an SDSI certificate, say
    return der.octets(der.only(items[1], der.CONTEXT_0, "A certificate bag's value"), 'A certificate');
  } catch (error) {
    if (error instanceof DerError) throw new InvalidCertificateFileError(`A PKCS#12 certificate bag is malformed: ${error.message}`);
    throw error;
  }
}

/**
 * Decrypts an EncryptedPrivateKeyInfo with a UTF-8 password: its PrivateKeyInfo, in a new buffer the
 * caller wipes.
 * @throws WrongPasswordError the password doesn't decrypt it to a key
 */
export function decryptPkcs8(encrypted: Buffer, password: Uint8Array | undefined, budget: pbe.IterationBudget): Buffer {
  let items: Element[];
  let ciphertext: Buffer;
  try {
    items = der.sequence(der.read(encrypted), 'An encrypted private key', 2, 2);
    ciphertext = der.octets(items[1], 'The encrypted key');
  } catch (error) {
    if (error instanceof DerError) throw new InvalidCertificateFileError(`An encrypted private key is malformed: ${error.message}`);
    throw error;
  }
  const plaintext = pbe.decrypt(items[0], password, ciphertext, budget);
  try {
    const key = der.sequence(der.read(plaintext), 'A private key', 3);
    der.integer(key[0], "A private key's version");
  } catch (error) {
    wipe(plaintext);
    // A key that decrypted to nonsense was decrypted with the wrong password.
    if (error instanceof DerError) throw new WrongPasswordError("The password doesn't decrypt the key to one.");
    throw error;
  }
  return plaintext;
}

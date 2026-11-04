// Reading certificate and key files: every file read whole into a Buffer sized once - libuv reads
// straight into it, so a key file is never copied anywhere that can't be wiped - and its certificates
// and keys found in it without its contents becoming a string. Never exported from the package index.
import { createPrivateKey, createPublicKey, type KeyObject } from 'node:crypto';
import { open } from 'node:fs/promises';
import { wipe } from '@runsecure/hkdfguard-abstractions';
import { InvalidCertificateFileError, UnsupportedCertificateError } from './errors.js';
import * as pbe from './pbe.js';
import { decodeBase64, pemBlocks } from './pem.js';
import { decryptPkcs8, MAX_FILE_LENGTH } from './pkcs12.js';
import { parseCertificate, type ParsedCertificate } from './x509.js';

const PLAIN_KEYS: Record<string, 'pkcs8' | 'pkcs1' | 'sec1'> = { 'PRIVATE KEY': 'pkcs8', 'RSA PRIVATE KEY': 'pkcs1', 'EC PRIVATE KEY': 'sec1' };

/**
 * A whole file, read into a new Buffer sized once, which the caller wipes.
 * @throws the operating system's error (ENOENT, EACCES...) for a file that can't be read
 * @throws InvalidCertificateFileError it is far larger than any certificate or key file, or changed while it was read
 */
export async function readWholeFile(path: string): Promise<Buffer> {
  const handle = await open(path, 'r');
  try {
    const { size } = await handle.stat();
    if (size > MAX_FILE_LENGTH) throw new InvalidCertificateFileError(`'${path}' is ${size} bytes: too large to be a certificate or key file.`);
    const data = Buffer.alloc(size);
    let read = 0;
    while (read < size) {
      const { bytesRead } = await handle.read(data, read, size - read, read);
      if (bytesRead === 0) break;
      read += bytesRead;
    }
    // One byte more would mean the file grew while it was read.
    const probe = Buffer.alloc(1);
    const { bytesRead: extra } = await handle.read(probe, 0, 1, read);
    if (read !== size || extra !== 0) {
      wipe(data);
      wipe(probe);
      throw new InvalidCertificateFileError(`'${path}' changed while it was read.`);
    }
    return data;
  } finally {
    await handle.close();
  }
}

const failIn = (path: string) => (problem: string) => new InvalidCertificateFileError(`'${path}': ${problem}`);

/**
 * Every certificate in a PEM file, in file order, or the one DER certificate a file holds.
 * @throws InvalidCertificateFileError it holds no certificate, or one that isn't
 */
export function parseCertificates(data: Buffer, path: string): ParsedCertificate[] {
  if (data.indexOf('-----BEGIN', 0, 'latin1') < 0) return [parseCertificate(data, `'${path}'`)];
  const certificates: ParsedCertificate[] = [];
  for (const block of pemBlocks(data, failIn(path))) {
    if (block.label !== 'CERTIFICATE') continue;
    certificates.push(parseCertificate(decodeBase64(block.body, failIn(path)), `A certificate in '${path}'`));
  }
  if (certificates.length === 0) throw new InvalidCertificateFileError(`'${path}' holds no CERTIFICATE.`);
  return certificates;
}

/**
 * The PrivateKeyInfo the ENCRYPTED PRIVATE KEY in a PEM key file decrypts to, in a new buffer the
 * caller wipes.
 * @throws UnsupportedCertificateError a legacy OpenSSL-encrypted PEM key (Proc-Type)
 * @throws InvalidCertificateFileError there is none, or the key is plaintext
 * @throws WrongPasswordError the password doesn't decrypt it
 */
export function decryptPemKey(data: Buffer, password: Uint8Array, path: string): Buffer {
  for (const block of pemBlocks(data, failIn(path))) {
    if (block.headers.has('Proc-Type')) {
      throw new UnsupportedCertificateError(`'${path}' holds a legacy OpenSSL-encrypted PEM key (Proc-Type); convert it to encrypted PKCS#8: `
        + 'openssl pkcs8 -topk8 -v2 aes-256-cbc.');
    }
    if (block.label === 'ENCRYPTED PRIVATE KEY') {
      const encrypted = decodeBase64(block.body, failIn(path)); // ciphertext and its parameters only
      try {
        return decryptPkcs8(encrypted, password, new pbe.IterationBudget());
      } finally {
        wipe(encrypted);
      }
    }
    if (PLAIN_KEYS[block.label] !== undefined) {
      throw new InvalidCertificateFileError(`The key in '${path}' isn't encrypted, but File.PasswordSecretName names a password for it; `
        + 'encrypt it, or leave PasswordSecretName unset and set AllowUnprotectedPrivateKey.');
    }
  }
  throw new InvalidCertificateFileError(`'${path}' holds no ENCRYPTED PRIVATE KEY.`);
}

/**
 * The plaintext key in a PEM key file - PKCS#8, PKCS#1 or SEC 1 - as a PKCS#8 PrivateKeyInfo in a new
 * buffer the caller wipes.
 * @throws InvalidCertificateFileError there is none, or it is encrypted
 */
export function plainPemKey(data: Buffer, path: string): Buffer {
  for (const block of pemBlocks(data, failIn(path))) {
    if (block.headers.has('Proc-Type') || block.label === 'ENCRYPTED PRIVATE KEY') {
      throw new InvalidCertificateFileError(`The key in '${path}' is encrypted, but no File.PasswordSecretName names its password.`);
    }
    const type = PLAIN_KEYS[block.label];
    if (type === undefined) continue;
    const decoded = decodeBase64(block.body, failIn(path));
    try {
      if (type === 'pkcs8') return Buffer.from(decoded); // a copy, so `decoded` can be wiped here as on every other path
      try {
        return createPrivateKey({ key: decoded, format: 'der', type }).export({ format: 'der', type: 'pkcs8' });
      } catch (error) {
        throw new InvalidCertificateFileError(`The key in '${path}' isn't one: ${(error as Error).message}`, { cause: error });
      }
    } finally {
      wipe(decoded);
    }
  }
  throw new InvalidCertificateFileError(`'${path}' holds no PRIVATE KEY, RSA PRIVATE KEY or EC PRIVATE KEY.`);
}

/**
 * The public key of a PKCS#8 PrivateKeyInfo, which node:crypto parses into OpenSSL for the moment it
 * takes to derive it.
 * @throws InvalidCertificateFileError it isn't a key node:crypto can parse
 */
export function publicKeyOf(privateKeyInfo: Buffer): KeyObject {
  try {
    return createPublicKey(createPrivateKey({ key: privateKeyInfo, format: 'der', type: 'pkcs8' }));
  } catch (error) {
    throw new InvalidCertificateFileError(`The private key isn't one: ${(error as Error).message}`, { cause: error });
  }
}

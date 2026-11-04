// What a private key operation asks for, checked once for every kind of key: the hash and scheme to
// sign with, or the padding to decrypt with, read from node:crypto's own option shapes and constants
// (padding, saltLength, dsaEncoding, oaepHash, oaepLabel) - so a call written for crypto.sign or
// crypto.privateDecrypt reads the same here.
import { constants, type KeyObject } from 'node:crypto';
import { InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';
import { UnsupportedCertificateError } from './errors.js';

/** A hash a signature or OAEP decryption uses, as node:crypto names it. SHA-224 isn't available with a Windows (CNG) key. */
export type HashAlgorithm = 'sha1' | 'sha224' | 'sha256' | 'sha384' | 'sha512';

const DIGEST_LENGTHS: Record<HashAlgorithm, number> = { sha1: 20, sha224: 28, sha256: 32, sha384: 48, sha512: 64 };

/**
 * How {@link LoadedCertificate.sign} signs, as crypto.sign's key options say it: for an RSA key,
 * `padding` is `constants.RSA_PKCS1_PADDING` (the default) or `constants.RSA_PKCS1_PSS_PADDING`, and
 * for PSS `saltLength` is a length in bytes, `constants.RSA_PSS_SALTLEN_DIGEST` or
 * `constants.RSA_PSS_SALTLEN_MAX_SIGN` (the default); MGF1 is always over the signature's hash. For an
 * ECDSA key, `dsaEncoding` is 'der' (the default) or 'ieee-p1363' (r || s).
 */
export interface SignOptions {
  padding?: number;
  saltLength?: number;
  dsaEncoding?: 'der' | 'ieee-p1363';
}

/**
 * How {@link LoadedCertificate.decrypt} decrypts with an RSA key, as crypto.privateDecrypt's options
 * say it: `padding` is `constants.RSA_PKCS1_OAEP_PADDING` (the default, as privateDecrypt's) or
 * `constants.RSA_PKCS1_PADDING`; for OAEP, `oaepHash` (default 'sha1', as privateDecrypt's) is the
 * hash of both OAEP and its MGF1, and `oaepLabel` the label (default empty).
 */
export interface DecryptOptions {
  padding?: number;
  oaepHash?: HashAlgorithm;
  oaepLabel?: Uint8Array;
}

/** A signature, resolved: the hash, the scheme, a PSS salt's length in bytes, and the ECDSA encoding asked for. */
export interface Signature {
  readonly hash: HashAlgorithm;
  readonly scheme: 'pkcs1' | 'pss' | 'ecdsa';
  readonly saltLength: number;
  readonly dsaEncoding: 'der' | 'ieee-p1363';
}

/** A decryption, resolved. */
export interface Decryption {
  readonly scheme: 'pkcs1' | 'oaep';
  readonly hash: HashAlgorithm;
  readonly label: Buffer;
}

export function checkHash(hash: unknown): HashAlgorithm {
  if (typeof hash !== 'string' || !(hash in DIGEST_LENGTHS)) {
    throw new InvalidArgumentError(`The hash must be 'sha1', 'sha224', 'sha256', 'sha384' or 'sha512', not ${typeof hash === 'string' ? `'${hash}'` : typeof hash}.`);
  }
  return hash as HashAlgorithm;
}

export function digestLength(hash: HashAlgorithm): number {
  return DIGEST_LENGTHS[hash];
}

/** The signature `options` ask of a key whose public key is `publicKey`. */
export function resolveSignature(hash: unknown, options: SignOptions | undefined, publicKey: KeyObject): Signature {
  const algorithm = checkHash(hash);
  const dsaEncoding = options?.dsaEncoding ?? 'der';
  if (dsaEncoding !== 'der' && dsaEncoding !== 'ieee-p1363') throw new InvalidArgumentError("dsaEncoding must be 'der' or 'ieee-p1363'.");
  if (publicKey.asymmetricKeyType === 'ec') {
    if (options?.padding !== undefined || options?.saltLength !== undefined) throw new InvalidArgumentError('An ECDSA key signs with no padding or salt length.');
    return { hash: algorithm, scheme: 'ecdsa', saltLength: 0, dsaEncoding };
  }
  if (publicKey.asymmetricKeyType !== 'rsa') throw new UnsupportedCertificateError('Only RSA and ECDSA keys sign here.');
  const padding = options?.padding ?? constants.RSA_PKCS1_PADDING;
  if (padding === constants.RSA_PKCS1_PADDING) {
    if (options?.saltLength !== undefined) throw new InvalidArgumentError('A salt length is for PSS only.');
    return { hash: algorithm, scheme: 'pkcs1', saltLength: 0, dsaEncoding };
  }
  if (padding !== constants.RSA_PKCS1_PSS_PADDING) throw new InvalidArgumentError('An RSA key signs with RSA_PKCS1_PADDING or RSA_PKCS1_PSS_PADDING.');
  const modulusLength = publicKey.asymmetricKeyDetails?.modulusLength ?? 0;
  const maximum = Math.ceil((modulusLength - 1) / 8) - digestLength(algorithm) - 2;
  const requested = options?.saltLength ?? constants.RSA_PSS_SALTLEN_MAX_SIGN;
  const saltLength = requested === constants.RSA_PSS_SALTLEN_DIGEST ? digestLength(algorithm)
    : requested === constants.RSA_PSS_SALTLEN_MAX_SIGN ? maximum
      : requested;
  if (!Number.isInteger(saltLength) || saltLength < 0 || saltLength > maximum) {
    throw new InvalidArgumentError(`A PSS salt of ${requested} doesn't fit this ${modulusLength}-bit key with ${algorithm}.`);
  }
  return { hash: algorithm, scheme: 'pss', saltLength, dsaEncoding };
}

/** The decryption `options` ask of a key whose public key is `publicKey`. */
export function resolveDecryption(options: DecryptOptions | undefined, publicKey: KeyObject): Decryption {
  if (publicKey.asymmetricKeyType !== 'rsa') throw new UnsupportedCertificateError('Only an RSA key decrypts.');
  const padding = options?.padding ?? constants.RSA_PKCS1_OAEP_PADDING;
  const label = Buffer.from(options?.oaepLabel ?? new Uint8Array(0));
  if (padding === constants.RSA_PKCS1_PADDING) {
    if (options?.oaepHash !== undefined || label.length > 0) throw new InvalidArgumentError('An OAEP hash or label is for OAEP only.');
    return { scheme: 'pkcs1', hash: 'sha1', label };
  }
  if (padding !== constants.RSA_PKCS1_OAEP_PADDING) throw new InvalidArgumentError('An RSA key decrypts with RSA_PKCS1_OAEP_PADDING or RSA_PKCS1_PADDING.');
  return { scheme: 'oaep', hash: checkHash(options?.oaepHash ?? 'sha1'), label };
}

/** The byte length of each of r and s for an ECDSA key's curve. */
export function ecFieldLength(publicKey: KeyObject): number {
  switch (publicKey.asymmetricKeyDetails?.namedCurve) {
    case 'prime256v1': return 32;
    case 'secp384r1': return 48;
    case 'secp521r1': return 66;
    default: throw new UnsupportedCertificateError(`The ECDSA curve ${publicKey.asymmetricKeyDetails?.namedCurve ?? '(unknown)'} isn't supported: use P-256, P-384 or P-521.`);
  }
}

/** An IEEE P1363 ECDSA signature (r || s) as DER: SEQUENCE { r INTEGER, s INTEGER }. */
export function p1363ToDer(signature: Uint8Array): Buffer {
  const half = signature.length / 2;
  if (!Number.isInteger(half) || half === 0) throw new UnsupportedCertificateError('An ECDSA signature is malformed.');
  const integer = (bytes: Uint8Array) => {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    const body = bytes.subarray(start);
    const padded = (body[0]! & 0x80) !== 0 ? Buffer.concat([Buffer.from([0]), body]) : Buffer.from(body);
    return Buffer.concat([Buffer.from([0x02]), length(padded.length), padded]);
  };
  const body = Buffer.concat([integer(signature.subarray(0, half)), integer(signature.subarray(half))]);
  return Buffer.concat([Buffer.from([0x30]), length(body.length), body]);
}

function length(n: number): Buffer {
  return n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]);
}

/** A DER ECDSA signature as IEEE P1363 (r || s), each `size` bytes. */
export function derToP1363(signature: Uint8Array, size: number): Buffer {
  const data = Buffer.from(signature);
  let offset = 0;
  const readLength = () => {
    const first = data[offset++]!;
    if (first < 0x80) return first;
    const count = first & 0x7f;
    let n = 0;
    for (let i = 0; i < count; i++) n = n * 256 + data[offset++]!;
    return n;
  };
  if (data[offset++] !== 0x30) throw new UnsupportedCertificateError('An ECDSA signature is malformed.');
  readLength();
  const out = Buffer.alloc(size * 2);
  for (const half of [0, 1]) {
    if (data[offset++] !== 0x02) throw new UnsupportedCertificateError('An ECDSA signature is malformed.');
    const n = readLength();
    let value = data.subarray(offset, offset + n);
    offset += n;
    while (value.length > size && value[0] === 0) value = value.subarray(1);
    if (value.length > size) throw new UnsupportedCertificateError('An ECDSA signature is malformed.');
    value.copy(out, half * size + (size - value.length));
  }
  return out;
}

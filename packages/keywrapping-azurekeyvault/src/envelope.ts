import { InvalidArgumentError, isWellFormed } from '@runsecure/hkdfguard-abstractions';

/*
 * The wrapped-DEK format AzureKeyVaultKeyWrapper writes and reads, byte for byte the .NET
 * AzureKeyVaultKeyWrapper's, the Java AzureKeyVaultKeyWrapperImpl's and the Python
 * AzureKeyVaultKeyWrapper's:
 *
 *   offset  length  field
 *   0       4       magic "HGKV"
 *   4       1       format version (1)
 *   5       16      wrapping key version (Key Vault's 32 hex digits, as bytes)
 *   21      2       n, the RSA-OAEP-256 ciphertext's length (big-endian)
 *   23      n       the DEK, wrapped under that version of the wrapping key
 *   23+n    16      signing key version
 *   39+n    64      ES256 signature (r || s) by that version of the signing key
 *
 * Only key versions are stored: the vault and key names are the wrapper's own, so a key file can never
 * point it at another key. The signature covers signedData: a domain string, the wrapper's context,
 * and every byte before the signing key version.
 */

export const MAGIC = new Uint8Array([0x48, 0x47, 0x4b, 0x56]); // "HGKV"
export const FORMAT_VERSION = 1;
export const KEY_VERSION_LENGTH = 16;
export const SIGNATURE_LENGTH = 64;

/** Magic, format version, wrapping key version and ciphertext length. */
export const HEADER_LENGTH = 4 + 1 + KEY_VERSION_LENGTH + 2;

/** Everything besides the RSA ciphertext. */
export const OVERHEAD = HEADER_LENGTH + KEY_VERSION_LENGTH + SIGNATURE_LENGTH;

const MAX_FIELD_LENGTH = 0xffff;
const DOMAIN = new TextEncoder().encode('HkdfGuard-AzureKeyVault-wrap-v1\0');
const HEX_VERSION = /^[0-9A-Fa-f]{32}$/;

/** Makes the error a malformed envelope or Key Vault answer fails with: the wrapper's AzureKeyVaultError. */
export type Fail = (message: string) => Error;

/** A parsed envelope: the parts, and where the signed part ends. */
export interface Parts {
  readonly wrappingKeyVersion: string;
  readonly wrappedDek: Uint8Array;
  readonly signingKeyVersion: string;
  readonly signature: Uint8Array;
  readonly unsignedLength: number;
}

/**
 * The header and ciphertext: everything the signature covers besides the domain and context.
 *
 * @throws the `fail` error: the version isn't Key Vault's form, or the ciphertext is empty or too long to encode.
 */
export function buildUnsigned(wrappingKeyVersion: string | undefined, wrappedDek: Uint8Array, fail: Fail): Uint8Array {
  if (wrappedDek.length === 0 || wrappedDek.length > MAX_FIELD_LENGTH) throw fail(`Azure Key Vault returned a ${wrappedDek.length}-byte wrapped key.`);
  const version = versionBytes(wrappingKeyVersion, fail);
  const unsigned = new Uint8Array(HEADER_LENGTH + wrappedDek.length);
  unsigned.set(MAGIC, 0);
  unsigned[4] = FORMAT_VERSION;
  unsigned.set(version, 5);
  new DataView(unsigned.buffer).setUint16(21, wrappedDek.length);
  unsigned.set(wrappedDek, HEADER_LENGTH);
  return unsigned;
}

/** What the signing key signs: the domain, the length-prefixed context, then `unsigned`. */
export function signedData(unsigned: Uint8Array, context: Uint8Array): Uint8Array {
  const data = new Uint8Array(DOMAIN.length + 2 + context.length + unsigned.length);
  data.set(DOMAIN, 0);
  new DataView(data.buffer).setUint16(DOMAIN.length, context.length);
  data.set(context, DOMAIN.length + 2);
  data.set(unsigned, DOMAIN.length + 2 + context.length);
  return data;
}

/**
 * Writes the complete envelope into `result`, resolving to the number of bytes written.
 *
 * @throws InvalidArgumentError `result` is too small.
 * @throws the `fail` error: the version or signature isn't the expected form.
 */
export function write(unsigned: Uint8Array, signingKeyVersion: string | undefined, signature: Uint8Array, result: Uint8Array, fail: Fail): number {
  if (signature.length !== SIGNATURE_LENGTH) {
    throw fail(`Azure Key Vault returned a ${signature.length}-byte signature; an ES256 signature is ${SIGNATURE_LENGTH}. `
      + 'The signing key must be an EC P-256 key.');
  }
  // Checked before anything is written, so a refused version leaves result as it was.
  const version = versionBytes(signingKeyVersion, fail);
  const length = unsigned.length + KEY_VERSION_LENGTH + SIGNATURE_LENGTH;
  if (length > result.length) throw new InvalidArgumentError(`The wrapped DEK is ${length} bytes; result holds ${result.length}.`);
  result.set(unsigned, 0);
  result.set(version, unsigned.length);
  result.set(signature, unsigned.length + KEY_VERSION_LENGTH);
  return length;
}

/**
 * Splits an envelope into its parts, refusing anything that isn't exactly one. The parts are copies.
 *
 * @throws the `fail` error: it isn't.
 */
export function parse(envelope: Uint8Array, fail: Fail): Parts {
  if (envelope.length < OVERHEAD + 1 || !MAGIC.every((byte, i) => envelope[i] === byte)) {
    throw fail('This is not a wrapped DEK written by AzureKeyVaultKeyWrapper.');
  }
  if (envelope[4] !== FORMAT_VERSION) throw fail(`This wrapped DEK is format version ${envelope[4]}; only version ${FORMAT_VERSION} is supported.`);

  const wrappedLength = (envelope[21]! << 8) | envelope[22]!;
  if (wrappedLength === 0 || envelope.length !== OVERHEAD + wrappedLength) {
    throw fail(`This wrapped DEK is ${envelope.length} bytes, but its header describes ${OVERHEAD + wrappedLength}.`);
  }

  const unsignedLength = HEADER_LENGTH + wrappedLength;
  return {
    wrappingKeyVersion: hex(envelope.subarray(5, 5 + KEY_VERSION_LENGTH)),
    wrappedDek: envelope.slice(HEADER_LENGTH, unsignedLength),
    signingKeyVersion: hex(envelope.subarray(unsignedLength, unsignedLength + KEY_VERSION_LENGTH)),
    signature: envelope.slice(unsignedLength + KEY_VERSION_LENGTH),
    unsignedLength,
  };
}

/**
 * The UTF-8 bytes of a context, refusing one too long to length-prefix, or one that isn't well-formed
 * text (a lone surrogate), which TextEncoder would quietly replace and .NET would encode differently.
 * Omitted and empty are the same: no context.
 *
 * @throws InvalidArgumentError it is, or it isn't a string.
 */
export function encodeContext(context: string | undefined): Uint8Array {
  if (context === undefined || context === null) return new Uint8Array(0);
  if (typeof context !== 'string') throw new InvalidArgumentError('context must be a string.');
  if (!isWellFormed(context)) throw new InvalidArgumentError('The context isn\'t well-formed text: it holds a lone surrogate.');
  const encoded = new TextEncoder().encode(context);
  if (encoded.length > MAX_FIELD_LENGTH) {
    throw new InvalidArgumentError(`The context is ${encoded.length} bytes in UTF-8; at most ${MAX_FIELD_LENGTH} are allowed.`);
  }
  return encoded;
}

// Key Vault key versions are 32 hex digits; stored as the 16 bytes they spell.
function versionBytes(version: string | undefined, fail: Fail): Uint8Array {
  if (typeof version !== 'string' || !HEX_VERSION.test(version)) {
    throw fail(`Azure Key Vault returned key version ${JSON.stringify(version) ?? 'undefined'}, not 32 hex digits.`);
  }
  return new Uint8Array(Buffer.from(version, 'hex'));
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.length).toString('hex');
}

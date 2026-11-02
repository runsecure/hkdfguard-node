// Base64 (RFC 4648, standard alphabet, padded) straight between byte buffers - so a DEK encoded into
// a request body, or decoded out of Vault's answer, never passes through a string, as
// Buffer.toString('base64') and Buffer.from(text, 'base64') would make it. The counterparts of
// .NET's Base64.EncodeToUtf8 and Base64.DecodeFromUtf8.

const ALPHABET = new TextEncoder().encode('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/');
const PAD = 0x3d; // =

// Each byte's 6-bit value, or -1 for a byte outside the alphabet.
const VALUES = new Int8Array(256).fill(-1);
ALPHABET.forEach((byte, value) => { VALUES[byte] = value; });

/** The length of `length` bytes base64-encoded, padding included. */
export function encodedLength(length: number): number {
  return Math.ceil(length / 3) * 4;
}

/**
 * Encodes `source` into `destination` from `offset`, padded, and returns the offset just past it.
 * `destination` must hold {@link encodedLength} bytes from `offset`.
 */
export function encodeInto(source: Uint8Array, destination: Uint8Array, offset: number): number {
  let o = offset;
  let i = 0;
  for (; i + 3 <= source.length; i += 3) {
    const n = (source[i]! << 16) | (source[i + 1]! << 8) | source[i + 2]!;
    destination[o++] = ALPHABET[n >>> 18]!;
    destination[o++] = ALPHABET[(n >>> 12) & 63]!;
    destination[o++] = ALPHABET[(n >>> 6) & 63]!;
    destination[o++] = ALPHABET[n & 63]!;
  }
  const rest = source.length - i;
  if (rest > 0) {
    const n = (source[i]! << 16) | (rest === 2 ? source[i + 1]! << 8 : 0);
    destination[o++] = ALPHABET[n >>> 18]!;
    destination[o++] = ALPHABET[(n >>> 12) & 63]!;
    destination[o++] = rest === 2 ? ALPHABET[(n >>> 6) & 63]! : PAD;
    destination[o++] = PAD;
  }
  return o;
}

/**
 * Decodes `source` - padded base64, a multiple of four characters, '=' only as its last one or two -
 * into `destination`, which must hold three bytes for every four characters. Returns the number of
 * bytes written, or -1 (having written nothing that isn't zeroed by the caller anyway) if `source`
 * isn't base64.
 */
export function decodeInto(source: Uint8Array, destination: Uint8Array): number {
  if (source.length % 4 !== 0) return -1;
  let padding = 0;
  if (source.length > 0 && source[source.length - 1] === PAD) padding = source[source.length - 2] === PAD ? 2 : 1;

  let written = 0;
  for (let i = 0; i < source.length; i += 4) {
    const last = i + 4 === source.length;
    const a = VALUES[source[i]!]!, b = VALUES[source[i + 1]!]!;
    const c = last && padding === 2 ? 0 : VALUES[source[i + 2]!]!;
    const d = last && padding >= 1 ? 0 : VALUES[source[i + 3]!]!;
    if ((a | b | c | d) < 0) return -1;

    const n = (a << 18) | (b << 12) | (c << 6) | d;
    destination[written++] = n >>> 16;
    if (!(last && padding === 2)) destination[written++] = (n >>> 8) & 0xff;
    if (!(last && padding >= 1)) destination[written++] = n & 0xff;
  }
  return written;
}

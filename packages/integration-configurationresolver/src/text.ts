// How text and keys are read, exactly as .NET reads them. Not exported from the package.
import { wipe } from '@runsecure/hkdfguard-abstractions';

// Non-fatal: each ill-formed sequence becomes U+FFFD, replacing the same maximal subparts .NET's
// decoder does. ignoreBOM keeps a leading U+FEFF, as Encoding.UTF8.GetString does.
const utf8Decoder = new TextDecoder('utf-8', { ignoreBOM: true });
const utf8Encoder = new TextEncoder();

/**
 * .NET's char.IsWhiteSpace, which string.Trim removes: U+0009-U+000D, U+0020, U+0085, U+00A0 and the
 * Zs, Zl and Zp characters. JavaScript's String.prototype.trim also removes U+FEFF and keeps U+0085,
 * so it isn't used.
 */
function isDotNetWhiteSpace(c: number): boolean {
  return (c >= 0x09 && c <= 0x0d) || c === 0x20 || c === 0x85 || c === 0xa0 || c === 0x1680
    || (c >= 0x2000 && c <= 0x200a) || c === 0x2028 || c === 0x2029 || c === 0x202f || c === 0x205f || c === 0x3000;
}

/** `s` trimmed as .NET's string.Trim trims it. */
export function trimDotNet(s: string): string {
  let start = 0;
  let end = s.length;
  while (start < end && isDotNetWhiteSpace(s.charCodeAt(start))) start++;
  while (end > start && isDotNetWhiteSpace(s.charCodeAt(end - 1))) end--;
  return start === 0 && end === s.length ? s : s.slice(start, end);
}

/** The key of the item whose UTF-8 text is `text[start, end)`: decoded as .NET decodes it, then trimmed. */
export function itemKey(text: Uint8Array, start: number, end: number): string {
  return trimDotNet(utf8Decoder.decode(text.subarray(start, end)));
}

/** `bytes` decoded as UTF-8, as .NET's Encoding.UTF8.GetString decodes them. */
export function decodeUtf8(bytes: Uint8Array): string {
  return utf8Decoder.decode(bytes);
}

/**
 * `text` as UTF-8 bytes, and whether they are a copy the caller zeroes. A string is encoded as every
 * port encodes it (an unpaired surrogate becomes U+FFFD); a Uint8Array is used as it is.
 * @throws TypeError text is neither
 */
export function utf8Of(text: string | Uint8Array, name: string): { bytes: Uint8Array; owned: boolean } {
  if (typeof text === 'string') return { bytes: utf8Encoder.encode(text), owned: true };
  if (text instanceof Uint8Array) return { bytes: text, owned: false };
  throw new TypeError(`${name} must be a string or a Uint8Array.`);
}

/** The sequence as UTF-8 bytes, or an empty array for none. */
export function utf8Sequence(sequence: string | undefined): Uint8Array {
  return sequence === undefined ? new Uint8Array(0) : utf8Encoder.encode(sequence);
}

/** The first index at or after `from` where `needle` (never empty) starts in `haystack`, or -1. */
export function indexOf(haystack: Uint8Array, needle: Uint8Array, from: number): number {
  return Buffer.from(haystack.buffer, haystack.byteOffset, haystack.byteLength).indexOf(needle, from);
}

/** Whether `text[from, end)` ends with `suffix`, which is never empty. */
export function endsWith(text: Uint8Array, suffix: Uint8Array, from: number, end: number): boolean {
  const start = end - suffix.length;
  if (start < from) return false;
  for (let i = 0; i < suffix.length; i++) {
    if (text[start + i] !== suffix[i]) return false;
  }
  return true;
}

// The byte order marks a .NET StreamReader detects, longest first where one starts another.
const BOMS: readonly (readonly [readonly number[], string])[] = [
  [[0xff, 0xfe, 0x00, 0x00], 'utf-32le'],
  [[0x00, 0x00, 0xfe, 0xff], 'utf-32be'],
  [[0xef, 0xbb, 0xbf], 'utf-8'],
  [[0xff, 0xfe], 'utf-16le'],
  [[0xfe, 0xff], 'utf-16be'],
];

/**
 * `data`, read from a stream, as a .NET StreamReader that detects byte order marks reads it: a UTF-8,
 * UTF-16 or UTF-32 byte order mark selects that encoding and is dropped; without one the text is in
 * `encoding` (a WHATWG encoding label, or "utf-32le" or "utf-32be"), UTF-8 by default. Ill-formed
 * input becomes U+FFFD.
 * @throws RangeError encoding isn't an encoding Node can decode
 */
export function decodeStreamText(data: Uint8Array, encoding: string | undefined): string {
  for (const [bom, bomEncoding] of BOMS) {
    if (data.length >= bom.length && bom.every((byte, i) => data[i] === byte)) {
      return decode(data.subarray(bom.length), bomEncoding);
    }
  }
  return decode(data, encoding ?? 'utf-8');
}

function decode(data: Uint8Array, encoding: string): string {
  const label = encoding.trim().toLowerCase();
  if (label === 'utf-32le' || label === 'utf-32' || label === 'utf32') return decodeUtf32(data, true);
  if (label === 'utf-32be') return decodeUtf32(data, false);
  return new TextDecoder(label, { ignoreBOM: true }).decode(data);
}

// Node's TextDecoder has no UTF-32; this one replaces what .NET's UTF32Encoding replaces.
function decodeUtf32(data: Uint8Array, littleEndian: boolean): string {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const parts: string[] = [];
  let i = 0;
  for (; i + 4 <= data.length; i += 4) {
    const c = view.getUint32(i, littleEndian);
    parts.push(c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff) ? '�' : String.fromCodePoint(c));
  }
  if (i < data.length) parts.push('�');
  return parts.join('');
}

/** Reads `stream` to its end into one buffer, which the caller zeroes. */
export async function readAll(stream: AsyncIterable<Uint8Array> | Iterable<Uint8Array>): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for await (const chunk of stream) {
      if (!(chunk instanceof Uint8Array)) throw new TypeError('stream must yield Uint8Array chunks; read it without an encoding.');
      const copy = Uint8Array.from(chunk);
      chunks.push(copy);
      length += copy.length;
    }
    const all = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      all.set(chunk, offset);
      offset += chunk.length;
    }
    return all;
  } finally {
    for (const chunk of chunks) wipe(chunk);
  }
}

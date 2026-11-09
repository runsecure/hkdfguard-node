// A small BER/DER reader, and a DER writer for what isn't secret - enough for PKCS#12, PKCS#8 and an
// X.509 certificate's names and validity - shared by the PKCS#12 reader here and the certificate package.
//
// The reader never copies: every element is a subarray of the buffer it was read from, so decrypted
// contents are parsed where they lie and wiped once used. It reads BER as well as DER - indefinite
// lengths and constructed strings, as NSS and older Java tools write PKCS#12 files - and octets()
// joins a constructed OCTET STRING's segments into a new buffer the caller wipes. Exported from the
// internal index as `der`, never from the package index.
import { wipe } from '../rules.js';

export const INTEGER = 0x02;
export const BIT_STRING = 0x03;
export const OCTET_STRING = 0x04;
export const NULL = 0x05;
export const OBJECT_IDENTIFIER = 0x06;
export const UTF8_STRING = 0x0c;
export const VISIBLE_STRING = 0x1a;
export const SEQUENCE = 0x30;
export const SET = 0x31;
export const CONTEXT_0 = 0xa0; // [0], constructed

const CONSTRUCTED = 0x20;
const MAX_DEPTH = 32;

/** The bytes aren't the ASN.1 they were read as. */
export class DerError extends Error {}

/** One element: its identifier octet, its contents (for an indefinite length, up to its end-of-contents), and its whole encoding. */
export interface Element {
  readonly tag: number;
  readonly constructed: boolean;
  readonly contents: Buffer;
  readonly encoding: Buffer;
  readonly depth: number;
}

/** The one element `data` holds, refusing anything after it. */
export function read(data: Uint8Array): Element {
  const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  const { element, end } = readAt(buffer, 0, 0);
  if (end !== buffer.length) throw new DerError('There is data after the element.');
  return element;
}

function readAt(buffer: Buffer, offset: number, depth: number): { element: Element; end: number } {
  if (depth > MAX_DEPTH) throw new DerError('The elements are nested too deep.');
  if (offset + 2 > buffer.length) throw new DerError('An element is truncated.');
  const tag = buffer[offset]!;
  if ((tag & 0x1f) === 0x1f) throw new DerError('A multi-byte tag.');
  const constructed = (tag & CONSTRUCTED) !== 0;
  let position = offset + 1;
  const first = buffer[position++]!;
  if (first === 0x80) {
    // An indefinite length (BER): constructed only, its elements up to the end-of-contents octets 00 00.
    if (!constructed) throw new DerError('A primitive element has an indefinite length.');
    let cursor = position;
    for (;;) {
      if (cursor + 2 > buffer.length) throw new DerError('An indefinite length has no end-of-contents.');
      if (buffer[cursor] === 0 && buffer[cursor + 1] === 0) break;
      cursor = readAt(buffer, cursor, depth + 1).end;
    }
    return {
      element: { tag, constructed, contents: buffer.subarray(position, cursor), encoding: buffer.subarray(offset, cursor + 2), depth },
      end: cursor + 2,
    };
  }
  let length = first;
  if (first > 0x80) {
    const count = first & 0x7f;
    if (count > 4 || position + count > buffer.length) throw new DerError('A length is too long or truncated.');
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + buffer[position++]!;
  }
  const end = position + length;
  if (end > buffer.length) throw new DerError('An element is longer than its data.');
  return { element: { tag, constructed, contents: buffer.subarray(position, end), encoding: buffer.subarray(offset, end), depth }, end };
}

/** The elements a constructed element holds. */
export function children(element: Element): Element[] {
  if (!element.constructed) throw new DerError(`A primitive element (tag 0x${hex(element.tag)}) holds no elements.`);
  const result: Element[] = [];
  for (let offset = 0; offset < element.contents.length;) {
    const { element: child, end } = readAt(element.contents, offset, element.depth + 1);
    result.push(child);
    offset = end;
  }
  return result;
}

/** `element`, if it has `tag`. */
export function expect(element: Element | undefined, tag: number, what: string): Element {
  if (element === undefined) throw new DerError(`${what} is missing.`);
  if (element.tag !== tag) throw new DerError(`${what} isn't tag 0x${hex(tag)} but 0x${hex(element.tag)}.`);
  return element;
}

/** A SEQUENCE's elements, between `minimum` and `maximum` of them. */
export function sequence(element: Element | undefined, what: string, minimum = 0, maximum = Infinity): Element[] {
  const items = children(expect(element, SEQUENCE, what));
  if (items.length < minimum || items.length > maximum) throw new DerError(`${what} has ${items.length} elements.`);
  return items;
}

/** An explicitly tagged element's one child. */
export function only(element: Element | undefined, tag: number, what: string): Element {
  const items = children(expect(element, tag, what));
  if (items.length !== 1) throw new DerError(`${what} isn't one element.`);
  return items[0]!;
}

/** An OBJECT IDENTIFIER, dotted. */
export function oid(element: Element | undefined): string {
  const data = expect(element, OBJECT_IDENTIFIER, 'An object identifier').contents;
  if (data.length === 0 || (data[data.length - 1]! & 0x80) !== 0) throw new DerError('An object identifier is malformed.');
  const arcs: number[] = [];
  let value = 0;
  for (const octet of data) {
    value = value * 128 + (octet & 0x7f);
    if (value > Number.MAX_SAFE_INTEGER / 128) throw new DerError('An object identifier arc is too large.');
    if ((octet & 0x80) === 0) {
      arcs.push(value);
      value = 0;
    }
  }
  const head = arcs[0]!;
  const start = head < 40 ? [0, head] : head < 80 ? [1, head - 40] : [2, head - 80];
  return [...start, ...arcs.slice(1)].join('.');
}

/** A small non-negative INTEGER (up to 2^48). */
export function integer(element: Element | undefined, what: string): number {
  const data = expect(element, INTEGER, what).contents;
  if (data.length === 0) throw new DerError(`${what} is empty.`);
  if ((data[0]! & 0x80) !== 0) throw new DerError(`${what} is negative.`);
  let start = 0;
  while (start < data.length - 1 && data[start] === 0) start++;
  if (data.length - start > 6) throw new DerError(`${what} is too large.`);
  return data.readUIntBE(start, data.length - start);
}

/**
 * An OCTET STRING's bytes - or a string's with another (implicit) tag number - joined from its
 * segments when it is constructed, as BER allows: always a new buffer the caller wipes, sized once.
 */
export function octets(element: Element | undefined, what: string, tag = OCTET_STRING): Buffer {
  if (element === undefined) throw new DerError(`${what} is missing.`);
  if ((element.tag & ~CONSTRUCTED) !== (tag & ~CONSTRUCTED)) throw new DerError(`${what} isn't tag 0x${hex(tag)} but 0x${hex(element.tag)}.`);
  if (!element.constructed) {
    const copy = Buffer.alloc(element.contents.length);
    element.contents.copy(copy);
    return copy;
  }
  const segments: Buffer[] = [];
  try {
    collect(element, what, segments, 0);
    const out = Buffer.alloc(segments.reduce((total, segment) => total + segment.length, 0));
    let written = 0;
    for (const segment of segments) written += segment.copy(out, written);
    return out;
  } finally {
    for (const segment of segments) wipe(segment);
  }
}

function collect(element: Element, what: string, into: Buffer[], depth: number): void {
  if (depth > MAX_DEPTH) throw new DerError(`${what} is nested too deep.`);
  for (const segment of children(element)) {
    if ((segment.tag & ~CONSTRUCTED) !== OCTET_STRING) throw new DerError(`${what} has a segment that isn't an OCTET STRING.`);
    if (segment.constructed) collect(segment, what, into, depth + 1);
    else into.push(octets(segment, what));
  }
}

/** An AlgorithmIdentifier: its OID and its parameters, if any. */
export function algorithm(element: Element | undefined, what: string): { oid: string; parameters: Element | undefined } {
  const items = sequence(element, what, 1, 2);
  return { oid: oid(items[0]), parameters: items[1] };
}

function hex(tag: number): string {
  return tag.toString(16).toUpperCase().padStart(2, '0');
}

// --- Writing DER, for what isn't secret ---------------------------------------------------------

/** One element, DER: `tag`, a definite length, `contents`. */
export function encode(tag: number, ...contents: Uint8Array[]): Buffer {
  const body = Buffer.concat(contents);
  const length = body.length;
  let header: Buffer;
  if (length < 0x80) {
    header = Buffer.from([tag, length]);
  } else {
    const bytes: number[] = [];
    for (let rest = length; rest > 0; rest = Math.floor(rest / 256)) bytes.unshift(rest & 0xff);
    header = Buffer.from([tag, 0x80 | bytes.length, ...bytes]);
  }
  return Buffer.concat([header, body]);
}

/** An OBJECT IDENTIFIER, DER. */
export function encodeOid(dotted: string): Buffer {
  const arcs = dotted.split('.').map(Number);
  const body: number[] = [];
  for (const arc of [arcs[0]! * 40 + arcs[1]!, ...arcs.slice(2)]) {
    const chunk = [arc & 0x7f];
    for (let rest = Math.floor(arc / 128); rest > 0; rest = Math.floor(rest / 128)) chunk.unshift(0x80 | (rest & 0x7f));
    body.push(...chunk);
  }
  return encode(OBJECT_IDENTIFIER, Buffer.from(body));
}

/** A non-negative INTEGER, DER. */
export function encodeInteger(value: number | bigint): Buffer {
  let n = BigInt(value);
  const bytes: number[] = [];
  do {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  } while (n > 0n);
  if ((bytes[0]! & 0x80) !== 0) bytes.unshift(0);
  return encode(INTEGER, Buffer.from(bytes));
}

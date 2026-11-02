// A strict, forward-only JSON reader over bytes, for taking secrets out of JSON without ever making
// one a string. Shared by HkdfGuard's own packages: the cache's SecretJsonBody, ErrorResponseBody and
// SecretValueSink.setBytesWithJsonKeys, and the Vault transit wrapper, read through it.
import { wipe } from '../rules.js';

export const enum JsonToken {
  StartObject,
  EndObject,
  StartArray,
  EndArray,
  PropertyName,
  String,
  Number,
  True,
  False,
  Null,
}

const QUOTE = 0x22;
const BACKSLASH = 0x5c;
const NEWLINE = 0x0a;

const encoder = new TextEncoder();
const decoder = new TextDecoder(); // not fatal: invalid UTF-8 becomes U+FFFD

const isWhitespace = (b: number) => b === 0x20 || b === 0x09 || b === 0x0d || b === NEWLINE;
const isDelimiter = (b: number) => isWhitespace(b) || b === 0x2c || b === 0x7d || b === 0x5d; // , } ]
const isDigit = (b: number) => b >= 0x30 && b <= 0x39;

/** What each simple escape's character stands for, by that character. */
const SIMPLE_ESCAPES = new Map<number, number>([
  [0x22, 0x22], [0x5c, 0x5c], [0x2f, 0x2f], [0x62, 0x08], [0x66, 0x0c], [0x6e, 0x0a], [0x72, 0x0d], [0x74, 0x09],
]);

/** Malformed JSON, at `position` bytes into line `line` (both from 0). Says where, never quotes what. */
export class MalformedJsonError extends Error {
  constructor(readonly position: number, readonly line: number) {
    super(`Malformed JSON at byte ${position} of line ${line}.`);
    this.name = 'MalformedJsonError';
  }
}

/**
 * A forward-only reader over UTF-8 JSON (RFC 8259) held in a Uint8Array, for taking secrets out of
 * it without ever making one a string: a string token is reported by where its escaped text lies,
 * and unescaped only into a buffer the caller provides ({@link copyString}). The counterpart of
 * .NET's Utf8JsonReader, as strict: no comments, trailing commas, leading zeros or unescaped control
 * characters, nesting at most `maxDepth` ({@link MAX_DEPTH} by default) deep, and nothing but whitespace after the root
 * value. A \u escape must be a whole code point - a surrogate pair, never half of one. Duplicate
 * property names are reported as they are, for the caller to decide about. Malformed JSON throws
 * {@link MalformedJsonError}, which says where but never quotes it. The input is read in place,
 * never copied.
 */
export class JsonReader {
  /** The deepest nesting of objects and arrays read, unless the constructor is given less. */
  static readonly MAX_DEPTH = 64;

  readonly #json: Uint8Array;
  readonly #end: number;
  readonly #maxDepth: number;
  // Whether each open container is an object (true) or an array.
  readonly #containers: boolean[] = [];
  #position = 0;
  #line = 0;
  #lineStart = 0;
  #token: JsonToken | undefined;
  #tokenStart = 0;
  #valueStart = 0;
  #valueEnd = 0;
  #valueEscaped = false;
  #rootDone = false;

  /** A reader over json[0, length) - all of it when length is omitted - nesting at most `maxDepth` deep. */
  constructor(json: Uint8Array, length = json.length, maxDepth = JsonReader.MAX_DEPTH) {
    this.#json = json;
    this.#end = length;
    this.#maxDepth = maxDepth;
  }

  /** The token last read; undefined before the first. A method, not a getter, since every read changes it. */
  token(): JsonToken | undefined {
    return this.#token;
  }

  /** Where the token last read starts: a string's opening quote. */
  get tokenStart(): number {
    return this.#tokenStart;
  }

  /** Where the token last read ends: just past a string's closing quote. */
  get bytesConsumed(): number {
    return this.#position;
  }

  /** The length of a string's escaped text, or of a number's or literal's. */
  get valueLength(): number {
    return this.#valueEnd - this.#valueStart;
  }

  /**
   * Reads the next token; false at the end of the input, once the root value is complete (or before
   * it starts, for empty input).
   * @throws MalformedJsonError the input isn't JSON, or holds anything but whitespace after the root value
   */
  read(): boolean {
    this.#skipWhitespace();
    if (this.#position >= this.#end) {
      if (this.#token !== undefined && !this.#rootDone) throw this.#malformed(this.#position);
      return false;
    }
    if (this.#rootDone) throw this.#malformed(this.#position);

    const containers = this.#containers;
    if (containers.length === 0) this.#readValue();
    else if (containers[containers.length - 1]) this.#readInObject();
    else this.#readInArray();
    return true;
  }

  /** Skips the children of the object or array just started, leaving the reader at its end; does nothing after any other token. */
  skip(): void {
    if (this.#token !== JsonToken.StartObject && this.#token !== JsonToken.StartArray) return;
    const target = this.#containers.length - 1;
    while (this.#containers.length > target) this.read();
  }

  /** Whether the string or property name just read is, unescaped, exactly `text` - for matching property names, never secrets. */
  valueTextEquals(text: string): boolean {
    const expected = encoder.encode(text);
    if (!this.#valueEscaped) return equalBytes(this.#json.subarray(this.#valueStart, this.#valueEnd), expected);

    const unescaped = new Uint8Array(this.valueLength);
    try {
      return equalBytes(unescaped.subarray(0, this.copyString(unescaped)), expected);
    } finally {
      wipe(unescaped);
    }
  }

  /**
   * Unescapes the string or property name just read into `destination`, which must hold at least
   * {@link valueLength} bytes - unescaped, a string is never longer than it is escaped. Returns the
   * number of bytes written.
   */
  copyString(destination: Uint8Array): number {
    const json = this.#json;
    const start = this.#valueStart, end = this.#valueEnd;
    if (!this.#valueEscaped) {
      destination.set(json.subarray(start, end));
      return end - start;
    }

    let written = 0;
    let i = start;
    while (i < end) {
      const b = json[i]!;
      if (b !== BACKSLASH) {
        destination[written++] = b;
        i++;
        continue;
      }

      const escaped = json[i + 1]!;
      i += 2;
      if (escaped !== 0x75) { // u
        destination[written++] = SIMPLE_ESCAPES.get(escaped)!;
        continue;
      }

      let codePoint = this.#hex(i);
      i += 4;
      if (codePoint >= 0xd800 && codePoint <= 0xdbff) {
        codePoint = 0x10000 + ((codePoint - 0xd800) << 10) + (this.#hex(i + 2) - 0xdc00);
        i += 6;
      }
      written = writeUtf8(codePoint, destination, written);
    }
    return written;
  }

  /** Copies the number or literal just read, as its JSON text, into `destination`; returns the bytes written. */
  copyRaw(destination: Uint8Array): number {
    destination.set(this.#json.subarray(this.#valueStart, this.#valueEnd));
    return this.valueLength;
  }

  /**
   * The string or property name just read, as a string: only for text that isn't secret, such as a
   * property name or an error message. Invalid UTF-8 becomes U+FFFD.
   */
  getString(): string {
    const unescaped = new Uint8Array(this.valueLength);
    try {
      return decoder.decode(unescaped.subarray(0, this.copyString(unescaped)));
    } finally {
      wipe(unescaped);
    }
  }

  #readInObject(): void {
    if (this.#token === JsonToken.PropertyName) {
      this.#expect(0x3a); // :
      this.#readValue();
    } else if (this.#json[this.#position] === 0x7d) { // }
      this.#close(JsonToken.EndObject);
    } else {
      if (this.#token !== JsonToken.StartObject) this.#expect(0x2c); // ,
      if (this.#position >= this.#end || this.#json[this.#position] !== QUOTE) throw this.#malformed(this.#position);
      this.#readString(JsonToken.PropertyName);
    }
  }

  #readInArray(): void {
    if (this.#json[this.#position] === 0x5d) { // ]
      this.#close(JsonToken.EndArray);
    } else {
      if (this.#token !== JsonToken.StartArray) this.#expect(0x2c); // ,
      this.#readValue();
    }
  }

  #readValue(): void {
    if (this.#position >= this.#end) throw this.#malformed(this.#position);
    switch (this.#json[this.#position]) {
      case 0x7b: this.#open(true, JsonToken.StartObject); break; // {
      case 0x5b: this.#open(false, JsonToken.StartArray); break; // [
      case QUOTE: this.#readString(JsonToken.String); break;
      case 0x74: this.#readLiteral('true', JsonToken.True); break;
      case 0x66: this.#readLiteral('false', JsonToken.False); break;
      case 0x6e: this.#readLiteral('null', JsonToken.Null); break;
      default: this.#readNumber();
    }
  }

  #open(isObject: boolean, opened: JsonToken): void {
    if (this.#containers.length === this.#maxDepth) throw this.#malformed(this.#position);
    this.#containers.push(isObject);
    this.#tokenStart = this.#position++;
    this.#token = opened;
  }

  #close(closed: JsonToken): void {
    this.#containers.pop();
    this.#tokenStart = this.#position++;
    this.#token = closed;
    this.#rootDone = this.#containers.length === 0;
  }

  #readString(read: JsonToken): void {
    const json = this.#json;
    this.#tokenStart = this.#position;
    let escaped = false;
    let i = this.#position + 1;
    for (;;) {
      if (i >= this.#end) throw this.#malformed(this.#end);
      const b = json[i]!;
      if (b === QUOTE) break;
      if (b < 0x20) throw this.#malformed(i);
      if (b === BACKSLASH) {
        escaped = true;
        i = this.#checkEscape(i + 1);
      } else {
        i++;
      }
    }

    this.#valueStart = this.#tokenStart + 1;
    this.#valueEnd = i;
    this.#valueEscaped = escaped;
    this.#position = i + 1;
    this.#token = read;
    this.#rootDone = read === JsonToken.String && this.#containers.length === 0;
  }

  // Checks the escape whose character is at i; returns the index just past it.
  #checkEscape(i: number): number {
    if (i >= this.#end) throw this.#malformed(i);
    const c = this.#json[i]!;
    if (SIMPLE_ESCAPES.has(c)) return i + 1;
    if (c !== 0x75) throw this.#malformed(i); // u

    const unit = this.#hexOrThrow(i + 1);
    if (unit >= 0xdc00 && unit <= 0xdfff) throw this.#malformed(i);
    if (unit < 0xd800 || unit > 0xdbff) return i + 5;

    // A high surrogate must be followed by an escaped low one.
    const following = i + 5;
    if (following + 1 >= this.#end || this.#json[following] !== BACKSLASH || this.#json[following + 1] !== 0x75) {
      throw this.#malformed(following);
    }
    const low = this.#hexOrThrow(following + 2);
    if (low < 0xdc00 || low > 0xdfff) throw this.#malformed(following + 1);
    return following + 6;
  }

  #hexOrThrow(i: number): number {
    if (i + 4 > this.#end) throw this.#malformed(Math.min(i, this.#end));
    let value = 0;
    for (let j = i; j < i + 4; j++) {
      const digit = hexDigit(this.#json[j]!);
      if (digit < 0) throw this.#malformed(j);
      value = value * 16 + digit;
    }
    return value;
  }

  // Four hex digits already checked by #checkEscape.
  #hex(i: number): number {
    let value = 0;
    for (let j = i; j < i + 4; j++) value = value * 16 + hexDigit(this.#json[j]!);
    return value;
  }

  #readLiteral(literal: string, read: JsonToken): void {
    this.#tokenStart = this.#position;
    for (let k = 0; k < literal.length; k++) {
      if (this.#position + k >= this.#end || this.#json[this.#position + k] !== literal.charCodeAt(k)) {
        throw this.#malformed(this.#position + k);
      }
    }

    this.#valueStart = this.#position;
    this.#valueEnd = this.#position + literal.length;
    this.#position = this.#valueEnd;
    this.#checkDelimiter();
    this.#token = read;
    this.#rootDone = this.#containers.length === 0;
  }

  // -?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)?
  #readNumber(): void {
    const json = this.#json, end = this.#end;
    this.#tokenStart = this.#position;
    let i = this.#position;
    if (json[i] === 0x2d) i++; // -

    if (i < end && json[i] === 0x30) i++; // 0
    else i = this.#digits(i);
    if (i < end && json[i] === 0x2e) i = this.#digits(i + 1); // .
    if (i < end && (json[i] === 0x65 || json[i] === 0x45)) { // e E
      i++;
      if (i < end && (json[i] === 0x2b || json[i] === 0x2d)) i++; // + -
      i = this.#digits(i);
    }

    this.#valueStart = this.#position;
    this.#valueEnd = i;
    this.#position = i;
    this.#checkDelimiter();
    this.#token = JsonToken.Number;
    this.#rootDone = this.#containers.length === 0;
  }

  // One or more digits from i; returns the index past them.
  #digits(i: number): number {
    if (i >= this.#end || !isDigit(this.#json[i]!)) throw this.#malformed(i);
    while (i < this.#end && isDigit(this.#json[i]!)) i++;
    return i;
  }

  // A number or literal must be followed by whitespace, a separator, a closing bracket or the end.
  #checkDelimiter(): void {
    if (this.#position < this.#end && !isDelimiter(this.#json[this.#position]!)) throw this.#malformed(this.#position);
  }

  #expect(c: number): void {
    if (this.#position >= this.#end || this.#json[this.#position] !== c) throw this.#malformed(this.#position);
    this.#position++;
    this.#skipWhitespace();
  }

  #skipWhitespace(): void {
    const json = this.#json, end = this.#end;
    while (this.#position < end && isWhitespace(json[this.#position]!)) {
      if (json[this.#position] === NEWLINE) {
        this.#line++;
        this.#lineStart = this.#position + 1;
      }
      this.#position++;
    }
  }

  #malformed(at: number): MalformedJsonError {
    return new MalformedJsonError(at - this.#lineStart, this.#line);
  }
}

function hexDigit(b: number): number {
  if (b >= 0x30 && b <= 0x39) return b - 0x30;
  if (b >= 0x61 && b <= 0x66) return b - 0x61 + 10;
  if (b >= 0x41 && b <= 0x46) return b - 0x41 + 10;
  return -1;
}

function writeUtf8(c: number, destination: Uint8Array, written: number): number {
  if (c < 0x80) {
    destination[written] = c;
    return written + 1;
  }
  if (c < 0x800) {
    destination[written] = 0xc0 | (c >> 6);
    destination[written + 1] = 0x80 | (c & 0x3f);
    return written + 2;
  }
  if (c < 0x10000) {
    destination[written] = 0xe0 | (c >> 12);
    destination[written + 1] = 0x80 | ((c >> 6) & 0x3f);
    destination[written + 2] = 0x80 | (c & 0x3f);
    return written + 3;
  }
  destination[written] = 0xf0 | (c >> 18);
  destination[written + 1] = 0x80 | ((c >> 12) & 0x3f);
  destination[written + 2] = 0x80 | ((c >> 6) & 0x3f);
  destination[written + 3] = 0x80 | (c & 0x3f);
  return written + 4;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

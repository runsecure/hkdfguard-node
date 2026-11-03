// The JSON a VaultClient reads Vault's answers into and writes request bodies with.
import { JsonReader, JsonToken, MalformedJsonError } from '@runsecure/hkdfguard-abstractions/internal';
import { SecureBuffer } from './body.js';
import { VaultJsonError } from './client-errors.js';

const MAX_DEPTH = 64;
const HEX = '0123456789abcdef';
const SHORT_ESCAPES = new Map<number, string>([[0x22, '\\"'], [0x5c, '\\\\'], [0x0a, '\\n'], [0x0d, '\\r'], [0x09, '\\t'], [0x08, '\\b'], [0x0c, '\\f']]);
const encoder = new TextEncoder();
// Go writes up to nine fractional digits; a Date holds three.
const FRACTION = /(\.\d{3})\d+/;
const RFC_3339 = /^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})?$/;

/** What kind of JSON value a {@link JsonValue} is. */
export const JsonKind = {
  null: 'null',
  string: 'string',
  number: 'number',
  boolean: 'boolean',
  object: 'object',
  array: 'array',
} as const;

/** A {@link JsonKind} value. */
export type JsonKind = (typeof JsonKind)[keyof typeof JsonKind];

const DESCRIBED: Record<JsonKind, string> = {
  null: 'null', string: 'a string', number: 'a number', boolean: 'a boolean', object: 'an object', array: 'an array',
};

/**
 * A JSON value from a Vault response: what the client returns where Vault's spec types a value
 * loosely (a secret's data, free-form metadata), and what the generated models are read from.
 * Immutable; objects keep their members in document order, the last of a repeated name winning.
 *
 * The `as...` methods are strict: each throws {@link VaultJsonError} for a value of another kind.
 * The `read...` methods are what the generated models read members with, as leniently as the other
 * ports: each returns undefined for JSON null, and accepts what Vault writes in place of what its
 * spec declares - a number or boolean where a string is declared (its text), an object or array
 * there (its JSON text), a number in a string where a number is declared.
 *
 * Strings are ordinary JavaScript strings, as in any API client. To read a secret into memory an
 * application uses, prefer @runsecure/hkdfguard-cache-hashicorpvault, which never makes one a string.
 */
export class JsonValue {
  /** JSON null; also what {@link member} returns for a member that isn't there. */
  static readonly NULL: JsonValue = new JsonValue(JsonKind.null);
  static readonly #TRUE = new JsonValue(JsonKind.boolean, undefined, true);
  static readonly #FALSE = new JsonValue(JsonKind.boolean, undefined, false);

  readonly #kind: JsonKind;
  // A string's value, or a number's JSON text.
  readonly #text: string | undefined;
  readonly #boolean: boolean;
  readonly #members: ReadonlyMap<string, JsonValue> | undefined;
  readonly #elements: readonly JsonValue[] | undefined;

  private constructor(kind: JsonKind, text?: string, boolean = false, members?: ReadonlyMap<string, JsonValue>, elements?: readonly JsonValue[]) {
    this.#kind = kind;
    this.#text = text;
    this.#boolean = boolean;
    this.#members = members;
    this.#elements = elements;
  }

  /** A string. */
  static of(value: string): JsonValue {
    if (typeof value !== 'string') throw new TypeError('value must be a string.');
    return new JsonValue(JsonKind.string, value);
  }

  /**
   * `json` - the first `length` bytes of a buffer, or a string - which must be one JSON value (RFC
   * 8259) and nothing else.
   * @throws VaultJsonError it isn't JSON
   */
  static parse(json: string | Uint8Array, length?: number): JsonValue {
    const data = typeof json === 'string' ? encoder.encode(json) : json;
    try {
      const reader = new JsonReader(data, length ?? data.length);
      if (!reader.read()) throw new VaultJsonError('Expected JSON, found nothing.');
      const value = JsonValue.readFrom(reader);
      if (reader.read()) throw new VaultJsonError('Expected one JSON value; more follows it.');
      return value;
    } catch (error) {
      if (error instanceof MalformedJsonError) throw new VaultJsonError(error.message);
      throw error;
    }
  }

  /** The value `reader` has just read the first token of, leaving the reader at its last token. */
  static readFrom(reader: JsonReader): JsonValue {
    switch (reader.token()) {
      case JsonToken.Null:
        return JsonValue.NULL;
      case JsonToken.True:
        return JsonValue.#TRUE;
      case JsonToken.False:
        return JsonValue.#FALSE;
      case JsonToken.String:
        return new JsonValue(JsonKind.string, reader.getString());
      case JsonToken.Number: {
        const raw = new Uint8Array(reader.valueLength);
        reader.copyRaw(raw);
        return new JsonValue(JsonKind.number, Buffer.from(raw).toString('latin1'));
      }
      case JsonToken.StartObject: {
        const members = new Map<string, JsonValue>();
        while (reader.read() && reader.token() === JsonToken.PropertyName) {
          const name = reader.getString();
          reader.read();
          // The last of a repeated name wins, in the place the first held.
          members.set(name, JsonValue.readFrom(reader));
        }
        return new JsonValue(JsonKind.object, undefined, false, members);
      }
      case JsonToken.StartArray: {
        const elements: JsonValue[] = [];
        while (reader.read() && reader.token() !== JsonToken.EndArray) elements.push(JsonValue.readFrom(reader));
        return new JsonValue(JsonKind.array, undefined, false, undefined, elements);
      }
      default:
        throw new VaultJsonError('Expected a JSON value.');
    }
  }

  get kind(): JsonKind {
    return this.#kind;
  }

  get isNull(): boolean {
    return this.#kind === JsonKind.null;
  }

  /** The member named `name` of an object; {@link NULL} if it has none, or this isn't an object. */
  member(name: string): JsonValue {
    return this.#members?.get(name) ?? JsonValue.NULL;
  }

  /**
   * This value, which must be an object.
   * @param what what it is read as, for the message, e.g. "KvV2ReadResponse"
   * @throws VaultJsonError it isn't an object
   */
  requireObject(what: string): this {
    if (this.#kind !== JsonKind.object) throw new VaultJsonError(`Expected a JSON object for ${what}, not ${DESCRIBED[this.#kind]}.`);
    return this;
  }

  // --- Strict ---------------------------------------------------------------------------------

  /** A string's value. */
  asString(): string {
    this.#expect(JsonKind.string);
    return this.#text!;
  }

  /** A number's value. */
  asNumber(): number {
    this.#expect(JsonKind.number);
    return Number(this.#text);
  }

  /** A number's value, which must be an integer, exactly: a bigint. */
  asBigInt(): bigint {
    this.#expect(JsonKind.number);
    return parseBigInt(this.#text);
  }

  /** A boolean's value. */
  asBoolean(): boolean {
    this.#expect(JsonKind.boolean);
    return this.#boolean;
  }

  /** An object's members, in document order. */
  asRecord(): Record<string, JsonValue> {
    this.#expect(JsonKind.object);
    return Object.fromEntries(this.#members!);
  }

  /** An array's elements. */
  asArray(): JsonValue[] {
    this.#expect(JsonKind.array);
    return [...this.#elements!];
  }

  // --- Lenient, for the generated models --------------------------------------------------------

  /** A string as it is; a number or boolean as its text; an object or array as its JSON text; undefined for null. */
  readString(): string | undefined {
    switch (this.#kind) {
      case JsonKind.null: return undefined;
      case JsonKind.string:
      case JsonKind.number: return this.#text;
      case JsonKind.boolean: return this.#boolean ? 'true' : 'false';
      default: return this.toString();
    }
  }

  /** A number, or a string holding one, that is an integer ("4.0" and "1e3" are); undefined for null. */
  readInteger(): number | undefined {
    switch (this.#kind) {
      case JsonKind.null: return undefined;
      case JsonKind.number:
      case JsonKind.string: {
        const value = Number((this.#text ?? '').trim());
        if ((this.#text ?? '').trim() === '' || !Number.isInteger(value)) throw new VaultJsonError('Expected an integer; the value isn\'t one.');
        return value;
      }
      default: throw this.#mismatch('an integer');
    }
  }

  /** A number, or a string holding one; undefined for null. */
  readNumber(): number | undefined {
    switch (this.#kind) {
      case JsonKind.null: return undefined;
      case JsonKind.number: return Number(this.#text);
      case JsonKind.string: {
        const text = (this.#text ?? '').trim();
        const value = Number(text);
        if (text === '' || !Number.isFinite(value)) throw new VaultJsonError('Expected a number; the string doesn\'t hold one.');
        return value;
      }
      default: throw this.#mismatch('a number');
    }
  }

  /** A boolean; undefined for null. */
  readBoolean(): boolean | undefined {
    if (this.#kind === JsonKind.null) return undefined;
    if (this.#kind !== JsonKind.boolean) throw this.#mismatch('a boolean');
    return this.#boolean;
  }

  /**
   * An RFC 3339 date-time as Vault (Go) writes it - fractional digits past three dropped, UTC
   * assumed without an offset; undefined for null or an empty string.
   */
  readDate(): Date | undefined {
    if (this.#kind === JsonKind.null) return undefined;
    if (this.#kind !== JsonKind.string) throw this.#mismatch('a date-time string');
    const text = this.#text ?? '';
    if (text === '') return undefined;
    if (!RFC_3339.test(text)) throw new VaultJsonError('Expected a date-time; the string isn\'t one.');
    const normalized = text.replace(FRACTION, '$1');
    const date = new Date(/([Zz]|[+-]\d{2}:\d{2})$/.test(normalized) ? normalized : `${normalized}Z`);
    if (Number.isNaN(date.getTime())) throw new VaultJsonError('Expected a date-time; the string isn\'t one.');
    return date;
  }

  /**
   * An array, each element read with `element`; undefined for null. An element that reads as
   * undefined (JSON null, where Vault writes a typed value) is refused: read an array that may hold
   * nulls with {@link readJsonArray} or {@link readUnknownArray}.
   */
  readArray<T>(element: (value: JsonValue) => T | undefined): T[] | undefined {
    if (this.#kind === JsonKind.null) return undefined;
    if (this.#kind !== JsonKind.array) throw this.#mismatch('an array');
    return this.#elements!.map((e) => required(element(e)));
  }

  /** An object, each member's value read with `value`; undefined for null. In document order; a value reading as undefined is refused. */
  readRecord<T>(value: (value: JsonValue) => T | undefined): Record<string, T> | undefined {
    if (this.#kind === JsonKind.null) return undefined;
    if (this.#kind !== JsonKind.object) throw this.#mismatch('an object');
    return Object.fromEntries([...this.#members!].map(([name, v]) => [name, required(value(v))]));
  }

  /** An object as its members' JSON values; undefined for null. */
  readJsonRecord(): Record<string, JsonValue> | undefined {
    if (this.#kind === JsonKind.null) return undefined;
    if (this.#kind !== JsonKind.object) throw this.#mismatch('an object');
    return Object.fromEntries(this.#members!);
  }

  /** An array as its elements' JSON values; undefined for null. */
  readJsonArray(): JsonValue[] | undefined {
    if (this.#kind === JsonKind.null) return undefined;
    if (this.#kind !== JsonKind.array) throw this.#mismatch('an array');
    return [...this.#elements!];
  }

  /** An object as plain JavaScript ({@link readUnknown}); undefined for null. */
  readUnknownRecord(): Record<string, unknown> | undefined {
    if (this.#kind === JsonKind.null) return undefined;
    if (this.#kind !== JsonKind.object) throw this.#mismatch('an object');
    return Object.fromEntries([...this.#members!].map(([name, v]) => [name, v.readUnknown()]));
  }

  /** An array as plain JavaScript ({@link readUnknown}); undefined for null. */
  readUnknownArray(): unknown[] | undefined {
    if (this.#kind === JsonKind.null) return undefined;
    if (this.#kind !== JsonKind.array) throw this.#mismatch('an array');
    return this.#elements!.map((e) => e.readUnknown());
  }

  /** This value read with `reader` - a model's read; undefined for null. */
  readModel<T>(reader: (json: JsonValue) => T | undefined): T | undefined {
    return this.#kind === JsonKind.null ? undefined : reader(this);
  }

  /** This value; undefined for null. */
  readJson(): JsonValue | undefined {
    return this.#kind === JsonKind.null ? undefined : this;
  }

  /**
   * This value as plain JavaScript: an object of values (in document order), an array, a string, a
   * number - a bigint for an integer a number can't hold exactly - a boolean, or null.
   */
  readUnknown(): unknown {
    switch (this.#kind) {
      case JsonKind.null: return null;
      case JsonKind.string: return this.#text;
      case JsonKind.boolean: return this.#boolean;
      case JsonKind.number: {
        const value = Number(this.#text);
        if (!Number.isSafeInteger(value) && /^-?\d+$/.test(this.#text!)) return BigInt(this.#text!);
        return value;
      }
      case JsonKind.object: return this.readUnknownRecord();
      default: return this.readUnknownArray();
    }
  }

  /** Writes this value with `writer`. */
  writeTo(writer: JsonWriter): void {
    switch (this.#kind) {
      case JsonKind.null: writer.literal('null'); break;
      case JsonKind.boolean: writer.literal(this.#boolean ? 'true' : 'false'); break;
      case JsonKind.number: writer.literal(this.#text!); break;
      case JsonKind.string: writer.value(this.#text); break;
      case JsonKind.object:
        writer.beginObject();
        for (const [name, v] of this.#members!) {
          writer.name(name);
          v.writeTo(writer);
        }
        writer.endObject();
        break;
      default:
        writer.beginArray();
        for (const e of this.#elements!) e.writeTo(writer);
        writer.endArray();
    }
  }

  /** Whether `other` is the same JSON: of the same kind, with equal members (in the same order) or elements. */
  equals(other: unknown): boolean {
    if (!(other instanceof JsonValue) || other.#kind !== this.#kind || other.#text !== this.#text || other.#boolean !== this.#boolean) return false;
    if (this.#members !== undefined) {
      const theirs = [...other.#members!];
      return theirs.length === this.#members.size && [...this.#members].every(([n, v], i) => theirs[i]![0] === n && v.equals(theirs[i]![1]));
    }
    if (this.#elements !== undefined) return other.#elements!.length === this.#elements.length && this.#elements.every((e, i) => e.equals(other.#elements![i]));
    return true;
  }

  /** This value as compact JSON text. */
  toString(): string {
    const buffer = new SecureBuffer();
    try {
      this.writeTo(new JsonWriter(buffer));
      return buffer.view().toString('utf8');
    } finally {
      buffer.close();
    }
  }

  #expect(expected: JsonKind): void {
    if (this.#kind !== expected) throw new VaultJsonError(`Expected a JSON ${expected}, not ${DESCRIBED[this.#kind]}.`);
  }

  #mismatch(expected: string): VaultJsonError {
    return new VaultJsonError(`Expected ${expected}, not ${DESCRIBED[this.#kind]}.`);
  }
}

function required<T>(value: T | undefined): T {
  if (value === undefined) throw new VaultJsonError('Expected a value, not null.');
  return value;
}

function parseBigInt(text: string | undefined): bigint {
  const value = (text ?? '').trim();
  if (/^-?\d+$/.test(value)) return BigInt(value);
  const number = Number(value);
  if (value !== '' && Number.isSafeInteger(number)) return BigInt(number);
  throw new VaultJsonError('Expected an integer; the value isn\'t one.');
}

/**
 * Reads and writes one model of a request or response body Vault's OpenAPI spec defines: the
 * constant of each interface's name in the generated schema. A model is written as a JSON object
 * holding only the members that are set.
 */
export interface VaultModel<T> {
  /** The model's name, e.g. "KvV2ReadResponse". */
  readonly name: string;

  /**
   * The model read from `json`: a JSON object, its members read leniently (see {@link JsonValue}).
   * @throws VaultJsonError json isn't an object, or a member isn't what the model holds there
   */
  read(json: JsonValue): T;

  /**
   * Writes `value` as one JSON object.
   * @throws TypeError a required member is missing
   */
  write(writer: JsonWriter, value: T): void;
}

/**
 * Writes a request body as compact UTF-8 JSON into a {@link SecureBuffer}, zeroed once the request
 * has been sent, as the generated models' writes do. A Uint8Array of UTF-8 is written as a string
 * without becoming one, so a secret in one never does.
 *
 * {@link value} writes undefined or null (as null), a string, a Uint8Array of UTF-8, a boolean, a
 * finite number, a bigint, a Date (RFC 3339, in UTC), a {@link JsonValue}, an array, a Map or a
 * plain object (its keys as strings, members holding undefined left out). Not reentrant.
 */
export class JsonWriter {
  readonly #output: SecureBuffer;
  // Whether each open container is an object (true) or an array, and whether it has a member yet.
  readonly #objects: boolean[] = [];
  readonly #started: boolean[] = [];
  #afterName = false;

  constructor(output: SecureBuffer) {
    this.#output = output;
  }

  /** Starts an object: then name, value, name, value... and {@link endObject}. */
  beginObject(): this {
    this.#beforeValue();
    this.#open(true);
    this.#output.writeByte(0x7b);
    return this;
  }

  endObject(): this {
    this.#close(true);
    this.#output.writeByte(0x7d);
    return this;
  }

  /** Starts an array: then values and {@link endArray}. */
  beginArray(): this {
    this.#beforeValue();
    this.#open(false);
    this.#output.writeByte(0x5b);
    return this;
  }

  endArray(): this {
    this.#close(false);
    this.#output.writeByte(0x5d);
    return this;
  }

  /**
   * The next member's name, inside an object.
   * @throws Error not inside an object, or right after another name
   */
  name(name: string): this {
    if (typeof name !== 'string') throw new TypeError('name must be a string.');
    if (this.#objects.length === 0 || !this.#objects[this.#objects.length - 1] || this.#afterName) {
      throw new Error('A name goes only inside an object, before its value.');
    }
    if (this.#started[this.#started.length - 1]) this.#output.writeByte(0x2c);
    this.#started[this.#started.length - 1] = true;
    this.#writeString(name);
    this.#output.writeByte(0x3a);
    this.#afterName = true;
    return this;
  }

  /**
   * Writes `value` as JSON; see the class description for the types written.
   * @throws TypeError a value of a type that isn't written
   * @throws RangeError a number that isn't finite, an invalid Date, text holding an unpaired
   *   surrogate or bytes that aren't UTF-8, or nesting more than 64 deep
   */
  value(value: unknown): this {
    if (value === undefined || value === null) this.literal('null');
    else if (typeof value === 'boolean') this.literal(value ? 'true' : 'false');
    else if (typeof value === 'string') {
      this.#beforeValue();
      this.#writeString(value);
    } else if (value instanceof Uint8Array) {
      this.#beforeValue();
      this.#writeUtf8(value);
    } else if (typeof value === 'number') {
      if (!Number.isFinite(value)) throw new RangeError(`JSON has no ${value}.`);
      this.literal(JSON.stringify(value));
    } else if (typeof value === 'bigint') this.literal(value.toString());
    else if (value instanceof Date) {
      if (Number.isNaN(value.getTime())) throw new RangeError('An invalid Date isn\'t written as JSON.');
      this.value(value.toISOString());
    } else if (value instanceof JsonValue) value.writeTo(this);
    else if (Array.isArray(value)) this.array(value, (item) => this.value(item));
    else if (value instanceof Map) {
      this.beginObject();
      for (const [key, member] of value) this.name(String(key)).value(member);
      this.endObject();
    } else if (typeof value === 'object' && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)) {
      this.record(value as Record<string, unknown>, (member) => this.value(member));
    } else {
      throw new TypeError(`A ${typeof value === 'object' ? value.constructor?.name ?? 'object' : typeof value} can't be written as JSON.`);
    }
    return this;
  }

  /** Writes `items` as an array, each with `write`. */
  array<T>(items: readonly T[], write: (item: T) => void): this {
    this.beginArray();
    for (const item of items) write(item);
    return this.endArray();
  }

  /** Writes `members` as an object, each value with `write`; members holding undefined are left out. */
  record<T>(members: Readonly<Record<string, T>>, write: (value: T) => void): this {
    this.beginObject();
    for (const [key, member] of Object.entries(members)) {
      if (member === undefined) continue;
      this.name(key);
      write(member);
    }
    return this.endObject();
  }

  /** Writes a JSON literal or number as it is. */
  literal(text: string): this {
    this.#beforeValue();
    this.#output.write(text);
    return this;
  }

  #beforeValue(): void {
    if (this.#objects.length === 0) return;
    if (this.#objects[this.#objects.length - 1]) {
      if (!this.#afterName) throw new Error('A value inside an object needs a name first.');
      this.#afterName = false;
      return;
    }
    if (this.#started[this.#started.length - 1]) this.#output.writeByte(0x2c);
    this.#started[this.#started.length - 1] = true;
  }

  #open(isObject: boolean): void {
    if (this.#objects.length === MAX_DEPTH) throw new RangeError(`JSON nested more than ${MAX_DEPTH} deep isn't written.`);
    this.#objects.push(isObject);
    this.#started.push(false);
  }

  #close(isObject: boolean): void {
    if (this.#objects.length === 0 || this.#objects[this.#objects.length - 1] !== isObject || this.#afterName) {
      throw new Error(`No open ${isObject ? 'object' : 'array'} to end.`);
    }
    this.#objects.pop();
    this.#started.pop();
  }

  #writeString(text: string): void {
    const output = this.#output;
    output.writeByte(0x22);
    for (let i = 0; i < text.length; i++) {
      const code = text.charCodeAt(i);
      if (code < 0x80) {
        this.#writeAscii(code);
        continue;
      }
      let point = code;
      if (code >= 0xd800 && code <= 0xdfff) {
        const low = text.charCodeAt(i + 1);
        if (code > 0xdbff || !(low >= 0xdc00 && low <= 0xdfff)) throw new RangeError('Text holding an unpaired surrogate isn\'t written as JSON.');
        point = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
        i++;
      }
      if (point < 0x800) {
        output.writeByte(0xc0 | (point >> 6));
      } else if (point < 0x10000) {
        output.writeByte(0xe0 | (point >> 12));
        output.writeByte(0x80 | ((point >> 6) & 0x3f));
      } else {
        output.writeByte(0xf0 | (point >> 18));
        output.writeByte(0x80 | ((point >> 12) & 0x3f));
        output.writeByte(0x80 | ((point >> 6) & 0x3f));
      }
      output.writeByte(0x80 | (point & 0x3f));
    }
    output.writeByte(0x22);
  }

  // Escapes what JSON must, copying the rest byte for byte - once it is known to be UTF-8.
  #writeUtf8(data: Uint8Array): void {
    if (!isUtf8(data)) throw new RangeError('Bytes written as a JSON string must be UTF-8.');
    const output = this.#output;
    output.writeByte(0x22);
    for (const b of data) {
      if (b < 0x80) this.#writeAscii(b);
      else output.writeByte(b);
    }
    output.writeByte(0x22);
  }

  #writeAscii(code: number): void {
    const output = this.#output;
    const escape = SHORT_ESCAPES.get(code);
    if (escape !== undefined) output.write(escape);
    else if (code < 0x20) output.write(`\\u00${HEX[code >> 4]}${HEX[code & 0xf]}`);
    else output.writeByte(code);
  }
}

// Well-formed UTF-8 (RFC 3629): no overlong forms, surrogates or code points past U+10FFFF.
function isUtf8(data: Uint8Array): boolean {
  let i = 0;
  while (i < data.length) {
    const b = data[i]!;
    if (b < 0x80) {
      i++;
      continue;
    }
    let count: number;
    let low = 0x80;
    let high = 0xbf;
    if (b >= 0xc2 && b <= 0xdf) count = 1;
    else if (b >= 0xe0 && b <= 0xef) {
      count = 2;
      if (b === 0xe0) low = 0xa0;
      else if (b === 0xed) high = 0x9f;
    } else if (b >= 0xf0 && b <= 0xf4) {
      count = 3;
      if (b === 0xf0) low = 0x90;
      else if (b === 0xf4) high = 0x8f;
    } else return false;
    if (i + count >= data.length) return false;
    const second = data[i + 1]!;
    if (second < low || second > high) return false;
    for (let k = 2; k <= count; k++) {
      const next = data[i + k]!;
      if (next < 0x80 || next > 0xbf) return false;
    }
    i += count + 1;
  }
  return true;
}

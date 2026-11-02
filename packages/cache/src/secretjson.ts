import { InvalidArgumentError, wipe } from '@runsecure/hkdfguard-abstractions';
import { JsonReader, JsonToken, MalformedJsonError } from '@runsecure/hkdfguard-abstractions/internal';
import { readSecretBody, type ResponseBody } from './body.js';
import { InvalidSecretDataError } from './errors.js';
import { setKeys } from './jsonkeys.js';
import { SecretValueSink } from './remote.js';

/** Where {@link SecretJsonBody.capture} looks for the secret, beyond its text property. */
export interface SecretJsonCaptureOptions {
  /**
   * A property that holds the value base64-encoded instead of as text - AWS Secrets Manager's
   * SecretBinary - handed over decoded, whole.
   */
  base64Property?: string;
  /**
   * The property names leading from the body to the object holding the properties - ["data", "data"]
   * for {"data":{"data":{"value":"..."}}}; the top level when empty or omitted.
   */
  objectPath?: readonly string[];
}

/**
 * Takes a secret out of a JSON response body before an SDK can turn it into a string. A stream body
 * is read into a buffer of the library's own (each chunk zeroed once copied); the named string
 * property is unescaped (and base64-decoded, for a binary property) straight into another buffer and
 * handed to a {@link SecretValueSink}; and what's returned is the same body with that value replaced
 * by "" - for the SDK to parse as usual, holding nothing secret. Every buffer of the library's that
 * held the value is zeroed before returning, on every path.
 *
 * Not erased: a whole body passed in as a Uint8Array, which is read in place, never copied, and left
 * as it is - its owner should zero it once done - and the HTTP stack's own buffers.
 */
export class SecretJsonBody {
  /** The largest body read: far beyond any secret store's response, so a larger one is refused. */
  static readonly MAX_BODY_LENGTH = 1024 * 1024;

  private constructor() {}

  /**
   * Hands the value of `body`'s `textProperty` (as UTF-8 bytes, with
   * {@link SecretValueSink.setBytesWithJsonKeys}, so a JSON object's members are keys too) - or,
   * when the body holds `options.base64Property` instead, the bytes it encodes, whole - to `sink`,
   * and returns the body with both values replaced by "". The properties are looked for at the top
   * level, or in the object reached through `options.objectPath`. A missing, null or empty property,
   * or a path that leads to no object, hands nothing over.
   * @param body the whole body; read in place and left as it is
   * @returns the body, redacted: a new Uint8Array
   * @throws TypeError body or sink is missing, or objectPath isn't an array
   * @throws InvalidArgumentError textProperty, or a name in objectPath, is missing or empty
   * @throws InvalidSecretDataError body isn't a JSON object, is {@link MAX_BODY_LENGTH} bytes or
   *   more, or holds more than one non-empty secret value; the base64 value isn't base64; or the value
   *   is a JSON object holding a member name more than once
   */
  static capture(body: Uint8Array, sink: SecretValueSink, textProperty: string, options: SecretJsonCaptureOptions = {}): Uint8Array {
    const target = textTarget(sink, textProperty, options);
    const path = checkArguments(body, sink, options.objectPath ?? []);
    if (!(body instanceof Uint8Array)) throw new TypeError('body must be a Uint8Array; use captureAsync for a stream.');
    if (body.length >= SecretJsonBody.MAX_BODY_LENGTH) {
      throw new InvalidSecretDataError(`The response body is ${SecretJsonBody.MAX_BODY_LENGTH} bytes or more.`);
    }
    return parse(body, body.length, path, target);
  }

  /**
   * {@link capture}, for a body that is a stream (or the whole body): it is read to its end - but not
   * closed - into a buffer of the library's own, which is zeroed before this settles.
   * @throws TypeError, InvalidArgumentError, InvalidSecretDataError as for {@link capture}; a stream
   *   yielding anything but Uint8Array chunks is a TypeError. Reading the stream may fail with its own error.
   */
  static async captureAsync(
    body: ResponseBody, sink: SecretValueSink, textProperty: string,
    options: SecretJsonCaptureOptions & { signal?: AbortSignal } = {},
  ): Promise<Uint8Array> {
    const target = textTarget(sink, textProperty, options);
    const path = checkArguments(body, sink, options.objectPath ?? []);
    return readAndParse(body, path, target, options.signal);
  }

  /**
   * Hands each member of the object reached through `objectPath`'s property names to `sink` as a key,
   * as {@link SecretValueSink.setBytesWithJsonKeys} describes - for a store whose secrets are sets of
   * keys, such as HashiCorp Vault's KV: ["data", "data"] for
   * {"data":{"data":{"username":"...","password":"..."}}}. A path that leads to no object hands
   * nothing over.
   * @param body the whole body; read in place and left as it is
   * @throws TypeError body or sink is missing, or objectPath isn't an array
   * @throws InvalidArgumentError a name in objectPath is missing or empty
   * @throws InvalidSecretDataError body isn't a JSON object, or is {@link MAX_BODY_LENGTH} bytes or
   *   more; or the object holds a member name more than once
   */
  static captureKeys(body: Uint8Array, sink: SecretValueSink, objectPath: readonly string[]): void {
    const path = checkArguments(body, sink, objectPath);
    if (!(body instanceof Uint8Array)) throw new TypeError('body must be a Uint8Array; use captureKeysAsync for a stream.');
    if (body.length >= SecretJsonBody.MAX_BODY_LENGTH) {
      throw new InvalidSecretDataError(`The response body is ${SecretJsonBody.MAX_BODY_LENGTH} bytes or more.`);
    }
    parse(body, body.length, path, newTarget(undefined, undefined, sink));
  }

  /**
   * {@link captureKeys}, for a body that is a stream (or the whole body): it is read to its end - but
   * not closed - into a buffer of the library's own, which is zeroed before this settles.
   * @throws as for {@link captureKeys}; a stream yielding anything but Uint8Array chunks is a TypeError
   */
  static async captureKeysAsync(body: ResponseBody, sink: SecretValueSink, objectPath: readonly string[], signal?: AbortSignal): Promise<void> {
    const path = checkArguments(body, sink, objectPath);
    await readAndParse(body, path, newTarget(undefined, undefined, sink), signal);
  }
}

// What one read looks for - a text (and base64) property, or, with no text property, every member as
// a key - and what it has found so far.
interface Target {
  readonly textProperty: string | undefined;
  readonly base64Property: string | undefined;
  readonly sink: SecretValueSink;
  readonly secrets: [start: number, end: number][];
  readonly keys: Set<string>;
  handedOver: boolean;
}

function newTarget(textProperty: string | undefined, base64Property: string | undefined, sink: SecretValueSink): Target {
  return { textProperty, base64Property, sink, secrets: [], keys: new Set(), handedOver: false };
}

function textTarget(sink: SecretValueSink, textProperty: string, options: SecretJsonCaptureOptions): Target {
  if (typeof textProperty !== 'string' || textProperty.length === 0) throw new InvalidArgumentError('The text property is undefined or empty.');
  return newTarget(textProperty, options.base64Property === '' ? undefined : options.base64Property, sink);
}

function checkArguments(body: unknown, sink: unknown, objectPath: readonly string[]): readonly string[] {
  if (body === undefined || body === null) throw new TypeError('body must not be undefined.');
  if (!(sink instanceof SecretValueSink)) throw new TypeError('sink must be a SecretValueSink.');
  if (!Array.isArray(objectPath)) throw new TypeError('objectPath must be an array of property names.');
  for (const name of objectPath) {
    if (typeof name !== 'string' || name.length === 0) throw new InvalidArgumentError('A property name in the path is undefined or empty.');
  }
  return [...objectPath];
}

async function readAndParse(body: ResponseBody, path: readonly string[], target: Target, signal: AbortSignal | undefined): Promise<Uint8Array> {
  const { buffer, length, owned } = await readSecretBody(body, SecretJsonBody.MAX_BODY_LENGTH, signal);
  try {
    return parse(buffer, length, path, target);
  } finally {
    if (owned) wipe(buffer);
  }
}

// Walks json[0, length) for target; returns the body redacted, for a target with a text property.
function parse(json: Uint8Array, length: number, path: readonly string[], target: Target): Uint8Array {
  const reader = new JsonReader(json, length);
  try {
    if (!reader.read() || reader.token() !== JsonToken.StartObject) throw new InvalidSecretDataError("The response body isn't a JSON object.");
    readObject(reader, path, target);
  } catch (error) {
    // Never chained, and never quoting the byte rejected, which may be in the secret.
    if (error instanceof MalformedJsonError) {
      throw new InvalidSecretDataError(`The response body isn't valid JSON (at byte ${error.position} of line ${error.line}).`);
    }
    throw error;
  }
  return target.textProperty === undefined ? new Uint8Array(0) : redact(json.subarray(0, length), target.secrets);
}

// Reads the properties of the object reader is at the start of, descending path; returns with
// reader at its end.
function readObject(reader: JsonReader, path: readonly string[], target: Target): void {
  if (path.length === 0 && target.textProperty === undefined) {
    setKeys(reader, target.sink, target.keys);
    return;
  }

  while (reader.read() && reader.token() === JsonToken.PropertyName) {
    if (path.length > 0) {
      const isParent = reader.valueTextEquals(path[0]!);
      reader.read();
      if (isParent && reader.token() === JsonToken.StartObject) readObject(reader, path.slice(1), target);
      else reader.skip();
      continue;
    }
    readProperty(reader, target);
  }
}

// Reads the property reader is at the name of, in the object holding the secret.
function readProperty(reader: JsonReader, target: Target): void {
  const isText = reader.valueTextEquals(target.textProperty!);
  const isBase64 = !isText && target.base64Property !== undefined && reader.valueTextEquals(target.base64Property);
  reader.read();

  if (!(isText || isBase64) || reader.token() !== JsonToken.String) {
    reader.skip();
    return;
  }

  if (reader.valueLength > 0) {
    if (target.handedOver) throw new InvalidSecretDataError('The response body holds more than one secret value.');
    handOver(reader, isBase64, target.sink);
    target.handedOver = true;
  }
  target.secrets.push([reader.tokenStart, reader.bytesConsumed]);
}

function handOver(reader: JsonReader, isBase64: boolean, sink: SecretValueSink): void {
  // Unescaped, a string is never longer than it is escaped.
  const text = new Uint8Array(reader.valueLength);
  let decoded: Uint8Array | undefined;
  try {
    const textLength = reader.copyString(text);
    if (!isBase64) {
      sink.setBytesWithJsonKeys(text.subarray(0, textLength));
      return;
    }

    decoded = new Uint8Array(Math.floor(textLength / 4) * 3 + 3);
    const written = decodeBase64(text.subarray(0, textLength), decoded);
    if (written < 0) throw new InvalidSecretDataError("The response body's binary secret value isn't base64.");
    sink.setBytes(decoded.subarray(0, written));
  } finally {
    wipe(text);
    wipe(decoded);
  }
}

const BASE64_VALUES = (() => {
  const values = new Int8Array(256).fill(-1);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  for (let i = 0; i < alphabet.length; i++) values[alphabet.charCodeAt(i)] = i;
  return values;
})();
const PAD = 0x3d; // =

// Standard base64 (RFC 4648 section 4) into destination, as strictly as Java's Base64.getDecoder():
// no whitespace or other characters, and padding, if any, complete. Decoded here rather than by
// Buffer.from(..., 'base64'), which silently skips what isn't base64 and makes a Buffer of its own.
// Returns the bytes written, or -1 if encoded isn't base64.
function decodeBase64(encoded: Uint8Array, destination: Uint8Array): number {
  const length = encoded.length;
  let padding = 0;
  if (length > 0 && encoded[length - 1] === PAD) padding = length > 1 && encoded[length - 2] === PAD ? 2 : 1;
  const dataLength = length - padding;
  if ((padding > 0 && length % 4 !== 0) || dataLength % 4 === 1) return -1;

  let accumulated = 0;
  let bits = 0;
  let written = 0;
  for (let i = 0; i < dataLength; i++) {
    const sextet = BASE64_VALUES[encoded[i]!]!;
    if (sextet < 0) return -1;
    accumulated = ((accumulated << 6) | sextet) & 0xffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      destination[written++] = (accumulated >> bits) & 0xff;
    }
  }
  return written;
}

// The body with each secret value's token - its quotes included - replaced by "".
function redact(json: Uint8Array, secrets: readonly [number, number][]): Uint8Array {
  let length = json.length;
  for (const [start, end] of secrets) length -= end - start - 2;

  const redacted = new Uint8Array(length);
  let from = 0;
  let to = 0;
  for (const [start, end] of secrets) {
    redacted.set(json.subarray(from, start), to);
    to += start - from;
    redacted[to++] = 0x22;
    redacted[to++] = 0x22;
    from = end;
  }
  redacted.set(json.subarray(from), to);
  return redacted;
}

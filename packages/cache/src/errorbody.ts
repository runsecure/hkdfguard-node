import { readLimitedBody, type ResponseBody } from './body.js';
import { JsonReader, JsonToken, MalformedJsonError } from './json.js';

const decoder = new TextDecoder(); // not fatal: invalid UTF-8 becomes U+FFFD

/**
 * Reads the error messages out of a secret store's JSON error response - one that holds nothing
 * secret, such as HashiCorp Vault's {"errors":["permission denied"]} - with the same strict reader
 * {@link SecretJsonBody} uses, so a provider needs one JSON reading rule throughout. Never use it on
 * a body that may hold a secret: it makes strings.
 */
export class ErrorResponseBody {
  /** The largest error body read; anything beyond it is ignored, and the body reads as not JSON. */
  static readonly MAX_BODY_LENGTH = 64 * 1024;

  private constructor() {}

  /**
   * The elements of `body`'s top-level `arrayProperty`: a string as its text, anything else as its
   * JSON text. Only the first {@link MAX_BODY_LENGTH} bytes are read.
   * @returns the elements; empty if the body is a JSON object without that property; undefined if
   *   the body isn't a JSON object (a proxy's HTML page, say), or the property isn't an array
   * @throws TypeError body or arrayProperty is missing
   */
  static readStrings(body: Uint8Array, arrayProperty: string): string[] | undefined {
    checkArguments(body, arrayProperty);
    if (!(body instanceof Uint8Array)) throw new TypeError('body must be a Uint8Array; use readStringsAsync for a stream.');
    return readStrings(body.subarray(0, ErrorResponseBody.MAX_BODY_LENGTH), arrayProperty);
  }

  /**
   * {@link readStrings}, for a body that is a stream (or the whole body): it is read up to
   * {@link MAX_BODY_LENGTH} bytes, and not closed - though stopping early ends a Node Readable's or
   * web stream's iteration, which destroys or cancels it.
   * @throws TypeError body or arrayProperty is missing, or a stream yields anything but Uint8Array
   *   chunks. Reading the stream may fail with its own error.
   */
  static async readStringsAsync(body: ResponseBody, arrayProperty: string, signal?: AbortSignal): Promise<string[] | undefined> {
    checkArguments(body, arrayProperty);
    return readStrings(await readLimitedBody(body, ErrorResponseBody.MAX_BODY_LENGTH, signal), arrayProperty);
  }
}

function checkArguments(body: unknown, arrayProperty: unknown): void {
  if (body === undefined || body === null) throw new TypeError('body must not be undefined.');
  if (typeof arrayProperty !== 'string') throw new TypeError('arrayProperty must be a string.');
}

function readStrings(data: Uint8Array, arrayProperty: string): string[] | undefined {
  const reader = new JsonReader(data);
  try {
    if (!reader.read() || reader.token() !== JsonToken.StartObject) return undefined;

    let found: string[] = [];
    while (reader.read() && reader.token() === JsonToken.PropertyName) {
      const isArray = reader.valueTextEquals(arrayProperty);
      reader.read();
      if (!isArray) reader.skip();
      else if (reader.token() !== JsonToken.StartArray) return undefined;
      else found = elements(reader, data);
    }

    // Anything after the object makes it not JSON.
    return reader.read() ? undefined : found;
  } catch (error) {
    if (error instanceof MalformedJsonError) return undefined;
    throw error;
  }
}

function elements(reader: JsonReader, data: Uint8Array): string[] {
  const found: string[] = [];
  while (reader.read() && reader.token() !== JsonToken.EndArray) {
    const start = reader.tokenStart;
    if (reader.token() === JsonToken.String) {
      found.push(reader.getString());
      continue;
    }
    reader.skip();
    found.push(decoder.decode(data.subarray(start, reader.bytesConsumed)));
  }
  return found;
}

import { wipe } from '@runsecure/hkdfguard-abstractions';
import { InvalidSecretDataError } from './errors.js';

/**
 * A response body SecretJsonBody and ErrorResponseBody read: the whole body already read, or its
 * chunks - a Node Readable (an http.IncomingMessage, say, with no encoding set), a web
 * ReadableStream<Uint8Array> (a fetch Response's body), or any other iterable or async iterable of
 * Uint8Array chunks.
 */
export type ResponseBody = Uint8Array | AsyncIterable<Uint8Array> | Iterable<Uint8Array>;

const INITIAL_BUFFER_LENGTH = 16 * 1024;

/** `body`'s chunks, each checked to be bytes. */
async function* chunksOf(body: ResponseBody, signal: AbortSignal | undefined): AsyncGenerator<Uint8Array> {
  if (body === undefined || body === null) throw new TypeError('body must not be undefined.');
  if (body instanceof Uint8Array) {
    yield body;
    return;
  }
  if (typeof (body as Partial<AsyncIterable<unknown>>)[Symbol.asyncIterator] !== 'function'
    && typeof (body as Partial<Iterable<unknown>>)[Symbol.iterator] !== 'function') {
    throw new TypeError('body must be a Uint8Array, or an iterable or async iterable of Uint8Array chunks.');
  }
  for await (const chunk of body as AsyncIterable<unknown>) {
    signal?.throwIfAborted();
    if (!(chunk instanceof Uint8Array)) {
      throw new TypeError('A response body must yield Uint8Array chunks, never strings: set no encoding on the stream.');
    }
    yield chunk;
  }
}

/**
 * Reads a secret-holding `body` to its end into a buffer of the library's own, returning it and how
 * much of it holds the body; the caller zeroes it. Each chunk of a stream is zeroed once copied
 * (the stream has handed it over); the buffer is never resized in place, and every buffer outgrown
 * is zeroed. A whole-body Uint8Array is returned as it is, to be read in place and left to its owner.
 * @throws InvalidSecretDataError the body is `limit` bytes or more
 */
export async function readSecretBody(
  body: ResponseBody, limit: number, signal: AbortSignal | undefined,
): Promise<{ buffer: Uint8Array; length: number; owned: boolean }> {
  if (body instanceof Uint8Array) {
    if (body.length >= limit) throw new InvalidSecretDataError(`The response body is ${limit} bytes or more.`);
    return { buffer: body, length: body.length, owned: false };
  }

  let buffer: Uint8Array = new Uint8Array(INITIAL_BUFFER_LENGTH);
  let length = 0;
  try {
    for await (const chunk of chunksOf(body, signal)) {
      try {
        for (let offset = 0; offset < chunk.length;) {
          const copied = Math.min(buffer.length - length, chunk.length - offset);
          buffer.set(chunk.subarray(offset, offset + copied), length);
          length += copied;
          offset += copied;
          buffer = growIfFull(buffer, length, limit);
        }
      } finally {
        wipe(chunk);
      }
    }
    return { buffer, length, owned: true };
  } catch (error) {
    wipe(buffer);
    throw error;
  }
}

// buffer, or once it's full a new one twice its size, the original zeroed.
function growIfFull(buffer: Uint8Array, length: number, limit: number): Uint8Array {
  if (length < buffer.length) return buffer;
  if (buffer.length >= limit) throw new InvalidSecretDataError(`The response body is ${limit} bytes or more.`);

  const larger = new Uint8Array(Math.min(buffer.length * 2, limit));
  larger.set(buffer.subarray(0, length));
  wipe(buffer);
  return larger;
}

/**
 * The first `limit` bytes of a body that holds nothing secret, such as an error response; whatever
 * follows is never read. Chunks are copied, not zeroed.
 */
export async function readLimitedBody(body: ResponseBody, limit: number, signal: AbortSignal | undefined): Promise<Uint8Array> {
  if (body instanceof Uint8Array) return body.subarray(0, limit);

  const buffer = new Uint8Array(limit);
  let length = 0;
  for await (const chunk of chunksOf(body, signal)) {
    const copied = Math.min(limit - length, chunk.length);
    buffer.set(chunk.subarray(0, copied), length);
    length += copied;
    if (length >= limit) break;
  }
  return buffer.subarray(0, length);
}

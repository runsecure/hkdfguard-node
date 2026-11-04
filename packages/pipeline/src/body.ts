import { wipe } from '@runsecure/hkdfguard-abstractions';
import { InvalidSecretDataError, type ResponseBody } from '@runsecure/hkdfguard-cache';

const INITIAL_BUFFER_LENGTH = 16 * 1024;

/**
 * Reads a response body that holds a secret into a buffer of the library's own, for a pipeline
 * writer to take it from. The name is .NET's, whose PinnedBody reads into pinned memory; JavaScript
 * can't pin memory, so here it means a Uint8Array the library allocated itself - never Buffer's
 * shared pool, nor a buffer anything else holds - which the caller zeroes.
 */
export class PinnedBody {
  /** The largest body read: far beyond any secret store's response, so a larger one is refused. */
  static readonly MAX_LENGTH = 1024 * 1024;

  private constructor() {}

  /**
   * Reads `body` to its end into a buffer of the library's own, growing it as needed, each smaller
   * buffer zeroed. Each chunk of a stream is zeroed once copied - the stream has handed it over; a
   * whole body given as a Uint8Array is copied and left to its owner. The stream is read, not closed.
   * @returns the buffer, which the caller must zero, and how much of it the body filled
   * @throws TypeError (rejecting) body is missing, or a stream yields anything but Uint8Array chunks
   * @throws InvalidSecretDataError (rejecting) the body is {@link MAX_LENGTH} bytes or more
   */
  static async read(body: ResponseBody, signal?: AbortSignal): Promise<{ buffer: Uint8Array; length: number }> {
    if (body === undefined || body === null) throw new TypeError('body must not be undefined.');
    let buffer: Uint8Array = new Uint8Array(INITIAL_BUFFER_LENGTH);
    let length = 0;
    try {
      if (body instanceof Uint8Array) {
        buffer = append(buffer, length, body);
        length = body.length;
        return { buffer, length };
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
        try {
          buffer = append(buffer, length, chunk);
          length += chunk.length;
        } finally {
          wipe(chunk);
        }
      }
      return { buffer, length };
    } catch (error) {
      wipe(buffer);
      throw error;
    }
  }
}

// buffer with data copied in after its first length bytes - into a larger buffer when it doesn't
// fit, the original zeroed. The result always has room to spare, so a body of MAX_LENGTH is refused.
function append(buffer: Uint8Array, length: number, data: Uint8Array): Uint8Array {
  const needed = length + data.length;
  if (needed >= PinnedBody.MAX_LENGTH) throw new InvalidSecretDataError(`The response body is ${PinnedBody.MAX_LENGTH} bytes or more.`);
  if (needed >= buffer.length) {
    let size = buffer.length;
    while (size <= needed) size *= 2;
    const larger = new Uint8Array(Math.min(size, PinnedBody.MAX_LENGTH));
    larger.set(buffer.subarray(0, length));
    wipe(buffer);
    buffer = larger;
  }
  buffer.set(data, length);
  return buffer;
}

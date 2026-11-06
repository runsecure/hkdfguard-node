// Writing to a caller's Writable - a process's standard input, most often - for the pipeline
// protector's writeDek and the pipeline writer's stream writes.
import type { Writable } from 'node:stream';
import { HkdfGuardError } from '../errors.js';
import { abortReason } from './abort.js';

/** Whether `destination` looks like a Node Writable: something with write, on and removeListener. */
export function isWritable(destination: unknown): destination is Writable {
  const stream = destination as Partial<Writable> | null | undefined;
  return typeof stream?.write === 'function' && typeof stream.on === 'function' && typeof stream.removeListener === 'function';
}

/**
 * Writes each of `chunks` to `destination` in turn, waiting for each write's callback - the stream
 * has accepted the chunk: a process's stdin or a socket has handed it to the operating system, a
 * file stream has written it - before the next, so no more than one chunk is ever buffered however
 * slowly the destination drains. Resolves once the last chunk is accepted; `destination` is left
 * open, for the caller to end.
 *
 * Rejects with the stream's error if a write fails or the stream errors meanwhile (an 'error'
 * listener is held for the length of the call, so the error is the caller's rejection rather than
 * an uncaught one), with HkdfGuardError ERR_HKDFGUARD_INVALID_STATE - before writing anything - if
 * it has already ended or been destroyed, and with `signal`'s reason once it is aborted: a chunk
 * already handed to the stream may still be written, so destroy a stream whose write was aborted.
 * `onSettled(chunk)` is called once the stream is done with each chunk handed to it - its write
 * called back, or the call aborted - for a caller that must zero what it wrote.
 * @throws TypeError (rejecting) destination isn't a Writable
 */
export async function writeChunks(destination: Writable, chunks: Iterable<Uint8Array>, signal?: AbortSignal,
  onSettled?: (chunk: Uint8Array) => void): Promise<void> {
  if (!isWritable(destination)) throw new TypeError('destination must be a Writable stream.');
  signal?.throwIfAborted();
  if (destination.destroyed === true || destination.writableEnded === true) {
    throw new HkdfGuardError('ERR_HKDFGUARD_INVALID_STATE', 'The destination stream has already been ended or destroyed.');
  }

  let failed: Error | undefined;
  let fail: ((error: Error) => void) | undefined;
  const onError = (error: Error) => {
    failed ??= error;
    fail?.(error);
  };
  const onAbort = () => fail?.(abortReason(signal!));
  destination.on('error', onError);
  signal?.addEventListener('abort', onAbort);
  let succeeded = false;
  try {
    for (const chunk of chunks) {
      signal?.throwIfAborted();
      if (failed !== undefined) throw failed;
      await new Promise<void>((resolve, reject) => {
        let settled = false;
        const settle = () => {
          if (settled) return;
          settled = true;
          onSettled?.(chunk);
        };
        fail = (error) => {
          settle();
          reject(error);
        };
        destination.write(chunk, (error?: Error | null) => {
          settle();
          if (error !== undefined && error !== null) reject(error);
          else resolve();
        });
      });
    }
    succeeded = true;
  } finally {
    fail = undefined;
    signal?.removeEventListener('abort', onAbort);
    // A failed stream emits 'error' after the write's callback; held until then, so it is never uncaught.
    if (succeeded) destination.removeListener('error', onError);
    else setImmediate(() => destination.removeListener('error', onError));
  }
}

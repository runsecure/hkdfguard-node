import { strict as assert } from 'node:assert';
import { PassThrough, Writable } from 'node:stream';
import { describe, it } from 'node:test';
import { isWritable, writeChunks } from './index.js';

const utf8 = (s: string) => new TextEncoder().encode(s);
const INVALID_STATE = (error: unknown) => (error as { code?: unknown }).code === 'ERR_HKDFGUARD_INVALID_STATE';

/** A Writable that copies each chunk, calling back on a later turn, and records how many writes were ever outstanding at once. */
class SlowStream extends Writable {
  readonly chunks: Buffer[] = [];
  maxPending = 0;
  #pending = 0;

  constructor(private readonly failWith?: Error) {
    super({ highWaterMark: 1 });
  }

  override _write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.chunks.push(Buffer.from(chunk));
    this.maxPending = Math.max(this.maxPending, ++this.#pending);
    setImmediate(() => {
      this.#pending--;
      callback(this.failWith);
    });
  }
}

describe('writeChunks', () => {
  it('writes each chunk once the one before is accepted, and leaves the stream open', async () => {
    const stream = new SlowStream();
    const settled: Uint8Array[] = [];
    const chunks = ['one', 'two', 'three'].map(utf8);

    await writeChunks(stream, chunks, undefined, (chunk) => settled.push(chunk));

    assert.equal(Buffer.concat(stream.chunks).toString(), 'onetwothree');
    assert.equal(stream.maxPending, 1);
    assert.deepEqual(settled, chunks);
    assert.ok(stream.writable && !stream.writableEnded);
    assert.equal(stream.listenerCount('error'), 0);
  });

  it('writes nothing to a stream that has ended or been destroyed', async () => {
    const ended = new SlowStream();
    ended.end();
    const destroyed = new SlowStream();
    destroyed.destroy();

    for (const stream of [ended, destroyed]) await assert.rejects(writeChunks(stream, [utf8('x')]), INVALID_STATE);
    assert.equal(ended.chunks.length, 0);
  });

  it('rejects with the stream\'s error, never leaving it uncaught', async () => {
    const stream = new SlowStream(new Error('broken pipe'));
    const settled: Uint8Array[] = [];

    await assert.rejects(writeChunks(stream, [utf8('a'), utf8('b')], undefined, (chunk) => settled.push(chunk)), /broken pipe/);

    assert.equal(stream.chunks.length, 1);
    assert.equal(settled.length, 1);
    // The 'error' event the stream emits after the callback found a listener.
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(stream.listenerCount('error'), 0);
  });

  it('rejects when the stream errors between writes', async () => {
    const stream = new PassThrough();
    const chunks = (function* () {
      yield utf8('a');
      stream.emit('error', new Error('gone'));
      yield utf8('b');
    })();

    await assert.rejects(writeChunks(stream, chunks), /gone/);
  });

  it('stops once the signal is aborted, settling the chunk in flight', async () => {
    const controller = new AbortController();
    const stream = new Writable({ write: () => controller.abort(new Error('stop')) }); // never calls back
    const settled: Uint8Array[] = [];

    await assert.rejects(writeChunks(stream, [utf8('a'), utf8('b')], controller.signal, (chunk) => settled.push(chunk)), /stop/);

    assert.equal(settled.length, 1);
    await assert.rejects(writeChunks(new SlowStream(), [utf8('a')], AbortSignal.abort(new Error('before'))), /before/);
  });

  it('refuses anything but a Writable', async () => {
    for (const destination of [undefined, null, {}, { write() {} }, 'stream']) {
      assert.equal(isWritable(destination), false);
      await assert.rejects(writeChunks(destination as unknown as Writable, [utf8('a')]), TypeError);
    }
    assert.ok(isWritable(new PassThrough()));
  });
});

import { strict as assert } from 'node:assert';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { PassThrough, Transform, Writable } from 'node:stream';
import { describe, it } from 'node:test';
import {
  AuthenticationFailedError, ClosedError, EncryptionLimitReachedError, InvalidArgumentError, InvalidConfigurationKeyError, isZero,
  KeyNotFoundError, type EncryptedFormatProvider,
} from '@runsecure/hkdfguard-abstractions';
import { TestFormatProvider } from '@runsecure/hkdfguard-test-support';
import { AesGcmPipelineDataProtector, base64Bytes, pipelineForTests } from './pipeline.js';
import { EncryptionBudget } from './session.js';

const id = 'Pipeline:Secret';
const newPipeline = () => new AesGcmPipelineDataProtector(new TestFormatProvider(), 42);

function decrypt(p: AesGcmPipelineDataProtector, formatted: string, identifier: string): string {
  const result = new Uint8Array(p.maxDecryptedLength(formatted));
  return new TextDecoder().decode(result.subarray(0, p.decrypt(formatted, identifier, result)));
}

describe('AesGcmPipelineDataProtector', () => {
  it('round-trips strings and bytes', () => {
    const p = newPipeline();
    for (const plaintext of ['hello', 'héllo wörld ✓ 🔐', '']) {
      assert.equal(decrypt(p, p.encrypt(plaintext, id), id), plaintext);
    }
    assert.equal(decrypt(p, p.encrypt(new TextEncoder().encode('bytes'), id), id), 'bytes');
  });

  it("leaves the caller's plaintext bytes alone", () => {
    const plaintext = new TextEncoder().encode("caller's copy");
    newPipeline().encrypt(plaintext, id);
    assert.equal(new TextDecoder().decode(plaintext), "caller's copy");
  });

  it('refuses an empty or invalid identifier', () => {
    const p = newPipeline();
    const formatted = p.encrypt('hello', id);
    for (const identifier of ['', 'Key\uD800']) {
      assert.throws(() => p.encrypt('hello', identifier), InvalidConfigurationKeyError);
      assert.throws(() => decrypt(p, formatted, identifier), InvalidConfigurationKeyError);
    }
  });

  it('treats identifiers as case-insensitive, like configuration keys', () => {
    const p = newPipeline();
    const formatted = p.encrypt('hello', id);
    for (const lookup of ['pipeline:secret', 'PIPELINE:SECRET']) assert.equal(decrypt(p, formatted, lookup), 'hello');
  });

  it('binds each value to its identifier exactly', () => {
    const p = newPipeline();
    const long = `${'Section:'.repeat(60)}Leaf`;
    assert.equal(decrypt(p, p.encrypt('hello', long), long), 'hello');
    assert.throws(() => decrypt(p, p.encrypt('hello', long), `${long}X`), AuthenticationFailedError);
    const admin = p.encrypt('admin-secret', 'ConnectionStrings:Admin');
    assert.equal(decrypt(p, p.encrypt('reporting-secret', 'ConnectionStrings:Reporting'), 'ConnectionStrings:Reporting'), 'reporting-secret');
    assert.throws(() => decrypt(p, admin, 'ConnectionStrings:Reporting'), AuthenticationFailedError);
  });

  it('stamps the key version and never repeats output', () => {
    const p = newPipeline();
    const formatted = p.encrypt('hello', id);
    assert.equal(p.keyVersion, 42);
    assert.ok(formatted.startsWith('enc::v42::') && !formatted.includes('hello'));
    assert.notEqual(formatted, p.encrypt('hello', id));
  });

  it('fails for another version, another instance, or malformed input', () => {
    const p = newPipeline();
    const formatted = p.encrypt('hello', id);
    assert.throws(() => decrypt(p, formatted.replace('v42', 'v7'), id), KeyNotFoundError);
    assert.throws(() => decrypt(newPipeline(), formatted, id), AuthenticationFailedError);
    assert.throws(() => p.decrypt('not-a-valid-format', id, new Uint8Array(16)));
  });

  it('exposes its key as base64 in one reused buffer', () => {
    const key = new Uint8Array(randomBytes(32));
    const p = pipelineForTests(new TestFormatProvider(), 1, { key: Uint8Array.from(key) });
    const first = p.keyBase64();
    assert.equal(new TextDecoder().decode(first), Buffer.from(key).toString('base64'));
    assert.equal(p.keyBase64(), first);
  });

  it('encodes base64 byte to byte, matching Node for every length and byte value', () => {
    for (let length = 0; length <= 66; length++) {
      const data = new Uint8Array(randomBytes(length));
      assert.equal(new TextDecoder().decode(base64Bytes(data)), Buffer.from(data).toString('base64'), `length ${length}`);
    }
    const every = Uint8Array.from({ length: 256 * 3 }, (_, i) => (i % 3 === 0 ? i / 3 : 255 - (i % 256)));
    assert.equal(new TextDecoder().decode(base64Bytes(every)), Buffer.from(every).toString('base64'));
    const allDigits = Uint8Array.from(Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', 'base64'));
    assert.equal(new TextDecoder().decode(base64Bytes(allDigits)), 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/');
  });

  it("counts against the key's budget", () => {
    const p = pipelineForTests(new TestFormatProvider(), 1, { budget: new EncryptionBudget(1, 2) });
    const formatted = p.encrypt('one', id);
    p.encrypt('two', id);
    assert.throws(() => p.encrypt('three', id), EncryptionLimitReachedError);
    assert.equal(p.encryptionCount, 2);
    assert.equal(decrypt(p, formatted, id), 'one');
  });

  it('close zeroes the key and its base64 form, and fails later use', () => {
    const key = new Uint8Array(randomBytes(32));
    const p = pipelineForTests(new TestFormatProvider(), 1, { key });
    const formatted = p.encrypt('hello', id);
    const encoded = p.keyBase64();
    p.close();
    p.close();
    assert.ok(isZero(key) && isZero(encoded));
    assert.throws(() => p.encrypt('hello', id), ClosedError);
    assert.throws(() => decrypt(p, formatted, id), ClosedError);
    assert.throws(() => p.keyBase64(), ClosedError);
  });

  it('requires a format provider', () => {
    assert.throws(() => new AesGcmPipelineDataProtector(undefined as unknown as EncryptedFormatProvider, 1), InvalidArgumentError);
  });
});

describe('AesGcmPipelineDataProtector.writeDek', () => {
  /** A Writable that keeps both the very chunk it is handed and a copy of it as it was then. */
  class RecordingStream extends Writable {
    readonly handed: Uint8Array[] = [];
    readonly copies: Buffer[] = [];

    constructor(private readonly delayMs = 0) {
      super({ highWaterMark: 1 });
    }

    override _write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
      this.handed.push(chunk);
      this.copies.push(Buffer.from(chunk));
      setTimeout(callback, this.delayMs);
    }
  }

  it('writes the base64 key as ASCII, without a line ending, and leaves the stream open', async () => {
    const key = new Uint8Array(randomBytes(32));
    const p = pipelineForTests(new TestFormatProvider(), 1, { key: Uint8Array.from(key) });
    const stdin = new RecordingStream();

    await p.writeDek(stdin);

    const written = Buffer.concat(stdin.copies);
    assert.deepEqual(written, Buffer.from(Buffer.from(key).toString('base64'), 'ascii'));
    assert.equal(written.length, 44);
    assert.ok(stdin.writable && !stdin.writableEnded);
  });

  it('zeroes the bytes it wrote once the stream accepts them, leaving keyBase64 alone', async () => {
    const p = newPipeline();
    const encoded = Uint8Array.from(p.keyBase64());
    const stdin = new RecordingStream(20);

    const writing = p.writeDek(stdin);
    await new Promise((resolve) => setTimeout(resolve, 5));
    assert.ok(stdin.handed.length === 1 && !isZero(stdin.handed[0]!), 'zeroed before the write called back');
    await writing;

    assert.ok(Buffer.isBuffer(stdin.handed[0]) && isZero(stdin.handed[0]!));
    assert.deepEqual(new Uint8Array(stdin.copies[0]!), encoded);
    assert.deepEqual(p.keyBase64(), encoded);
  });

  it('hands the key to a child process\'s standard input', async () => {
    const key = new Uint8Array(randomBytes(32));
    const p = pipelineForTests(new TestFormatProvider(), 1, { key: Uint8Array.from(key) });
    // Prints the length and SHA-256 of everything it reads, never the bytes.
    const child = spawn(process.execPath, ['-e', `
      const chunks = [];
      process.stdin.on('data', (c) => chunks.push(c)).on('end', () => {
        const all = Buffer.concat(chunks);
        process.stdout.write(all.length + ' ' + require('node:crypto').createHash('sha256').update(all).digest('hex'));
      });`], { stdio: ['pipe', 'pipe', 'inherit'] });
    let output = '';
    child.stdout.setEncoding('utf8').on('data', (c: string) => { output += c; });
    const exited = once(child, 'exit');

    await p.writeDek(child.stdin);
    child.stdin.end();
    assert.deepEqual(await exited, [0, null]);

    const expected = Buffer.from(Buffer.from(key).toString('base64'), 'ascii');
    assert.equal(output, `44 ${createHash('sha256').update(expected).digest('hex')}`);
  });

  it('refuses no stream, a closed protector and an aborted signal, writing nothing', async () => {
    const p = newPipeline();
    await assert.rejects(p.writeDek(undefined as unknown as Writable), TypeError);
    const stdin = new RecordingStream();
    await assert.rejects(p.writeDek(stdin, AbortSignal.abort()), { name: 'AbortError' });

    p.close();
    await assert.rejects(p.writeDek(stdin), ClosedError);
    assert.equal(stdin.copies.length, 0);
  });

  it('rejects with the stream\'s failure, and zeroes what it handed over', async () => {
    const p = newPipeline();
    let handed: Uint8Array | undefined;
    const failing = new Writable({
      write(chunk: Buffer, _encoding, callback) {
        handed = chunk;
        setImmediate(() => callback(new Error('EPIPE')));
      },
    });

    await assert.rejects(p.writeDek(failing), /EPIPE/);
    assert.ok(handed !== undefined && isZero(handed));

    const ended = new RecordingStream();
    ended.end();
    await assert.rejects(p.writeDek(ended), { code: 'ERR_HKDFGUARD_INVALID_STATE' });
  });

  it('refuses a Transform, which would hand its reader the very buffer it then zeroes', async () => {
    const p = newPipeline();
    for (const stream of [new PassThrough(), new Transform({ transform: (chunk, _e, callback) => callback(null, chunk) })]) {
      await assert.rejects(p.writeDek(stream), (e: unknown) => e instanceof TypeError && /Transform/.test((e as Error).message));
      assert.equal(stream.readableLength, 0, 'nothing reached its reader');
    }
  });

  it('on abort, destroys the stream and zeroes the key only once the stream lets go of it', async () => {
    const p = newPipeline();
    const controller = new AbortController();
    let handed: Uint8Array | undefined;
    // A write in flight the stream never finishes - a pipe whose reader has stopped reading - and a
    // destroy that, like closing a pipe's handle, lets go of it only later.
    const stuck = new Writable({
      write(chunk: Buffer) {
        handed = chunk;
        setImmediate(() => controller.abort(new Error('cancelled')));
      },
      destroy(error, callback) {
        setTimeout(() => callback(error), 20);
      },
    });

    await assert.rejects(p.writeDek(stuck, controller.signal), /cancelled/);

    assert.ok(stuck.destroyed, 'no more of the key can be written');
    assert.ok(handed !== undefined && !isZero(handed), 'not zeroed while the stream may still be reading it');
    if (!stuck.closed) await once(stuck, 'close');
    assert.ok(isZero(handed!), 'zeroed once the stream has closed');
  });
});

// Test support (not part of the package API): what every SecretPipelineWriter must do, whatever its
// store - the port of .NET's SecretPipelineWriterContractTests. Each store's tests run it against
// their writer over a fake store, so every writer meets every scenario. Secret names here are
// lower-case letters, digits and hyphens, which every store accepts; a store's own tests cover what
// only it does.
import { strict as assert } from 'node:assert';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { describe, it, type TestContext } from 'node:test';
import type { PipelineDataProtector, SecretPipelineWriter } from '@runsecure/hkdfguard-abstractions';

/** One test's store, and how to make writers over it. */
export interface PipelineStoreUnderTest {
  /** The store's writer, reading from this test's fake. */
  createWriter(protector: PipelineDataProtector, secretNames: readonly string[]): SecretPipelineWriter;
  /** Stores text as the value a name without a key reads. */
  setText(name: string, text: string): void;
  /** Stores a secret whose keys are the members of json, a JSON object - which may hold a member twice. */
  setKeys(name: string, json: string): void;
  /** Makes every later read fail as the store fails. */
  failReads(): void;
  /** Whether `error` is what a failing read rejects with. */
  isReadFailure(error: unknown): boolean;
  /** The name of every secret the store was asked for, in order. */
  reads(): readonly string[];
}

/** What the contract runs against. */
export interface PipelineWriterFixture {
  /**
   * A new protector, the only key in the pipeline: an AesGcmPipelineDataProtector at key version 3
   * (the contract checks values start "enc::v3::") over the dek package's DefaultFormatProvider,
   * allowing values as long as FilePerSecretCache reads - `new DefaultFormatProvider(PIPELINE_FORMAT_LIMIT)` -
   * so {@link LARGE_VALUE_LENGTH} fits. Closed when the test ends.
   */
  newProtector(): PipelineDataProtector;
  /** A new fake store for one test; anything it starts is stopped when `t` ends. */
  setUp(t: TestContext): PipelineStoreUnderTest | Promise<PipelineStoreUnderTest>;
}

/** How large a value the contract checks is protected: past the 16 KiB a body is first read into. */
export const LARGE_VALUE_LENGTH = 16 * 1024 + 1;

/** The longest formatted value the fixture's protector must allow: the 64 KiB FilePerSecretCache reads. */
export const PIPELINE_FORMAT_LIMIT = 64 * 1024;

const hasCode = (code: string) => (error: unknown) => (error as { code?: unknown } | undefined)?.code === code;
const SECRETS_NOT_FOUND = hasCode('ERR_HKDFGUARD_SECRETS_NOT_FOUND');
const INVALID_SECRET_DATA = hasCode('ERR_HKDFGUARD_INVALID_SECRET_DATA');
const INVALID_STATE = hasCode('ERR_HKDFGUARD_INVALID_STATE');
const INVALID_ARGUMENT = hasCode('ERR_HKDFGUARD_INVALID_ARGUMENT');
const AUTHENTICATION_FAILED = hasCode('ERR_HKDFGUARD_AUTHENTICATION_FAILED');

/** Decrypts a value the protector encrypted for `fileName`, as a string - only ever a test's own value. */
export function decryptPipelineValue(protector: PipelineDataProtector, encrypted: string, fileName: string): string {
  const result = new Uint8Array(protector.maxDecryptedLength(encrypted));
  return new TextDecoder().decode(result.subarray(0, protector.decrypt(encrypted, fileName, result)));
}

/** One entry of a tar archive, as {@link readTar} reads it. */
export interface TarEntry {
  /** Its name: a PAX 'path' record's when there is one, else the ustar header's. */
  readonly name: string;
  /** Its ustar type flag: '0' for a regular file. */
  readonly type: string;
  /** Its permission bits. */
  readonly mode: number;
  /** Its modification time, in seconds since the Unix epoch. */
  readonly mtime: number;
  /** Its contents. */
  readonly data: Buffer;
}

/**
 * Every entry of the tar archive `archive`, PAX extended headers ('x') applied to the entry after
 * them rather than listed - a strict little reader for tests: each header's checksum and ustar magic
 * are checked, and the archive must end with two zero blocks and nothing after them.
 */
export function readTar(archive: Uint8Array): TarEntry[] {
  const bytes = Buffer.from(archive.buffer, archive.byteOffset, archive.length);
  const text = (offset: number, length: number) => {
    const field = bytes.subarray(offset, offset + length);
    const end = field.indexOf(0);
    return field.subarray(0, end < 0 ? length : end).toString('utf8');
  };
  const octal = (offset: number, length: number) => Number.parseInt(text(offset, length).trim() || '0', 8);
  assert.equal(bytes.length % 512, 0, 'The archive isn\'t a whole number of blocks.');

  const entries: TarEntry[] = [];
  let pax = new Map<string, string>();
  let offset = 0;
  for (;;) {
    assert.ok(offset + 512 <= bytes.length, 'The archive ends without its two zero blocks.');
    const header = bytes.subarray(offset, offset + 512);
    if (header.every((b) => b === 0)) {
      assert.ok(bytes.subarray(offset).every((b) => b === 0) && bytes.length - offset === 1024, 'The archive doesn\'t end with exactly two zero blocks.');
      return entries;
    }

    let sum = 0;
    for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 0x20 : header[i]!;
    assert.equal(octal(offset + 148, 8), sum, 'A header\'s checksum is wrong.');
    assert.equal(text(offset + 257, 6), 'ustar', 'A header isn\'t ustar.');
    assert.equal(bytes.subarray(offset + 263, offset + 265).toString('latin1'), '00', 'A header isn\'t ustar version 00.');

    const start = offset;
    const type = String.fromCharCode(header[156]!);
    const size = octal(start + 124, 12);
    const data = Buffer.from(bytes.subarray(start + 512, start + 512 + size));
    offset += 512 + Math.ceil(size / 512) * 512;
    if (type === 'x') {
      pax = parsePax(data);
      continue;
    }

    entries.push({
      name: pax.get('path') ?? text(start, 100),
      type,
      mode: octal(start + 100, 8),
      mtime: Number(pax.get('mtime') ?? octal(start + 136, 12)),
      data,
    });
    pax = new Map();
  }
}

// A PAX extended header's records, each "<length> <key>=<value>\n" with length counting the whole record.
function parsePax(data: Buffer): Map<string, string> {
  const records = new Map<string, string>();
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    const length = Number(data.subarray(offset, space).toString('latin1'));
    const record = data.subarray(space + 1, offset + length).toString('utf8');
    assert.ok(record.endsWith('\n'), 'A PAX record doesn\'t end with its newline.');
    const equals = record.indexOf('=');
    records.set(record.slice(0, equals), record.slice(equals + 1, -1));
    offset += length;
  }
  return records;
}

/** A Writable that keeps a copy of everything written to it, calling each write back on a later turn. */
export class CollectingStream extends Writable {
  readonly #chunks: Buffer[] = [];
  /** How many writes have been handed to it and not yet called back, at most. */
  maxPending = 0;
  #pending = 0;

  constructor() {
    super({ highWaterMark: 16 });
  }

  /** Everything written so far. */
  get bytes(): Buffer {
    return Buffer.concat(this.#chunks);
  }

  override _write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.#chunks.push(Buffer.from(chunk));
    this.maxPending = Math.max(this.maxPending, ++this.#pending);
    setImmediate(() => {
      this.#pending--;
      callback();
    });
  }
}

interface Context {
  store: PipelineStoreUnderTest;
  protector: PipelineDataProtector;
  /** A folder to write to, which doesn't exist until a test makes it. */
  folder: string;
  /** A writer over the store with the test's protector, closed when the test ends. */
  writer(...secretNames: string[]): SecretPipelineWriter;
  decrypt(encrypted: string, fileName: string): string;
}

async function context(t: TestContext, fixture: PipelineWriterFixture): Promise<Context> {
  const protector = fixture.newProtector();
  t.after(() => protector.close());
  const parent = await mkdtemp(join(tmpdir(), 'hkdfguard-pipeline-'));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const store = await fixture.setUp(t);
  return {
    store,
    protector,
    folder: join(parent, 'secrets'),
    writer: (...secretNames) => {
      const writer = store.createWriter(protector, secretNames);
      t.after(() => writer.close());
      return writer;
    },
    decrypt: (encrypted, fileName) => decryptPipelineValue(protector, encrypted, fileName),
  };
}

/** Registers the contract's tests, under `title`, against the writers `fixture` makes. */
export function secretPipelineWriterContract(title: string, fixture: PipelineWriterFixture): void {
  describe(`${title}: the SecretPipelineWriter contract`, () => {
    it('reads each secret once, and keeps every value encrypted for its file name', async (t) => {
      const c = await context(t, fixture);
      c.store.setKeys('db-login', '{"username":"app","password":"s3cr\\"et","port":5432,"tls":true,"off":false,"unasked":"x"}');
      c.store.setText('api-key', 'api-key-value');
      const writer = c.writer('db-login#username', 'db-login#password', 'db-login#port', 'db-login#tls', 'db-login#off', 'api-key');

      await writer.pullSecrets();

      const secrets = writer.protectedSecrets;
      assert.equal(secrets.size, 6);
      assert.ok(secrets.get('db-login__password')!.startsWith('enc::v3::'));
      assert.equal(c.decrypt(secrets.get('db-login__username')!, 'db-login__username'), 'app');
      assert.equal(c.decrypt(secrets.get('db-login__password')!, 'db-login__password'), 's3cr"et');
      assert.equal(c.decrypt(secrets.get('db-login__port')!, 'db-login__port'), '5432');
      assert.equal(c.decrypt(secrets.get('db-login__tls')!, 'db-login__tls'), 'true');
      assert.equal(c.decrypt(secrets.get('db-login__off')!, 'db-login__off'), 'false');
      assert.equal(c.decrypt(secrets.get('api-key')!, 'api-key'), 'api-key-value');
      assert.deepEqual(c.store.reads(), ['db-login', 'api-key']);
    });

    it('binds a value to its file name', async (t) => {
      const c = await context(t, fixture);
      c.store.setText('item', 's3cret');
      const writer = c.writer('item');
      await writer.pullSecrets();

      assert.throws(() => c.decrypt(writer.protectedSecrets.get('item')!, 'other'), AUTHENTICATION_FAILED);
    });

    it('protects a large value', async (t) => {
      const c = await context(t, fixture);
      const large = 'x'.repeat(LARGE_VALUE_LENGTH);
      c.store.setText('big', large);
      const writer = c.writer('big');

      await writer.pullSecrets();

      assert.equal(c.decrypt(writer.protectedSecrets.get('big')!, 'big'), large);
    });

    it('replaces what the last pull kept when pulled again', async (t) => {
      const c = await context(t, fixture);
      c.store.setText('item', 'first');
      const writer = c.writer('item');
      await writer.pullSecrets();
      c.store.setText('item', 'second');

      await writer.pullSecrets();

      assert.equal(c.decrypt(writer.protectedSecrets.get('item')!, 'item'), 'second');
    });

    it('reports every missing value at once, and keeps the rest', async (t) => {
      const c = await context(t, fixture);
      c.store.setKeys('db-login', '{"username":"app","empty":"","nothing":null,"nested":{"a":"b"},"list":[1]}');
      c.store.setText('plain', 'not json');
      c.store.setText('trailing', '{"key":"v"} more');
      c.store.setText('array', '["key"]');
      c.store.setText('blank', '');
      const writer = c.writer('absent', 'db-login#username', 'db-login#password', 'db-login#empty', 'db-login#nothing',
        'db-login#nested', 'db-login#list', 'plain#key', 'trailing#key', 'array#key', 'blank');

      await assert.rejects(writer.pullSecrets(), (error: unknown) => {
        assert.ok(SECRETS_NOT_FOUND(error));
        assert.equal((error as Error).message, 'The secret store holds no value for: absent, db-login#password, db-login#empty, db-login#nothing, '
          + 'db-login#nested, db-login#list, plain#key, trailing#key, array#key, blank.');
        assert.deepEqual((error as { secretNames?: unknown }).secretNames, ['absent', 'db-login#password', 'db-login#empty', 'db-login#nothing',
          'db-login#nested', 'db-login#list', 'plain#key', 'trailing#key', 'array#key', 'blank']);
        return true;
      });
      assert.deepEqual([...writer.protectedSecrets.keys()], ['db-login__username']);

      // What was found is still written.
      await writer.writeProtectedSecretFiles(c.folder);
      assert.deepEqual(await readdir(c.folder), ['db-login__username']);
    });

    it('refuses a secret holding a key twice', async (t) => {
      const c = await context(t, fixture);
      c.store.setKeys('db-login', '{"password":"a","password":"b"}');
      const writer = c.writer('db-login#password');

      await assert.rejects(writer.pullSecrets(), INVALID_SECRET_DATA);
      assert.equal(writer.protectedSecrets.size, 0);
    });

    it('propagates a failed read, and keeps nothing', async (t) => {
      const c = await context(t, fixture);
      c.store.setText('item', 's3cret');
      const writer = c.writer('item');
      await writer.pullSecrets();
      c.store.failReads();

      await assert.rejects(writer.pullSecrets(), (error: unknown) => {
        assert.ok(c.store.isReadFailure(error), `unexpected failure: ${String(error)}`);
        return true;
      });
      assert.equal(writer.protectedSecrets.size, 0);
      await assert.rejects(writer.writeProtectedSecretFiles(c.folder), INVALID_STATE);
    });

    it('writes one file per secret through the interface, as UTF-8 without a BOM', async (t) => {
      const c = await context(t, fixture);
      c.store.setKeys('db-login', '{"password":"pässwörd"}');
      c.store.setText('api-key', 'key');
      const writer: SecretPipelineWriter = c.writer('db-login#password', 'api-key');
      await writer.pullSecrets();

      await writer.writeProtectedSecretFiles(c.folder);

      assert.deepEqual((await readdir(c.folder)).sort(), ['api-key', 'db-login__password']);
      const bytes = await readFile(join(c.folder, 'db-login__password'));
      assert.notEqual(bytes[0], 0xef);
      assert.equal(c.decrypt(bytes.toString('utf8'), 'db-login__password'), 'pässwörd');
    });

    it('replaces only its own files', async (t) => {
      const c = await context(t, fixture);
      await mkdir(c.folder, { recursive: true });
      await writeFile(join(c.folder, 'item'), 'old');
      await writeFile(join(c.folder, 'unrelated'), 'untouched');
      c.store.setText('item', 'new');
      const writer = c.writer('item');
      await writer.pullSecrets();

      await writer.writeProtectedSecretFiles(c.folder);

      assert.equal(c.decrypt(await readFile(join(c.folder, 'item'), 'utf8'), 'item'), 'new');
      assert.equal(await readFile(join(c.folder, 'unrelated'), 'utf8'), 'untouched');
    });

    it('refuses to write before a pull, or without a folder', async (t) => {
      const c = await context(t, fixture);
      const writer = c.writer('item');

      await assert.rejects(writer.writeProtectedSecretFiles(c.folder), INVALID_STATE);
      await assert.rejects(writer.writeProtectedSecretFiles(undefined as unknown as string), TypeError);
      await assert.rejects(writer.writeProtectedSecretFiles(''), INVALID_ARGUMENT);
      assert.equal(existsSync(c.folder), false);
    });

    it('writes one JSON object of file names and values through the interface', async (t) => {
      const c = await context(t, fixture);
      c.store.setKeys('db-login', '{"password":"pässwörd"}');
      c.store.setText('api-key', 'key');
      const writer: SecretPipelineWriter = c.writer('db-login#password', 'api-key');
      await writer.pullSecrets();
      const path = join(c.folder, 'nested', 'secrets.json');

      await writer.writeJsonSecrets(path);

      const bytes = await readFile(path);
      assert.equal(bytes[0], 0x7b); // '{': no BOM
      const json = JSON.parse(bytes.toString('utf8')) as Record<string, string>;
      assert.deepEqual(Object.keys(json), ['api-key', 'db-login__password']);
      assert.equal(json['db-login__password'], writer.protectedSecrets.get('db-login__password'));
      assert.equal(c.decrypt(json['db-login__password']!, 'db-login__password'), 'pässwörd');
      assert.ok(!bytes.toString('utf8').includes('\\u'));
    });

    it('replaces the JSON file, and needs a pull and a path', async (t) => {
      const c = await context(t, fixture);
      const writer = c.writer('item');
      const path = join(c.folder, 'secrets.json');
      await assert.rejects(writer.writeJsonSecrets(path), INVALID_STATE);
      await assert.rejects(writer.writeJsonSecrets(undefined as unknown as string), TypeError);
      await assert.rejects(writer.writeJsonSecrets(''), INVALID_ARGUMENT);
      assert.equal(existsSync(c.folder), false);

      await mkdir(c.folder, { recursive: true });
      await writeFile(path, '{"stale":"value","padding":"making the old file longer than the new one"}');
      c.store.setText('item', 'new');
      await writer.pullSecrets();

      await writer.writeJsonSecrets(path);

      const json = JSON.parse(await readFile(path, 'utf8')) as Record<string, string>;
      assert.deepEqual(Object.keys(json), ['item']);
      assert.equal(c.decrypt(json['item']!, 'item'), 'new');
    });

    it('streams a tar of the files through the interface, leaving the stream open', async (t) => {
      const c = await context(t, fixture);
      c.store.setKeys('db-login', '{"password":"pässwörd"}');
      c.store.setText('api-key', 'key');
      const writer: SecretPipelineWriter = c.writer('db-login#password', 'api-key');
      await writer.pullSecrets();
      const stdin = new CollectingStream();
      const before = Math.floor(Date.now() / 1000);

      await writer.writeProtectedSecretFilesTo(stdin);

      assert.ok(stdin.writable && !stdin.writableEnded);
      const entries = readTar(stdin.bytes);
      assert.deepEqual(entries.map((e) => e.name), ['api-key', 'db-login__password']);
      for (const entry of entries) {
        assert.equal(entry.type, '0');
        assert.equal(entry.mode, 0o644);
        assert.ok(entry.mtime >= before && entry.mtime <= Math.floor(Date.now() / 1000) + 1);
      }
      // The same bytes writeProtectedSecretFiles writes.
      await writer.writeProtectedSecretFiles(c.folder);
      for (const entry of entries) assert.deepEqual(entry.data, await readFile(join(c.folder, entry.name)));
      assert.equal(c.decrypt(entries[1]!.data.toString('utf8'), 'db-login__password'), 'pässwörd');
    });

    it('streams the JSON object byte for byte as the file holds it', async (t) => {
      const c = await context(t, fixture);
      c.store.setText('item', 's3cret');
      const writer: SecretPipelineWriter = c.writer('item');
      await writer.pullSecrets();
      const stdin = new CollectingStream();

      await writer.writeJsonSecretsTo(stdin);
      await writer.writeJsonSecrets(join(c.folder, 'secrets.json'));

      assert.ok(stdin.writable && !stdin.writableEnded);
      assert.deepEqual(stdin.bytes, await readFile(join(c.folder, 'secrets.json')));
      const json = JSON.parse(stdin.bytes.toString('utf8')) as Record<string, string>;
      assert.equal(c.decrypt(json['item']!, 'item'), 's3cret');
    });

    it('needs a pull and a stream to stream to', async (t) => {
      const c = await context(t, fixture);
      const writer = c.writer('item');
      const stdin = new CollectingStream();

      await assert.rejects(writer.writeProtectedSecretFilesTo(stdin), INVALID_STATE);
      await assert.rejects(writer.writeJsonSecretsTo(stdin), INVALID_STATE);
      await assert.rejects(writer.writeProtectedSecretFilesTo(undefined as unknown as Writable), TypeError);
      await assert.rejects(writer.writeJsonSecretsTo({} as Writable), TypeError);
      assert.equal(stdin.bytes.length, 0);
    });

    for (const secretName of ['', 'bad name', '#key', 'db-login#', 'db-login#bad key', 'db-login#a:b']) {
      it(`refuses the invalid name '${secretName}'`, async (t) => {
        const c = await context(t, fixture);
        assert.throws(() => c.writer(secretName), INVALID_ARGUMENT);
      });
    }

    it('checks the list and the protector', async (t) => {
      const c = await context(t, fixture);
      const create = (protector: PipelineDataProtector, names: readonly string[]) => {
        const writer = c.store.createWriter(protector, names);
        t.after(() => writer.close());
      };
      assert.throws(() => create(undefined as unknown as PipelineDataProtector, ['item']), TypeError);
      assert.throws(() => create(c.protector, undefined as unknown as string[]), TypeError);
      assert.throws(() => create(c.protector, []), INVALID_ARGUMENT);
      assert.throws(() => create(c.protector, [null as unknown as string]), INVALID_ARGUMENT);
      assert.throws(() => create(c.protector, ['item', 'ITEM']), INVALID_ARGUMENT);
      assert.throws(() => create(c.protector, ['item', 'item']), INVALID_ARGUMENT);
    });
  });
}

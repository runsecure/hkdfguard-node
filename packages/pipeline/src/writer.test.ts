import { strict as assert } from 'node:assert';
import { Readable } from 'node:stream';
import { describe, it } from 'node:test';
import { ClosedError, HkdfGuardError, InvalidArgumentError, isZero, type PipelineDataProtector } from '@runsecure/hkdfguard-abstractions';
import { AesGcmPipelineDataProtector } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { DefaultFormatProvider } from '@runsecure/hkdfguard-dek';
import { decryptPipelineValue, PIPELINE_FORMAT_LIMIT, secretPipelineWriterContract } from '@runsecure/hkdfguard-test-support';
import { InvalidSecretDataError, PinnedBody, SecretPipelineWriter, SecretsNotFoundError, type SecretRequest } from './index.js';

const utf8 = (s: string) => new TextEncoder().encode(s);

/** A store of secret values by name, as UTF-8 bytes; names are ASCII letters, digits, hyphens and '/'. */
class FakeStore {
  readonly secrets = new Map<string, Uint8Array>();
  readonly reads: string[] = [];
  failWith: Error | undefined;
  /** Awaited inside every read, e.g. to hold it open. */
  hold: Promise<void> | undefined;

  static isValidName(name: string): boolean {
    return /^[A-Za-z0-9/-]*$/.test(name);
  }

  set(name: string, value: string): void {
    this.secrets.set(name, utf8(value));
  }
}

class FakeWriter extends SecretPipelineWriter {
  closed = 0;

  constructor(protector: PipelineDataProtector, secretNames: readonly string[], private readonly store: FakeStore, defaultKey?: string) {
    super(protector, secretNames, FakeStore.isValidName, defaultKey);
  }

  protected override async readSecret(name: string, requests: readonly SecretRequest[], values: Map<string, string>): Promise<void> {
    this.store.reads.push(name);
    await this.store.hold;
    if (this.store.failWith !== undefined) throw this.store.failWith;
    const secret = this.store.secrets.get(name);
    if (secret !== undefined) this.protectSecret(secret, requests, values);
  }

  protected override closeStore(): void {
    this.closed++;
  }
}

/** A writer whose name rule is missing. */
class NullRuleWriter extends SecretPipelineWriter {
  constructor(protector: PipelineDataProtector) {
    super(protector, ['app'], undefined as unknown as (name: string) => boolean);
  }

  protected override async readSecret(): Promise<void> {}
}

const newProtector = () => new AesGcmPipelineDataProtector(new DefaultFormatProvider(PIPELINE_FORMAT_LIMIT), 3);

secretPipelineWriterContract('SecretPipelineWriter over an in-memory store', {
  newProtector,
  setUp: () => {
    const store = new FakeStore();
    return {
      createWriter: (protector, secretNames) => new FakeWriter(protector, secretNames, store),
      setText: (name, text) => store.set(name, text),
      setKeys: (name, json) => store.set(name, json),
      failReads: () => {
        store.failWith = new Error('down');
      },
      isReadFailure: (error) => error instanceof Error && error.message === 'down',
      reads: () => store.reads,
    };
  },
});

describe('SecretPipelineWriter', () => {
  const fixture = (t: { after(fn: () => unknown): void }) => {
    const protector = newProtector();
    t.after(() => protector.close());
    const store = new FakeStore();
    const decrypt = (encrypted: string | undefined, fileName: string) => decryptPipelineValue(protector, encrypted!, fileName);
    return { protector, store, decrypt };
  };

  it('reads the whole value for a name without a key, or the default key when there is one', async (t) => {
    const { protector, store, decrypt } = fixture(t);
    store.set('app', '{"value":"s3cret"}');
    const whole = new FakeWriter(protector, ['app'], store);
    const byDefault = new FakeWriter(protector, ['app'], store, 'value');

    await whole.pullSecrets();
    await byDefault.pullSecrets();

    assert.equal(decrypt(whole.protectedSecrets.get('app'), 'app'), '{"value":"s3cret"}');
    assert.equal(decrypt(byDefault.protectedSecrets.get('app'), 'app'), 's3cret');
  });

  it('reads a secret once, for its whole value and its keys', async (t) => {
    const { protector, store, decrypt } = fixture(t);
    store.set('prod/app', '{"user":"app"}');
    const writer = new FakeWriter(protector, ['prod/app', 'prod/app#user'], store);

    await writer.pullSecrets();

    assert.deepEqual(store.reads, ['prod/app']);
    assert.equal(decrypt(writer.protectedSecrets.get('prod__app'), 'prod__app'), '{"user":"app"}');
    assert.equal(decrypt(writer.protectedSecrets.get('prod__app__user'), 'prod__app__user'), 'app');
  });

  it('refuses a value that isn\'t UTF-8 text, as a whole value or a key', async (t) => {
    const { protector, store } = fixture(t);
    // Not UTF-8, and an encoded surrogate (U+D800), which UTF-8 never holds.
    for (const value of [new Uint8Array([0xff, 0xfe, 0x00, 0x80]), new Uint8Array([0xed, 0xa0, 0x80])]) {
      store.secrets.set('binary', value);
      const writer = new FakeWriter(protector, ['binary'], store);
      await assert.rejects(writer.pullSecrets(), InvalidSecretDataError);
      assert.equal(writer.protectedSecrets.size, 0);
    }

    // A member's raw bytes are checked too: an overlong '/' inside a string.
    store.secrets.set('keys', new Uint8Array([...utf8('{"k":"a'), 0xc0, 0xaf, ...utf8('"}')]));
    await assert.rejects(new FakeWriter(protector, ['keys#k'], store).pullSecrets(), InvalidSecretDataError);
  });

  it('protects the UTF-8 bytes it is given, never a decoded copy', async (t) => {
    const { protector, store, decrypt } = fixture(t);
    store.set('emoji', 'päss \u{1f511}');
    const writer = new FakeWriter(protector, ['emoji'], store);

    await writer.pullSecrets();

    assert.equal(decrypt(writer.protectedSecrets.get('emoji'), 'emoji'), 'päss \u{1f511}');
  });

  it('finds no keys in a whitespace value', async (t) => {
    const { protector, store } = fixture(t);
    store.set('blank', '   ');
    const writer = new FakeWriter(protector, ['blank#key'], store);

    await assert.rejects(writer.pullSecrets(), SecretsNotFoundError);
  });

  it('matches a key escaped in the JSON, and unescapes its value', async (t) => {
    const { protector, store, decrypt } = fixture(t);
    store.set('app', '{"pass\\u0077ord":"a\\nb\\u00e9\\ud83d\\udd11"}');
    const writer = new FakeWriter(protector, ['app#password'], store);

    await writer.pullSecrets();

    assert.equal(decrypt(writer.protectedSecrets.get('app__password'), 'app__password'), 'a\nbé\u{1f511}');
  });

  it('closes the store once through the interface, and refuses a pull afterwards', async (t) => {
    const { protector, store } = fixture(t);
    const writer = new FakeWriter(protector, ['app'], store);

    await writer.close();
    await writer.close();

    assert.equal(writer.closed, 1);
    await assert.rejects(writer.pullSecrets(), ClosedError);
  });

  it('refuses a pull while another runs', async (t) => {
    const { protector, store } = fixture(t);
    store.set('app', 'x');
    const held = Promise.withResolvers<void>();
    store.hold = held.promise;
    const writer = new FakeWriter(protector, ['app'], store);

    const first = writer.pullSecrets();
    await assert.rejects(writer.pullSecrets(), (error: unknown) => error instanceof HkdfGuardError && error.code === 'ERR_HKDFGUARD_INVALID_STATE');
    held.resolve();
    await first;
    assert.equal(writer.protectedSecrets.size, 1);
  });

  it('stops pulling once the signal is aborted', async (t) => {
    const { protector, store } = fixture(t);
    const controller = new AbortController();
    controller.abort(new Error('stop'));
    const writer = new FakeWriter(protector, ['app'], store);

    await assert.rejects(writer.pullSecrets(controller.signal), /stop/);
    assert.deepEqual(store.reads, []);
    await assert.rejects(writer.writeProtectedSecretFiles('x'), (error: unknown) => (error as HkdfGuardError).code === 'ERR_HKDFGUARD_INVALID_STATE');
  });

  for (const [secretName, fileName] of [['prod/app#password', 'prod__app__password'], ['prod/app', 'prod__app'], ['app', 'app']] as const) {
    it(`writes '${secretName}' as ${fileName}`, () => {
      assert.equal(SecretPipelineWriter.getFileName(secretName), fileName);
    });
  }

  it('refuses names that map to one file name', (t) => {
    const { protector, store } = fixture(t);
    assert.throws(() => new FakeWriter(protector, ['a/b', 'a#b'], store), InvalidArgumentError);
    assert.throws(() => new FakeWriter(protector, ['a/b', 'A__B'], store), InvalidArgumentError);
  });

  it('checks the default key and the name rule', (t) => {
    const { protector, store } = fixture(t);
    assert.throws(() => SecretPipelineWriter.getFileName(undefined as unknown as string), TypeError);
    assert.throws(() => new FakeWriter(protector, ['app'], store, ''), InvalidArgumentError);
    assert.throws(() => new FakeWriter(protector, ['app'], store, 'a#b'), InvalidArgumentError);
    assert.throws(() => new NullRuleWriter(protector), TypeError);
    assert.throws(() => new FakeWriter(protector, 'app' as unknown as string[], store), TypeError);
  });

  it('copies the list', async (t) => {
    const { protector, store } = fixture(t);
    store.set('item', 's3cret');
    const names = ['item'];
    const writer = new FakeWriter(protector, names, store);
    names.push('other');

    await writer.pullSecrets();

    assert.deepEqual([...writer.protectedSecrets.keys()], ['item']);
  });
});

describe('PinnedBody', () => {
  it('reads the whole body, growing as needed, and zeroes each chunk and outgrown buffer', async () => {
    const body = utf8(JSON.stringify({ value: 'x'.repeat(100_000) }));
    const chunks: Uint8Array[] = [];
    for (let i = 0; i < body.length; i += 7000) chunks.push(Uint8Array.from(body.subarray(i, i + 7000)));

    const { buffer, length } = await PinnedBody.read(Readable.from(chunks.map((c) => Buffer.from(c))));

    assert.deepEqual(buffer.subarray(0, length), body);
    assert.ok(length < buffer.length);
  });

  it('copies a whole body, leaving it to its owner', async () => {
    const body = utf8('{"value":"s3cret"}');
    const { buffer, length } = await PinnedBody.read(body);
    assert.deepEqual(buffer.subarray(0, length), body);
    assert.notEqual(buffer.buffer, body.buffer);
    assert.ok(!isZero(body));
  });

  it('zeroes the chunks it was handed', async () => {
    const chunks = [utf8('{"value":'), utf8('"s3cret"}')];
    await PinnedBody.read(chunks);
    assert.ok(chunks.every(isZero));
  });

  it('refuses a body of the maximum or more, and anything but bytes', async () => {
    await assert.rejects(PinnedBody.read([new Uint8Array(PinnedBody.MAX_LENGTH)]), InvalidSecretDataError);
    await assert.rejects(PinnedBody.read([new Uint8Array(PinnedBody.MAX_LENGTH - 1), new Uint8Array(1)]), InvalidSecretDataError);
    const { length } = await PinnedBody.read([new Uint8Array(PinnedBody.MAX_LENGTH - 1)]);
    assert.equal(length, PinnedBody.MAX_LENGTH - 1);
    await assert.rejects(PinnedBody.read(undefined as never), TypeError);
    await assert.rejects(PinnedBody.read(['text'] as never), TypeError);
    await assert.rejects(PinnedBody.read(42 as never), TypeError);
  });
});

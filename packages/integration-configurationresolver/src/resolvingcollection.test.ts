import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { cacheAad, InvalidArgumentError, type ProtectedReadOnlyCache } from '@runsecure/hkdfguard-abstractions';
import { AttributeNames, HkdfGuardTelemetry, SpanNames } from '@runsecure/hkdfguard-diagnostics';
import type { KeyRing } from '@runsecure/hkdfguard-dek';
import { RecordingKey, useSpanRecorder } from '@runsecure/hkdfguard-test-support';
import { decryptText, FakeRemoteSecretCache, newCache, newRing, PlainSource, SettingsProvider, text } from './cache.test-support.js';
import {
  ConfigurationItemTokenBase, ConfigurationKeyError, ConfigurationKeyErrorCode, DefaultToken, DestinationTooSmallError,
  ResolvedValueTooLongError, ResolvingProtectedCacheCollection,
} from './index.js';
import { storeKey } from './resolvingcollection.js';

const CONN = 'Host=db.internal;Password=s3cret';

function create(ring: KeyRing = newRing()): { collection: ResolvingProtectedCacheCollection; source: PlainSource } {
  const source = new PlainSource({ conn: 'Host=${host};Password=${password}', host: 'db.internal', password: 's3cret' });
  return { collection: new ResolvingProtectedCacheCollection(ring).add(source), source };
}

async function decryptInto(cache: ProtectedReadOnlyCache, name: string, length = 64): Promise<string> {
  const result = new Uint8Array(length);
  return text(result.subarray(0, await cache.decrypt(name, result)));
}

describe('ResolvingProtectedCacheCollection', () => {
  it('resolves a template from the sources and caches it', async () => {
    const { collection, source } = create();

    assert.equal(await decryptText(collection, 'conn'), CONN);
    assert.equal(await decryptText(collection, 'conn'), CONN);

    // Read and resolved once; every later lookup decrypts the cached result.
    assert.equal(source.decryptCount('conn'), 1);
    assert.equal(source.decryptCount('password'), 1);
  });

  it('resolves a template on a first decrypt, without sizing first', async () => {
    assert.equal(await decryptInto(create().collection, 'conn'), CONN);
  });

  it('caches the resolved value encrypted, not as the sources hold its parts', async () => {
    const maxLength = await create().collection.maxDecryptedLength('conn');

    // An AEAD bound: longer than the 32-byte resolved value it encloses.
    assert.ok(maxLength !== undefined && maxLength > CONN.length);
  });

  it('answers a value without items from its source, which it remembers', async () => {
    const { collection, source } = create();

    assert.equal(await decryptText(collection, 'password'), 's3cret');
    assert.equal(await decryptText(collection, 'password'), 's3cret');

    // One search through the sources, then only the lookups the remembered source answers.
    assert.equal(source.lengthLookupCount('password'), 3);
    assert.equal(source.decryptCount('password'), 3);
  });

  it('reports a missing name missing', async () => {
    const { collection } = create();

    assert.equal(await collection.decrypt('absent', new Uint8Array(16)), 0);
    assert.equal(await collection.maxDecryptedLength('absent'), undefined);
  });

  it('checks sources in order, for names and items alike', async () => {
    const first = new PlainSource({ conn: '${password}', password: 'first' });
    const second = new PlainSource({ conn: 'ignored', password: 'second', 'only-second': '${password}' });
    const collection = new ResolvingProtectedCacheCollection(newRing()).add(first).add(second);

    assert.equal(await decryptText(collection, 'conn'), 'first');
    assert.equal(await decryptText(collection, 'only-second'), 'first');
    assert.equal(second.decryptCount('conn'), 0);
  });

  it('asks value providers after the sources, growing the buffer when a value needs it', async () => {
    const large = 'x'.repeat(5000);
    const source = new PlainSource({ conn: 'Host=${host};Blob=${blob}', host: 'from-source' });
    const collection = new ResolvingProtectedCacheCollection(newRing())
      .add(source)
      .addValueProvider(new SettingsProvider({ host: 'ignored', blob: large }));

    assert.equal(await decryptText(collection, 'conn'), `Host=from-source;Blob=${large}`);
  });

  it("never answers a value provider's values by name on their own", async () => {
    const collection = new ResolvingProtectedCacheCollection(newRing()).addValueProvider(new SettingsProvider({ host: 'db' }));

    assert.equal(await collection.maxDecryptedLength('host'), undefined);
  });

  it('rejects a value that resolves to more than maxResolvedLength', async () => {
    const collection = new ResolvingProtectedCacheCollection(newRing(), { maxResolvedLength: 16 })
      .add(new PlainSource({ conn: '${blob}' }))
      .addValueProvider(new SettingsProvider({ blob: 'x'.repeat(17) }));

    await assert.rejects(
      collection.decrypt('conn', new Uint8Array(64)),
      (error: unknown) => error instanceof ResolvedValueTooLongError
        && error.code === 'ERR_HKDFGUARD_RESOLVED_VALUE_TOO_LONG'
        && error.cause instanceof DestinationTooSmallError,
    );
  });

  it('defaults maxResolvedLength and the token, and rejects an invalid length', () => {
    const collection = new ResolvingProtectedCacheCollection(newRing());

    assert.equal(collection.maxResolvedLength, ResolvingProtectedCacheCollection.DEFAULT_MAX_RESOLVED_LENGTH);
    assert.equal(collection.maxResolvedLength, 1 << 20);
    assert.ok(collection.token instanceof DefaultToken);
    for (const maxResolvedLength of [0, -1, 1.5, Number.NaN]) {
      assert.throws(() => new ResolvingProtectedCacheCollection(newRing(), { maxResolvedLength }), InvalidArgumentError);
    }
  });

  it('marks items with a custom token', async () => {
    const source = new PlainSource({ conn: 'Host={{host}};Literal=${host}', host: 'db' });
    const collection = new ResolvingProtectedCacheCollection(newRing(), { token: new ConfigurationItemTokenBase('{{', '}}') }).add(source);

    assert.equal(await decryptText(collection, 'conn'), 'Host=db;Literal=${host}');
  });

  it('rejects a template naming a value nothing has', async () => {
    const collection = new ResolvingProtectedCacheCollection(newRing()).add(new PlainSource({ conn: '${absent}' }));
    const notFound = (error: unknown) => error instanceof ConfigurationKeyError && error.error === ConfigurationKeyErrorCode.notFound;

    await assert.rejects(collection.decrypt('conn', new Uint8Array(64)), notFound);
    await assert.rejects(collection.maxDecryptedLength('conn'), notFound);
  });

  it('reports a template that resolves to nothing missing', async () => {
    const collection = new ResolvingProtectedCacheCollection(newRing())
      .add(new PlainSource({ conn: '${empty}' }))
      .addValueProvider(new SettingsProvider({ empty: '' }));

    assert.equal(await collection.maxDecryptedLength('conn'), undefined);
    assert.equal(await collection.decrypt('conn', new Uint8Array(16)), 0);
  });

  it('fails the lookup when a source throws', async () => {
    const denied = new Error('access denied');
    const refusing: ProtectedReadOnlyCache = {
      decrypt: async () => { throw denied; },
      maxDecryptedLength: async () => { throw denied; },
    };
    const collection = new ResolvingProtectedCacheCollection(newRing()).add(new PlainSource({ conn: '${remote}' })).add(refusing);

    await assert.rejects(collection.decrypt('conn', new Uint8Array(64)), (error) => error === denied);
    await assert.rejects(collection.maxDecryptedLength('absent'), (error) => error === denied);
  });

  it('keeps a resolved value until it is invalidated', async () => {
    const { collection, source } = create();
    assert.equal(await decryptText(collection, 'conn'), CONN);

    source.set('password', 'rotated');
    assert.equal(await decryptText(collection, 'conn'), CONN);

    assert.equal(collection.invalidate('conn'), true);
    assert.equal(await decryptText(collection, 'conn'), 'Host=db.internal;Password=rotated');
    assert.equal(collection.invalidate('never-looked-up'), false);
  });

  it('invalidate forgets which source holds a plain value', async () => {
    const first = new PlainSource();
    const second = new PlainSource({ password: 'second' });
    const collection = new ResolvingProtectedCacheCollection(newRing()).add(first).add(second);
    assert.equal(await decryptText(collection, 'password'), 'second');

    first.set('password', 'first');
    assert.equal(await decryptText(collection, 'password'), 'second');

    assert.equal(collection.invalidate('password'), true);
    assert.equal(await decryptText(collection, 'password'), 'first');
  });

  it('clear forgets everything', async () => {
    const { collection, source } = create();
    await decryptText(collection, 'conn');
    await decryptText(collection, 'host');

    source.set('host', 'db2');
    source.set('password', 'rotated');
    collection.clear();

    assert.equal(await decryptText(collection, 'conn'), 'Host=db2;Password=rotated');
    assert.equal(await decryptText(collection, 'host'), 'db2');
  });

  it('keeps the result of a resolve that an invalidate overlapped out of the cache', async () => {
    const { collection, source } = create();
    source.onFirstDecrypt = {
      name: 'password',
      run: () => {
        source.set('password', 'rotated');
        collection.invalidate('conn');
      },
    };

    // The first resolution read the old value's length, so it is dropped and the lookup resolves again.
    assert.equal(await decryptInto(collection, 'conn'), 'Host=db.internal;Password=rotated');
    assert.equal(source.decryptCount('conn'), 2);

    assert.equal(await decryptInto(collection, 'conn'), 'Host=db.internal;Password=rotated');
    assert.equal(source.decryptCount('conn'), 2);
  });

  it('does not remember the source of a plain lookup that a clear overlapped', async () => {
    const { collection, source } = create();
    source.onFirstDecrypt = { name: 'host', run: () => collection.clear() };

    assert.equal(await decryptText(collection, 'host'), 'db.internal');
    const lookups = source.lengthLookupCount('host');

    assert.equal(await decryptText(collection, 'host'), 'db.internal');
    assert.equal(source.lengthLookupCount('host'), lookups + 1);
  });

  it('matches names exactly, even where the resolved store ignores case', async () => {
    const source = new PlainSource({
      Db: 'upper ${value}',
      db: 'lower ${value}',
      aB: 'camel ${value}',
      value: 'v',
      'a!b': 'bang ${value}',
      'a!!b': 'double ${value}',
      'app/Db-1': 'path ${value}',
    });
    const collection = new ResolvingProtectedCacheCollection(newRing()).add(source);

    assert.equal(await decryptText(collection, 'Db'), 'upper v');
    assert.equal(await decryptText(collection, 'db'), 'lower v');
    assert.equal(await decryptText(collection, 'a!b'), 'bang v');
    assert.equal(await decryptText(collection, 'aB'), 'camel v');
    assert.equal(await decryptText(collection, 'a!!b'), 'double v');
    assert.equal(await decryptText(collection, 'app/Db-1'), 'path v');
    assert.equal(await decryptText(collection, 'Db'), 'upper v');
  });

  it('stores each name under a key with no upper-case ASCII, whose AAD no other name shares', () => {
    const names = ['', 'db', 'Db', 'DB', 'dB', '!', '!!', '!d', '!D', 'a!b', 'aB', 'a!!b', 'a!Bb', 'app/Db-1', 'café', 'CAFÉ'];
    const aads = new Map<string, string>();
    for (const name of names) {
      const key = storeKey(name);
      assert.ok(!/[A-Z]/.test(key), `${name} -> ${key}`);
      const aad = Buffer.from(cacheAad(key)).toString('hex');
      assert.ok(!aads.has(aad), `${name} shares an AAD with ${aads.get(aad)}`);
      aads.set(aad, name);
    }
  });

  it('resolves from a remote source, fetching each secret once', async () => {
    const ring = newRing();
    const remote = new FakeRemoteSecretCache(ring, { conn: 'Host=${host};Password=${password}', host: 'db.internal', password: 's3cret' });
    const collection = new ResolvingProtectedCacheCollection(ring).add(remote);

    const maxLength = await collection.maxDecryptedLength('conn');
    assert.ok(maxLength !== undefined);
    const result = new Uint8Array(maxLength);
    assert.equal(text(result.subarray(0, await collection.decrypt('conn', result))), CONN);
    assert.equal(await collection.maxDecryptedLength('conn'), maxLength);

    // A plain value, found and then remembered.
    assert.ok(((await collection.maxDecryptedLength('host')) ?? 0) > 0);
    assert.equal(await decryptText(collection, 'password'), 's3cret');

    assert.deepEqual([...remote.fetches].sort(), ['conn', 'host', 'password']);
  });

  it('resolves again after the template was invalidated', async () => {
    const { collection, source } = create();
    assert.ok(((await collection.maxDecryptedLength('conn')) ?? 0) > 0);

    source.set('password', 'rotated');
    collection.invalidate('conn');

    assert.equal(await decryptInto(collection, 'conn'), 'Host=db.internal;Password=rotated');
  });

  it('gives every overlapping lookup the resolved value', async () => {
    const { collection } = create();

    const lookups = Array.from({ length: 64 }, async (_, index) => {
      if (index % 8 === 0) collection.invalidate('conn');
      return decryptInto(collection, 'conn');
    });

    assert.deepEqual(new Set(await Promise.all(lookups)), new Set([CONN]));
  });

  it('resolves a value again under the current key once the ring retires its key', async () => {
    const ring = newRing();
    const { collection, source } = create(ring);
    assert.equal(await decryptText(collection, 'conn'), CONN);

    const current = new RecordingKey();
    ring.add(2, current);
    await ring.remove(1);
    source.set('password', 'rotated');

    assert.equal(await decryptText(collection, 'conn'), 'Host=db.internal;Password=rotated');
    assert.equal(current.encryptAads.length, 1);
    assert.equal(source.decryptCount('conn'), 2);
  });

  it('resolves values from a ProtectedCache', async () => {
    const ring = newRing();
    const cache = newCache(ring, { conn: 'Host=${host};Password=${password}', host: 'db.internal', password: 's3cret' });
    const collection = new ResolvingProtectedCacheCollection(ring).add(cache);

    assert.equal(await decryptText(collection, 'conn'), CONN);
  });

  it('an aborted signal cancels a lookup', async () => {
    const ring = newRing();
    const remote = new FakeRemoteSecretCache(ring, { conn: '${password}', password: 's3cret' });
    const collection = new ResolvingProtectedCacheCollection(ring).add(remote);

    await assert.rejects(collection.decrypt('conn', new Uint8Array(64), AbortSignal.abort()), { name: 'AbortError' });
    assert.equal(await decryptText(collection, 'conn'), 's3cret');
  });

  it('records the name on its decrypt span while sensitive logging is enabled', async () => {
    const recorder = useSpanRecorder();
    const telemetry = HkdfGuardTelemetry.cache;
    const original = telemetry.enableSensitiveLogging;
    telemetry.enableSensitiveLogging = true;
    try {
      const { collection } = create();

      assert.equal(await decryptText(collection, 'password'), 's3cret');

      const names = recorder.spans()
        .filter((span) => span.name === SpanNames.cache.decrypt)
        .flatMap((span) => span.events.map((event) => event.attributes?.[AttributeNames.name]));
      assert.ok(names.includes('password'));
    } finally {
      telemetry.enableSensitiveLogging = original;
      await recorder.dispose();
    }
  });

  it('members reject undefined arguments', async () => {
    const collection = new ResolvingProtectedCacheCollection(newRing());
    const missing = undefined as never;

    assert.throws(() => new ResolvingProtectedCacheCollection(missing), TypeError);
    assert.throws(() => collection.add(missing), TypeError);
    assert.throws(() => collection.addValueProvider(missing), TypeError);
    assert.throws(() => collection.invalidate(missing), TypeError);
    await assert.rejects(collection.decrypt(missing, new Uint8Array(1)), TypeError);
    await assert.rejects(collection.maxDecryptedLength(missing), TypeError);
  });
});

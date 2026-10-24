import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import {
  AlreadyExistsError, AuthenticationFailedError, cacheAad, InvalidCacheNameError, isZero, KeyNotFoundError,
  type ProtectedCache as ProtectedCacheContract, type ProtectedReadOnlyCache,
} from '@runsecure/hkdfguard-abstractions';
import { HkdfGuardTelemetry, MetricNames } from '@runsecure/hkdfguard-diagnostics';
import { KeyRing } from '@runsecure/hkdfguard-dek';
import { capturingLogger, FakeKeyWrapper, RecordingFactory, RecordingKey, useMetricRecorder } from '@runsecure/hkdfguard-test-support';
import { cacheEntriesForTests, ProtectedCache, ReadOnlyProtectedCache } from './cache.js';
import { ProtectedCacheCollection } from './collection.js';
import { EmptyValueError, type CacheSource } from './store.js';

const utf8 = (s: string) => new TextEncoder().encode(s);

function ringWith(...versions: number[]): { ring: KeyRing; keys: Map<number, RecordingKey> } {
  const ring = new KeyRing();
  const keys = new Map<number, RecordingKey>();
  for (const v of versions) {
    const key = new RecordingKey();
    ring.add(v, key);
    keys.set(v, key);
  }
  return { ring, keys };
}

const newCache = (options = {}) => new ProtectedCache(ringWith(1).ring, options);

/** name's value, sized by maxDecryptedLength; undefined when nothing is stored. */
async function get(cache: ProtectedReadOnlyCache, name: string): Promise<string | undefined> {
  const length = await cache.maxDecryptedLength(name);
  if (length === undefined) return undefined;
  const result = new Uint8Array(length);
  return new TextDecoder().decode(result.subarray(0, await cache.decrypt(name, result)));
}

/** A source serving values from a map, counting fetches and keeping what it served. */
class FakeSource implements CacheSource {
  fetches = 0;
  served: Uint8Array[] = [];
  error: unknown;
  constructor(private readonly values: Record<string, string>) {}
  async fetch(name: string): Promise<Uint8Array | undefined> {
    this.fetches++;
    if (this.error !== undefined) throw this.error;
    const value = this.values[name];
    if (value === undefined) return undefined;
    const plaintext = utf8(value);
    this.served.push(plaintext);
    return plaintext;
  }
}

describe('ProtectedCache', () => {
  it('is a ProtectedCache that round-trips', async () => {
    const cache: ProtectedCacheContract = newCache();
    cache.add('plain', utf8('hello'));
    cache.add('multibyte', utf8('héllo wörld ✓ 🔐'));
    assert.equal(await get(cache, 'plain'), 'hello');
    assert.equal(await get(cache, 'multibyte'), 'héllo wörld ✓ 🔐');
  });

  it('zeroes the plaintext on success and failure', () => {
    const cache = newCache();
    const ok = utf8('secret'), duplicate = utf8('secret'), badName = utf8('secret');
    cache.add('item', ok);
    assert.throws(() => cache.add('item', duplicate));
    assert.throws(() => cache.add('bad\uD800name', badName));
    assert.ok(isZero(ok) && isZero(duplicate) && isZero(badName));
  });

  it('refuses a duplicate name in any ASCII case, keeping the first value', async () => {
    const cache = newCache();
    cache.add('Item', utf8('first'));
    for (const name of ['Item', 'ITEM', 'item']) assert.throws(() => cache.add(name, utf8('second')), AlreadyExistsError);
    assert.equal(await get(cache, 'item'), 'first');
  });

  it('replaces any value with addOrUpdate', async () => {
    const cache = newCache();
    cache.add('item', utf8('first'));
    cache.addOrUpdate('ITEM', utf8('second'));
    cache.addOrUpdate('new', utf8('fresh'));
    assert.equal(await get(cache, 'Item'), 'second');
    assert.equal(await get(cache, 'new'), 'fresh');
  });

  it('matches names ignoring only ASCII case', async () => {
    const cache = newCache();
    cache.add('Api-Key_1', utf8('ascii'));
    cache.add('café', utf8('lower'));
    cache.add('CAFÉ', utf8('upper'));
    assert.equal(await get(cache, 'api-key_1'), 'ascii');
    assert.equal(await get(cache, 'café'), 'lower');
    assert.equal(await get(cache, 'CAFÉ'), 'upper');
  });

  it('decrypts a missing name to nothing, bounds what is stored, and refuses a too-small buffer', async () => {
    const cache = newCache();
    assert.equal(await cache.decrypt('missing', new Uint8Array(8)), 0);
    assert.equal(await cache.maxDecryptedLength('missing'), undefined);
    cache.add('item', utf8('hello'));
    assert.ok((await cache.maxDecryptedLength('item'))! >= 5);
    await assert.rejects(cache.decrypt('item', new Uint8Array(2)));
  });

  it('refuses an empty value or invalid name, storing nothing', async () => {
    const cache = newCache();
    assert.throws(() => cache.add('empty', new Uint8Array(0)), EmptyValueError);
    assert.throws(() => cache.addOrUpdate('empty', new Uint8Array(0)), EmptyValueError);
    assert.throws(() => cache.add('bad\uD800name', utf8('value')), InvalidCacheNameError);
    assert.equal(await cache.maxDecryptedLength('empty'), undefined);
  });

  it('round-trips a large value', async () => {
    const cache = newCache();
    const large = 'x'.repeat(2 << 20);
    cache.addOrUpdate('large', utf8(large));
    assert.equal(await get(cache, 'large'), large);
  });

  it('serves many concurrent readers and writers', async () => {
    const cache = newCache();
    await Promise.all(Array.from({ length: 64 }, async (_, i) => {
      cache.add(`item-${i}`, utf8(`value-${i}`));
      assert.equal(await get(cache, `item-${i}`), `value-${i}`);
    }));
  });
});

describe('name binding and rotation', () => {
  it("encrypts and decrypts every value with its name's AAD", async () => {
    const { ring, keys } = ringWith(1);
    const cache = new ProtectedCache(ring);
    cache.add('Item', utf8('value'));
    await get(cache, 'ITEM');
    await get(cache, 'item');
    const key = keys.get(1)!;
    assert.deepEqual(key.encryptAads, [cacheAad('Item')]);
    assert.ok(key.decryptAads.length > 0 && key.decryptAads.every((aad) => Buffer.compare(aad, cacheAad('Item')) === 0));
  });

  it('fails authentication for a ciphertext moved under another name, while the original still decrypts', async () => {
    const cache = newCache();
    cache.add('admin', utf8('admin-secret'));
    cache.add('reporting', utf8('reporting-secret'));
    cacheEntriesForTests(cache).set('REPORTING', cacheEntriesForTests(cache).get('ADMIN')!);
    await assert.rejects(cache.decrypt('reporting', new Uint8Array(64)), AuthenticationFailedError);
    assert.equal(await get(cache, 'admin'), 'admin-secret');
  });

  it('uses each value its own key across a rotation, re-encrypting on update', async () => {
    const { ring, keys } = ringWith(1);
    const cache = new ProtectedCache(ring);
    cache.add('before', utf8('old'));
    ring.add(2, new RecordingKey());
    cache.add('after', utf8('new'));
    assert.equal(keys.get(1)!.encryptAads.length, 1);
    assert.equal(await get(cache, 'before'), 'old');
    assert.equal(await get(cache, 'after'), 'new');
    cache.addOrUpdate('before', utf8('re-encrypted'));
    assert.equal(cacheEntriesForTests(cache).get('BEFORE')!.keyVersion, 2);
  });

  it('fails for an entry whose version was swapped or removed', async () => {
    const cache = new ProtectedCache(ringWith(1, 2).ring);
    cache.add('item', utf8('value'));
    const entry = cacheEntriesForTests(cache).get('ITEM')!;
    cacheEntriesForTests(cache).set('ITEM', { ...entry, keyVersion: 1 });
    await assert.rejects(cache.decrypt('item', new Uint8Array(64)), AuthenticationFailedError);
    cacheEntriesForTests(cache).set('ITEM', { ...entry, keyVersion: 9 });
    await assert.rejects(cache.decrypt('item', new Uint8Array(64)), KeyNotFoundError);
  });
});

describe('expiry with key retirement', () => {
  /** A ring at version 2 whose version 1 has just been retired, as a scheduled rotation retires it. */
  async function rotateAndRetire(ring: KeyRing): Promise<void> {
    ring.add(2, new RecordingKey());
    assert.equal(await ring.remove(1), true);
  }

  it('treats a value under a retired key as missing, and lets add store the name again', async () => {
    const { ring } = ringWith(1);
    const cache = new ProtectedCache(ring);
    cache.add('item', utf8('old'));
    await rotateAndRetire(ring);

    assert.equal(await cache.maxDecryptedLength('item'), undefined);
    assert.equal(await cache.decrypt('item', new Uint8Array(64)), 0);
    assert.equal(cacheEntriesForTests(cache).has('ITEM'), false);

    cache.add('ITEM', utf8('new'));
    assert.equal(cacheEntriesForTests(cache).get('ITEM')!.keyVersion, 2);
    assert.equal(await get(cache, 'item'), 'new');
  });

  it('lets add replace an expired value without first reading it', async () => {
    const { ring } = ringWith(1);
    const cache = new ProtectedCache(ring);
    cache.add('item', utf8('old'));
    await rotateAndRetire(ring);
    cache.add('item', utf8('new'));
    assert.equal(await get(cache, 'item'), 'new');
  });

  it('fetches a value under a retired key again, under the current key', async () => {
    const { ring } = ringWith(1);
    const source = new FakeSource({ db: 'secret' });
    const cache = new ProtectedCache(ring, { source });
    assert.equal(await get(cache, 'db'), 'secret');
    assert.equal(source.fetches, 1);

    await rotateAndRetire(ring);
    assert.equal(await get(cache, 'db'), 'secret');
    assert.equal(source.fetches, 2);
    assert.equal(cacheEntriesForTests(cache).get('DB')!.keyVersion, 2);
    assert.equal(await get(cache, 'db'), 'secret');
    assert.equal(source.fetches, 2, 'the refetched value is served from the cache');
  });

  it('keeps serving values under a superseded key until it is retired', async () => {
    const { ring } = ringWith(1);
    const source = new FakeSource({ db: 'secret' });
    const cache = new ReadOnlyProtectedCache(ring, source);
    assert.equal(await get(cache, 'db'), 'secret');
    ring.add(2, new RecordingKey());
    assert.equal(await get(cache, 'db'), 'secret');
    assert.equal(source.fetches, 1);
  });

  it('refetches after the key it was cached under is retired', async () => {
    // What a ring's scheduled rotation does, through the ring's own API: a new current key, then
    // the old one removed once its retention runs out.
    const { ring } = ringWith(1);
    const source = new FakeSource({ db: 'secret' });
    const cache = new ReadOnlyProtectedCache(ring, source);
    assert.equal(await get(cache, 'db'), 'secret');

    ring.add(2, new RecordingKey());
    assert.equal(await ring.remove(1), true);
    assert.equal(ring.tryGet(1), undefined);

    assert.equal(await get(cache, 'db'), 'secret');
    assert.equal(source.fetches, 2);
    await ring.close();
  });
});

describe('telemetry', () => {
  it('logs sensitive operations while enabled, and every failure', async () => {
    const telemetry = HkdfGuardTelemetry.cache;
    telemetry.enableSensitiveLogging = true;
    try {
      const { logger, withEventId } = capturingLogger();
      const cache = newCache({ logger });
      cache.add('item', utf8('value'));
      assert.throws(() => cache.add('item', utf8('duplicate')));
      assert.throws(() => cache.addOrUpdate('empty', new Uint8Array(0)));
      assert.equal(withEventId(1).length, 3);
      assert.equal(withEventId(2).length, 2);
      assert.equal(withEventId(2)[0]!.message, 'hkdfguard.cache.add failed.');
      assert.equal(await get(cache, 'item'), 'value');
    } finally {
      telemetry.enableSensitiveLogging = false;
    }
  });

  it('counts operations by success and failure', async () => {
    const recorder = useMetricRecorder();
    try {
      const cache = newCache();
      cache.add('item', utf8('value'));
      assert.throws(() => cache.add('item', utf8('duplicate')));
      cache.addOrUpdate('item', utf8('update'));
      const points = await recorder.collect();
      const count = (operation: string, result: string) =>
        points.get(`HkdfGuard.Cache|${MetricNames.cacheOperations}|{operation}|hkdfguard.operation.name=${operation},hkdfguard.result=${result}`);
      assert.equal(count('hkdfguard.cache.add', 'success'), 1);
      assert.equal(count('hkdfguard.cache.add', 'error'), 1);
      assert.equal(count('hkdfguard.cache.add_or_update', 'success'), 1);
    } finally {
      await recorder.dispose();
    }
  });
});

describe('sources', () => {
  it('fetch a miss once, then serve every ASCII-case spelling from the cache, zeroing what was fetched', async () => {
    const source = new FakeSource({ 'api-key': 'from the store' });
    const cache = new ReadOnlyProtectedCache(ringWith(1).ring, source);
    for (const name of ['api-key', 'API-KEY', 'Api-Key']) assert.equal(await get(cache, name), 'from the store');
    assert.equal(source.fetches, 1);
    assert.ok(isZero(source.served[0]!));
  });

  it('report a name the source lacks as missing, and return its errors', async () => {
    const cache = new ReadOnlyProtectedCache(ringWith(1).ring, new FakeSource({}));
    assert.equal(await cache.decrypt('missing', new Uint8Array(8)), 0);
    const failing = new FakeSource({});
    failing.error = new Error('store unreachable');
    const broken = new ReadOnlyProtectedCache(ringWith(1).ring, failing);
    await assert.rejects(broken.decrypt('item', new Uint8Array(8)), /store unreachable/);
    await assert.rejects(broken.maxDecryptedLength('item'), /store unreachable/);
  });

  it('refuse an empty value from the source', async () => {
    const cache = new ReadOnlyProtectedCache(ringWith(1).ring, new FakeSource({ empty: '' }));
    await assert.rejects(cache.decrypt('empty', new Uint8Array(8)), EmptyValueError);
  });

  it('pull misses through a read/write cache, but not hits', async () => {
    const source = new FakeSource({ pulled: 'from the store', added: 'never used' });
    const cache = new ProtectedCache(ringWith(1).ring, { source });
    cache.add('added', utf8('added locally'));
    assert.equal(await get(cache, 'added'), 'added locally');
    assert.equal(await get(cache, 'pulled'), 'from the store');
    assert.equal(source.fetches, 1);
  });
});

describe('ProtectedCacheCollection', () => {
  const cacheWith = (values: Record<string, string>) => {
    const cache = newCache();
    for (const [name, value] of Object.entries(values)) cache.add(name, utf8(value));
    return cache;
  };

  it('chains adds and has nothing without sources', async () => {
    const collection = new ProtectedCacheCollection();
    const [first, second] = [newCache(), newCache()];
    assert.equal(collection.add(first).add(second), collection);
    assert.deepEqual(collection.sources, [first, second]);
    assert.equal(await new ProtectedCacheCollection().decrypt('item', new Uint8Array(8)), 0);
    assert.equal(await new ProtectedCacheCollection().maxDecryptedLength('item'), undefined);
  });

  it('returns the first source with the name, falling back to later ones', async () => {
    const collection = new ProtectedCacheCollection(
      cacheWith({ shared: 'from first', 'only-first': 'first only' }),
      cacheWith({ shared: 'from second', 'only-second': 'second only' }));
    assert.equal(await get(collection, 'shared'), 'from first');
    assert.equal(await get(collection, 'only-first'), 'first only');
    assert.equal(await get(collection, 'only-second'), 'second only');
    assert.equal(await get(collection, 'nowhere'), undefined);
  });

  it('mixes writable and pull-through sources', async () => {
    const collection = new ProtectedCacheCollection(
      cacheWith({ local: 'added here' }),
      new ReadOnlyProtectedCache(ringWith(1).ring, new FakeSource({ remote: 'from the store' })));
    assert.equal(await get(collection, 'local'), 'added here');
    assert.equal(await get(collection, 'remote'), 'from the store');
  });

  it("stops at a source's error, returning it", async () => {
    const failing = new FakeSource({});
    failing.error = new Error('store unreachable');
    const collection = new ProtectedCacheCollection(new ReadOnlyProtectedCache(ringWith(1).ring, failing), cacheWith({ item: 'value' }));
    await assert.rejects(collection.decrypt('item', new Uint8Array(64)), /store unreachable/);
    await assert.rejects(collection.maxDecryptedLength('item'), /store unreachable/);
  });
});

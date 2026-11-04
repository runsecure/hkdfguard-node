import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { isZero, type ProtectedReadOnlyCache } from '@runsecure/hkdfguard-abstractions';
import { FakeRemoteSecretCache, newCache, newRing, SettingsProvider, text } from './cache.test-support.js';
import {
  ConfigurationItemReader, ConfigurationItemResolver, ConfigurationKeyError, ConfigurationKeyErrorCode, ConfigurationResolverBuilder,
  DefaultToken, DestinationTooSmallError, ProtectedCacheValueProvider, StringValuesNotAllowedError, ValueStatus,
  type ConfigurationResolver,
} from './index.js';

function createResolver(template: string, cache: ProtectedReadOnlyCache): ConfigurationResolver {
  const token = new DefaultToken();
  const reader = new ConfigurationItemReader(token);
  reader.readKeys(template);
  return new ConfigurationItemResolver(token, reader, [new ProtectedCacheValueProvider(cache)]);
}

describe('ProtectedCacheValueProvider', () => {
  it('resolve replaces items with cached values', async () => {
    const cache = newCache(newRing(), { 'db-user': 'app', 'db-password': 'pässword' });
    const template = 'User=${db-user};Password=${db-password}';

    const destination = new Uint8Array(256);
    const written = await createResolver(template, cache).resolve(template, destination);

    assert.equal(text(destination.subarray(0, written)), 'User=app;Password=pässword');
  });

  it('resolve of a UTF-8 source replaces items with cached values', async () => {
    const cache = newCache(newRing(), { 'db-password': 'pässword' });

    const destination = new Uint8Array(256);
    const written = await createResolver('Password=${db-password}', cache)
      .resolve(new TextEncoder().encode('Password=${db-password}'), destination);

    assert.equal(text(destination.subarray(0, written)), 'Password=pässword');
  });

  it('resolve of a missing name rejects with NotFound', async () => {
    const cache = newCache(newRing(), { present: 'value' });

    await assert.rejects(
      createResolver('${absent}', cache).resolve('${absent}', new Uint8Array(64)),
      (error: unknown) => error instanceof ConfigurationKeyError && error.error === ConfigurationKeyErrorCode.notFound,
    );
  });

  // The cache's bound is the ciphertext's length, so a destination with exactly the value's room is
  // below it: the value goes through a buffer of its own.
  for (const valueLength of [5, 612]) {
    it(`resolve into a destination below the bound that the ${valueLength}-byte value fits resolves`, async () => {
      const value = 'v'.repeat(valueLength);
      const cache = newCache(newRing(), { item: value });

      const destination = new Uint8Array(valueLength);
      const written = await createResolver('${item}', cache).resolve('${item}', destination);

      assert.equal(text(destination.subarray(0, written)), value);
    });
  }

  it('resolve of a value larger than the destination rejects and zeroes the destination', async () => {
    const cache = newCache(newRing(), { item: 'too long a value' });
    const destination = new TextEncoder().encode('XXXX');

    await assert.rejects(createResolver('${item}', cache).resolve('${item}', destination), DestinationTooSmallError);

    assert.ok(isZero(destination));
  });

  it('tryGetBytes of a value larger than the room reports DestinationTooSmall and writes nothing', async () => {
    const provider = new ProtectedCacheValueProvider(newCache(newRing(), { item: 'value' }));
    const destination = new Uint8Array(4);

    assert.deepEqual(await provider.tryGetBytes('item', destination), { status: ValueStatus.destinationTooSmall, written: 0 });
    assert.ok(isZero(destination));
  });

  it('tryGetBytes writes into a subarray', async () => {
    const provider = new ProtectedCacheValueProvider(newCache(newRing(), { item: 'value' }));
    const destination = new Uint8Array(64);
    destination.set(new TextEncoder().encode('--'));

    assert.deepEqual(await provider.tryGetBytes('item', destination.subarray(2)), { status: ValueStatus.found, written: 5 });
    assert.equal(text(destination.subarray(0, 7)), '--value');
  });

  it("a cache's error propagates, and resolve zeroes the destination", async () => {
    const denied = new Error('access denied');
    const refusing: ProtectedReadOnlyCache = {
      decrypt: async () => { throw denied; },
      maxDecryptedLength: async () => { throw denied; },
    };
    const destination = new Uint8Array(16).fill(0x58);

    await assert.rejects(createResolver('a${item}', refusing).resolve('a${item}', destination), (error) => error === denied);

    assert.ok(isZero(destination));
  });

  it('a value the cache no longer holds by the time it is decrypted is reported missing', async () => {
    // A bound, then nothing: a remote value that expired with its key in between, say.
    const vanishing: ProtectedReadOnlyCache = { decrypt: async () => 0, maxDecryptedLength: async () => 64 };
    const provider = new ProtectedCacheValueProvider(vanishing);

    assert.deepEqual(await provider.tryGetBytes('item', new Uint8Array(64)), { status: ValueStatus.notFound, written: 0 });
    assert.deepEqual(await provider.tryGetBytes('item', new Uint8Array(8)), { status: ValueStatus.notFound, written: 0 });
  });

  it('tryGetValue by default rejects', async () => {
    const provider = new ProtectedCacheValueProvider(newCache(newRing(), { item: 'value' }));

    assert.equal(provider.allowStringValues, false);
    await assert.rejects(provider.tryGetValue('item'), StringValuesNotAllowedError);
  });

  it('tryGetValue when allowed returns the value as a string', async () => {
    const provider = new ProtectedCacheValueProvider(newCache(newRing(), { item: 'value' }), { allowStringValues: true });

    assert.deepEqual(await provider.tryGetValue('item'), { status: ValueStatus.found, value: 'value' });
    assert.deepEqual(await provider.tryGetValue('absent'), { status: ValueStatus.notFound, value: undefined });
  });

  it('a later provider supplies the names the cache does not have', async () => {
    const cache = newCache(newRing(), { 'db-password': 's3cret' });
    const template = 'Host=${db-host};Password=${db-password}';
    const token = new DefaultToken();
    const reader = new ConfigurationItemReader(token);
    reader.readKeys(template);
    const resolver = new ConfigurationItemResolver(token, reader, [
      new ProtectedCacheValueProvider(cache),
      new SettingsProvider({ 'db-host': 'db.internal' }),
    ]);

    const destination = new Uint8Array(256);
    const written = await resolver.resolve(template, destination);

    assert.equal(text(destination.subarray(0, written)), 'Host=db.internal;Password=s3cret');
  });

  it('addProtectedCache adds a provider over the cache', async () => {
    const cache = newCache(newRing(), { 'db-password': 's3cret' });
    const template = 'Password=${db-password}';
    const token = new DefaultToken();
    const reader = new ConfigurationItemReader(token);
    reader.readKeys(template);

    const resolver = new ConfigurationResolverBuilder().withToken(token).withReader(reader).addProtectedCache(cache).build();

    const destination = new Uint8Array(64);
    const written = await resolver.resolve(template, destination);
    assert.equal(text(destination.subarray(0, written)), 'Password=s3cret');
  });

  it('a remote secret is fetched once, by prefetch, and resolve reads it from the cache', async () => {
    const ring = newRing();
    const cache = new FakeRemoteSecretCache(ring, { 'app-config': '{"user":"app","password":"s3cret"}' });
    const template = 'User=${app-config#user};Password=${app-config#password};Again=${app-config#user}';
    const token = new DefaultToken();
    const reader = new ConfigurationItemReader(token);
    reader.readKeys(template);
    const provider = new ProtectedCacheValueProvider(cache);

    await provider.prefetch(reader);
    assert.deepEqual(cache.fetches, ['app-config']);

    const destination = new Uint8Array(256);
    const written = await new ConfigurationItemResolver(token, reader, [provider]).resolve(template, destination);

    assert.equal(text(destination.subarray(0, written)), 'User=app;Password=s3cret;Again=app');
    assert.deepEqual(cache.fetches, ['app-config']);
  });

  it('resolve fetches a remote secret it has not prefetched', async () => {
    const cache = new FakeRemoteSecretCache(newRing(), { 'db-password': 's3cret' });

    const destination = new Uint8Array(64);
    const written = await createResolver('Password=${db-password}', cache).resolve('Password=${db-password}', destination);

    assert.equal(text(destination.subarray(0, written)), 'Password=s3cret');
    assert.deepEqual(cache.fetches, ['db-password']);
  });

  it('prefetchKeys skips keys the cache does not have, asking for each once', async () => {
    const cache = new FakeRemoteSecretCache(newRing(), { present: 'value' });
    const provider = new ProtectedCacheValueProvider(cache);

    await provider.prefetchKeys(['present', 'absent', 'absent']);

    assert.deepEqual(cache.fetches, ['present', 'absent']);
    assert.deepEqual(await provider.tryGetBytes('absent', new Uint8Array(16)), { status: ValueStatus.notFound, written: 0 });
  });

  it('an aborted signal cancels prefetch and resolve', async () => {
    const cache = new FakeRemoteSecretCache(newRing(), { item: 'value' });
    const provider = new ProtectedCacheValueProvider(cache);
    const signal = AbortSignal.abort();

    await assert.rejects(provider.prefetchKeys(['item'], signal), { name: 'AbortError' });
    await assert.rejects(createResolver('${item}', cache).resolve('${item}', new Uint8Array(16), signal), { name: 'AbortError' });
    assert.deepEqual(cache.fetches, []);
  });

  it('members reject undefined arguments', async () => {
    const cache = newCache(newRing());
    const provider = new ProtectedCacheValueProvider(cache);
    const missing = undefined as never;

    assert.equal(provider.cache, cache);
    assert.throws(() => new ProtectedCacheValueProvider(missing), TypeError);
    await assert.rejects(provider.tryGetBytes(missing, new Uint8Array(1)), TypeError);
    await assert.rejects(provider.prefetch(missing), TypeError);
    await assert.rejects(provider.prefetchKeys(missing), TypeError);
    await assert.rejects(provider.prefetchKeys('item'), TypeError);
    assert.throws(() => new ConfigurationResolverBuilder().addProtectedCache(missing), TypeError);
  });
});

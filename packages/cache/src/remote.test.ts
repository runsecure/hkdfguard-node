import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { SpanStatusCode } from '@opentelemetry/api';
import { cacheAad, InvalidArgumentError, isZero, type ProtectedReadOnlyCache } from '@runsecure/hkdfguard-abstractions';
import { AttributeNames, HkdfGuardTelemetry, MetricNames, SpanNames, type Logger } from '@runsecure/hkdfguard-diagnostics';
import { KeyRing } from '@runsecure/hkdfguard-dek';
import { capturingLogger, RecordingKey, useMetricRecorder, useSpanRecorder } from '@runsecure/hkdfguard-test-support';
import { ProtectedCache } from './cache.js';
import { ProtectedCacheCollection } from './collection.js';
import { InvalidSecretDataError } from './errors.js';
import { RemoteSecretCache, SecretNameMatching, SecretValueSink } from './remote.js';
import { entryName, secretName } from './secretnames.js';

const utf8 = (s: string) => new TextEncoder().encode(s);

type OnFetch = (name: string, sink: SecretValueSink, signal?: AbortSignal) => void | Promise<void>;

/**
 * A RemoteSecretCache over an in-memory map, matched as `matching` says. Names are valid unless they
 * are empty or hold a ':'. Every fetch is recorded, with its signal, and onFetch can replace one.
 */
class FakeRemoteSecretCache extends RemoteSecretCache {
  readonly secrets = new Map<string, string>();
  /** Every name fetch was called with, in order. */
  readonly fetches: string[] = [];
  readonly signals: (AbortSignal | undefined)[] = [];
  onFetch: OnFetch | undefined;
  defaultKeyToRead: string | undefined;

  constructor(readonly ring: KeyRing, readonly matching: SecretNameMatching = SecretNameMatching.exact, logger?: Logger) {
    super(ring, matching, logger);
  }

  set(name: string, value: string): void {
    this.secrets.set(this.#key(name), value);
  }

  #key(name: string): string {
    return this.matching === SecretNameMatching.exact ? name : name.toLowerCase();
  }

  protected override defaultKey(): string | undefined {
    return this.defaultKeyToRead;
  }

  protected override isValidName(name: string): boolean {
    return name.length > 0 && !name.includes(':');
  }

  protected override async fetch(name: string, sink: SecretValueSink, signal?: AbortSignal): Promise<void> {
    this.fetches.push(name);
    this.signals.push(signal);
    if (this.onFetch !== undefined) {
      await this.onFetch(name, sink, signal);
      return;
    }
    const secret = this.secrets.get(this.#key(name));
    if (secret !== undefined) sink.setText(secret);
  }
}

class UnreachableError extends Error {}

function newRing(): { ring: KeyRing; key: RecordingKey } {
  const ring = new KeyRing();
  const key = new RecordingKey();
  ring.add(1, key);
  return { ring, key };
}

const newCache = (matching: SecretNameMatching = SecretNameMatching.exact, logger?: Logger) =>
  new FakeRemoteSecretCache(newRing().ring, matching, logger);

async function decryptString(cache: ProtectedReadOnlyCache, name: string, size = 64, signal?: AbortSignal): Promise<string> {
  const result = new Uint8Array(size);
  return new TextDecoder().decode(result.subarray(0, await cache.decrypt(name, result, signal)));
}

const missing = async (cache: ProtectedReadOnlyCache, name: string) => assert.equal(await cache.decrypt(name, new Uint8Array(16)), 0);

/** Lets every pending callback and timer run, so concurrent lookups reach where they wait. */
const settle = () => new Promise<void>((resolve) => setTimeout(resolve, 10));

/** `promise`, or the signal's reason once it is aborted. */
function abortable<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (signal === undefined) return promise;
  signal.throwIfAborted();
  return new Promise<T>((resolve, reject) => {
    signal.addEventListener('abort', () => reject(signal.reason), { once: true });
    promise.then(resolve, reject);
  });
}

/** An onFetch that waits for release, honouring the fetch's signal, then hands over `value`. */
function gate(cache: FakeRemoteSecretCache, value: string) {
  const started = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const state = { started: started.promise, release: () => release.resolve(), aborted: false, fetches: 0 };
  cache.onFetch = async (_name, sink, signal) => {
    state.fetches++;
    started.resolve();
    try {
      await abortable(release.promise, signal);
    } catch (error) {
      state.aborted = true;
      throw error;
    }
    sink.setText(value);
  };
  return state;
}

function withSensitiveLogging(): () => void {
  const original = HkdfGuardTelemetry.cache.enableSensitiveLogging;
  HkdfGuardTelemetry.cache.enableSensitiveLogging = true;
  return () => { HkdfGuardTelemetry.cache.enableSensitiveLogging = original; };
}

describe('RemoteSecretCache: fetch on miss and name matching', () => {
  it('fetches a miss once, then serves every lookup from the cache', async () => {
    const cache = newCache();
    cache.set('item', 'value');
    assert.ok((await cache.maxDecryptedLength('item'))! >= 5);
    assert.equal(await decryptString(cache, 'item'), 'value');
    assert.equal(await decryptString(cache, 'item'), 'value');
    assert.deepEqual(cache.fetches, ['item']);
  });

  it('ignoreAsciiCase: spellings differing in case share one entry and one fetch', async () => {
    const cache = newCache(SecretNameMatching.ignoreAsciiCase);
    cache.set('Db-Password', 'value');
    assert.equal(await decryptString(cache, 'db-password'), 'value');
    assert.equal(await decryptString(cache, 'DB-PASSWORD'), 'value');
    assert.deepEqual(cache.fetches, ['db-password']);
  });

  it('exact: spellings differing in case are separate entries, fetched by their own spelling', async () => {
    const cache = newCache();
    cache.set('prod/Db', 'upper');
    cache.set('prod/db', 'lower');
    assert.equal(await decryptString(cache, 'prod/Db'), 'upper');
    assert.equal(await decryptString(cache, 'prod/db'), 'lower');
    await missing(cache, 'PROD/DB');
    assert.equal(await decryptString(cache, 'prod/Db'), 'upper');
    assert.deepEqual(cache.fetches, ['prod/Db', 'prod/db', 'PROD/DB']);
  });

  it('exact: a name holding the case marker is missing without a fetch', async () => {
    const cache = newCache();
    await missing(cache, 'prod/!db');
    assert.deepEqual(cache.fetches, []);
  });

  it('ignoreAsciiCase: a name holding the case marker is fetched like any other', async () => {
    const cache = newCache(SecretNameMatching.ignoreAsciiCase);
    cache.set('bang!', 'value');
    assert.equal(await decryptString(cache, 'bang!'), 'value');
  });

  for (const name of ['prod/Db', 'ALLCAPS', 'a/B_c+D=e.F@g-H', 'nocaps']) {
    it(`entryName round-trips ${name} and holds no upper case`, () => {
      const escaped = entryName(name);
      assert.ok(!/[A-Z]/.test(escaped));
      assert.equal(secretName(escaped), name);
    });
  }

  it('binds each value to its case-escaped entry name', async () => {
    const exact = newRing();
    const cache = new FakeRemoteSecretCache(exact.ring);
    cache.onFetch = (_name, sink) => sink.setBytesWithJsonKeys(utf8('{"Key":"v"}'));
    assert.equal(await decryptString(cache, 'prod/Db#Key'), 'v');
    assert.deepEqual(exact.key.encryptAads, [cacheAad('prod/!db#!key'), cacheAad('prod/!db')]);

    const ignoring = newRing();
    const azure = new FakeRemoteSecretCache(ignoring.ring, SecretNameMatching.ignoreAsciiCase);
    azure.onFetch = (_name, sink) => sink.setText('v');
    assert.equal(await decryptString(azure, 'Prod-Db'), 'v');
    assert.deepEqual(ignoring.key.encryptAads, [cacheAad('Prod-Db')]);
  });

  it('reports an invalid name missing without a fetch', async () => {
    const cache = newCache();
    await missing(cache, 'Connection:Strings');
    assert.equal(await cache.maxDecryptedLength('Connection:Strings'), undefined);
    assert.deepEqual(cache.fetches, []);
  });

  it('reports a name that is not well-formed UTF-16 missing without a fetch', async () => {
    const cache = newCache();
    await missing(cache, 'bad\uD800name');
    await missing(cache, 'item#\uDC00');
    assert.deepEqual(cache.fetches, []);
  });

  it('rejects a name that is not a string', async () => {
    const cache = newCache();
    await assert.rejects(cache.decrypt(undefined as unknown as string, new Uint8Array(16)), TypeError);
    await assert.rejects(cache.maxDecryptedLength(null as unknown as string), TypeError);
  });

  it('refuses a missing ring or an unknown matching', () => {
    assert.throws(() => new FakeRemoteSecretCache(undefined as unknown as KeyRing), TypeError);
    assert.throws(() => new FakeRemoteSecretCache(newRing().ring, 'other' as SecretNameMatching), TypeError);
  });

  it('reports a fetch that sets nothing as missing, and fetches it again next time', async () => {
    const cache = newCache();
    await missing(cache, 'later');
    assert.equal(await cache.maxDecryptedLength('later'), undefined);
    cache.set('later', 'now here');
    assert.equal(await decryptString(cache, 'later'), 'now here');
    assert.equal(cache.fetches.length, 3);
  });

  it('reports an empty value as missing', async () => {
    const cache = newCache();
    cache.onFetch = (_name, sink) => sink.setBytes(new Uint8Array(0));
    await missing(cache, 'empty');
    cache.onFetch = (_name, sink) => sink.setText('');
    await missing(cache, 'empty');
  });

  it('refetches a value whose key was retired, under the current key', async () => {
    const cache = newCache();
    cache.set('item', 'value');
    assert.equal(await decryptString(cache, 'item'), 'value');
    cache.ring.add(2, new RecordingKey());
    assert.equal(await cache.ring.remove(1), true);
    assert.equal(await decryptString(cache, 'item'), 'value');
    assert.equal(await decryptString(cache, 'item'), 'value');
    assert.equal(cache.fetches.length, 2);
  });
});

describe('SecretValueSink', () => {
  it('stores what setBytes is given and zeroes it', async () => {
    const cache = newCache();
    const given = Uint8Array.of(1, 2, 3);
    cache.onFetch = (_name, sink) => sink.setBytes(given);
    const result = new Uint8Array(16);
    assert.deepEqual(result.subarray(0, await cache.decrypt('binary', result)), Uint8Array.of(1, 2, 3));
    assert.ok(isZero(given));
  });

  it('takes a view of part of a buffer, and zeroes only that part', async () => {
    const cache = newCache();
    const buffer = utf8('xxsecretyy');
    cache.onFetch = (_name, sink) => sink.setBytes(buffer.subarray(2, 8));
    assert.equal(await decryptString(cache, 'item'), 'secret');
    assert.deepEqual(buffer, Uint8Array.of(0x78, 0x78, 0, 0, 0, 0, 0, 0, 0x79, 0x79));
  });

  it('refuses anything but a Uint8Array in every setter', async () => {
    const cache = newCache();
    cache.onFetch = (_name, sink) => {
      const notBytes = 'immutable' as unknown as Uint8Array;
      assert.throws(() => sink.setBytes(notBytes), TypeError);
      assert.throws(() => sink.setKeyBytes('k', notBytes), TypeError);
      assert.throws(() => sink.setBytesWithJsonKeys([1, 2] as unknown as Uint8Array), TypeError);
      sink.setText('fine');
    };
    assert.equal(await decryptString(cache, 'item'), 'fine');
  });

  it('round-trips a large setText', async () => {
    const cache = newCache();
    const large = 'é-秘密-'.repeat(1500);
    cache.set('large', large);
    assert.equal(await decryptString(cache, 'large', (await cache.maxDecryptedLength('large'))!), large);
  });

  it('refuses a second value, and nothing from that fetch is cached', async () => {
    const cache = newCache();
    cache.onFetch = (_name, sink) => {
      sink.setText('first');
      sink.setText('second');
    };
    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), (error: Error & { code?: string }) =>
      error.code === 'ERR_HKDFGUARD_INVALID_STATE' && /already been set/.test(error.message));
    cache.onFetch = undefined;
    await missing(cache, 'item');
  });

  it('refuses every value once its fetch has returned, or failed, zeroing what it is given', async () => {
    const cache = newCache();
    const kept: SecretValueSink[] = [];
    cache.onFetch = (_name, sink) => { kept.push(sink); };
    await missing(cache, 'item');

    const given = Uint8Array.of(9);
    assert.throws(() => kept[0]!.setBytes(given), /already returned/);
    assert.ok(isZero(given));
    assert.throws(() => kept[0]!.setText('late'), /already returned/);

    cache.onFetch = (_name, sink) => {
      kept.push(sink);
      throw new UnreachableError('unreachable');
    };
    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), UnreachableError);
    assert.throws(() => kept[1]!.setText('late'), /already returned/);
  });

  it('cannot be constructed', () => {
    assert.throws(() => Reflect.construct(SecretValueSink, []));
  });
});

describe('RemoteSecretCache: failures and shared fetches', () => {
  it('propagates a fetch failure, and fetches again on the next lookup', async () => {
    const cache = newCache();
    cache.onFetch = () => { throw new UnreachableError('unreachable'); };
    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), UnreachableError);
    await assert.rejects(cache.maxDecryptedLength('item'), UnreachableError);

    cache.onFetch = undefined;
    cache.set('item', 'value');
    assert.equal(await decryptString(cache, 'item'), 'value');
    assert.equal(cache.fetches.length, 3);
  });

  it('propagates whatever a fetch throws, Error or not', async () => {
    const cache = newCache();
    const thrown = { not: 'an Error' };
    cache.onFetch = async () => { throw thrown; };
    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), (error) => error === thrown);
    cache.onFetch = undefined;
    await missing(cache, 'item');
  });

  it('shares one fetch between concurrent misses on one name', async () => {
    const cache = newCache();
    const fetch = gate(cache, 'value');
    const lookups = Array.from({ length: 8 }, () => decryptString(cache, 'shared'));
    await fetch.started;
    await settle();
    fetch.release();
    assert.deepEqual(await Promise.all(lookups), Array(8).fill('value'));
    assert.equal(cache.fetches.length, 1);
  });

  it('shares one fetch between concurrent misses on different keys and spellings of one secret', async () => {
    const cache = newCache(SecretNameMatching.ignoreAsciiCase);
    const json = '{"a":"1","b":"2","c":"3"}';
    const release = Promise.withResolvers<void>();
    cache.onFetch = async (_name, sink) => {
      await release.promise;
      sink.setBytesWithJsonKeys(utf8(json));
    };
    const lookups = ['s#a', 'S#b', 's#c', 'S'].map((name) => decryptString(cache, name));
    await settle();
    release.resolve();
    assert.deepEqual(await Promise.all(lookups), ['1', '2', '3', json]);
    assert.equal(cache.fetches.length, 1);
  });

  it('gives every lookup waiting on a failed fetch the same failure', async () => {
    const cache = newCache();
    const release = Promise.withResolvers<void>();
    cache.onFetch = async () => {
      await release.promise;
      throw new UnreachableError('shared failure');
    };
    const lookups = [decryptString(cache, 'shared'), decryptString(cache, 'shared')];
    await settle();
    release.resolve();
    const [first, second] = await Promise.allSettled(lookups);
    assert.ok(first?.status === 'rejected' && second?.status === 'rejected');
    assert.ok(first.reason instanceof UnreachableError && first.reason === second.reason);
    assert.equal(cache.fetches.length, 1);
  });

  it('keeps a cached value when a later fetch of the same secret hands it over again', async () => {
    const cache = newCache();
    cache.onFetch = (_name, sink) => sink.setBytesWithJsonKeys(utf8('{"a":"first"}'));
    assert.equal(await decryptString(cache, 's#a'), 'first');
    await missing(cache, 's#b');

    cache.onFetch = (_name, sink) => sink.setBytesWithJsonKeys(utf8('{"a":"second","b":"added"}'));
    assert.equal(await decryptString(cache, 's#b'), 'added');
    assert.equal(await decryptString(cache, 's#a'), 'first');
    assert.equal(await decryptString(cache, 's'), '{"a":"first"}');
    assert.equal(cache.fetches.length, 3);
  });
});

describe('RemoteSecretCache: cancellation', () => {
  it('gives fetch the signal of the lookup that started it', async () => {
    const cache = newCache();
    cache.set('item', 'value');
    const controller = new AbortController();
    assert.equal(await decryptString(cache, 'item', 64, controller.signal), 'value');
    assert.equal(cache.signals[0], controller.signal);
  });

  it('rejects a lookup whose signal is already aborted, without a fetch', async () => {
    const cache = newCache();
    cache.set('item', 'value');
    const reason = new Error('gave up');
    await assert.rejects(cache.decrypt('item', new Uint8Array(16), AbortSignal.abort(reason)), (error) => error === reason);
    assert.deepEqual(cache.fetches, []);
    assert.equal(await decryptString(cache, 'item'), 'value');
    // A cached value is served whatever the signal says: nothing is left to cancel.
    assert.equal(await decryptString(cache, 'item', 64, AbortSignal.abort()), 'value');
  });

  it('cancels the fetch when the lookup that started it is aborted, caching nothing', async () => {
    const cache = newCache();
    const fetch = gate(cache, 'never');
    const controller = new AbortController();
    const lookup = decryptString(cache, 'item', 64, controller.signal);
    await fetch.started;
    controller.abort();
    await assert.rejects(lookup, { name: 'AbortError' });
    assert.ok(fetch.aborted);
    cache.onFetch = undefined;
    await missing(cache, 'item');
  });

  it('lets a waiting lookup stop waiting under its own signal, leaving the fetch running for the others', async () => {
    const cache = newCache();
    const fetch = gate(cache, 'value');
    const owner = decryptString(cache, 'shared');
    await fetch.started;
    const controller = new AbortController();
    const joiner = decryptString(cache, 'shared', 64, controller.signal);
    await settle();
    const reason = new Error('joiner gave up');
    controller.abort(reason);

    await assert.rejects(joiner, (error) => error === reason);
    fetch.release();
    assert.equal(await owner, 'value');
    assert.ok(!fetch.aborted);
    assert.equal(cache.fetches.length, 1);
  });

  it('starts a new fetch for a waiting lookup when the lookup that started the shared one is aborted', async () => {
    const cache = newCache();
    const fetch = gate(cache, 'never');
    const controller = new AbortController();
    const owner = decryptString(cache, 'shared', 64, controller.signal);
    await fetch.started;
    const joiner = decryptString(cache, 'shared');
    const otherKey = decryptString(cache, 'shared#k');
    await settle();

    // The fetch the joiners start once the first is cancelled answers at once.
    cache.onFetch = (_name, sink) => sink.setBytesWithJsonKeys(utf8('{"k":"second fetch"}'));
    controller.abort();

    await assert.rejects(owner, { name: 'AbortError' });
    assert.ok(fetch.aborted);
    assert.equal(await joiner, '{"k":"second fetch"}');
    assert.equal(await otherKey, 'second fetch');
    assert.equal(cache.fetches.length, 2, 'the joiners share the second fetch too');
    assert.equal(cache.signals[1], undefined, 'the new fetch runs under the joiner\'s signal');
  });

  it('fails a waiting lookup aborted alongside the lookup that started the fetch with its own reason', async () => {
    const cache = newCache();
    const fetch = gate(cache, 'never');
    const ownerController = new AbortController();
    const joinerController = new AbortController();
    const owner = decryptString(cache, 'shared', 64, ownerController.signal);
    await fetch.started;
    const joiner = decryptString(cache, 'shared', 64, joinerController.signal);
    await settle();
    const reason = new Error('joiner gave up');
    joinerController.abort(reason);
    ownerController.abort();

    await assert.rejects(owner, { name: 'AbortError' });
    await assert.rejects(joiner, (error) => error === reason);
    assert.equal(cache.fetches.length, 1);
  });

  it("treats a fetch's own abort - its lookup not aborted - as a failure every waiter shares", async () => {
    const cache = newCache();
    const release = Promise.withResolvers<void>();
    cache.onFetch = async () => {
      await release.promise;
      throw new DOMException('A timeout inside the fetch.', 'TimeoutError');
    };
    const lookups = [decryptString(cache, 'shared'), decryptString(cache, 'shared')];
    await settle();
    release.resolve();
    for (const outcome of await Promise.allSettled(lookups)) {
      assert.ok(outcome.status === 'rejected' && outcome.reason.name === 'TimeoutError');
    }
    assert.equal(cache.fetches.length, 1);
  });

  it('waits for a fetch that ignores the abort, and caches what it hands over before returning', async () => {
    // As .NET: aborting cancels the fetch only as far as the fetch honours its signal.
    const cache = newCache();
    const release = Promise.withResolvers<void>();
    cache.onFetch = async (_name, sink) => {
      await release.promise;
      sink.setText('finished anyway');
    };
    const controller = new AbortController();
    const lookup = decryptString(cache, 'item', 64, controller.signal);
    await settle();
    controller.abort();
    release.resolve();
    assert.equal(await lookup, 'finished anyway');
    assert.equal(await decryptString(cache, 'item'), 'finished anyway');
  });

  it('refuses a value handed to the sink of a fetch that was aborted', async () => {
    const cache = newCache();
    const kept: SecretValueSink[] = [];
    cache.onFetch = async (_name, sink, signal) => {
      kept.push(sink);
      await abortable(new Promise<void>(() => undefined), signal);
    };
    const controller = new AbortController();
    const lookup = cache.decrypt('item', new Uint8Array(16), controller.signal);
    await settle();
    controller.abort();
    await assert.rejects(lookup, { name: 'AbortError' });
    assert.throws(() => kept[0]!.setText('late'), /already returned/);
    cache.onFetch = undefined;
    await missing(cache, 'item');
  });
});

describe('RemoteSecretCache: telemetry', () => {
  it('logs, with sensitive logging, the secret\'s own name for each fetch, and every failure', async () => {
    const restore = withSensitiveLogging();
    try {
      const { logger, entries, withEventId } = capturingLogger();
      const cache = newCache(SecretNameMatching.exact, logger);
      cache.set('prod/Item', 'never-logged');
      assert.equal(await decryptString(cache, 'prod/Item'), 'never-logged');

      cache.onFetch = () => { throw new UnreachableError('boom'); };
      await assert.rejects(cache.decrypt('other', new Uint8Array(16)), UnreachableError);

      // The secret's own spelling, not its escaped entry name.
      assert.ok(withEventId(1).some((e) => e.level === 'debug' && e.message === 'hkdfguard.cache.populate completed for prod/Item.'));
      const failures = withEventId(2);
      assert.equal(failures.length, 1);
      assert.equal(failures[0]!.message, 'hkdfguard.cache.populate failed.');
      assert.ok(failures[0]!.attributes.error instanceof UnreachableError);
      assert.ok(!entries.some((e) => e.message.includes('never-logged')));
    } finally {
      restore();
    }
  });

  it('logs only failures without sensitive logging', async () => {
    const { logger, entries } = capturingLogger();
    const cache = newCache(SecretNameMatching.exact, logger);
    cache.set('item', 'value');
    assert.equal(await decryptString(cache, 'item'), 'value');
    assert.deepEqual(entries, []);
  });

  it('works without a logger, with sensitive logging on', async () => {
    const restore = withSensitiveLogging();
    try {
      const cache = newCache(SecretNameMatching.ignoreAsciiCase);
      cache.set('item', 'value');
      assert.equal(await decryptString(cache, 'item'), 'value');
      cache.onFetch = () => { throw new UnreachableError('boom'); };
      await assert.rejects(cache.decrypt('other', new Uint8Array(16)), UnreachableError);
    } finally {
      restore();
    }
  });

  it('makes each fetch a populate span, counted as success, not_found or error', async () => {
    const restore = withSensitiveLogging();
    const spans = useSpanRecorder();
    const metrics = useMetricRecorder();
    try {
      const cache = newCache();
      cache.set('Found', 'value');
      assert.equal(await decryptString(cache, 'Found'), 'value');
      await missing(cache, 'missing');
      cache.onFetch = () => { throw new UnreachableError('boom'); };
      await assert.rejects(cache.decrypt('failing', new Uint8Array(16)), UnreachableError);

      const [found, notFound, failed, ...rest] = spans.spans().filter((s) => s.name === SpanNames.cache.populate);
      assert.equal(rest.length, 0);
      assert.equal(found?.instrumentationScope.name, HkdfGuardTelemetry.cache.sourceName);
      assert.ok(found?.events.some((e) => e.attributes?.[AttributeNames.name] === 'Found'));
      assert.notEqual(found?.status.code, SpanStatusCode.ERROR);
      assert.notEqual(notFound?.status.code, SpanStatusCode.ERROR);
      assert.equal(failed?.status.code, SpanStatusCode.ERROR);
      assert.equal(failed?.events.filter((e) => e.name === 'exception').length, 1);

      const points = await metrics.collect();
      for (const result of ['success', 'not_found', 'error']) {
        const key = `HkdfGuard.Cache|${MetricNames.cacheOperations}|{operation}|${AttributeNames.operationName}=${SpanNames.cache.populate},${AttributeNames.result}=${result}`;
        assert.equal(points.get(key), 1, result);
      }
    } finally {
      await metrics.dispose();
      await spans.dispose();
      restore();
    }
  });
});

// A key/value secret as AWS Secrets Manager's console stores one.
const KEY_VALUE_SECRET = `{
  "test-credential-1": "This is my first credential",
  "service-credential-3": "This is my third credential",
  "api-credential-21": "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==",
  "domain-credential-17": "fakedomain/thiscredential"
}`;

const setJson = (json: string): OnFetch => (_name, sink) => sink.setBytesWithJsonKeys(utf8(json));

describe('RemoteSecretCache: names holding a key', () => {
  it('caches the whole value and every key from one fetch', async () => {
    const cache = newCache();
    cache.onFetch = setJson(KEY_VALUE_SECRET);
    assert.equal(await decryptString(cache, 'creds#api-credential-21', 512),
      '0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==');
    assert.equal(await decryptString(cache, 'creds#test-credential-1', 512), 'This is my first credential');
    assert.equal(await decryptString(cache, 'creds#service-credential-3', 512), 'This is my third credential');
    assert.equal(await decryptString(cache, 'creds#domain-credential-17', 512), 'fakedomain/thiscredential');
    assert.equal(await decryptString(cache, 'creds', 512), KEY_VALUE_SECRET);
    assert.deepEqual(cache.fetches, ['creds']);
  });

  it('matches keys exactly even where secret names ignore case', async () => {
    const cache = newCache(SecretNameMatching.ignoreAsciiCase);
    cache.onFetch = setJson('{"Key":"upper","key":"lower"}');
    assert.equal(await decryptString(cache, 'Db#Key'), 'upper');
    assert.equal(await decryptString(cache, 'DB#key'), 'lower');
    assert.equal(await decryptString(cache, 'db#Key'), 'upper');
    await missing(cache, 'db#KEY');
    assert.deepEqual(cache.fetches, ['Db', 'db']);
  });

  it('matches secret names and keys both exactly under exact matching', async () => {
    const cache = newCache();
    cache.onFetch = (name, sink) => sink.setBytesWithJsonKeys(utf8(`{"Pass":"${name}"}`));
    assert.equal(await decryptString(cache, 'Prod/Db#Pass'), 'Prod/Db');
    assert.equal(await decryptString(cache, 'prod/db#Pass'), 'prod/db');
    await missing(cache, 'prod/db#pass');
  });

  for (const name of ['s#', 's#a#b', 's#a b', 's#bang!', 's#café', '#key', 'in:valid#key', `s#${'k'.repeat(257)}`]) {
    it(`reports ${name.length > 40 ? 'a too-long key' : JSON.stringify(name)} missing without a fetch`, async () => {
      const cache = newCache();
      await missing(cache, name);
      assert.equal(await cache.maxDecryptedLength(name), undefined);
      assert.deepEqual(cache.fetches, []);
    });
  }

  it('isValidKey accepts printable ASCII but space, bang and hash, up to the limit', () => {
    assert.ok(RemoteSecretCache.isValidKey('a'));
    assert.ok(RemoteSecretCache.isValidKey('ConnectionStrings:Admin'));
    assert.ok(RemoteSecretCache.isValidKey('"$%&\'()*+,-./0-9;<=>?@A-Z[\\]^_`a-z{|}~'));
    assert.ok(RemoteSecretCache.isValidKey('k'.repeat(RemoteSecretCache.MAX_KEY_LENGTH)));
    assert.ok(!RemoteSecretCache.isValidKey('k'.repeat(RemoteSecretCache.MAX_KEY_LENGTH + 1)));
    for (const key of [undefined, null, '', 'a b', 'a!', 'a#', 'tab\t', 'del\x7f', 'café']) {
      assert.ok(!RemoteSecretCache.isValidKey(key), String(key));
    }
    assert.deepEqual([RemoteSecretCache.KEY_SEPARATOR, RemoteSecretCache.MAX_KEY_LENGTH], ['#', 256]);
  });

  it('reads the default key, not the whole value, for a name without one', async () => {
    const cache = newCache();
    cache.defaultKeyToRead = 'value';
    cache.onFetch = (_name, sink) => {
      sink.setText('the whole value');
      sink.setKeyBytes('value', utf8('the default key'));
      sink.setKeyBytes('other', utf8('another key'));
    };
    assert.equal(await decryptString(cache, 's'), 'the default key');
    assert.equal(await decryptString(cache, 's#value'), 'the default key');
    assert.equal(await decryptString(cache, 's#other'), 'another key');
    assert.equal(cache.fetches.length, 1);
  });

  it('setKeyBytes zeroes what it is given, and refuses an invalid key', async () => {
    const cache = newCache();
    const given = Uint8Array.of(1, 2, 3);
    const refused = Uint8Array.of(4, 5, 6);
    cache.onFetch = (_name, sink) => {
      assert.throws(() => sink.setKeyBytes('not a key', refused), (error: Error) => error instanceof InvalidArgumentError && /isn't a key/.test(error.message));
      assert.throws(() => sink.setKeyBytes(undefined as unknown as string, refused), InvalidArgumentError);
      sink.setKeyBytes('k', given);
    };
    const result = new Uint8Array(16);
    assert.deepEqual(result.subarray(0, await cache.decrypt('s#k', result)), Uint8Array.of(1, 2, 3));
    assert.ok(isZero(given) && isZero(refused));
  });

  it('refuses a key set twice, and nothing from that fetch is cached', async () => {
    const cache = newCache();
    cache.onFetch = (_name, sink) => {
      sink.setKeyBytes('k', utf8('first'));
      sink.setText('whole');
      sink.setKeyBytes('k', utf8('second'));
    };
    await assert.rejects(cache.decrypt('s#k', new Uint8Array(16)), /already been set/);
    cache.onFetch = undefined;
    await missing(cache, 's');
    await missing(cache, 's#k');
  });

  it('treats an empty key as unset, so it can still be set afterwards', async () => {
    const cache = newCache();
    cache.onFetch = (_name, sink) => {
      sink.setKeyBytes('k', new Uint8Array(0));
      sink.setKeyBytes('k', utf8('set'));
    };
    assert.equal(await decryptString(cache, 's#k'), 'set');
  });

  it('refuses keys in a sink kept past its fetch, zeroing them', async () => {
    const cache = newCache();
    const kept: SecretValueSink[] = [];
    cache.onFetch = (_name, sink) => { kept.push(sink); };
    await missing(cache, 's#k');

    const given = Uint8Array.of(9);
    assert.throws(() => kept[0]!.setKeyBytes('k', given), /already returned/);
    assert.ok(isZero(given));
    const json = utf8('{"k":"v"}');
    assert.throws(() => kept[0]!.setBytesWithJsonKeys(json), /already returned/);
    assert.ok(isZero(json));
  });

  it('caches JSON members as their text, or leaves them out', async () => {
    const cache = newCache();
    cache.onFetch = setJson('{"text":"a\\"b\\\\cé\\n","int":3306,"real":-1.5e3,"yes":true,"no":false,\n'
      + ' "null":null,"object":{"x":"y"},"array":["z"],"empty":"","bad key":"x","bang!":"x","Ascaped":"name"}\n');
    assert.equal(await decryptString(cache, 's#text'), 'a"b\\cé\n');
    assert.equal(await decryptString(cache, 's#int'), '3306');
    assert.equal(await decryptString(cache, 's#real'), '-1.5e3');
    assert.equal(await decryptString(cache, 's#yes'), 'true');
    assert.equal(await decryptString(cache, 's#no'), 'false');
    assert.equal(await decryptString(cache, 's#Ascaped'), 'name');
    for (const key of ['null', 'object', 'array', 'empty', 'x']) await missing(cache, `s#${key}`);
  });

  for (const value of [
    'plain text', '["a","b"]', '"a json string"', '42', '{"k":"unterminated', '{"k":"v"} trailing', '{"k":"v"}{"k":"w"}',
    '{"k":"v", // a comment\n"j":"w"}', '{"k":"\\ud800"}',
  ]) {
    it(`caches ${JSON.stringify(value)}, which isn't one JSON object, whole only`, async () => {
      const cache = newCache();
      cache.onFetch = setJson(value);
      assert.equal(await decryptString(cache, 's'), value);
      await missing(cache, 's#k');
      await missing(cache, 's#a');
    });
  }

  it('splits a JSON object with whitespace around it', async () => {
    const cache = newCache();
    cache.onFetch = setJson('  \r\n{"k":"v"}\n  ');
    assert.equal(await decryptString(cache, 's#k'), 'v');
  });

  it('refuses a duplicated key without naming it, and nothing is cached', async () => {
    const cache = newCache();
    cache.onFetch = setJson('{"dup-key-name":"a","other":"b","dup-key-name":"c"}');
    await assert.rejects(cache.decrypt('s#other', new Uint8Array(16)), (error: Error) =>
      error instanceof InvalidSecretDataError && error.code === 'ERR_HKDFGUARD_INVALID_SECRET_DATA'
      && !error.message.includes('dup-key-name') && error.cause === undefined);
    cache.onFetch = undefined;
    await missing(cache, 's');
  });

  it('setBytesWithJsonKeys zeroes what it is given', async () => {
    const cache = newCache();
    const given = utf8('{"k":"v"}');
    cache.onFetch = (_name, sink) => sink.setBytesWithJsonKeys(given);
    assert.equal(await decryptString(cache, 's#k'), 'v');
    assert.ok(isZero(given));
  });

  it('reports an empty value with JSON keys as missing', async () => {
    const cache = newCache();
    cache.onFetch = (_name, sink) => sink.setBytesWithJsonKeys(new Uint8Array(0));
    await missing(cache, 's');
  });
});

describe('RemoteSecretCache in a ProtectedCacheCollection', () => {
  it('is asked after the sources before it, and only for its own names', async () => {
    const { ring } = newRing();
    const remote = new FakeRemoteSecretCache(ring);
    remote.onFetch = async (_name, sink) => {
      await settle();
      sink.setText('remote value');
    };
    const local = new ProtectedCache(ring);
    local.add('local', utf8('local value'));
    const collection = new ProtectedCacheCollection(local, remote);

    assert.equal(await decryptString(collection, 'local'), 'local value');
    assert.equal(await decryptString(collection, 'remote'), 'remote value');
    assert.ok((await collection.maxDecryptedLength('remote'))! >= 'remote value'.length);
    assert.ok((await collection.maxDecryptedLength('local'))! >= 'local value'.length);
    assert.equal(await collection.maxDecryptedLength('in:valid'), undefined);
    assert.deepEqual(remote.fetches, ['remote']);
  });

  it('aborts the remote fetch when the lookup is aborted', async () => {
    const remote = newCache();
    const collection = new ProtectedCacheCollection(remote);
    const fetch = gate(remote, 'value');
    const controller = new AbortController();
    const lookup = collection.decrypt('item', new Uint8Array(16), controller.signal);
    await fetch.started;
    controller.abort();
    await assert.rejects(lookup, { name: 'AbortError' });
    assert.ok(fetch.aborted);
  });
});

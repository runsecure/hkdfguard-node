import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { mkdirSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, it, type TestContext } from 'node:test';
import { SpanStatusCode } from '@opentelemetry/api';
import {
  AuthenticationFailedError, configurationPurpose, InvalidArgumentError, KeyNotFoundError, type PipelineDataProtector, type ProtectedReadOnlyCache,
} from '@runsecure/hkdfguard-abstractions';
import { ProtectedCacheCollection } from '@runsecure/hkdfguard-cache';
import { AesGcmCryptoProviderFactory, AesGcmPipelineDataProtector } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { DataEncryptionKey, DefaultFormatProvider, KeyRing } from '@runsecure/hkdfguard-dek';
import { AttributeNames, HkdfGuardTelemetry, MetricNames, SpanNames } from '@runsecure/hkdfguard-diagnostics';
import { SecretPipelineWriter, type SecretRequest } from '@runsecure/hkdfguard-pipeline';
import { FILE_TOO_LARGE, KeyFileError, KeyFileTrust } from '@runsecure/hkdfguard-securefile';
import {
  capturingLogger, FakeKeyWrapper, keyFileDirectory, RecordingKey, useMetricRecorder, useSpanRecorder, windowsCurrentUserSid,
} from '@runsecure/hkdfguard-test-support';
import { InvalidSecretDataError, JsonSecretsFileReadOnlyCache, type JsonSecretsFileCacheOptions } from './index.js';

/*
 * JsonSecretsFileReadOnlyCache over a real file readTrustedFile accepts, with values written by a
 * ring's protectors over real AES-256-GCM (RecordingKey), or by a pipeline - the port of .NET's
 * JsonSecretsFileReadOnlyCacheTests.
 */

const isWindows = process.platform === 'win32';
const isRoot = process.getuid?.() === 0;
const utf8 = (s: string) => new TextEncoder().encode(s);

/** Trusts the account running the tests, whose folders keyFileDirectory makes. */
const trustCurrentUser = () => (isWindows
  ? new KeyFileTrust({ windowsPrincipals: [windowsCurrentUserSid()] })
  : new KeyFileTrust({ unixUserIds: [process.geteuid!()], unixGroupIds: [process.getegid!()] }));

/** A pipeline writer over values held in memory, so a test reads exactly what writeJsonSecrets writes. */
class InMemoryWriter extends SecretPipelineWriter {
  constructor(protector: PipelineDataProtector, private readonly secrets: ReadonlyMap<string, string>) {
    super(protector, [...secrets.keys()], () => true);
  }

  protected override async readSecret(name: string, requests: readonly SecretRequest[], values: Map<string, string>): Promise<void> {
    this.protectSecret(utf8(this.secrets.get(name)!), requests, values);
  }
}

interface Fixture {
  /** A fresh folder the trust checks accept once the current user is trusted, removed when the test ends. */
  folder: string;
  /** The secrets file's path in it. */
  path: string;
  trust: KeyFileTrust;
  ring: KeyRing;
  cache(options?: JsonSecretsFileCacheOptions): JsonSecretsFileReadOnlyCache;
  /** name's value encrypted as a pipeline or deployer would: bound to that name. */
  encrypt(name: string, value: string): string;
  /** Writes each secret encrypted for its name, as one JSON object. */
  write(...secrets: [string, string][]): void;
  /** Writes `json` as the file. */
  writeRaw(json: string | Uint8Array): void;
}

/** A fixture for `t`, or undefined - the test skipped, saying why - when this host has no trusted folder. */
function fixture(t: TestContext, ring = ringWith(1)): Fixture | undefined {
  const folder = keyFileDirectory(t, 'hkdfguard-jsonsecrets-');
  if (folder === undefined) return undefined;
  const trust = trustCurrentUser();
  const path = join(folder, 'secrets.json');
  const encrypt = (name: string, value: string) => ring.createProtector(configurationPurpose(name)).encrypt(value);
  const writeRaw = (json: string | Uint8Array) => writeFileSync(path, json);
  return {
    folder,
    path,
    trust,
    ring,
    cache: (options) => new JsonSecretsFileReadOnlyCache(path, trust, ring, new DefaultFormatProvider(), options),
    encrypt,
    write: (...secrets) => writeRaw(JSON.stringify(Object.fromEntries(secrets.map(([name, value]) => [name, encrypt(name, value)])))),
    writeRaw,
  };
}

function ringWith(...versions: number[]): KeyRing {
  const ring = new KeyRing();
  for (const version of versions) ring.add(version, new RecordingKey());
  return ring;
}

/** name's value, sized by maxDecryptedLength; undefined when there is none. */
async function get(cache: ProtectedReadOnlyCache, name: string): Promise<string | undefined> {
  const length = await cache.maxDecryptedLength(name);
  if (length === undefined) return undefined;
  const result = new Uint8Array(length);
  return new TextDecoder().decode(result.subarray(0, await cache.decrypt(name, result)));
}

/** Asserts name is missing through both members. */
async function assertMissing(cache: ProtectedReadOnlyCache, name: string): Promise<void> {
  assert.equal(await cache.decrypt(name, new Uint8Array(16)), 0, name);
  assert.equal(await cache.maxDecryptedLength(name), undefined, name);
}

describe('JsonSecretsFileReadOnlyCache: loading', () => {
  it('decrypts what a pipeline writes under the key it wraps', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    const protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), 1);
    t.after(() => protector.close());
    const writer = new InMemoryWriter(protector, new Map([['db-password', 'pässwörd'], ['api-key', 'key']]));
    await writer.pullSecrets();
    await writer.writeJsonSecrets(f.path);

    // What the application holds once the pipeline's key has been wrapped and unwrapped.
    const key = new Uint8Array(Buffer.from(new TextDecoder().decode(protector.keyBase64()), 'base64'));
    const provider = await new AesGcmCryptoProviderFactory().create(new FakeKeyWrapper(key), utf8('wrapped'), { expirySeconds: 60 });
    const ring = new KeyRing(new DefaultFormatProvider());
    ring.add(1, new DataEncryptionKey(provider));
    t.after(() => ring.close());
    const cache = new JsonSecretsFileReadOnlyCache(f.path, f.trust, ring, new DefaultFormatProvider());

    assert.equal(await get(cache, 'db-password'), 'pässwörd');
    assert.equal(await get(cache, 'api-key'), 'key');
  });

  it('decrypts a value through both members, and through a collection, under its name ignoring ASCII case', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    f.write(['Db-Password', 'value']);
    const cache = f.cache();

    for (const name of ['Db-Password', 'DB-PASSWORD', 'db-password']) assert.equal(await get(cache, name), 'value');
    const result = new Uint8Array(16);
    assert.equal(new TextDecoder().decode(result.subarray(0, await cache.decrypt('db-password', result))), 'value');
    const max = await cache.maxDecryptedLength('Db-Password');
    assert.ok(max !== undefined && max >= 5);
    assert.equal(await get(new ProtectedCacheCollection(cache), 'DB-password'), 'value');
  });

  it('reads the file once, even for concurrent lookups, then serves it from memory', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    const secrets = Array.from({ length: 200 }, (_, i): [string, string] => [`secret-${String(i).padStart(3, '0')}`, `value-${i}`]);
    f.write(...secrets);
    const cache = f.cache();
    const spans = useSpanRecorder();
    try {
      const results = await Promise.all(secrets.map(([name]) => get(cache, name)));
      unlinkSync(f.path);

      assert.deepEqual(results, secrets.map(([, value]) => value));
      assert.equal(await get(cache, 'secret-007'), 'value-7');
      assert.equal(spans.spans().filter((s) => s.name === SpanNames.cache.populate).length, 1);
    } finally {
      await spans.dispose();
    }
  });

  it('keeps what it loaded: a changed file is picked up by a new instance', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    f.write(['item', 'first']);
    const cache = f.cache();
    assert.equal(await get(cache, 'item'), 'first');

    f.write(['item', 'second']);
    assert.equal(await get(cache, 'item'), 'first');
    assert.equal(await get(f.cache(), 'item'), 'second');
  });

  it('reports a missing file as every secret missing, and doesn\'t remember it', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    f.write(['item', 'value']);
    const cache = f.cache();
    unlinkSync(f.path);

    await assertMissing(cache, 'item');

    f.write(['item', 'later']);
    assert.equal(await get(cache, 'item'), 'later');
  });

  it('reports every secret missing once the folder is removed', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    const folder = join(f.folder, 'sub');
    mkdirSync(folder);
    const path = join(folder, 'secrets.json');
    writeFileSync(path, JSON.stringify({ item: f.encrypt('item', 'value') }));
    const cache = new JsonSecretsFileReadOnlyCache(path, f.trust, f.ring, new DefaultFormatProvider());
    rmSync(folder, { recursive: true, force: true });

    await assertMissing(cache, 'item');
  });
});

describe('JsonSecretsFileReadOnlyCache: names', () => {
  it('reports a name the file doesn\'t hold, or that can\'t be one, missing', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    f.write(['item', 'value']);
    const cache = f.cache();

    // 'ıtem': a dotless i, which Unicode case folding would match to 'item' and ASCII never does.
    for (const name of ['absent', '', '.hidden', '../item', 'ıtem', 'it em', 'ITEM\0']) await assertMissing(cache, name);
    assert.equal(await get(cache, 'item'), 'value');
  });

  it('refuses a name that isn\'t a string', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    f.write(['item', 'value']);
    const cache = f.cache();

    await assert.rejects(cache.decrypt(undefined as unknown as string, new Uint8Array(16)), TypeError);
    await assert.rejects(cache.maxDecryptedLength(null as unknown as string), TypeError);
  });
});

describe('JsonSecretsFileReadOnlyCache: refusals', () => {
  const VALUE = '{0}';
  const cases: [string, string | Uint8Array, string][] = [
    ['an empty file', '', "isn't valid JSON"],
    ['whitespace', ' \r\n', "isn't valid JSON"],
    ['text', 'not json', "isn't valid JSON"],
    ['an array', '["item"]', 'holds an array, not an object of secrets'],
    ['a string', '"item"', 'holds a string, not an object of secrets'],
    ['a number', '{"item":1}', "no value for 'item'"],
    ['an object', '{"item":{"a":"b"}}', "no value for 'item'"],
    ['null', '{"item":null}', "no value for 'item'"],
    ['a blank value', '{"item":"  "}', "no value for 'item'"],
    ['a name that isn\'t a secret\'s', '{"../item":"x"}', "names a secret '../item', which isn't a secret's name"],
    ['a name twice, in another case', `{"item":"${VALUE}","ITEM":"${VALUE}"}`, "names 'ITEM' more than once"],
    ['a name twice', `{"item":"${VALUE}","item":"${VALUE}"}`, "names 'item' more than once"],
    ['a second value', `{"item":"${VALUE}"} {}`, "isn't valid JSON"],
    ['an incomplete object', `{"item":"${VALUE}" `, "isn't valid JSON"],
    ['a trailing comma', `{"item":"${VALUE}",}`, "isn't valid JSON"],
    ['bytes that aren\'t UTF-8', new Uint8Array([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x22, 0x78, 0x22, 0x7d]), "isn't valid JSON: it isn't UTF-8"],
    ['a byte order mark', `﻿{"item":"${VALUE}"}`, "isn't valid JSON"],
  ];
  for (const [what, json, problem] of cases) {
    it(`refuses a file holding ${what}, and keeps nothing`, async (t) => {
      const f = fixture(t);
      if (f === undefined) return;
      f.writeRaw(typeof json === 'string' ? json.replaceAll(VALUE, f.encrypt('item', 'value')) : json);
      const cache = f.cache();

      const refused = (e: unknown) => e instanceof InvalidSecretDataError && e.code === 'ERR_HKDFGUARD_INVALID_SECRET_DATA'
        && e.message.startsWith(`The secrets file '${f.path}' `) && e.message.includes(problem) && !e.message.includes('enc::') && !e.message.endsWith('..');
      await assert.rejects(cache.decrypt('item', new Uint8Array(16)), refused);
      await assert.rejects(cache.maxDecryptedLength('item'), refused);

      f.write(['item', 'fixed']);
      assert.equal(await get(cache, 'item'), 'fixed');
    });
  }

  it('fails the whole file for a value moved under another name', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    f.writeRaw(JSON.stringify({ reader: f.encrypt('reader', 'fine'), writer: f.encrypt('reader', 'moved') }));
    const cache = f.cache();

    await assert.rejects(cache.decrypt('reader', new Uint8Array(16)), AuthenticationFailedError);
    await assert.rejects(cache.maxDecryptedLength('reader'), AuthenticationFailedError);
  });

  it('fails the whole file for a value under a key version the ring doesn\'t hold', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    f.writeRaw(JSON.stringify({
      item: f.encrypt('item', 'fine'),
      old: new DefaultFormatProvider().format({ keyVersion: 7, value: new Uint8Array(randomBytes(40)) }),
    }));

    await assert.rejects(f.cache().decrypt('item', new Uint8Array(16)), KeyNotFoundError);
  });

  it('fails the whole file for a value that isn\'t in the format', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    f.writeRaw(JSON.stringify({ item: f.encrypt('item', 'fine'), other: 'plain text' }));

    await assert.rejects(f.cache().decrypt('item', new Uint8Array(16)), { code: 'ERR_HKDFGUARD_INVALID_FORMAT' });
  });

  it('refuses a file in an untrusted location, and keeps nothing', async (t) => {
    if (isRoot) {
      t.skip('Running as root, whose files are trusted.');
      return;
    }
    const f = fixture(t);
    if (f === undefined) return;
    f.write(['item', 'value']);
    const untrusted = new JsonSecretsFileReadOnlyCache(f.path, KeyFileTrust.administratorsOnly, f.ring, new DefaultFormatProvider());

    const refused = (e: unknown) => e instanceof KeyFileError && e.code === 'EACCES' && e.message.includes('not trusted');
    await assert.rejects(untrusted.decrypt('item', new Uint8Array(16)), refused);
    await assert.rejects(untrusted.maxDecryptedLength('item'), refused);
    assert.equal(await get(f.cache(), 'item'), 'value');
  });

  it('refuses a file over the maximum length', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    f.write(['item', 'value']);
    const cache = f.cache({ maxFileLength: 16 });

    const tooLarge = (e: unknown) => e instanceof KeyFileError && e.code === FILE_TOO_LARGE;
    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), tooLarge);
    await assert.rejects(cache.maxDecryptedLength('item'), tooLarge);
    assert.equal(JsonSecretsFileReadOnlyCache.DEFAULT_MAX_FILE_LENGTH, 1024 * 1024);
  });

  it('is cancelled by an aborted signal, which never stops a load another lookup waits on', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    f.write(['item', 'value']);
    const cache = f.cache();

    await assert.rejects(cache.decrypt('item', new Uint8Array(16), AbortSignal.abort()), { name: 'AbortError' });
    await assert.rejects(cache.maxDecryptedLength('item', AbortSignal.abort()), { name: 'AbortError' });

    const controller = new AbortController();
    const aborted = cache.decrypt('item', new Uint8Array(16), controller.signal);
    const waiting = get(cache, 'item');
    controller.abort();
    await assert.rejects(aborted, { name: 'AbortError' });
    assert.equal(await waiting, 'value');
  });
});

describe('JsonSecretsFileReadOnlyCache: keys', () => {
  it('still decrypts values under older key versions after rotation', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    const old = f.encrypt('item', 'old');
    f.ring.add(2, new RecordingKey());
    const current = f.encrypt('other', 'new');
    assert.match(current, /^enc::v2::/);
    f.writeRaw(JSON.stringify({ item: old, other: current }));
    const cache = f.cache();

    assert.equal(await get(cache, 'item'), 'old');
    assert.equal(await get(cache, 'other'), 'new');
  });

  it('decrypts a value over the default format\'s limit with a format provider that allows it', async (t) => {
    const format = new DefaultFormatProvider(16 * 1024);
    const ring = new KeyRing(format);
    ring.add(1, new RecordingKey());
    const f = fixture(t, ring);
    if (f === undefined) return;
    const value = 'x'.repeat(8000);
    f.write(['large', value]);
    const cache = new JsonSecretsFileReadOnlyCache(f.path, f.trust, ring, format);

    const result = new Uint8Array(value.length);
    assert.equal(await cache.decrypt('large', result), value.length);
    assert.deepEqual(result, utf8(value));
    await assert.rejects(f.cache().decrypt('large', new Uint8Array(16)), { code: 'ERR_HKDFGUARD_INVALID_FORMAT' });
  });
});

describe('JsonSecretsFileReadOnlyCache: construction', () => {
  it('validates its arguments, and that the file exists', (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    f.write(['item', 'value']);
    const format = new DefaultFormatProvider();
    const { path, trust, ring } = f;

    assert.throws(() => new JsonSecretsFileReadOnlyCache(undefined as unknown as string, trust, ring, format), TypeError);
    assert.throws(() => new JsonSecretsFileReadOnlyCache('', trust, ring, format), InvalidArgumentError);
    assert.throws(() => new JsonSecretsFileReadOnlyCache(path, undefined as unknown as KeyFileTrust, ring, format), TypeError);
    assert.throws(() => new JsonSecretsFileReadOnlyCache(path, { windowsPrincipals: [] } as unknown as KeyFileTrust, ring, format), TypeError);
    assert.throws(() => new JsonSecretsFileReadOnlyCache(path, trust, undefined as unknown as KeyRing, format), TypeError);
    assert.throws(() => new JsonSecretsFileReadOnlyCache(path, trust, ring, undefined as unknown as DefaultFormatProvider), TypeError);
    for (const maxFileLength of [0, -1, 1.5, Number.NaN, 2 ** 53]) {
      assert.throws(() => new JsonSecretsFileReadOnlyCache(path, trust, ring, format, { maxFileLength }), InvalidArgumentError, String(maxFileLength));
    }
    for (const missing of [join(f.folder, 'absent.json'), f.folder]) {
      assert.throws(() => new JsonSecretsFileReadOnlyCache(missing, trust, ring, format),
        (e: unknown) => e instanceof KeyFileError && e.code === 'ENOENT' && e.message.includes("doesn't exist"));
    }
    assert.equal(new JsonSecretsFileReadOnlyCache(path, trust, ring, format).filePath, resolve(path));
  });
});

describe('JsonSecretsFileReadOnlyCache: telemetry', () => {
  function withSensitiveLogging(): () => void {
    const original = HkdfGuardTelemetry.cache.enableSensitiveLogging;
    HkdfGuardTelemetry.cache.enableSensitiveLogging = true;
    return () => { HkdfGuardTelemetry.cache.enableSensitiveLogging = original; };
  }

  it('returns the same result with sensitive logging on, logging the path but never a value', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    f.write(['item', 'never-logged']);
    const restore = withSensitiveLogging();
    try {
      const { logger, entries, withEventId } = capturingLogger();
      const cache = f.cache({ logger });
      assert.equal(await get(cache, 'item'), 'never-logged');
      assert.ok(withEventId(1).some((e) => e.level === 'debug' && e.message === `hkdfguard.cache.populate completed for ${f.path}.`));
      assert.ok(!entries.some((e) => e.message.includes('never-logged')));
    } finally {
      restore();
    }
  });

  it('makes each load a populate span, counted as success, not_found or error, and logs a failure', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    const { logger, withEventId } = capturingLogger();
    const restore = withSensitiveLogging();
    const spans = useSpanRecorder();
    const metrics = useMetricRecorder();
    try {
      f.writeRaw(JSON.stringify({ reader: f.encrypt('reader', 'fine'), writer: f.encrypt('reader', 'moved') }));
      const failing = f.cache({ logger });
      await assert.rejects(failing.decrypt('reader', new Uint8Array(16)), AuthenticationFailedError);
      unlinkSync(f.path);
      await assertMissing(failing, 'reader'); // looked for twice: not remembered
      f.write(['Found', 'value']);
      assert.equal(await get(failing, 'found'), 'value'); // loaded once, then served from memory
      await assertMissing(failing, 'not:a:name'); // never looked for

      const populates = spans.spans().filter((s) => s.name === SpanNames.cache.populate);
      assert.equal(populates.length, 4);
      const [failed, notFound, , found] = populates;
      assert.equal(found?.instrumentationScope.name, HkdfGuardTelemetry.cache.sourceName);
      assert.ok(found?.events.some((e) => e.attributes?.[AttributeNames.name] === f.path));
      assert.notEqual(found?.status.code, SpanStatusCode.ERROR);
      assert.notEqual(notFound?.status.code, SpanStatusCode.ERROR);
      assert.equal(failed?.status.code, SpanStatusCode.ERROR);
      assert.equal(failed?.events.filter((e) => e.name === 'exception').length, 1);
      assert.ok(spans.spans().some((s) => s.name === SpanNames.cache.decrypt && s.events.some((e) => e.attributes?.[AttributeNames.name] === 'found')));

      const points = await metrics.collect();
      for (const [result, count] of [['success', 1], ['not_found', 2], ['error', 1]] as const) {
        const key = `HkdfGuard.Cache|${MetricNames.cacheOperations}|{operation}|${AttributeNames.operationName}=${SpanNames.cache.populate},${AttributeNames.result}=${result}`;
        assert.equal(points.get(key), count, result);
      }

      const failures = withEventId(2);
      assert.equal(failures.length, 1);
      assert.equal(failures[0]!.message, 'hkdfguard.cache.populate failed.');
      assert.ok(failures[0]!.attributes.error instanceof AuthenticationFailedError);
    } finally {
      await metrics.dispose();
      await spans.dispose();
      restore();
    }
  });
});

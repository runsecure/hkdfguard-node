import { strict as assert } from 'node:assert';
import { randomBytes, randomInt } from 'node:crypto';
import { copyFileSync, mkdirSync, readdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, it, type TestContext } from 'node:test';
import { SpanStatusCode } from '@opentelemetry/api';
import {
  AuthenticationFailedError, configurationPurpose, InvalidArgumentError, KeyNotFoundError, type ProtectedReadOnlyCache,
} from '@runsecure/hkdfguard-abstractions';
import { AttributeNames, HkdfGuardTelemetry, MetricNames, SpanNames } from '@runsecure/hkdfguard-diagnostics';
import { DefaultFormatProvider, KeyRing } from '@runsecure/hkdfguard-dek';
import { FILE_TOO_LARGE, KeyFileError, KeyFileTrust } from '@runsecure/hkdfguard-securefile';
import {
  capturingLogger, keyFileDirectory, RecordingKey, useMetricRecorder, useSpanRecorder, windowsCurrentUserSid,
} from '@runsecure/hkdfguard-test-support';
import { ProtectedCacheCollection } from './collection.js';
import { FilePerSecretCache } from './filepersecret.js';

/*
 * FilePerSecretCache over a real folder readTrustedFile accepts, with values written by a ring's
 * protectors over real AES-256-GCM (RecordingKey).
 */

const isWindows = process.platform === 'win32';
const isRoot = process.getuid?.() === 0;
const utf8 = (s: string) => new TextEncoder().encode(s);

/** Trusts the account running the tests, whose folders keyFileDirectory makes. */
const trustCurrentUser = () => (isWindows
  ? new KeyFileTrust({ windowsPrincipals: [windowsCurrentUserSid()] })
  : new KeyFileTrust({ unixUserIds: [process.geteuid!()], unixGroupIds: [process.getegid!()] }));

interface Fixture {
  /** A fresh folder the trust checks accept once the current user is trusted, removed when the test ends. */
  folder: string;
  trust: KeyFileTrust;
  ring: KeyRing;
  cache(): FilePerSecretCache;
  /** Writes value to name's file, encrypted as a pipeline or deployer would: bound to that name. */
  write(name: string, value: string, suffix?: string): void;
}

/** A fixture for `t`, or undefined - the test skipped, saying why - when this host has no trusted folder. */
function fixture(t: TestContext, ring = ringWith(1)): Fixture | undefined {
  const folder = keyFileDirectory(t, 'hkdfguard-filepersecret-');
  if (folder === undefined) return undefined;
  const trust = trustCurrentUser();
  return {
    folder,
    trust,
    ring,
    cache: () => new FilePerSecretCache(folder, trust, ring, new DefaultFormatProvider()),
    write: (name, value, suffix = '') => writeFileSync(join(folder, name), ring.createProtector(configurationPurpose(name)).encrypt(value) + suffix),
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

const SECRET_COUNT = 20;

// Non-ASCII fragments, so each secret also exercises multi-byte UTF-8 - "🔑" as a surrogate pair.
const NON_ASCII = ['café', 'naïve', '日本語', 'Ωμέγα', '🔑', 'Größe'];

/** SECRET_COUNT secrets, each a random base64 run of random length plus random non-ASCII text, under names that differ only by number. */
function randomSecrets(): Map<string, string> {
  const fragment = () => NON_ASCII[randomInt(NON_ASCII.length)]!;
  return new Map(Array.from({ length: SECRET_COUNT }, (_, i) =>
    [`Secret-${String(i).padStart(2, '0')}`, `${randomBytes(randomInt(16, 129)).toString('base64')} ${fragment()} ${fragment()}`]));
}

/** Writes every secret encrypted, and checks each file holds only the formatted ciphertext: ASCII base64, with neither the secret's random text nor its non-ASCII text anywhere in it. */
function writeAndVerifyEncrypted(f: Fixture, secrets: Map<string, string>): void {
  for (const [name, value] of secrets) {
    f.write(name, value);
    const onDisk = readFileSync(join(f.folder, name));
    assert.ok(onDisk.every((b) => b < 0x80), 'The file holds a non-ASCII byte.');
    const text = onDisk.toString('latin1');
    assert.match(text, /^enc::v1::[A-Za-z0-9+/]+=*$/);
    assert.ok(!text.includes(value.split(' ')[0]!));
    assert.equal(onDisk.indexOf(Buffer.from(value, 'utf8')), -1);
  }
}

/** Checks every secret decrypts, and its bound covers its UTF-8 length. */
async function assertEachDecrypts(cache: FilePerSecretCache, secrets: Map<string, string>): Promise<void> {
  for (const [name, value] of secrets) {
    const max = await cache.maxDecryptedLength(name);
    assert.ok(max !== undefined && max >= Buffer.byteLength(value, 'utf8'), name);
    const result = new Uint8Array(max);
    assert.equal(new TextDecoder().decode(result.subarray(0, await cache.decrypt(name, result))), value, name);
  }
}

describe('FilePerSecretCache: loading', () => {
  it('decrypts a file through both members, and through a collection', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    f.write('Db-Password', 'value');
    const cache = f.cache();

    const result = new Uint8Array(16);
    assert.equal(new TextDecoder().decode(result.subarray(0, await cache.decrypt('Db-Password', result))), 'value');
    const max = await cache.maxDecryptedLength('Db-Password');
    assert.ok(max !== undefined && max >= 5);
    assert.equal(await get(new ProtectedCacheCollection(cache), 'Db-Password'), 'value');
  });

  it('holds twenty random secrets only as ciphertext on disk, and decrypts each', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    const secrets = randomSecrets();
    writeAndVerifyEncrypted(f, secrets);

    await assertEachDecrypts(f.cache(), secrets);
  });

  it('serves twenty random secrets loaded concurrently from memory once their files are gone', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    const secrets = randomSecrets();
    writeAndVerifyEncrypted(f, secrets);
    const cache = f.cache();

    // Every secret's first lookup at once, half of them twice, so loads also race each other.
    const names = [...secrets.keys()];
    const loads = await Promise.all([...names, ...names.slice(0, SECRET_COUNT / 2)].map((name) => cache.maxDecryptedLength(name)));
    assert.ok(loads.every((max) => max !== undefined && max > 0));

    for (const name of names) unlinkSync(join(f.folder, name));
    assert.deepEqual(readdirSync(f.folder), []);

    await assertEachDecrypts(cache, secrets);
  });

  it('ignores surrounding whitespace', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    f.write('item', 'value', '\r\n');
    assert.equal(await get(f.cache(), 'item'), 'value');
  });

  it('reads a file once, then serves it from memory', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    const cache = f.cache();
    f.write('item', 'first');
    assert.equal(await get(cache, 'item'), 'first');

    f.write('item', 'second');
    assert.equal(await get(cache, 'item'), 'first');
    unlinkSync(join(f.folder, 'item'));
    assert.equal(await get(cache, 'item'), 'first');
  });

  it('picks up a changed file in a new instance', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    f.write('item', 'first');
    assert.equal(await get(f.cache(), 'item'), 'first');

    f.write('item', 'second');
    assert.equal(await get(f.cache(), 'item'), 'second');
  });

  it('does not remember a missing secret, so a file added later is found', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    const cache = f.cache();
    assert.equal(await cache.decrypt('item', new Uint8Array(16)), 0);

    f.write('item', 'value');
    assert.equal(await get(cache, 'item'), 'value');
  });

  it('reports a missing or empty file as missing', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    writeFileSync(join(f.folder, 'empty'), ' \n');
    writeFileSync(join(f.folder, 'zero'), '');
    const cache = f.cache();
    for (const name of ['absent', 'empty', 'zero']) await assertMissing(cache, name);
  });

  it('reports every secret missing once the folder is removed', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    f.write('item', 'value');
    const cache = f.cache();
    rmSync(f.folder, { recursive: true, force: true });

    await assertMissing(cache, 'item');
  });
});

describe('FilePerSecretCache: names', () => {
  it('reports a name that can\'t be a file name missing, without reading outside the folder', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    mkdirSync(join(f.folder, 'sub'));
    f.write('item', 'value');
    // A secret beside the folder, so "../item" would find one if it were ever read.
    const cache = new FilePerSecretCache(join(f.folder, 'sub'), f.trust, f.ring, new DefaultFormatProvider());

    for (const name of ['', '.hidden', '..', '../item', 'sub/item', 'sub\\item', 'db:password', 'café', 'item\0']) {
      assert.ok(!FilePerSecretCache.isValidName(name), JSON.stringify(name));
      await assertMissing(cache, name);
    }
  });

  it('refuses Windows device names and a trailing dot, which would name another file or a device', () => {
    for (const name of ['con', 'CON', 'Nul', 'nul.txt', 'aux', 'prn.key', 'com1', 'COM9.json', 'lpt1', 'LPT3.bin', 'key.', 'a..']) {
      assert.ok(!FilePerSecretCache.isValidName(name), name);
    }
    // Names that only start like one are names.
    for (const name of ['console', 'nullable', 'com10', 'com0', 'lpt', 'auxiliary.txt', 'prod__con', 'a.b']) {
      assert.ok(FilePerSecretCache.isValidName(name), name);
    }
  });

  it('accepts up to MAX_NAME_LENGTH letters, digits and punctuation', () => {
    assert.ok(FilePerSecretCache.isValidName('Db-Password_v2.txt'));
    assert.ok(FilePerSecretCache.isValidName('a'.repeat(FilePerSecretCache.MAX_NAME_LENGTH)));
    assert.ok(!FilePerSecretCache.isValidName('a'.repeat(FilePerSecretCache.MAX_NAME_LENGTH + 1)));
    assert.ok(!FilePerSecretCache.isValidName(undefined));
    assert.ok(!FilePerSecretCache.isValidName(null));
  });

  it('refuses a name that isn\'t a string', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    const cache = f.cache();
    await assert.rejects(cache.decrypt(undefined as unknown as string, new Uint8Array(16)), TypeError);
    await assert.rejects(cache.maxDecryptedLength(null as unknown as string), TypeError);
  });
});

describe('FilePerSecretCache: refusals', () => {
  it('fails authentication for a file copied under another name, through both members', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    f.write('admin', 'secret');
    copyFileSync(join(f.folder, 'admin'), join(f.folder, 'reader'));
    const cache = f.cache();

    await assert.rejects(cache.decrypt('reader', new Uint8Array(16)), AuthenticationFailedError);
    await assert.rejects(cache.maxDecryptedLength('reader'), AuthenticationFailedError);
  });

  it('does not cache a file that fails authentication, so a fixed file is read next time', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    f.write('admin', 'secret');
    copyFileSync(join(f.folder, 'admin'), join(f.folder, 'reader'));
    const cache = f.cache();
    await assert.rejects(cache.decrypt('reader', new Uint8Array(16)), AuthenticationFailedError);

    f.write('reader', 'fixed');
    assert.equal(await get(cache, 'reader'), 'fixed');
  });

  it('refuses a file in an untrusted location, and does not cache it', async (t) => {
    if (isRoot) {
      t.skip('Running as root, whose files are trusted.');
      return;
    }
    const f = fixture(t);
    if (f === undefined) return;
    f.write('item', 'value');
    const untrusted = new FilePerSecretCache(f.folder, KeyFileTrust.administratorsOnly, f.ring, new DefaultFormatProvider());

    const refused = (e: unknown) => e instanceof KeyFileError && e.code === 'EACCES' && e.message.includes('not trusted');
    await assert.rejects(untrusted.decrypt('item', new Uint8Array(16)), refused);
    await assert.rejects(untrusted.maxDecryptedLength('item'), refused);
    assert.equal(await get(f.cache(), 'item'), 'value');
  });

  it('refuses a file over MAX_FILE_LENGTH', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    writeFileSync(join(f.folder, 'huge'), new Uint8Array(FilePerSecretCache.MAX_FILE_LENGTH + 1));
    const cache = f.cache();

    const tooLarge = (e: unknown) => e instanceof KeyFileError && e.code === FILE_TOO_LARGE;
    await assert.rejects(cache.decrypt('huge', new Uint8Array(16)), tooLarge);
    await assert.rejects(cache.maxDecryptedLength('huge'), tooLarge);
  });

  it('is cancelled by an aborted signal', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    await assert.rejects(f.cache().decrypt('item', new Uint8Array(16), AbortSignal.abort()), { name: 'AbortError' });
    await assert.rejects(f.cache().maxDecryptedLength('item', AbortSignal.abort()), { name: 'AbortError' });
  });
});

describe('FilePerSecretCache: keys', () => {
  it('still decrypts a value under an older key version after rotation', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    f.write('item', 'old');
    f.ring.add(2, new RecordingKey());
    f.write('other', 'new');
    assert.match(readFileSync(join(f.folder, 'other'), 'latin1'), /^enc::v2::/);
    const cache = f.cache();

    assert.equal(await get(cache, 'item'), 'old');
    assert.equal(await get(cache, 'other'), 'new');
  });

  it('refuses a value under a key version the ring doesn\'t hold', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    writeFileSync(join(f.folder, 'item'), new DefaultFormatProvider().format({ keyVersion: 7, value: new Uint8Array(randomBytes(40)) }));

    await assert.rejects(f.cache().decrypt('item', new Uint8Array(64)), KeyNotFoundError);
  });

  it('decrypts a value over the default format\'s limit with a format provider that allows it', async (t) => {
    // Over the default format's 4096 characters, so ring and cache both allow longer values.
    const format = new DefaultFormatProvider(16 * 1024);
    const ring = new KeyRing(format);
    ring.add(1, new RecordingKey());
    const f = fixture(t, ring);
    if (f === undefined) return;
    const value = 'x'.repeat(8000);
    f.write('large', value);
    const cache = new FilePerSecretCache(f.folder, f.trust, ring, format);

    const result = new Uint8Array(value.length);
    assert.equal(await cache.decrypt('large', result), value.length);
    assert.deepEqual(result, utf8(value));
    await assert.rejects(f.cache().decrypt('large', new Uint8Array(16)), { code: 'ERR_HKDFGUARD_INVALID_FORMAT' });
  });
});

describe('FilePerSecretCache: construction', () => {
  it('validates its arguments, and that the folder exists', (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    const format = new DefaultFormatProvider();
    const { folder, trust, ring } = f;

    assert.throws(() => new FilePerSecretCache(undefined as unknown as string, trust, ring, format), TypeError);
    assert.throws(() => new FilePerSecretCache('', trust, ring, format), InvalidArgumentError);
    assert.throws(() => new FilePerSecretCache(folder, undefined as unknown as KeyFileTrust, ring, format), TypeError);
    assert.throws(() => new FilePerSecretCache(folder, { windowsPrincipals: [] } as unknown as KeyFileTrust, ring, format), TypeError);
    assert.throws(() => new FilePerSecretCache(folder, trust, undefined as unknown as KeyRing, format), TypeError);
    assert.throws(() => new FilePerSecretCache(folder, trust, ring, undefined as unknown as DefaultFormatProvider), TypeError);
    writeFileSync(join(folder, 'file'), '');
    for (const missing of [join(folder, 'absent'), join(folder, 'file')]) {
      assert.throws(() => new FilePerSecretCache(missing, trust, ring, format),
        (e: unknown) => e instanceof KeyFileError && e.code === 'ENOENT' && e.message.includes("doesn't exist"));
    }
    assert.equal(new FilePerSecretCache(folder, trust, ring, format).folderPath, resolve(folder));
  });
});

describe('FilePerSecretCache: telemetry', () => {
  function withSensitiveLogging(): () => void {
    const original = HkdfGuardTelemetry.cache.enableSensitiveLogging;
    HkdfGuardTelemetry.cache.enableSensitiveLogging = true;
    return () => { HkdfGuardTelemetry.cache.enableSensitiveLogging = original; };
  }

  it('returns the same result with sensitive logging on, logging the name but never the value', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    f.write('item', 'never-logged');
    const restore = withSensitiveLogging();
    try {
      const { logger, entries, withEventId } = capturingLogger();
      const cache = new FilePerSecretCache(f.folder, f.trust, f.ring, new DefaultFormatProvider(), logger);
      assert.equal(await get(cache, 'item'), 'never-logged');
      assert.ok(withEventId(1).some((e) => e.level === 'debug' && e.message === 'hkdfguard.cache.populate completed for item.'));
      assert.ok(!entries.some((e) => e.message.includes('never-logged')));
    } finally {
      restore();
    }
  });

  it('makes each load a populate span, counted as success, not_found or error, and logs a failure', async (t) => {
    const f = fixture(t);
    if (f === undefined) return;
    f.write('Found', 'value');
    f.write('admin', 'secret');
    copyFileSync(join(f.folder, 'admin'), join(f.folder, 'failing'));
    const { logger, withEventId } = capturingLogger();
    const restore = withSensitiveLogging();
    const spans = useSpanRecorder();
    const metrics = useMetricRecorder();
    try {
      const cache = new FilePerSecretCache(f.folder, f.trust, f.ring, new DefaultFormatProvider(), logger);
      assert.equal(await get(cache, 'Found'), 'value'); // loaded once, then served from memory
      await assertMissing(cache, 'missing'); // looked for twice: not remembered
      await assert.rejects(cache.decrypt('failing', new Uint8Array(16)), AuthenticationFailedError);
      await assertMissing(cache, 'not:a:file'); // never looked for

      const populates = spans.spans().filter((s) => s.name === SpanNames.cache.populate);
      assert.equal(populates.length, 4);
      const [found, notFound, , failed] = populates;
      assert.equal(found?.instrumentationScope.name, HkdfGuardTelemetry.cache.sourceName);
      assert.ok(found?.events.some((e) => e.attributes?.[AttributeNames.name] === 'Found'));
      assert.notEqual(found?.status.code, SpanStatusCode.ERROR);
      assert.notEqual(notFound?.status.code, SpanStatusCode.ERROR);
      assert.equal(failed?.status.code, SpanStatusCode.ERROR);
      assert.equal(failed?.events.filter((e) => e.name === 'exception').length, 1);
      assert.ok(spans.spans().some((s) => s.name === SpanNames.cache.decrypt && s.instrumentationScope.name === HkdfGuardTelemetry.cache.sourceName));

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

import { strict as assert } from 'node:assert';
import { chmodSync, mkdtempSync, readFileSync, statSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, it, mock } from 'node:test';
import {
  AuthenticationFailedError, CACHE_AAD_PREFIX, ClosedError, configurationAad, configurationPurpose, EncryptionLimitReachedError, HkdfGuardError, InvalidArgumentError,
  InvalidServiceNameError, isZero, KeyNotFoundError, MAX_WRAPPED_KEY_BYTES, NoCurrentKeyError, RefreshFailurePolicy,
  type DataEncryptionKey as DataEncryptionKeyContract, type DataProtector, type KeyWrapper,
} from '@runsecure/hkdfguard-abstractions';
import { capturingLogger, FakeKeyWrapper, RecordingFactory, TestProvider } from '@runsecure/hkdfguard-test-support';
import { buildKeyRing, buildKeyRingForTests, InvalidKeyFileError, MAX_EPHEMERAL_KEY_ROTATION_HOURS, type KeyRingConfig } from './build.js';
import { DefaultFormatProvider, InvalidFormatError } from './format.js';
import { DataEncryptionKey } from './key.js';
import { DuplicateVersionError, KeyRing, Rotation } from './keyring.js';

const utf8 = (s: string) => new TextEncoder().encode(s);
const INT32_MAX = 2 ** 31 - 1, INT32_MIN = -(2 ** 31);

function newKey(): { key: DataEncryptionKey; provider: TestProvider } {
  const provider = new TestProvider();
  return { key: new DataEncryptionKey(provider), provider };
}

function ringWith(...versions: number[]): { ring: KeyRing; providers: Map<number, TestProvider> } {
  const ring = new KeyRing();
  const providers = new Map<number, TestProvider>();
  for (const v of versions) {
    const { key, provider } = newKey();
    ring.add(v, key);
    providers.set(v, provider);
  }
  return { ring, providers };
}

function unprotect(p: DataProtector, formatted: string): string {
  const result = new Uint8Array(p.maxDecryptedLength(formatted));
  return new TextDecoder().decode(result.subarray(0, p.decrypt(formatted, result)));
}

function keyFile(contents: Uint8Array | string, ageDays = 0): string {
  const path = join(mkdtempSync(join(tmpdir(), 'hkdfguard-dek-')), 'key.bin');
  writeFileSync(path, contents);
  if (ageDays !== 0) {
    const written = new Date(Date.now() - ageDays * DAY_MS);
    utimesSync(path, written, written);
  }
  return path;
}

const DAY_MS = 24 * 60 * 60 * 1000;

describe('DataEncryptionKey', () => {
  it('round-trips with and without AAD, and rejects mismatched AAD', () => {
    const { key } = newKey();
    for (const aad of [undefined, utf8('purpose')]) {
      const ciphertext = key.encrypt(utf8('hello'), aad);
      const result = new Uint8Array(5);
      key.decrypt(ciphertext, result, aad);
      assert.equal(new TextDecoder().decode(result), 'hello');
    }
    assert.throws(() => key.decrypt(key.encrypt(utf8('hello'), utf8('right')), new Uint8Array(5), utf8('wrong')), AuthenticationFailedError);
  });

  it('zeroes the plaintext, and trims to what the provider wrote', () => {
    const { key, provider } = newKey();
    const plaintext = utf8('top secret');
    key.encrypt(plaintext);
    assert.ok(isZero(plaintext));
    provider.overAllocate = 10;
    assert.equal(key.encrypt(utf8('hello')).length, 5 + 28);
  });

  it('closes its provider once', async () => {
    const { key, provider } = newKey();
    await key.close();
    await key.close();
    assert.equal(provider.closes, 1);
  });

  it('stops encrypting at its deadline, zeroing the plaintext, but keeps decrypting', () => {
    const calls: string[] = [];
    const now = Date.now();
    const deadline = { warnAt: now + 1000, refuseAt: now + 2000, reason: 'rotate me', onWarning: () => calls.push('warn'), onExpired: () => calls.push('expired') };
    const key = new DataEncryptionKey(new TestProvider(), deadline);
    const ciphertext = key.encrypt(utf8('before'));
    assert.equal(key.checkDeadline(now), false);
    assert.deepEqual(calls, []);

    mock.timers.enable({ apis: ['Date'], now: now + 1500 });
    try {
      key.encrypt(utf8('warned'));
      key.encrypt(utf8('warned again'));
      assert.deepEqual(calls, ['warn']);

      mock.timers.setTime(now + 2000);
      const plaintext = utf8('refused');
      assert.throws(() => key.encrypt(plaintext), (e: unknown) => e instanceof EncryptionLimitReachedError && e.message === 'rotate me');
      assert.ok(isZero(plaintext));
      assert.throws(() => key.encrypt(utf8('refused again')), EncryptionLimitReachedError);
      assert.deepEqual(calls, ['warn', 'expired']);

      const result = new Uint8Array(6);
      key.decrypt(ciphertext, result);
      assert.equal(new TextDecoder().decode(result), 'before');
    } finally {
      mock.timers.reset();
    }
  });

  it('announces expiry once even when the warning was skipped, and ignores a throwing callback', () => {
    let expired = 0;
    const key = new DataEncryptionKey(new TestProvider(), {
      warnAt: 0, refuseAt: 1, reason: 'old', onWarning: () => { throw new Error('never called'); }, onExpired: () => { expired++; throw new Error('bad logger'); },
    });
    assert.throws(() => key.encrypt(utf8('x')), EncryptionLimitReachedError);
    assert.throws(() => key.encrypt(utf8('x')), EncryptionLimitReachedError);
    assert.equal(expired, 1);
  });

  it('encrypts without limit when it has no deadline', () => {
    const { key } = newKey();
    assert.equal(key.checkDeadline(Number.MAX_SAFE_INTEGER), false);
    assert.equal(key.encrypt(utf8('hello')).length, 5 + 28);
  });
});

describe('DefaultFormatProvider', () => {
  const f = new DefaultFormatProvider();

  it('produces the known vector every port must', () => {
    assert.equal(f.format({ keyVersion: 1, value: new Uint8Array([1, 2, 3]) }), 'enc::v1::AQID');
  });

  it('round-trips, including empty values and negative versions', () => {
    for (const value of [{ keyVersion: 7, value: utf8('ciphertext bytes') }, { keyVersion: 1, value: new Uint8Array(0) }, { keyVersion: -5, value: new Uint8Array([9]) }]) {
      const formatted = f.format(value);
      assert.deepEqual(f.parse(formatted), value);
      assert.equal(f.maxDecryptedLength(formatted), value.value.length);
    }
  });

  it('refuses anything but the canonical form', () => {
    for (const input of ['', 'no-delimiters-at-all', 'enc::onlyonepart', 'wrong::v1::AAAA', 'enc::1::AAAA', 'enc::vNotANumber::AAAA',
      'enc::v1::not-valid-base64!!!', 'enc::v+1::AQID', 'enc::v 1::AQID', 'enc::v1 ::AQID', 'enc::v~1::AQID', 'enc::v::AQID', 'enc::v-::AQID',
      'enc::v2147483648::AQID', 'enc::v1::AQID    ', 'enc::v1::AQ ID', 'enc::v1::AQID\t', 'enc::v1::AQID\r\n', 'enc::v1:: AQID', 'enc::v1::AQI']) {
      assert.throws(() => f.parse(input), InvalidFormatError, input);
      assert.throws(() => f.maxDecryptedLength(input), InvalidFormatError, input);
    }
  });

  it('applies its length limit to format and parse', () => {
    assert.equal(f.maxEncryptedLength, 4096);
    assert.ok(f.format({ keyVersion: 1, value: new Uint8Array(3063) }).length <= 4096);
    assert.throws(() => f.format({ keyVersion: 1, value: new Uint8Array(3072) }), InvalidFormatError);
    assert.throws(() => f.parse(`enc::v1::${'A'.repeat(4096)}`), InvalidFormatError);
    const custom = new DefaultFormatProvider(17);
    const exact = custom.format({ keyVersion: 1, value: new Uint8Array(6) });
    assert.equal(exact.length, 17);
    custom.parse(exact);
    assert.throws(() => custom.format({ keyVersion: 1, value: new Uint8Array(9) }), InvalidFormatError);
    for (const limit of [0, -1, 1.5]) assert.throws(() => new DefaultFormatProvider(limit), InvalidArgumentError);
  });
});

describe('KeyRing', () => {
  it('starts empty', () => {
    const ring = new KeyRing();
    assert.throws(() => ring.currentVersion, NoCurrentKeyError);
    assert.throws(() => ring.getCurrent(), NoCurrentKeyError);
  });

  it('makes the highest version current, whatever the order', () => {
    const { ring } = ringWith(1, 3, 2);
    assert.equal(ring.currentVersion, 3);
  });

  it('works for every 32-bit version, and no other', () => {
    for (const version of [INT32_MIN, -1, 0, INT32_MAX]) {
      const { ring } = ringWith(version);
      assert.equal(ring.currentVersion, version);
      const protector = ring.createProtector('range');
      assert.equal(unprotect(protector, protector.encrypt('value')), 'value');
    }
    const { ring } = ringWith(INT32_MIN, 5);
    assert.equal(ring.currentVersion, 5);
    for (const version of [INT32_MAX + 1, INT32_MIN - 1, 1.5]) {
      assert.throws(() => ring.add(version, newKey().key), (e: unknown) => e instanceof HkdfGuardError && e.code === 'ERR_HKDFGUARD_VERSION_OUT_OF_RANGE');
    }
  });

  it('refuses a duplicate version, leaving ownership with the caller', async () => {
    const { ring } = ringWith(1);
    const { key, provider } = newKey();
    assert.throws(() => ring.add(1, key), DuplicateVersionError);
    await ring.close();
    assert.equal(provider.closes, 0);
  });

  it('gets, tries and reads the current key', () => {
    const ring = new KeyRing();
    const { key } = newKey();
    ring.add(4, key);
    assert.equal(ring.get(4), key);
    assert.equal(ring.tryGet(4), key);
    assert.deepEqual(ring.getCurrent(), { version: 4, key });
    assert.throws(() => ring.get(9), KeyNotFoundError);
    assert.equal(ring.tryGet(9), undefined);
  });

  it('closes every key once, refusing later adds, and leaves non-closable keys alone', async () => {
    const { ring, providers } = ringWith(1, 2);
    await ring.close();
    await ring.close();
    assert.deepEqual([...providers.values()].map((p) => p.closes), [1, 1]);
    assert.throws(() => ring.add(3, newKey().key), ClosedError);
    assert.throws(() => ring.createProtector('after').encrypt('x'), ClosedError);

    const plain = new KeyRing();
    const notClosable: DataEncryptionKeyContract = { encrypt: () => new Uint8Array(0), decrypt: () => 0 };
    plain.add(1, notClosable);
    await plain.close();
  });
});

describe('protectors', () => {
  it("round-trip, leaving the caller's plaintext alone", () => {
    const { ring } = ringWith(1);
    const protector = ring.createProtector('purpose');
    const plaintext = utf8('héllo wörld ✓');
    const formatted = protector.encrypt(plaintext);
    assert.equal(new TextDecoder().decode(plaintext), 'héllo wörld ✓');
    assert.equal(unprotect(protector, formatted), 'héllo wörld ✓');
  });

  it('encrypt under the current version and decrypt under the one named', () => {
    const { ring } = ringWith(1);
    const protector = ring.createProtector('purpose');
    const underV1 = protector.encrypt('old');
    ring.add(2, newKey().key);
    assert.ok(underV1.startsWith('enc::v1:') && protector.encrypt('new').startsWith('enc::v2:'));
    assert.equal(unprotect(protector, underV1), 'old');
  });

  it('fail for another name, a missing version, malformed input, or an empty ring', () => {
    const { ring } = ringWith(1);
    const formatted = ring.createProtector('one').encrypt('hello');
    assert.throws(() => unprotect(ring.createProtector('two'), formatted), AuthenticationFailedError);
    assert.throws(() => unprotect(ring.createProtector('one'), formatted.replace('v1', 'v9')), KeyNotFoundError);
    assert.throws(() => ring.createProtector('one').decrypt('not-a-valid-format', new Uint8Array(16)), InvalidFormatError);
    assert.throws(() => new KeyRing().createProtector('empty').encrypt('x'), NoCurrentKeyError);
  });

  it('refuse empty, invalid and cache-reserved names', () => {
    const ring = new KeyRing();
    for (const name of ['', 'Key\uD800', CACHE_AAD_PREFIX, `${CACHE_AAD_PREFIX}item`]) {
      assert.throws(() => ring.createProtector(name), (e: unknown) => e instanceof HkdfGuardError && e.code === 'ERR_HKDFGUARD_INVALID_PROTECTOR_NAME', name);
    }
    for (const name of ['HkdfGuard.Cache', 'hkdfguard.cache:item', `x${CACHE_AAD_PREFIX}`]) ring.createProtector(name);
  });

  it('for a configuration purpose, use the same AAD as the pipeline', () => {
    const ring = new KeyRing();
    const key = new (class extends DataEncryptionKey {
      lastAad: Uint8Array | undefined;
      override encrypt(plaintext: Uint8Array, aad?: Uint8Array): Uint8Array { this.lastAad = aad; return super.encrypt(plaintext, aad); }
    })(new TestProvider());
    ring.add(1, key);
    ring.createProtector(configurationPurpose('ConnectionStrings:Admin')).encrypt('x');
    assert.deepEqual(key.lastAad, configurationAad('ConnectionStrings:Admin'));
  });
});

describe('buildKeyRing', () => {
  const base = (factory: RecordingFactory): KeyRingConfig => ({ keyWrapper: new FakeKeyWrapper(), cryptoProviderFactory: factory, keyRefreshInterval: 60 });

  it('accepts the longest rotation a Node.js timer can honour, and nothing longer', async () => {
    // A timer delay over 2^31-1 ms is clamped to 1 ms by Node, so every accepted interval must fit.
    assert.equal(MAX_EPHEMERAL_KEY_ROTATION_HOURS, 596);
    const ring = await buildKeyRing({ ...base(new RecordingFactory()), ephemeralKeys: [1], ephemeralKeyRotationHours: MAX_EPHEMERAL_KEY_ROTATION_HOURS });
    try {
      assert.ok(ring.ephemeralKeyRotationIntervalMs! <= 2 ** 31 - 1);
    } finally {
      await ring.close();
    }
  });

  it('a rotation timer refuses an interval Node.js would clamp to 1 ms', () => {
    const ring = new KeyRing();
    for (const intervalMs of [0, 2 ** 31, 1193 * 60 * 60 * 1000]) {
      assert.throws(() => new Rotation(ring, intervalMs, 60_000, [], async () => { throw new Error('unused'); }, undefined, true), InvalidArgumentError);
    }
  });

  it('refuses an incomplete or out-of-range config before creating anything', async () => {
    const factory = new RecordingFactory();
    const valid = { ...base(factory), ephemeralKeys: [1] };
    const cases: Partial<KeyRingConfig>[] = [
      { keyWrapper: undefined }, { cryptoProviderFactory: undefined }, { ephemeralKeys: [] }, { keyRefreshInterval: 0 },
      { keyRefreshInterval: 301 }, { ephemeralKeyRotationHours: 0 }, { ephemeralKeyRotationHours: 597 }, { ephemeralKeyRotationHours: 1193 },
      { ephemeralKeyRetentionMinutes: 0.5 }, { disableEphemeralKeyRotation: true, ephemeralKeyRotationHours: 6 }, { keyFiles: { 2: ' ' } },
      { keyFileMaxAgeDays: 0 }, { keyFileMaxAgeDays: 3651 }, { keyFileMaxAgeDays: 1.5 },
    ];
    for (const change of cases) {
      await assert.rejects(buildKeyRing({ ...valid, ...change } as KeyRingConfig), (e: unknown) => e instanceof HkdfGuardError && e.code === 'ERR_HKDFGUARD_INVALID_CONFIG', JSON.stringify(change));
    }
    await assert.rejects(buildKeyRing({ ...valid, serviceName: 'my..service' }), InvalidServiceNameError);
    assert.equal(factory.created.length, 0);
  });

  it('registers key files and ephemeral keys, the highest current, passing the interval and policy', async () => {
    const factory = new RecordingFactory();
    const ring = await buildKeyRing({
      ...base(factory), keyFiles: { 3: keyFile('wrapped three'), 1: keyFile('wrapped one') }, ephemeralKeys: [5],
      refreshFailurePolicy: RefreshFailurePolicy.failClosedAfter(4), disableEphemeralKeyRotation: true,
    });
    try {
      assert.equal(ring.currentVersion, 5);
      for (const v of [1, 3, 5]) assert.ok(ring.tryGet(v));
      assert.deepEqual(factory.wrapped.map((w) => new TextDecoder().decode(w)), ['wrapped one', 'wrapped three']);
      assert.equal(factory.ephemerals, 1);
      assert.ok(factory.options.every((o) => o.expirySeconds === 60 && o.refreshFailurePolicy?.maxFailures === 4));
      const protector = ring.createProtector('built');
      assert.equal(unprotect(protector, protector.encrypt('hello')), 'hello');
    } finally {
      await ring.close();
    }
  });

  it('refuses a wrapped key that is empty or over the limit, whatever the key wrapper', async () => {
    for (const length of [0, MAX_WRAPPED_KEY_BYTES + 1]) {
      const factory = new RecordingFactory();
      await assert.rejects(buildKeyRing({ ...base(factory), keyFiles: { 1: keyFile(new Uint8Array(length)) } }), InvalidKeyFileError);
      assert.equal(factory.wrapped.length, 0);
    }
  });

  it('reads every key file through the key wrapper when it has readKeyFile', async () => {
    const factory = new RecordingFactory();
    const paths = { 1: keyFile('on disk one'), 2: keyFile('on disk two') };
    const reads: { path: string; signal?: AbortSignal }[] = [];
    const wrapper = Object.assign(new FakeKeyWrapper(), {
      async readKeyFile(path: string, signal?: AbortSignal): Promise<Uint8Array> {
        reads.push({ path, signal });
        return utf8(`through the wrapper ${path === paths[1] ? 'one' : 'two'}`);
      },
    });
    const signal = new AbortController().signal;
    const ring = await buildKeyRing({ ...base(factory), keyWrapper: wrapper, keyFiles: paths, signal });
    try {
      assert.deepEqual(reads.map((r) => r.path), [paths[1], paths[2]]);
      assert.ok(reads.every((r) => r.signal === signal));
      assert.deepEqual(factory.wrapped.map((w) => new TextDecoder().decode(w)), ['through the wrapper one', 'through the wrapper two']);
    } finally {
      await ring.close();
    }
  });

  it("surfaces the key wrapper's refusal of a key file, closing what it created", async () => {
    const factory = new RecordingFactory();
    const refusal = Object.assign(new Error("Key file 'k' was refused"), { code: 'EACCES' });
    const wrapper = Object.assign(new FakeKeyWrapper(), { readKeyFile: async () => { throw refusal; } });
    await assert.rejects(buildKeyRing({ ...base(factory), keyWrapper: wrapper, keyFiles: { 1: keyFile('wrapped') }, ephemeralKeys: [2] }), (e: unknown) => e === refusal);
    assert.equal(factory.created.length, 0);
  });

  it('limits each key file to its age from the time it was last written, 365 days by default', async () => {
    const path = keyFile('wrapped');
    const written = statSync(path).mtimeMs;
    for (const [maxAge, days] of [[undefined, 365], [30, 30]] as const) {
      const ring = await buildKeyRing({ ...base(new RecordingFactory()), keyFiles: { 1: path }, keyFileMaxAgeDays: maxAge });
      try {
        const deadline = (ring.get(1) as DataEncryptionKey).deadline!;
        assert.equal(deadline.refuseAt, written + days * DAY_MS);
        assert.equal(deadline.warnAt, written + days * DAY_MS * 0.9);
        assert.match(deadline.reason, new RegExp(`more than ${days} days ago`));
      } finally {
        await ring.close();
      }
    }
  });

  it('reports a current key file nearing its age at startup, once, and keeps encrypting', async () => {
    const { logger, withEventId } = capturingLogger();
    const ring = await buildKeyRing({ ...base(new RecordingFactory()), keyFiles: { 1: keyFile('wrapped', 340) }, logger });
    try {
      assert.equal(withEventId(11).length, 1);
      assert.equal(withEventId(11)[0]!.level, 'warn');
      const protector = ring.createProtector('aging');
      assert.equal(unprotect(protector, protector.encrypt('still fine')), 'still fine');
      assert.equal(withEventId(11).length, 1);
      assert.equal(withEventId(12).length, 0);
    } finally {
      await ring.close();
    }
  });

  it('refuses to encrypt under a current key file past its age, reporting it at startup, but still decrypts', async () => {
    const path = keyFile('wrapped', 20);
    const factory = new RecordingFactory();
    const before = await buildKeyRing({ ...base(factory), keyFiles: { 1: path }, keyFileMaxAgeDays: 30 });
    const protector = before.createProtector('expiring');
    const formatted = protector.encrypt('written in time');

    const { logger, withEventId } = capturingLogger();
    mock.timers.enable({ apis: ['Date'], now: Date.now() + 15 * DAY_MS }); // now 35 days old
    try {
      assert.throws(() => protector.encrypt('too late'), EncryptionLimitReachedError);
      assert.equal(unprotect(protector, formatted), 'written in time');

      const after = await buildKeyRing({ ...base(new RecordingFactory()), keyFiles: { 1: path }, keyFileMaxAgeDays: 30, logger });
      try {
        assert.equal(withEventId(12).length, 1);
        assert.equal(withEventId(12)[0]!.attributes['log.level'], 'critical');
        assert.throws(() => after.createProtector('expiring').encrypt('too late'), (e: unknown) => e instanceof EncryptionLimitReachedError && e.message.includes(path));
        assert.equal(withEventId(12).length, 1);
      } finally {
        await after.close();
      }
    } finally {
      mock.timers.reset();
      await before.close();
    }
  });

  it('never reports a superseded key file, which never encrypts', async () => {
    const { logger, entries } = capturingLogger();
    const ring = await buildKeyRing({
      ...base(new RecordingFactory()), keyFiles: { 1: keyFile('old', 400), 2: keyFile('new') }, logger,
    });
    try {
      assert.equal(ring.currentVersion, 2);
      assert.deepEqual(entries, []);
      const protector = ring.createProtector('rotated');
      assert.equal(unprotect(protector, protector.encrypt('fine')), 'fine');
    } finally {
      await ring.close();
    }
  });

  it('puts no age limit on ephemeral keys', async () => {
    const ring = await buildKeyRing({ ...base(new RecordingFactory()), ephemeralKeys: [1], disableEphemeralKeyRotation: true, keyFileMaxAgeDays: 1 });
    try {
      assert.equal((ring.get(1) as DataEncryptionKey).deadline, undefined);
    } finally {
      await ring.close();
    }
  });

  it('reads every key file through the key wrapper, and fails with what it refuses', async () => {
    const refusal = Object.assign(new Error('untrusted key file'), { code: 'EACCES' });
    const paths: string[] = [];
    const wrapper = new FakeKeyWrapper();
    wrapper.readKeyFile = async (path: string) => {
      paths.push(path);
      if (path.endsWith('refused')) throw refusal;
      return utf8('wrapped');
    };
    const factory = new RecordingFactory();
    const accepted = keyFile('ignored');
    const ring = await buildKeyRing({ ...base(factory), keyWrapper: wrapper, keyFiles: { 1: accepted } });
    await ring.close();
    assert.deepEqual(paths, [accepted]);

    const refused = join(dirname(accepted), 'refused');
    writeFileSync(refused, 'wrapped');
    await assert.rejects(buildKeyRing({ ...base(new RecordingFactory()), keyWrapper: wrapper, keyFiles: { 1: refused } }), refusal);
  });

  it('only reads a key file: its contents, mode and times are unchanged', { skip: process.platform === 'win32' }, async () => {
    const path = keyFile('wrapped', 100);
    chmodSync(path, 0o400);
    const before = statSync(path);
    const ring = await buildKeyRing({ ...base(new RecordingFactory()), keyFiles: { 1: path } });
    await ring.close();
    const after = statSync(path);
    assert.equal(readFileSync(path, 'utf8'), 'wrapped');
    assert.equal(after.mode, before.mode);
    assert.equal(after.mtimeMs, before.mtimeMs);
    assert.equal(after.uid, before.uid);
  });

  it('uses the configured format provider', async () => {
    const ring = await buildKeyRing({ ...base(new RecordingFactory()), ephemeralKeys: [1], formatProvider: new DefaultFormatProvider(17), disableEphemeralKeyRotation: true });
    try {
      assert.throws(() => ring.createProtector('custom').encrypt('too long for 17 characters'), InvalidFormatError);
    } finally {
      await ring.close();
    }
  });

  it('closes every key it created when it fails partway', async () => {
    const failing: Partial<KeyRingConfig>[] = [
      { keyFiles: { 1: keyFile('wrapped') }, ephemeralKeys: [2, 1] },
      { ephemeralKeys: [4], keyFiles: { 1: keyFile('wrapped'), 3: join(tmpdir(), 'missing-hkdfguard-key') } },
    ];
    for (const change of failing) {
      const factory = new RecordingFactory();
      await assert.rejects(buildKeyRing({ ...base(factory), ...change }));
      assert.ok(factory.created.length > 0 && factory.created.every((p) => p.closes === 1));
    }
  });

  it('creates nothing when the signal is already aborted', async () => {
    const factory = new RecordingFactory();
    await assert.rejects(buildKeyRing({ ...base(factory), keyFiles: { 1: keyFile('wrapped') }, ephemeralKeys: [2], signal: AbortSignal.abort() }));
    assert.equal(factory.created.length, 0);
  });

});

describe('ephemeral key rotation', () => {
  async function rotating(change: Partial<KeyRingConfig> = {}) {
    const factory = new RecordingFactory();
    const log = capturingLogger();
    const ring = await buildKeyRingForTests({ keyWrapper: new FakeKeyWrapper(), cryptoProviderFactory: factory, keyRefreshInterval: 60, ephemeralKeys: [1], logger: log.logger, ...change }, { manualRotation: true });
    return { ring, factory, log, rotation: ring.rotation! };
  }

  it('defaults to 24 hours of rotation and retention', async () => {
    const { ring, rotation } = await rotating();
    assert.equal(ring.ephemeralKeyRotationIntervalMs, 24 * 3600 * 1000);
    assert.equal(rotation.retentionMs, 24 * 3600 * 1000);
    await ring.close();
  });

  it('adds a fresh current version each rotation, and old values still decrypt', async () => {
    const { ring, factory, log, rotation } = await rotating();
    const protector = ring.createProtector('rotation');
    const underV1 = protector.encrypt('written under v1');
    assert.ok(await rotation.rotate());
    assert.ok(await rotation.rotate());
    assert.equal(ring.currentVersion, 3);
    assert.ok(protector.encrypt('now').startsWith('enc::v3::'));
    assert.equal(unprotect(protector, underV1), 'written under v1');
    assert.equal(log.withEventId(6).length, 2);
    assert.equal(factory.ephemerals, 3);
    await ring.close();
  });

  it('never runs on a key-file ring, or when disabled', async () => {
    const factory = new RecordingFactory();
    const files = await buildKeyRing({ keyWrapper: new FakeKeyWrapper(), cryptoProviderFactory: factory, keyRefreshInterval: 60, keyFiles: { 4: keyFile('wrapped') } });
    assert.equal(files.ephemeralKeyRotationIntervalMs, undefined);
    const disabled = await buildKeyRing({ keyWrapper: new FakeKeyWrapper(), cryptoProviderFactory: factory, keyRefreshInterval: 60, ephemeralKeys: [1], disableEphemeralKeyRotation: true });
    assert.equal(disabled.ephemeralKeyRotationIntervalMs, undefined);
    await files.close();
    await disabled.close();
  });

  it('refuses a key file above every ephemeral version before reading one, unless disabled', async () => {
    const factory = new RecordingFactory();
    const reads: string[] = [];
    const wrapper = Object.assign(new FakeKeyWrapper(), {
      async readKeyFile(path: string): Promise<Uint8Array> {
        reads.push(path);
        return utf8('wrapped');
      },
    });
    const layout: KeyRingConfig = {
      keyWrapper: wrapper, cryptoProviderFactory: factory, keyRefreshInterval: 60, keyFiles: { 1: keyFile('wrapped'), 3: keyFile('wrapped') }, ephemeralKeys: [2],
    };
    await assert.rejects(buildKeyRing(layout),
      (e: unknown) => e instanceof HkdfGuardError && e.code === 'ERR_HKDFGUARD_INVALID_CONFIG' && e.message.startsWith('Key file version 3 is above every ephemeral version'));
    assert.deepEqual(reads, []);
    assert.equal(factory.created.length, 0);

    const disabled = await buildKeyRing({ ...layout, disableEphemeralKeyRotation: true });
    try {
      assert.equal(disabled.currentVersion, 3);
      assert.equal(disabled.ephemeralKeyRotationIntervalMs, undefined);
      assert.equal(reads.length, 2);
    } finally {
      await disabled.close();
    }
  });

  it('keeps the current key through a failure, and the next interval succeeds', async () => {
    const { ring, factory, log, rotation } = await rotating();
    factory.failNext = new Error('KEK unavailable');
    assert.ok(!(await rotation.rotate()));
    assert.equal(ring.currentVersion, 1);
    assert.ok(log.withEventId(7)[0]?.message.includes('version 1 stays current'));
    assert.ok(await rotation.rotate());
    assert.equal(ring.currentVersion, 2);
    await ring.close();
  });

  it('closes the key it made when the next version is taken meanwhile', async () => {
    const { ring, factory, log, rotation } = await rotating();
    factory.onCreate = () => ring.add(2, newKey().key);
    assert.ok(!(await rotation.rotate()));
    assert.equal(factory.created.at(-1)!.closes, 1);
    assert.equal(log.withEventId(7).length, 1);
    await ring.close();
  });

  it('refuses to rotate past the last version without creating a key', async () => {
    const { ring, factory, log, rotation } = await rotating();
    ring.add(INT32_MAX, newKey().key);
    const created = factory.created.length;
    assert.ok(!(await rotation.rotate()));
    assert.equal(factory.created.length, created);
    assert.equal(log.withEventId(7).length, 1);
    await ring.close();
  });

  it('keeps a superseded key for its retention, then closes and removes it', async () => {
    const { ring, factory, log, rotation } = await rotating({ ephemeralKeyRetentionMinutes: 60 });
    const protector = ring.createProtector('retire');
    const underV1 = protector.encrypt('old');
    await rotation.rotate();
    const start = performance.now();
    await rotation.retire(start + 59 * 60_000);
    assert.ok(ring.tryGet(1));
    await rotation.retire(start + 61 * 60_000);
    assert.equal(ring.tryGet(1), undefined);
    assert.equal(factory.created[0]!.closes, 1);
    assert.throws(() => unprotect(protector, underV1), KeyNotFoundError);
    assert.equal(log.withEventId(8).length, 1);
    assert.equal(ring.currentVersion, 2);
    await ring.close();
  });

  it('never retires key-file versions or the current key, and logs a failed close', async () => {
    const { ring, rotation } = await rotating({ keyFiles: { 0: keyFile('wrapped') }, ephemeralKeyRetentionMinutes: 1 });
    await rotation.rotate();
    await rotation.retire(performance.now() + 24 * 3600_000);
    await rotation.retire(performance.now() + 48 * 3600_000);
    assert.deepEqual([0, 1, 2].map((v) => ring.tryGet(v) !== undefined), [true, false, true]);
    await ring.close();

    const failing = await rotating({ ephemeralKeyRetentionMinutes: 1 });
    failing.factory.created[0]!.closeError = new Error('close failed');
    await failing.rotation.rotate();
    await failing.rotation.retire(performance.now());
    await failing.rotation.retire(performance.now() + 3600_000);
    assert.equal(failing.ring.tryGet(1), undefined);
    assert.equal(failing.log.withEventId(9).length, 1);
    await failing.ring.close();
  });

  it('stops when the ring closes', async () => {
    const { ring, rotation } = await rotating();
    await ring.close();
    assert.equal(await rotation.rotate(), false);
    assert.equal(ring.currentVersion, 1);
    assert.equal(ring.tryGet(2), undefined);
  });
});

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import {
  AuthenticationFailedError, configurationAad, configurationPurpose, HkdfGuardError, InvalidConfigurationKeyError,
  type ProtectedReadOnlyCache,
} from '@runsecure/hkdfguard-abstractions';
import { ProtectedCache, ProtectedCacheCollection } from '@runsecure/hkdfguard-cache';
import { HkdfGuardTelemetry } from '@runsecure/hkdfguard-diagnostics';
import { DataEncryptionKey, InvalidFormatError, KeyRing } from '@runsecure/hkdfguard-dek';
import { TestProvider } from '@runsecure/hkdfguard-test-support';
import { DuplicateKeyError, envLookup, flattenJson, mapLookup } from './lookup.js';
import { EncryptedConfigurationReader } from './reader.js';

function newRing(): KeyRing {
  const ring = new KeyRing();
  ring.add(1, new DataEncryptionKey(new TestProvider()));
  return ring;
}

/** Encrypts `plaintext` the way the pipeline does for a configuration key: bound to that key's purpose. */
const protectFor = (ring: KeyRing, key: string, plaintext: string) => ring.createProtector(configurationPurpose(key)).encrypt(plaintext);

async function read(r: ProtectedReadOnlyCache, name: string): Promise<string | undefined> {
  const length = await r.maxDecryptedLength(name);
  if (length === undefined) return undefined;
  const result = new Uint8Array(length);
  return new TextDecoder().decode(result.subarray(0, await r.decrypt(name, result)));
}

describe('EncryptedConfigurationReader', () => {
  it('decrypts a value protected for its key', async () => {
    const ring = newRing();
    const reader = new EncryptedConfigurationReader(ring, mapLookup({
      'ConnectionStrings:Admin': protectFor(ring, 'ConnectionStrings:Admin', 'Server=db;Password=hunter2'),
      Unicode: protectFor(ring, 'Unicode', 'héllo wörld ✓ 🔐'),
    }));
    assert.equal(await read(reader, 'ConnectionStrings:Admin'), 'Server=db;Password=hunter2');
    assert.equal(await read(reader, 'Unicode'), 'héllo wörld ✓ 🔐');
  });

  it('decrypts a missing key to nothing', async () => {
    const reader = new EncryptedConfigurationReader(newRing(), mapLookup({}));
    assert.equal(await reader.decrypt('Missing', new Uint8Array(8)), 0);
    assert.equal(await reader.maxDecryptedLength('Missing'), undefined);
  });

  it('looks keys up ignoring ASCII case', async () => {
    const ring = newRing();
    const reader = new EncryptedConfigurationReader(ring, mapLookup({ 'ConnectionStrings:Admin': protectFor(ring, 'ConnectionStrings:Admin', 'secret') }));
    for (const key of ['connectionstrings:admin', 'CONNECTIONSTRINGS:ADMIN', 'ConnectionStrings:Admin']) assert.equal(await read(reader, key), 'secret');
  });

  it('fails authentication for a value moved to another key, including a non-ASCII case variant', async () => {
    const ring = newRing();
    const reader = new EncryptedConfigurationReader(ring, mapLookup({
      'ConnectionStrings:Reporting': protectFor(ring, 'ConnectionStrings:Admin', 'admin-secret'),
      'CAFÉ': protectFor(ring, 'café', 'lower'),
    }));
    for (const key of ['ConnectionStrings:Reporting', 'CAFÉ']) {
      await assert.rejects(reader.decrypt(key, new Uint8Array(64)), AuthenticationFailedError);
    }
  });

  it('refuses a value protected under a plain purpose of the same name', async () => {
    const ring = newRing();
    const reader = new EncryptedConfigurationReader(ring, mapLookup({ Secret: ring.createProtector('Secret').encrypt('value') }));
    await assert.rejects(reader.decrypt('Secret', new Uint8Array(64)), AuthenticationFailedError);
  });

  it('fails to parse a value that is not protected, and refuses an empty key', async () => {
    const reader = new EncryptedConfigurationReader(newRing(), mapLookup({ Plain: 'not-a-protected-value' }));
    await assert.rejects(reader.decrypt('Plain', new Uint8Array(64)), InvalidFormatError);
    await assert.rejects(reader.maxDecryptedLength('Plain'), InvalidFormatError);
    const any = new EncryptedConfigurationReader(newRing(), () => 'enc::v1::AAAA');
    await assert.rejects(any.decrypt('', new Uint8Array(8)), InvalidConfigurationKeyError);
  });

  it('reads fresh on every call, so a reload takes effect', async () => {
    const ring = newRing();
    let current = protectFor(ring, 'Rotating', 'first');
    const reader = new EncryptedConfigurationReader(ring, (key) => (key === 'Rotating' ? current : undefined));
    assert.equal(await read(reader, 'Rotating'), 'first');
    current = protectFor(ring, 'Rotating', 'second');
    assert.equal(await read(reader, 'Rotating'), 'second');
  });

  it('sits in a cache collection beside other sources', async () => {
    const ring = newRing();
    const local = new ProtectedCache(ring);
    local.add('Local', new TextEncoder().encode('from the cache'));
    const secrets = new ProtectedCacheCollection(local, new EncryptedConfigurationReader(ring, mapLookup({ FromConfig: protectFor(ring, 'FromConfig', 'from config') })));
    assert.equal(await read(secrets, 'Local'), 'from the cache');
    assert.equal(await read(secrets, 'FromConfig'), 'from config');
  });

  it('uses the configuration AAD, and still round-trips with sensitive logging', async () => {
    const telemetry = HkdfGuardTelemetry.encryptedConfiguration;
    telemetry.enableSensitiveLogging = true;
    try {
      let seen: Uint8Array | undefined;
      const ring = new KeyRing();
      ring.add(1, new (class extends DataEncryptionKey {
        override decrypt(c: Uint8Array, r: Uint8Array, aad?: Uint8Array): number { seen = aad; return super.decrypt(c, r, aad); }
      })(new TestProvider()));
      const reader = new EncryptedConfigurationReader(ring, mapLookup({ Key: protectFor(ring, 'Key', 'value') }));
      assert.equal(await read(reader, 'Key'), 'value');
      assert.deepEqual(seen, configurationAad('Key'));
    } finally {
      telemetry.enableSensitiveLogging = false;
    }
  });
});

describe('lookups', () => {
  it('mapLookup refuses keys differing only in ASCII case, but not non-ASCII variants', () => {
    assert.throws(() => mapLookup({ Key: 'a', KEY: 'b' }), DuplicateKeyError);
    mapLookup({ 'café': 'a', 'CAFÉ': 'b' });
    assert.equal(mapLookup(new Map([['A:b', 'x']]))('a:B'), 'x');
  });

  it("envLookup follows .NET's double-underscore convention", () => {
    const lookup = envLookup('APP_', { APP_ConnectionStrings__Admin: 'from env' });
    assert.equal(lookup('ConnectionStrings:Admin'), 'from env');
    assert.equal(lookup('ConnectionStrings:Missing'), undefined);
  });

  it('envLookup returns only own string values, never an inherited property', () => {
    for (const env of [{}, process.env]) {
      const lookup = envLookup('', env);
      for (const inherited of ['constructor', 'toString', 'hasOwnProperty', '__proto__', 'valueOf']) {
        assert.equal(lookup(inherited), undefined, inherited);
      }
    }
    const name = 'HKDFGUARD_TEST_ENV_LOOKUP';
    process.env[name] = 'set';
    try {
      assert.equal(envLookup()(name), 'set');
    } finally {
      delete process.env[name];
    }
    assert.equal(envLookup('', { odd: 7 } as unknown as Record<string, string>)('odd'), undefined);
  });

  it('flattenJson keeps a "__proto__" key as an ordinary entry', () => {
    const values = flattenJson('{"__proto__":{"Secret":"x"},"constructor":"y"}');
    assert.equal(values['__proto__:Secret'], 'x');
    assert.equal(values['constructor'], 'y');
    assert.equal(mapLookup(values)('__PROTO__:secret'), 'x');
  });

  it('never repeats the document in a JSON error', () => {
    for (const document of ['{"Admin":"Password=hunter2;","x":tru}', '{"Admin":"Password=hunter2;"}}', '{"Admin":"Password=hunter2;", 7}', '"Password=hunter2"']) {
      assert.throws(() => flattenJson(document), (e: unknown) => e instanceof HkdfGuardError && !e.message.includes('hunter2') && !e.message.includes('Password'), document);
    }
    assert.throws(() => flattenJson('{"a":1,}'), /^InvalidArgumentError: Invalid JSON at (position \d+|line \d+ column \d+)\.$/);
  });

  it('flattenJson flattens like .NET configuration, keeping numbers as written', () => {
    assert.deepEqual(flattenJson(`{
      "ConnectionStrings": { "Admin": "enc::v1::AAAA", "Reporting": "plain" },
      "Hosts": ["a", "b"],
      "Port": 8080, "Ratio": 1.50, "Big": 12345678901234567890, "Enabled": true, "Nothing": null,
      "Nested": { "Deeper": { "Leaf": "x" } }
    }`), {
      'ConnectionStrings:Admin': 'enc::v1::AAAA', 'ConnectionStrings:Reporting': 'plain',
      'Hosts:0': 'a', 'Hosts:1': 'b',
      Port: '8080', Ratio: '1.50', Big: '12345678901234567890', Enabled: 'true', Nothing: '',
      'Nested:Deeper:Leaf': 'x',
    });
  });

  it('flattenJson refuses invalid documents and case-only collisions', () => {
    for (const document of ['{"a":', '["a"]', '"text"']) {
      assert.throws(() => flattenJson(document), (e: unknown) => e instanceof HkdfGuardError && e.code === 'ERR_HKDFGUARD_INVALID_JSON');
    }
    assert.throws(() => flattenJson('{"Key":"a","KEY":"b"}'), DuplicateKeyError);
  });
});

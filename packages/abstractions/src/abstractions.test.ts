import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import {
  AuthenticationFailedError, CACHE_AAD_PREFIX, cacheAad, CONFIGURATION_PURPOSE_PREFIX, configurationAad, configurationPurpose,
  DEFAULT_MAX_REFRESH_FAILURES, HkdfGuardError, InvalidCacheNameError, InvalidConfigurationKeyError, InvalidServiceNameError,
  isValidServiceName, isZero, jsonErrorLocation, jsonKind, KeyNotFoundError, MAX_SERVICE_NAME_LENGTH, MAX_WRAPPED_KEY_BYTES, RefreshFailurePolicy,
  serviceNameProblem, validateServiceName, wipe,
} from './index.js';

const utf8 = (s: string) => new TextEncoder().encode(s);

describe('configurationPurpose', () => {
  it('prefixes and upper-cases the full key path', () => {
    assert.equal(configurationPurpose('ConnectionStrings:Admin'), 'HkdfGuard.EncryptedConfiguration:CONNECTIONSTRINGS:ADMIN');
  });

  it('matches the known vector every port must produce', () => {
    assert.deepEqual(configurationAad('ConnectionStrings:café'), utf8('HkdfGuard.EncryptedConfiguration:CONNECTIONSTRINGS:CAFé'));
  });

  it('shares a purpose between keys differing only in ASCII case', () => {
    for (const [a, b] of [['secret', 'SECRET'], ['Secret', 'secret'], ['Connection_Strings:Admin-1', 'connection_strings:ADMIN-1']] as const) {
      assert.equal(configurationPurpose(a), configurationPurpose(b));
    }
  });

  it('never shares one between non-ASCII case variants', () => {
    for (const [a, b] of [['café', 'CAFÉ'], ['ſecret', 'Secret'], ['ıd', 'ID'], ['straße', 'STRASSE']] as const) {
      assert.notEqual(configurationPurpose(a), configurationPurpose(b));
    }
  });

  it('upper-cases only ASCII letters, for every code point', () => {
    const prefix = `${CONFIGURATION_PURPOSE_PREFIX}:`;
    for (let cp = 0; cp <= 0x10ffff; cp++) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      const key = String.fromCodePoint(cp);
      const want = cp >= 0x61 && cp <= 0x7a ? String.fromCodePoint(cp - 0x20) : key;
      if (configurationPurpose(key) !== prefix + want) {
        assert.fail(`U+${cp.toString(16)}`);
      }
    }
  });

  it('accepts a surrogate pair and a long key', () => {
    assert.equal(configurationPurpose('Key\u{1F600}Tail'), `${CONFIGURATION_PURPOSE_PREFIX}:KEY\u{1F600}TAIL`);
    const long = Array.from({ length: 60 }, (_, i) => `Section${i}`).join(':');
    assert.deepEqual(configurationAad(long), utf8(configurationPurpose(long)));
  });

  it('rejects an empty key and unpaired surrogates', () => {
    for (const key of ['', 'Key\uD800Tail', 'Key\uDC00Tail', 'Key\uD800']) {
      assert.throws(() => configurationPurpose(key), InvalidConfigurationKeyError);
      assert.throws(() => configurationAad(key), InvalidConfigurationKeyError);
    }
  });
});

describe('cacheAad', () => {
  it('matches the known vector every port must produce', () => {
    assert.deepEqual(cacheAad('api-Key_1:café'), utf8('HkdfGuard.Cache:API-KEY_1:CAFé'));
    assert.equal(CACHE_AAD_PREFIX, 'HkdfGuard.Cache:');
  });

  it('ignores only ASCII case', () => {
    assert.deepEqual(cacheAad('item'), cacheAad('ITEM'));
    assert.notDeepEqual(cacheAad('café'), cacheAad('CAFÉ'));
    assert.notDeepEqual(cacheAad('item'), cacheAad('items'));
  });

  it('rejects an unpaired surrogate', () => {
    assert.throws(() => cacheAad('bad\uD800name'), InvalidCacheNameError);
  });
});

describe('service names', () => {
  it('accepts valid names, up to the limit', () => {
    for (const name of ['a', '7', 'my.service', 'com.example.Orders2', 'trailing.', 'a'.repeat(128)]) {
      assert.ok(isValidServiceName(name), name);
      validateServiceName(name);
    }
    assert.equal(MAX_SERVICE_NAME_LENGTH, 128);
  });

  it('rejects invalid names with the same reason as the other ports', () => {
    const cases: [string | null | undefined, string][] = [
      [null, 'required'], [undefined, 'required'], ['', 'required'],
      ['.service', "can't start with '.'"], ['.', "can't start with '.'"],
      ['my..service', "can't contain '..'"], ['my...service', "can't contain '..'"], ['service..', "can't contain '..'"],
      ['my-service', 'U+002D at position 2'], ['my service', 'U+0020 at position 2'], ['my_service', 'U+005F at position 2'],
      ['café', 'U+00E9 at position 3'], ['a/b', 'U+002F at position 1'], ['a\0b', 'U+0000 at position 1'],
      ['a'.repeat(129), 'at most 128 characters; this one is 129'],
    ];
    for (const [name, reason] of cases) {
      assert.ok(!isValidServiceName(name));
      assert.ok(serviceNameProblem(name)?.includes(reason), `${name}: ${serviceNameProblem(name)}`);
      assert.throws(() => validateServiceName(name), (e: unknown) => e instanceof InvalidServiceNameError && e.message.includes(reason));
    }
  });
});

describe('RefreshFailurePolicy', () => {
  it('defaults to failing closed after three failures', () => {
    assert.equal(DEFAULT_MAX_REFRESH_FAILURES, 3);
    assert.equal(RefreshFailurePolicy.default.maxFailures, 3);
    assert.ok(RefreshFailurePolicy.default.failsClosed);
    assert.equal(String(RefreshFailurePolicy.default), 'fail closed after 3 consecutive failures');
  });

  it('fails closed after a chosen count, of at least one', () => {
    assert.equal(RefreshFailurePolicy.failClosedAfter(5).toString(), 'fail closed after 5 consecutive failures');
    for (const n of [0, -1, 1.5, Number.NaN]) {
      assert.throws(() => RefreshFailurePolicy.failClosedAfter(n), (e: unknown) => e instanceof HkdfGuardError && e.code === 'ERR_HKDFGUARD_INVALID_REFRESH_FAILURE_POLICY');
    }
  });

  it('fails open only when asked', () => {
    const policy = RefreshFailurePolicy.failOpen();
    assert.equal(policy.maxFailures, undefined);
    assert.ok(!policy.failsClosed);
    assert.equal(policy.toString(), 'fail open (the last good key stays in use)');
  });
});

describe('memory and limits', () => {
  it('wipe zeroes every byte, and tolerates empty or missing buffers', () => {
    const buffer = new Uint8Array([1, 2, 3, 4, 5]);
    wipe(buffer);
    assert.deepEqual(buffer, new Uint8Array(5));
    wipe(new Uint8Array(0));
    wipe(undefined);
  });

  it('isZero sees any non-zero byte, including the last', () => {
    assert.ok(isZero(new Uint8Array(0)) && isZero(new Uint8Array(16)));
    const last = new Uint8Array(64);
    last[63] = 1;
    assert.ok(!isZero(last));
  });

  it('caps a wrapped key at 512 bytes', () => {
    assert.equal(MAX_WRAPPED_KEY_BYTES, 512);
  });
});

describe('errors', () => {
  it('carry stable codes and names, and their cause', () => {
    const cause = new Error('inner');
    const error = new KeyNotFoundError('No key is registered for version 9.', { cause });
    assert.ok(error instanceof HkdfGuardError && error instanceof Error);
    assert.equal(error.code, 'ERR_HKDFGUARD_KEY_NOT_FOUND');
    assert.equal(error.name, 'KeyNotFoundError');
    assert.equal(error.cause, cause);
    assert.equal(new AuthenticationFailedError().code, 'ERR_HKDFGUARD_AUTHENTICATION_FAILED');
  });
});

describe('JSON error helpers', () => {
  it('give a location without any of the document', () => {
    for (const document of ['{"a":"secret",}', '{"a":"secret"}}', '{"a":"secret" "b"}', '{"a":\n"secret",\n}']) {
      let caught: unknown;
      try { JSON.parse(document); } catch (error) { caught = error; }
      const location = jsonErrorLocation(caught);
      assert.match(location, /^ at (position \d+|line \d+ column \d+)$/, document);
      assert.ok(!location.includes('secret'));
    }
    assert.equal(jsonErrorLocation(new Error('Unexpected token "secret"')), '');
    assert.equal(jsonErrorLocation('not an error'), '');
  });

  it('name the kind of a value, never the value', () => {
    assert.deepEqual([null, [], 'x', 1, 1.5, true, {}].map(jsonKind),
      ['null', 'an array', 'a string', 'an integer', 'a number with a fraction', 'a boolean', 'an object']);
  });
});

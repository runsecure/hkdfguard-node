import { strict as assert } from 'node:assert';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { HkdfGuardError } from '@runsecure/hkdfguard-abstractions';
import { FakeKeyWrapper, RecordingFactory } from '@runsecure/hkdfguard-test-support';
import { buildKeyRing } from './build.js';
import {
  InvalidOptionsError, keyRingConfigFromOptions, keyRingOptionsFromJson, validateKeyRingOptions, type KeyRingOptions,
} from './options.js';

const valid = (): KeyRingOptions => ({ ServiceName: 'com.example.orders', KeyRefreshInterval: 60, EphemeralKeys: [1] });

function failures(change: Partial<KeyRingOptions>): string[] {
  return validateKeyRingOptions({ ...valid(), ...change });
}

function includesAll(list: string[], ...parts: string[]): boolean {
  return parts.every((part) => list.some((f) => f.includes(part)));
}

describe('validateKeyRingOptions', () => {
  it('passes valid options, at every limit', () => {
    assert.deepEqual(failures({ KeyFiles: [{ Version: 2, Path: '/etc/app/key.v2' }], EphemeralKeys: [3], MaxRefreshFailures: 10, EphemeralKeyRotationHours: 596, EphemeralKeyRetentionHours: 24 * 365 }), []);
    for (const interval of [1, 300]) assert.deepEqual(failures({ KeyRefreshInterval: interval }), []);
    assert.deepEqual(failures({ KeyRefreshInterval: undefined }), []);
    assert.deepEqual(failures({ DisableEphemeralKeyRotation: true }), []);
    assert.deepEqual(failures({ FailOpenOnRefreshFailure: true }), []);
  });

  it('requires a valid service name, naming the rule', () => {
    for (const name of [undefined, '', '   ']) assert.ok(includesAll(failures({ ServiceName: name }), 'ServiceName is invalid'));
    for (const [name, reason] of [['.service', "can't start with '.'"], ['my..service', "can't contain '..'"], ['my-service', 'U+002D'], ['a'.repeat(129), 'at most 128']]) {
      assert.ok(includesAll(failures({ ServiceName: name }), 'ServiceName is invalid: ', reason!), name);
    }
  });

  it('checks every range', () => {
    const cases: [Partial<KeyRingOptions>, string][] = [
      [{ KeyRefreshInterval: 0 }, 'KeyRefreshInterval must be between 1 and 300'], [{ KeyRefreshInterval: 301 }, 'KeyRefreshInterval must be between 1 and 300'],
      [{ MaxRefreshFailures: 0 }, 'MaxRefreshFailures must be at least 1'],
      [{ EphemeralKeyRotationHours: 0 }, 'EphemeralKeyRotationHours must be between 1 and 596'], [{ EphemeralKeyRotationHours: 597 }, 'EphemeralKeyRotationHours must be between 1 and 596'],
      [{ EphemeralKeyRotationHours: 1193 }, 'EphemeralKeyRotationHours must be between 1 and 596'],
      [{ EphemeralKeyRetentionHours: -1 }, 'EphemeralKeyRetentionHours must be at least 1'],
      [{ KeyFileMaxAgeDays: 0 }, 'KeyFileMaxAgeDays must be between 1 and 3650'], [{ KeyFileMaxAgeDays: 3651 }, 'KeyFileMaxAgeDays must be between 1 and 3650'],
    ];
    for (const [change, reason] of cases) assert.ok(includesAll(failures(change), reason), reason);
  });

  it('refuses contradictory settings', () => {
    assert.ok(includesAll(failures({ DisableEphemeralKeyRotation: true, EphemeralKeyRotationHours: 6 }), "DisableEphemeralKeyRotation and EphemeralKeyRotationHours can't both be set"));
    assert.ok(includesAll(failures({ FailOpenOnRefreshFailure: true, MaxRefreshFailures: 3 }), "FailOpenOnRefreshFailure and MaxRefreshFailures can't both be set"));
  });

  it('checks the keys', () => {
    assert.ok(includesAll(failures({ EphemeralKeys: [] }), 'At least one key file or ephemeral key is required'));
    assert.ok(includesAll(failures({ KeyFiles: [{ Version: 2, Path: ' ' }] }), 'KeyFiles version 2 is missing a path'));
    assert.ok(includesAll(failures({ KeyFiles: [{ Version: 1, Path: '/a' }, { Version: 2, Path: '/b' }, { Version: 2, Path: '/c' }] }),
      'Version 1 is registered more than once', 'Version 2 is registered more than once'));
  });

  it('refuses a key file above every ephemeral version unless rotation is disabled', () => {
    const layout: Partial<KeyRingOptions> = { KeyFiles: [{ Version: 3, Path: '/etc/app/key.v3' }], EphemeralKeys: [2] };
    assert.ok(includesAll(failures(layout), 'Key file version 3 is above every ephemeral version', 'or set DisableEphemeralKeyRotation'));
    assert.deepEqual(failures({ ...layout, DisableEphemeralKeyRotation: true }), []);
  });

  it('accepts a key-file age at both limits, also from appsettings.json', () => {
    for (const days of [1, 3650]) assert.deepEqual(failures({ KeyFileMaxAgeDays: days }), []);
    assert.equal(keyRingOptionsFromJson('{"HkdfGuard":{"keyFileMaxAgeDays":"180"}}').KeyFileMaxAgeDays, 180);
  });

  it('reports every failure at once', () => {
    assert.ok(includesAll(validateKeyRingOptions({ KeyRefreshInterval: 0 }), 'ServiceName is invalid', 'KeyRefreshInterval must be', 'At least one key file'));
  });
});

describe('keyRingConfigFromOptions', () => {
  it('carries every setting, converting retention hours to minutes', () => {
    const wrapper = new FakeKeyWrapper(), factory = new RecordingFactory();
    const config = keyRingConfigFromOptions({
      ServiceName: 'com.example.orders', KeyRefreshInterval: 30, MaxRefreshFailures: 5, EphemeralKeyRotationHours: 6,
      EphemeralKeyRetentionHours: 48, KeyFileMaxAgeDays: 90, KeyFiles: [{ Version: 1, Path: '/etc/app/key.v1' }], EphemeralKeys: [2],
    }, wrapper, factory);
    assert.equal(config.keyFileMaxAgeDays, 90);
    assert.equal(config.keyWrapper, wrapper);
    assert.equal(config.cryptoProviderFactory, factory);
    assert.equal(config.serviceName, 'com.example.orders');
    assert.equal(config.keyRefreshInterval, 30);
    assert.equal(config.refreshFailurePolicy?.maxFailures, 5);
    assert.equal(config.ephemeralKeyRotationHours, 6);
    assert.equal(config.ephemeralKeyRetentionMinutes, 48 * 60);
    assert.deepEqual(config.keyFiles, { 1: '/etc/app/key.v1' });
    assert.deepEqual(config.ephemeralKeys, [2]);
  });

  it('leaves unset settings at their defaults, and maps fail-open and disabled rotation', () => {
    const plain = keyRingConfigFromOptions({ ServiceName: 'svc', EphemeralKeys: [1] }, new FakeKeyWrapper(), new RecordingFactory());
    assert.equal(plain.refreshFailurePolicy, undefined);
    assert.equal(plain.ephemeralKeyRotationHours, undefined);
    assert.equal(plain.ephemeralKeyRetentionMinutes, undefined);
    assert.equal(plain.keyFileMaxAgeDays, undefined);
    const open = keyRingConfigFromOptions({ ServiceName: 'svc', EphemeralKeys: [1], FailOpenOnRefreshFailure: true, DisableEphemeralKeyRotation: true }, new FakeKeyWrapper(), new RecordingFactory());
    assert.ok(!open.refreshFailurePolicy?.failsClosed);
    assert.ok(open.disableEphemeralKeyRotation);
  });

  it('refuses invalid options, listing every failure', () => {
    assert.throws(() => keyRingConfigFromOptions({}, new FakeKeyWrapper(), new RecordingFactory()),
      (e: unknown) => e instanceof InvalidOptionsError && e.failures.length >= 2 && e.message.includes('ServiceName is invalid'));
  });

  it('reports an unset KeyRefreshInterval when the ring is built, as the other ports do', async () => {
    const config = keyRingConfigFromOptions({ ServiceName: 'svc', EphemeralKeys: [1] }, new FakeKeyWrapper(), new RecordingFactory());
    await assert.rejects(buildKeyRing(config), (e: unknown) => e instanceof HkdfGuardError && e.message.includes('keyRefreshInterval'));
  });
});

describe('keyRingOptionsFromJson', () => {
  it('builds a working ring from an appsettings.json section, the way .NET binds it', async () => {
    const keyFile = join(mkdtempSync(join(tmpdir(), 'hkdfguard-options-')), 'key.v1');
    writeFileSync(keyFile, 'wrapped');
    const document = JSON.stringify({
      Logging: { LogLevel: { Default: 'Information' } },
      security: {
        hkdfguard: {
          serviceName: 'com.example.orders', KeyRefreshInterval: '60', MAXREFRESHFAILURES: 4,
          KeyFiles: [{ version: 1, path: keyFile }], EphemeralKeys: { 0: '2' }, SomeSettingThisPortDoesNotKnow: true,
        },
      },
    });
    const options = keyRingOptionsFromJson(document, 'Security:HkdfGuard');
    assert.deepEqual(options, { ServiceName: 'com.example.orders', KeyRefreshInterval: 60, MaxRefreshFailures: 4, KeyFiles: [{ Version: 1, Path: keyFile }], EphemeralKeys: [2] });

    const factory = new RecordingFactory();
    const ring = await buildKeyRing(keyRingConfigFromOptions(options, new FakeKeyWrapper(), factory));
    try {
      assert.equal(ring.currentVersion, 2);
      assert.ok(ring.tryGet(1));
      assert.ok(factory.options.every((o) => o.expirySeconds === 60 && o.refreshFailurePolicy?.maxFailures === 4));
    } finally {
      await ring.close();
    }
  });

  it('reads booleans from strings, and the whole document for an empty section', () => {
    assert.deepEqual(keyRingOptionsFromJson('{"ServiceName":"svc","EphemeralKeys":[1],"FailOpenOnRefreshFailure":"True"}', ''),
      { ServiceName: 'svc', EphemeralKeys: [1], FailOpenOnRefreshFailure: true });
  });

  it('never repeats a value or the document in its errors', () => {
    const secret = 'Password=hunter2';
    for (const document of [
      `{"HkdfGuard":{"KeyRefreshInterval":"${secret}"}}`, `{"HkdfGuard":{"FailOpenOnRefreshFailure":"${secret}"}}`,
      `{"HkdfGuard":{"EphemeralKeys":["${secret}"]}}`, `{"HkdfGuard":{"KeyFiles":[{"Version":"${secret}","Path":"/k"}]}}`,
      `{"HkdfGuard":{"ServiceName":"${secret}"},}`, `{"ConnectionStrings":"${secret}" "HkdfGuard":{}}`,
    ]) {
      assert.throws(() => keyRingOptionsFromJson(document), (e: unknown) => e instanceof HkdfGuardError && !e.message.includes('hunter2'), document);
    }
    assert.throws(() => keyRingOptionsFromJson('{"HkdfGuard":{"KeyRefreshInterval":"sixty"}}'), /'HkdfGuard:KeyRefreshInterval' must be an integer, got a string\./);
    assert.throws(() => keyRingOptionsFromJson('{"HkdfGuard":{"KeyRefreshInterval":1.5}}'), /got a number with a fraction\./);
  });

  it('reports a missing section, bad JSON, or a value of the wrong type', () => {
    const cases: [string, string][] = [
      ['{"Other":{}}', 'HkdfGuard'], ['{"Security":{}}', 'Security:HkdfGuard'], ['{"HkdfGuard":', 'HkdfGuard'],
      ['{"Security":"x"}', 'Security:HkdfGuard'], ['{"HkdfGuard":{"KeyRefreshInterval":"sixty"}}', 'HkdfGuard'],
      ['{"HkdfGuard":{"FailOpenOnRefreshFailure":"maybe"}}', 'HkdfGuard'], ['{"HkdfGuard":{"EphemeralKeys":"1"}}', 'HkdfGuard'],
      ['{"HkdfGuard":{"ServiceName":7}}', 'HkdfGuard'], ['{"HkdfGuard":[]}', 'HkdfGuard'],
    ];
    for (const [document, section] of cases) {
      assert.throws(() => keyRingOptionsFromJson(document, section), (e: unknown) => e instanceof HkdfGuardError && e.code === 'ERR_HKDFGUARD_INVALID_OPTIONS_JSON', document);
    }
  });
});

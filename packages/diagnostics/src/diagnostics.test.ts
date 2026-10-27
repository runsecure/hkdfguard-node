import { strict as assert } from 'node:assert';
import { afterEach, describe, it } from 'node:test';
import { SpanStatusCode } from '@opentelemetry/api';
import {
  AttributeNames, CacheMetrics, EventNames, HkdfGuardLog, HkdfGuardTelemetry, LogKeys, MetricNames, recordException,
  type ComponentTelemetry, type Logger,
} from './index.js';
import { useMetricRecorder, useSpanRecorder } from '@runsecure/hkdfguard-test-support';

const allComponents: [string, ComponentTelemetry][] = Object.entries(HkdfGuardTelemetry);

function withSensitiveLogging(component: ComponentTelemetry, enabled: boolean): () => void {
  const original = component.enableSensitiveLogging;
  component.enableSensitiveLogging = enabled;
  return () => { component.enableSensitiveLogging = original; };
}

describe('names', () => {
  it('match the other ports exactly', () => {
    assert.equal(AttributeNames.operationName, 'hkdfguard.operation.name');
    assert.equal(EventNames.sensitiveOperation, 'hkdfguard.sensitive_operation');
    assert.equal(MetricNames.cacheOperations, 'hkdfguard.cache.operations');
    assert.deepEqual(allComponents.map(([, c]) => c.sourceName), [
      'HkdfGuard', 'HkdfGuard.Cache', 'HkdfGuard.DataEncryptionKey', 'HkdfGuard.EncryptedConfiguration',
      'HkdfGuard.CryptoProvider.AesGcm256', 'HkdfGuard.KeyWrapping.V1',
    ]);
  });
});

describe('ComponentTelemetry', () => {
  let recorder: ReturnType<typeof useSpanRecorder> | undefined;
  afterEach(async () => { await recorder?.dispose(); recorder = undefined; });

  for (const [key, component] of allComponents) {
    it(`${key}: spans carry the component's scope name`, () => {
      recorder = useSpanRecorder();
      component.withSpan('test-span', () => undefined);
      assert.equal(recorder.spans()[0]?.instrumentationScope.name, component.sourceName);
    });

    it(`${key}: a thrown error is recorded, marks the span errored, and is rethrown`, () => {
      recorder = useSpanRecorder();
      assert.throws(() => component.withSpan('test-span', () => { throw new Error('boom'); }), /boom/);
      const span = recorder.spans()[0]!;
      assert.equal(span.status.code, SpanStatusCode.ERROR);
      assert.equal(span.status.message, 'boom');
      assert.ok(span.events.some((e) => e.name === 'exception'));
    });

    it(`${key}: a rejected promise is recorded too, and the span ends when it settles`, async () => {
      recorder = useSpanRecorder();
      await assert.rejects(component.withSpan('test-span', async () => { throw new Error('later'); }), /later/);
      assert.equal(recorder.spans()[0]?.status.code, SpanStatusCode.ERROR);
      assert.equal(await component.withSpan('ok', async () => 42), 42);
      assert.equal(recorder.spans().length, 2);
    });

    it(`${key}: sensitive operations are logged only while enabled`, () => {
      recorder = useSpanRecorder();
      let restore = withSensitiveLogging(component, false);
      component.withSpan('off', (span) => component.logSensitiveOperation(span, 'test-op', { key: 'value' }));
      restore();
      restore = withSensitiveLogging(component, true);
      component.withSpan('on', (span) => component.logSensitiveOperation(span, 'test-op', { [AttributeNames.name]: 'item' }));
      component.logSensitiveOperation(undefined, 'test-op');
      restore();

      const [off, on] = recorder.spans();
      assert.equal(off?.events.length, 0);
      assert.equal(on?.events.length, 1);
      assert.equal(on?.events[0]?.name, EventNames.sensitiveOperation);
      assert.equal(on?.events[0]?.attributes?.[AttributeNames.operationName], 'test-op');
      assert.equal(on?.events[0]?.attributes?.[AttributeNames.name], 'item');
    });
  }

  it('recordException with no span does nothing', () => {
    assert.doesNotThrow(() => recordException(undefined, new Error('boom')));
  });

  it('Root shares its flag with Cache, DataProtection and EncryptedConfiguration', () => {
    const { root, cache, dataProtection, encryptedConfiguration } = HkdfGuardTelemetry;
    const restore = withSensitiveLogging(root, true);
    try {
      assert.ok(cache.enableSensitiveLogging && dataProtection.enableSensitiveLogging && encryptedConfiguration.enableSensitiveLogging);
      cache.enableSensitiveLogging = false;
      assert.ok(!root.enableSensitiveLogging && !dataProtection.enableSensitiveLogging && !encryptedConfiguration.enableSensitiveLogging);
    } finally {
      restore();
    }
  });

  it('the crypto provider and key wrapping flags are independent of Root and each other', () => {
    const { root, cryptoProviderAesGcm256, keyWrapping } = HkdfGuardTelemetry;
    const restores = [withSensitiveLogging(root, true), withSensitiveLogging(cryptoProviderAesGcm256, false), withSensitiveLogging(keyWrapping, false)];
    try {
      assert.ok(!cryptoProviderAesGcm256.enableSensitiveLogging && !keyWrapping.enableSensitiveLogging);
      cryptoProviderAesGcm256.enableSensitiveLogging = true;
      assert.ok(!keyWrapping.enableSensitiveLogging);
    } finally {
      restores.reverse().forEach((restore) => restore());
    }
  });
});

describe('CacheMetrics', () => {
  it('counts operations on the Cache meter, with their attributes', async () => {
    const recorder = useMetricRecorder();
    try {
      CacheMetrics.operations.add(1, { [AttributeNames.result]: 'success' });
      const points = await recorder.collect();
      assert.equal(points.get(`HkdfGuard.Cache|${MetricNames.cacheOperations}|{operation}|${AttributeNames.result}=success`), 1);
    } finally {
      await recorder.dispose();
    }
  });
});

describe('HkdfGuardLog', () => {
  type Entry = { level: string; message: string; attributes: Record<string, unknown> };
  function capture(): { logger: Logger; entries: Entry[] } {
    const entries: Entry[] = [];
    const at = (level: string) => (message: string, attributes: Record<string, unknown>) => { entries.push({ level, message, attributes }); };
    return { logger: { debug: at('debug'), info: at('info'), warn: at('warn'), error: at('error') }, entries };
  }

  const cases: [string, (l: Logger) => void, string, number, string, boolean][] = [
    ['sensitiveOperationLogged', (l) => HkdfGuardLog.sensitiveOperationLogged(l, 'hkdfguard.cache.add', 'item'), 'debug', 1, 'hkdfguard.cache.add completed for item.', false],
    ['operationFailed', (l) => HkdfGuardLog.operationFailed(l, 'hkdfguard.cache.add', new Error('boom')), 'error', 2, 'hkdfguard.cache.add failed.', true],
    ['keyRefreshFailed', (l) => HkdfGuardLog.keyRefreshFailed(l, 2, 'fail closed after 3 consecutive failures', new Error('KEK')), 'error', 3, 'Background key refresh failed (2 consecutive). Policy: fail closed after 3 consecutive failures.', true],
    ['keyAccessSuspended', (l) => HkdfGuardLog.keyAccessSuspended(l, 3), 'error', 4, 'Key access suspended after 3 consecutive failed refreshes; the key has been zeroed and every operation under it fails until a refresh succeeds.', false],
    ['keyAccessResumed', (l) => HkdfGuardLog.keyAccessResumed(l, 4), 'info', 5, 'Key access resumed: a background refresh succeeded after 4 consecutive failures.', false],
    ['ephemeralKeyRotated', (l) => HkdfGuardLog.ephemeralKeyRotated(l, 8), 'info', 6, 'Ephemeral key rotated: version 8 is now current.', false],
    ['ephemeralKeyRotationFailed', (l) => HkdfGuardLog.ephemeralKeyRotationFailed(l, 7, new Error('KEK')), 'error', 7, 'Ephemeral key rotation failed; version 7 stays current until the next attempt.', true],
    ['ephemeralKeyRetired', (l) => HkdfGuardLog.ephemeralKeyRetired(l, 5), 'info', 8, 'Ephemeral key retired: version 5 has been removed and its key zeroed; values encrypted under it no longer decrypt.', false],
    ['ephemeralKeyRetirementFailed', (l) => HkdfGuardLog.ephemeralKeyRetirementFailed(l, 5, new Error('x')), 'error', 9, 'Ephemeral key version 5 was removed from the ring, but disposing it failed.', true],
    ['encryptionBudgetWarning', (l) => HkdfGuardLog.encryptionBudgetWarning(l, 100, 200), 'warn', 10, 'This key has performed 100 encryptions of its 200 AES-GCM limit; rotate it before the limit, when it stops encrypting.', false],
    ['keyFileAgeWarning', (l) => HkdfGuardLog.keyFileAgeWarning(l, 3, '/etc/app/key.v3', new Date(Date.UTC(2027, 0, 2))), 'warn', 11, "Key file '/etc/app/key.v3' (version 3) stops encrypting at 2027-01-02T00:00:00.000Z, when it reaches its maximum age; deploy a new key file at a higher version before then.", false],
    ['keyFileExpired', (l) => HkdfGuardLog.keyFileExpired(l, 3, '/etc/app/key.v3'), 'error', 12, "Key file '/etc/app/key.v3' (version 3) has passed its maximum age and no longer encrypts; values under it still decrypt. Deploy a new key file at a higher version.", false],
  ];

  for (const [name, call, level, eventId, message, carriesError] of cases) {
    it(`${name} writes event ${eventId} at ${level}`, () => {
      const { logger, entries } = capture();
      call(logger);
      assert.equal(entries.length, 1);
      const [entry] = entries;
      assert.equal(entry?.level, level);
      assert.equal(entry?.message, message);
      assert.equal(entry?.attributes[LogKeys.eventId], eventId);
      assert.equal(entry?.attributes[LogKeys.error] !== undefined, carriesError);
    });
  }

  it('marks critical entries, which go to error', () => {
    const { logger, entries } = capture();
    HkdfGuardLog.keyAccessSuspended(logger, 3);
    assert.equal(entries[0]?.attributes[LogKeys.level], 'critical');
  });

  it('writes nothing without a logger, or without the level', () => {
    for (const [name, call] of cases) {
      assert.doesNotThrow(() => call(undefined as unknown as Logger), name);
      assert.doesNotThrow(() => call({}), name);
    }
  });

  it('accepts console', () => {
    const logger: Logger = console;
    assert.ok(logger.warn);
  });
});

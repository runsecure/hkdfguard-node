// The port of the Python suite's test_composite_value_provider.py, itself the port of .NET's
// CompositeValueProviderTests. Values are UTF-8 bytes, so .NET's TryGetChar test is the tryGetBytes
// test here.
import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';
import { fromUtf8, O_DIAERESIS, SpyValueProvider } from './core.test-support.js';
import { ConfigurationKeyError, ConfigurationKeyErrorCode } from './errors.js';
import { CompositeValueProvider, ValueStatus, type ValueProvider } from './valueproviders.js';

const LOW_ONLY = 'l' + O_DIAERESIS;

const newHigh = () => new SpyValueProvider({ Shared: 'high', HighOnly: 'h' });
const newLow = () => new SpyValueProvider({ Shared: 'low', LowOnly: LOW_ONLY });

describe('CompositeValueProvider', () => {
  it('tryGetValue returns the value from the first provider that has the key', async () => {
    const high = newHigh();
    const low = newLow();
    const provider = new CompositeValueProvider(high, low);

    assert.deepEqual(await provider.tryGetValue('Shared'), { status: ValueStatus.found, value: 'high' });
    assert.deepEqual(await provider.tryGetValue('LowOnly'), { status: ValueStatus.found, value: LOW_ONLY });
    assert.deepEqual(await provider.tryGetValue('Missing'), { status: ValueStatus.notFound, value: undefined });

    assert.deepEqual(high.tryGetValueCalls, ['Shared', 'LowOnly', 'Missing']);
    assert.deepEqual(low.tryGetValueCalls, ['LowOnly', 'Missing']);
  });

  it('tryGetBytes writes the value from the first provider that has the key', async () => {
    const high = newHigh();
    const low = newLow();
    const provider = new CompositeValueProvider(high, low);
    const destination = new Uint8Array(8);

    const shared = await provider.tryGetBytes('Shared', destination);
    assert.equal(shared.status, ValueStatus.found);
    assert.equal(fromUtf8(destination.subarray(0, shared.written)), 'high');
    const lowOnly = await provider.tryGetBytes('LowOnly', destination);
    assert.equal(lowOnly.status, ValueStatus.found);
    assert.equal(fromUtf8(destination.subarray(0, lowOnly.written)), LOW_ONLY);
    assert.deepEqual(await provider.tryGetBytes('Missing', destination), { status: ValueStatus.notFound, written: 0 });
    assert.deepEqual(low.tryGetBytesCalls, ['LowOnly', 'Missing']);
  });

  it('DestinationTooSmall in the first provider does not fall through', async () => {
    const high = newHigh();
    const low = newLow();
    const provider = new CompositeValueProvider(high, low);

    assert.deepEqual(await provider.tryGetBytes('Shared', new Uint8Array(2)), { status: ValueStatus.destinationTooSmall, written: 0 });
    assert.deepEqual(low.tryGetBytesCalls, []);
  });

  it("a provider's error propagates", async () => {
    const low = newLow();
    const failing = new SpyValueProvider({}, { throwOnLookup: new ConfigurationKeyError('Shared', ConfigurationKeyErrorCode.valueUnstable) });
    const provider = new CompositeValueProvider(failing, low);

    await assert.rejects(provider.tryGetBytes('Shared', new Uint8Array(8)), ConfigurationKeyError);
    assert.deepEqual(low.tryGetBytesCalls, []);
  });

  it('the providers are in priority order and copied', () => {
    const high = newHigh();
    const low = newLow();
    const providers: ValueProvider[] = [high, low];
    const provider = new CompositeValueProvider(...providers);

    providers.length = 0;

    assert.equal(provider.providers.length, 2);
    assert.equal(provider.providers[0], high);
    assert.equal(provider.providers[1], low);
    assert.ok(Object.isFrozen(provider.providers));
  });

  it('the constructor with invalid providers throws', () => {
    for (const missing of [undefined, null]) {
      assert.throws(() => new CompositeValueProvider(missing as unknown as ValueProvider), TypeError);
    }
    assert.throws(
      () => new CompositeValueProvider(),
      (error) => error instanceof InvalidArgumentError && /At least one/.test(error.message),
    );
    // .NET throws ArgumentException for a null provider; Node reports it with TypeError.
    assert.throws(() => new CompositeValueProvider(newHigh(), null as unknown as ValueProvider), TypeError);
  });
});

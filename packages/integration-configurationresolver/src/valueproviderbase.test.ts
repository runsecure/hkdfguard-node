// The port of the Python suite's test_value_provider_base.py: .NET's ValueProviderBaseScenarioTests,
// and ProviderScenarioTests' sizing test over a map-backed ValueProviderBase in place of
// DictionaryValueProvider. ValueProviderBase builds only tryGetValue on a subclass's bytes - there is
// no TryGetChar or TryGetCharCount - so the tests of those are not ported.
import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { CAFE, createTemplateResolver, DictValueProvider, E_ACUTE, rejection, utf8, writeValue } from './core.test-support.js';
import { ConfigurationKeyError, ConfigurationKeyErrorCode } from './errors.js';
import { DefaultToken } from './tokens.js';
import { ValueProviderBase, ValueStatus, type BytesResult, type ValueProvider, type ValueResult } from './valueproviders.js';

const LARGE = 'x'.repeat(600);

/**
 * A byte-based provider whose reported sizes and actual contents are scripted per call. An undefined
 * count, or an undefined read, is a key not found.
 */
class ScriptedBytesProvider extends ValueProviderBase {
  #countCalls = 0;
  readCalls = 0;

  constructor(private readonly counts: (number | undefined)[], private readonly reads: (string | undefined)[]) {
    super();
  }

  static fixed(value: string): ScriptedBytesProvider {
    const count = utf8(value).length;
    return new ScriptedBytesProvider(new Array(4).fill(count), new Array(4).fill(value));
  }

  static missing(): ScriptedBytesProvider {
    return new ScriptedBytesProvider([undefined, undefined, undefined], []);
  }

  async tryGetBytes(_key: string, destination: Uint8Array): Promise<BytesResult> {
    const value = this.reads[this.readCalls];
    this.readCalls++;
    if (value === undefined) return { status: ValueStatus.notFound, written: 0 };
    return writeValue(utf8(value), destination);
  }

  protected async tryGetByteCount(): Promise<number | undefined> {
    const count = this.counts[this.#countCalls % this.counts.length];
    this.#countCalls++;
    return count;
  }
}

/** A provider that throws the same {@link ConfigurationKeyError} for every lookup. */
class ThrowingProvider implements ValueProvider {
  readonly exception: ConfigurationKeyError;

  constructor(sourceIndex: number | undefined) {
    this.exception = new ConfigurationKeyError('Key', ConfigurationKeyErrorCode.valueUnstable, sourceIndex);
  }

  async tryGetValue(): Promise<ValueResult> {
    throw this.exception;
  }

  async tryGetBytes(): Promise<BytesResult> {
    throw this.exception;
  }
}

function assertReportedAt(error: unknown, provider: ThrowingProvider, sourceIndex: number): void {
  assert.ok(error instanceof ConfigurationKeyError);
  assert.equal(error.key, 'Key');
  assert.equal(error.error, ConfigurationKeyErrorCode.valueUnstable);
  assert.equal(error.sourceIndex, sourceIndex);
  assert.ok(!error.message.includes('Key'));
  assert.equal(error.cause, provider.exception);
  assert.equal(provider.exception.sourceIndex, undefined);
}

describe('ValueProviderBase', () => {
  describe('a bytes source is read as a string', () => {
    for (const [name, value] of [['cafe', CAFE], ['empty', ''], ['large', LARGE]] as const) {
      it(name, async () => {
        const provider = ScriptedBytesProvider.fixed(value);

        assert.deepEqual(await provider.tryGetValue('Key'), { status: ValueStatus.found, value });
      });
    }
  });

  it("a bytes source's missing key is not found", async () => {
    const provider = ScriptedBytesProvider.missing();

    assert.deepEqual(await provider.tryGetValue('Key'), { status: ValueStatus.notFound, value: undefined });
    assert.equal(provider.readCalls, 0);
  });

  it('a bytes source removed between sizing and reading is not found', async () => {
    const provider = new ScriptedBytesProvider([4], [undefined]);

    assert.deepEqual(await provider.tryGetValue('Key'), { status: ValueStatus.notFound, value: undefined });
  });

  describe('a bytes source that changes size is read again', () => {
    const cases: [number, string][] = [
      [3, 'abcdef'],
      [3, 'y'.repeat(600)],
      [600, 'y'.repeat(700)],
      [600, 'abcdef'],
    ];
    for (const [firstCount, second] of cases) {
      it(`${firstCount} then ${second.length}`, async () => {
        const tooLarge = 'z'.repeat(firstCount + 1);
        const provider = new ScriptedBytesProvider([firstCount, utf8(second).length], [tooLarge, second]);

        assert.deepEqual(await provider.tryGetValue('Key'), { status: ValueStatus.found, value: second });
        assert.equal(provider.readCalls, 2);
      });
    }
  });

  it('a bytes source that keeps growing throws', async () => {
    const provider = new ScriptedBytesProvider([1, 1, 1], ['ab', 'ab', 'ab']);

    const error = await rejection(provider.tryGetValue('Key'));

    assert.ok(error instanceof ConfigurationKeyError);
    assert.equal(error.key, 'Key');
    assert.equal(error.error, ConfigurationKeyErrorCode.valueUnstable);
    assert.equal(error.sourceIndex, undefined);
    assert.equal(error.code, 'ERR_HKDFGUARD_CONFIGURATION_KEY');
    assert.equal(error.message, 'The value for a configuration key could not be resolved (ValueUnstable).');
    assert.equal(provider.readCalls, 3);
  });

  it("a provider's key error is reported at its position in the template", async () => {
    const provider = new ThrowingProvider(undefined);
    const resolver = createTemplateResolver(new DefaultToken(), provider, '${Key}');
    const source = `${E_ACUTE} \${Key}`;

    // The acute e is 2 UTF-8 bytes, so the item is at byte 3 whether the source is a string or bytes;
    // .NET's char index here is 2.
    for (const form of [source, utf8(source)]) {
      const error = await rejection(resolver.resolve(form, new Uint8Array(16)));

      assertReportedAt(error, provider, 3);
    }
  });

  it("a provider's key error with a position is not wrapped", async () => {
    const provider = new ThrowingProvider(7);
    const resolver = createTemplateResolver(new DefaultToken(), provider, '${Key}');

    for (const form of ['${Key}', utf8('${Key}')]) {
      const error = await rejection(resolver.resolve(form, new Uint8Array(16)));

      assert.equal(error, provider.exception);
    }
  });

  it("the base's sizing methods report the required buffer size", async () => {
    const provider = new DictValueProvider({ Key: CAFE });

    assert.equal(await provider.findByteCount('Key'), 5);
    assert.equal(await provider.findByteCount('Missing'), undefined);
    assert.deepEqual(await provider.tryGetValue('Key'), { status: ValueStatus.found, value: CAFE });
    assert.deepEqual(await provider.tryGetValue('Missing'), { status: ValueStatus.notFound, value: undefined });
  });
});

// The port of the Python suite's test_resolver.py, itself the port of .NET's
// ConfigurationItemResolverTests. Each char/byte pair of .NET tests is one test that resolves the
// source as a string and as UTF-8 bytes, and a source index is always a byte index into the UTF-8
// source.
import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';
import {
  assertKeyError, assertZeroed, both, CAFE, CHECK_MARK, CustomToken, DictValueProvider, E_ACUTE, filled, I_DIAERESIS,
  LEFT_GUILLEMET, ReadingResolver, rejection, resolveToString, RIGHT_GUILLEMET, SpyValueProvider, U_DIAERESIS, utf8,
} from './core.test-support.js';
import { ConfigurationKeyError, ConfigurationKeyErrorCode, DestinationTooSmallError } from './errors.js';
import { ConfigurationItemReader } from './reader.js';
import { ConfigurationItemResolver, type ConfigurationResolver } from './resolver.js';
import { DefaultToken } from './tokens.js';
import type { ValueProvider } from './valueproviders.js';

const VALUES: Record<string, string> = {
  Name: 'Ada',
  'value 1': 'ONE',
  value2: 'TWO',
  value3: 'THREE',
  'Db:Password': 'p@ss',
  Empty: '',
  Unicode: CAFE,
};

const NESTED: Record<string, string> = {
  Url: 'https://${Host}:${Port}/',
  Host: '${Region}.db.internal',
  Region: 'eu',
  Port: '5432',
  Self: 'a${Self}',
  Ping: '${Pong}',
  Pong: '${Ping}',
  Escaped: '$${Region}',
  Missing: '[${ Nope }]',
  Shrinks: '${Region}!',
};

const NESTED_KEYS = Object.values(NESTED);

const RESOLVED_TEXT: [string, string][] = [
  ['', ''],
  ['plain text', 'plain text'],
  ['${Name}', 'Ada'],
  ['Hello ${Name}!', 'Hello Ada!'],
  ['${ Name }', 'Ada'],
  ['${\tName\n}', 'Ada'],
  ['${Name}${Name}', 'AdaAda'],
  ['${Db:Password}', 'p@ss'],
  ['[${Empty}]', '[]'],
  [`${U_DIAERESIS}n${I_DIAERESIS} \${Unicode} ${CHECK_MARK}`, `${U_DIAERESIS}n${I_DIAERESIS} ${CAFE} ${CHECK_MARK}`],
  [
    'this is my ${ value 1 }, and this is ${value2} and lastly this is ${value3}',
    'this is my ONE, and this is TWO and lastly this is THREE',
  ],
];

const UNCHANGED_TEXT = ['${}', '${ }', 'start ${Name', '} stray end }', '$ {Name} $Name {Name}'];

const PARTIALLY_RESOLVED_TEXT: [string, string][] = [
  ['${Name}} extra', 'Ada} extra'],
  ['${Name} then ${unterminated', 'Ada then ${unterminated'],
  ['${} then ${Name}', '${} then Ada'],
];

const newResolver = () => new ReadingResolver(new DefaultToken(), [new DictValueProvider(VALUES)]);

const createNested = (depth: number) =>
  new ReadingResolver(new DefaultToken(), [new DictValueProvider(NESTED)], { maxResolutionDepth: depth, alsoAllowed: NESTED_KEYS });

function createAllowListed(): { reader: ConfigurationItemReader; resolver: ConfigurationItemResolver; spy: SpyValueProvider } {
  const reader = new ConfigurationItemReader(new DefaultToken());
  const spy = new SpyValueProvider(VALUES);
  return { reader, resolver: new ConfigurationItemResolver(new DefaultToken(), reader, [spy]), spy };
}

async function assertResolves(resolver: ConfigurationResolver, source: string, expected: string): Promise<void> {
  for (const form of both(source)) {
    assert.equal(await resolveToString(resolver, form), expected);
  }
}

const bytesOf = (s: string) => Array.from(utf8(s));

describe('ConfigurationItemResolver', () => {
  describe('resolve replaces items', () => {
    for (const [source, expected] of [...RESOLVED_TEXT, ...PARTIALLY_RESOLVED_TEXT]) {
      it(JSON.stringify(source), async () => {
        await assertResolves(newResolver(), source, expected);
      });
    }
  });

  describe('resolve copies text without complete items unchanged', () => {
    for (const source of UNCHANGED_TEXT) {
      it(JSON.stringify(source), async () => {
        await assertResolves(newResolver(), source, source);
      });
    }
  });

  describe('resolve returns the count and leaves the rest of the destination untouched', () => {
    const cases: [string, number, number[]][] = [
      ['x=${Name}', 16, [...bytesOf('x=Ada'), ...bytesOf('#'.repeat(11))]],
      ['${Unicode}', 8, [...bytesOf(CAFE), ...bytesOf('###')]],
    ];
    for (const [source, destinationLength, expected] of cases) {
      it(JSON.stringify(source), async () => {
        for (const form of both(source)) {
          const destination = filled(destinationLength);

          const written = await newResolver().resolve(form, destination);

          assert.equal(written, 5);
          assert.deepEqual(Array.from(destination), expected);
        }
      });
    }
  });

  describe('resolve succeeds when the destination is exactly the resolved length', () => {
    const cases: [string, number, string][] = [
      ['x=${Name}', 5, 'x=Ada'],
      // The acute e is 1 character but 2 UTF-8 bytes.
      ['x=${Unicode}', 7, 'x=' + CAFE],
    ];
    for (const [source, destinationLength, expected] of cases) {
      it(JSON.stringify(source), async () => {
        for (const form of both(source)) {
          assert.equal(await resolveToString(newResolver(), form, destinationLength), expected);
        }
      });
    }
  });

  it('resolve of an empty source into an empty destination writes nothing', async () => {
    const resolver = newResolver();

    assert.equal(await resolver.resolve('', new Uint8Array(0)), 0);
    assert.equal(await resolver.resolve(new Uint8Array(0), new Uint8Array(0)), 0);
  });

  describe("resolve uses the token's start and end sequences", () => {
    const cases: [string, string, string, string][] = [
      ['{{', '}}', '{{Name}} and ${Name}', 'Ada and ${Name}'],
      ['{{', '}}', '{{ Name }}{{Name}', 'Ada{{Name}'],
      ['<%', '%>', '<%Db:Password%>', 'p@ss'],
      [LEFT_GUILLEMET, RIGHT_GUILLEMET, `${LEFT_GUILLEMET} Unicode ${RIGHT_GUILLEMET} and ${LEFT_GUILLEMET}Name${RIGHT_GUILLEMET}`, `${CAFE} and Ada`],
    ];
    for (const [start, end, source, expected] of cases) {
      it(JSON.stringify(source), async () => {
        const resolver = new ReadingResolver(new CustomToken(start, end), [new DictValueProvider(VALUES)]);

        await assertResolves(resolver, source, expected);
      });
    }
  });

  describe('resolve writes values directly into the destination', () => {
    const cases: [string, string, string[], number[]][] = [
      ['ab-${Name}-${value2}', 'ab-Ada-TWO', ['Name', 'value2'], [32 - 3, 32 - 7]],
      // The u with diaeresis is 2 UTF-8 bytes, so the value is written after 3 bytes.
      [`${U_DIAERESIS}-\${Unicode}`, `${U_DIAERESIS}-${CAFE}`, ['Unicode'], [32 - 3]],
    ];
    for (const [source, expected, keys, bufferLengths] of cases) {
      it(JSON.stringify(source), async () => {
        for (const form of both(source)) {
          const spy = new SpyValueProvider(VALUES);
          const resolver = new ReadingResolver(new DefaultToken(), [spy]);

          assert.equal(await resolveToString(resolver, form, 32), expected);

          assert.deepEqual(spy.tryGetBytesCalls, keys);
          assert.deepEqual(spy.bufferLengths, bufferLengths);
          assert.deepEqual(spy.tryGetValueCalls, []);
        }
      });
    }
  });

  describe('resolve never reads values as strings, even when it fails', () => {
    const cases: [string, string, number][] = [
      ['${Name} ${missing}', 'missing', 64],
      ['${Name} ${value2}', 'value2', 5],
    ];
    for (const [source, failingKey, destinationLength] of cases) {
      it(JSON.stringify(source), async () => {
        for (const form of both(source)) {
          const spy = new SpyValueProvider(VALUES);
          const resolver = new ReadingResolver(new DefaultToken(), [spy]);

          await assert.rejects(
            resolveToString(resolver, form, destinationLength),
            (error) => error instanceof ConfigurationKeyError || error instanceof DestinationTooSmallError,
          );

          assert.deepEqual(spy.tryGetBytesCalls, ['Name', failingKey]);
          assert.deepEqual(spy.tryGetValueCalls, []);
        }
      });
    }
  });

  it('constructor with an undefined token throws', () => {
    assert.throws(
      () => new ConfigurationItemResolver(undefined as never, new ConfigurationItemReader(new DefaultToken()), [new DictValueProvider(VALUES)]),
      { name: 'TypeError', message: /token/ },
    );
  });

  it('constructor with an undefined reader throws', () => {
    assert.throws(
      () => new ConfigurationItemResolver(new DefaultToken(), undefined as never, [new DictValueProvider(VALUES)]),
      { name: 'TypeError', message: /reader/ },
    );
  });

  it('constructor with undefined value providers throws', () => {
    assert.throws(
      () => new ConfigurationItemResolver(new DefaultToken(), new ConfigurationItemReader(new DefaultToken()), undefined as never),
      { name: 'TypeError', message: /valueProviders/ },
    );
  });

  it('constructor with no value providers throws', () => {
    assert.throws(
      () => new ConfigurationItemResolver(new DefaultToken(), new ConfigurationItemReader(new DefaultToken()), []),
      (error) => error instanceof InvalidArgumentError && /value provider/.test(error.message),
    );
  });

  it('constructor with undefined among the value providers throws', () => {
    // .NET throws ArgumentException; Node reports an undefined or null, wherever it is, with TypeError.
    for (const missing of [undefined, null]) {
      assert.throws(
        () => new ConfigurationItemResolver(
          new DefaultToken(),
          new ConfigurationItemReader(new DefaultToken()),
          [new DictValueProvider(VALUES), missing as unknown as ValueProvider],
        ),
        { name: 'TypeError', message: /value providers/ },
      );
    }
  });

  it('resolve with several providers uses the first provider that has the key', async () => {
    for (const form of both('${Name} ${Db:Password}')) {
      const high = new SpyValueProvider({ Name: 'Grace' });
      const low = new SpyValueProvider(VALUES);
      const resolver = new ReadingResolver(new DefaultToken(), [high, low]);

      assert.equal(await resolveToString(resolver, form), 'Grace p@ss');

      assert.deepEqual(high.tryGetBytesCalls, ['Name', 'Db:Password']);
      assert.deepEqual(low.tryGetBytesCalls, ['Db:Password']);
    }
  });

  it('resolve with several providers, none of which has the key, throws NotFound', async () => {
    const resolver = new ReadingResolver(new DefaultToken(), [new DictValueProvider({ Name: 'Grace' }), new DictValueProvider(VALUES)]);

    for (const form of both('${Name} ${missing}')) {
      const error = await rejection(resolveToString(resolver, form));

      assertKeyError(error, 'missing', ConfigurationKeyErrorCode.notFound, 8);
    }
  });

  it('resolve with several providers: a value too large in the first provider does not fall through', async () => {
    const high = new DictValueProvider({ Name: 'Grace Hopper' });
    const low = new SpyValueProvider(VALUES);
    const resolver = new ReadingResolver(new DefaultToken(), [high, low]);

    for (const form of both('${Name}')) {
      await assert.rejects(resolveToString(resolver, form, 5), DestinationTooSmallError);
    }

    assert.deepEqual(low.tryGetBytesCalls, []);
  });

  describe('resolve with ignoreUnresolvablePlaceholders copies missing items unchanged', () => {
    const cases: [string, string][] = [
      ['${missing}', '${missing}'],
      ['a ${ missing } b ${Name}', 'a ${ missing } b Ada'],
      ['${Name}${missing}${Name}', 'Ada${missing}Ada'],
      [`${E_ACUTE} \${missing} \${Unicode}`, `${E_ACUTE} \${missing} ${CAFE}`],
    ];
    for (const [source, expected] of cases) {
      it(JSON.stringify(source), async () => {
        const resolver = new ReadingResolver(new DefaultToken(), [new DictValueProvider(VALUES)], { ignoreUnresolvablePlaceholders: true });

        await assertResolves(resolver, source, expected);
      });
    }
  });

  it("resolve with ignoreUnresolvablePlaceholders copies the token's own sequences", async () => {
    const resolver = new ReadingResolver(new CustomToken('{{', '}}'), [new DictValueProvider(VALUES)], { ignoreUnresolvablePlaceholders: true });

    await assertResolves(resolver, '{{Name}} {{ missing }}', 'Ada {{ missing }}');
  });

  it('resolve with ignoreUnresolvablePlaceholders: a key not read by the reader still throws', async () => {
    const reader = new ConfigurationItemReader(new DefaultToken());
    const spy = new SpyValueProvider(VALUES);
    const resolver = new ConfigurationItemResolver(new DefaultToken(), reader, [spy], { ignoreUnresolvablePlaceholders: true });
    reader.readKeys('${Name}');

    const error = await rejection(resolveToString(resolver, '${Name} ${Db:Password}'));

    assertKeyError(error, 'Db:Password', ConfigurationKeyErrorCode.notAllowed, 8);
    assert.deepEqual(spy.tryGetBytesCalls, ['Name']);
  });

  it("resolve with ignoreUnresolvablePlaceholders: a provider's error still propagates", async () => {
    const spy = new SpyValueProvider(VALUES, { throwOnLookup: new ConfigurationKeyError('Name', ConfigurationKeyErrorCode.valueUnstable) });
    const resolver = new ReadingResolver(new DefaultToken(), [spy], { ignoreUnresolvablePlaceholders: true });

    const error = await rejection(resolveToString(resolver, '${Name}'));

    assert.ok(error instanceof ConfigurationKeyError);
    assert.equal(error.error, ConfigurationKeyErrorCode.valueUnstable);
  });

  describe('resolve with ignoreUnresolvablePlaceholders: a destination too small for the item throws and clears the destination', () => {
    for (const destinationLength of [9, 13]) {
      it(String(destinationLength), async () => {
        const resolver = new ReadingResolver(new DefaultToken(), [new DictValueProvider(VALUES)], { ignoreUnresolvablePlaceholders: true });

        for (const form of both('Ada ${missing}')) {
          const destination = filled(destinationLength);

          await assert.rejects(resolver.resolve(form, destination), DestinationTooSmallError);

          assertZeroed(destination);
        }
      });
    }
  });

  it('ignoreUnresolvablePlaceholders is off by default', () => {
    const resolver = new ConfigurationItemResolver(new DefaultToken(), new ConfigurationItemReader(new DefaultToken()), [new DictValueProvider(VALUES)]);

    assert.equal(resolver.ignoreUnresolvablePlaceholders, false);
  });

  it('resolve: keys read from a trusted template are resolved in another source', async () => {
    const { reader, resolver } = createAllowListed();
    reader.readKeys('${Name} ${ Db:Password }');

    await assertResolves(resolver, '${Db:Password} for ${Name}', 'p@ss for Ada');
  });

  describe('resolve: a key not read by the reader throws without asking the provider', () => {
    const cases: [string, string, number][] = [
      ['${Db:Password}', 'Db:Password', 0],
      ['${Name} then ${Db:Password}', 'Db:Password', 13],
      ['${name}', 'name', 0],
      // The u with diaeresis is 2 UTF-8 bytes: .NET's char index here is 2.
      [`${U_DIAERESIS} \${ Db:Password }`, 'Db:Password', 3],
    ];
    for (const [source, rejectedKey, sourceIndex] of cases) {
      it(JSON.stringify(source), async () => {
        const { reader, resolver, spy } = createAllowListed();
        reader.readKeys('${Name}');

        for (const form of both(source)) {
          const destination = filled(64);

          const error = await rejection(resolver.resolve(form, destination));

          assertKeyError(error, rejectedKey, ConfigurationKeyErrorCode.notAllowed, sourceIndex);
          assert.ok(!spy.tryGetBytesCalls.includes(rejectedKey));
          assertZeroed(destination);
        }
      });
    }
  });

  it('resolve before any keys are read resolves only text without items', async () => {
    const { resolver, spy } = createAllowListed();

    assert.equal(await resolveToString(resolver, 'plain ${} text'), 'plain ${} text');
    await assert.rejects(resolveToString(resolver, '${Name}'), ConfigurationKeyError);
    assert.deepEqual(spy.tryGetBytesCalls, []);
  });

  it("resolve uses the reader's most recent keys", async () => {
    const { reader, resolver } = createAllowListed();
    reader.readKeys('${Name}');
    assert.equal(await resolveToString(resolver, '${Name}'), 'Ada');

    reader.readKeys('${value2}');

    assert.equal(await resolveToString(resolver, '${value2}'), 'TWO');
    await assert.rejects(resolveToString(resolver, '${Name}'), ConfigurationKeyError);
  });

  describe('resolve: a missing key throws and clears the destination', () => {
    const cases: [string, string, number][] = [
      ['${missing}', 'missing', 0],
      ['${Name} then ${ missing }', 'missing', 13],
      ['${name}', 'name', 0],
      ['${a${Name}}', 'a${Name', 0],
      // The acute e is 2 UTF-8 bytes: .NET's char index here is 2.
      [`${E_ACUTE} \${missing}`, 'missing', 3],
    ];
    for (const [source, missingKey, sourceIndex] of cases) {
      it(JSON.stringify(source), async () => {
        for (const form of both(source)) {
          const destination = filled(64);

          const error = await rejection(newResolver().resolve(form, destination));

          assertKeyError(error, missingKey, ConfigurationKeyErrorCode.notFound, sourceIndex);
          assertZeroed(destination);
        }
      });
    }
  });

  describe('resolve: a destination too small throws and clears the destination', () => {
    const cases: [string, number][] = [
      ['literal too long', 4],
      ['ab ${Name}', 2],
      ['ab ${Name}', 5],
      ['${Name} trailing text', 6],
      ['${Unicode}', 4],
      ['${Db:Password} ${Name}', 6],
      ['x', 0],
    ];
    for (const [source, destinationLength] of cases) {
      it(`${JSON.stringify(source)} into ${destinationLength}`, async () => {
        for (const form of both(source)) {
          const destination = filled(destinationLength);

          await assert.rejects(newResolver().resolve(form, destination), DestinationTooSmallError);

          assertZeroed(destination);
        }
      });
    }
  });

  it("resolve: a provider's error propagates and clears the destination", async () => {
    const spy = new SpyValueProvider(VALUES, { throwOnLookup: new Error('provider failed') });
    const resolver = new ReadingResolver(new DefaultToken(), [spy]);

    for (const form of both('ab ${Name}')) {
      const destination = filled(16);

      await assert.rejects(resolver.resolve(form, destination), { message: 'provider failed' });

      assertZeroed(destination);
    }
  });

  describe('resolve: an escaped start sequence is copied without the escape', () => {
    const cases: [string, string][] = [
      ['$${Name}', '${Name}'],
      ['$${', '${'],
      ['$${Name} is ${Name}', '${Name} is Ada'],
      ['$$${Name}', '$${Name}'],
      ['$${a ${Name}}', '${a Ada}'],
      ['$ ${Name} $$', '$ Ada $$'],
      [`${E_ACUTE} $\${Unicode}`, `${E_ACUTE} \${Unicode}`],
    ];
    for (const [source, expected] of cases) {
      it(JSON.stringify(source), async () => {
        await assertResolves(newResolver(), source, expected);
      });
    }
  });

  it('resolve: an escaped item is not a key, so it needs no permission', async () => {
    const { reader, resolver, spy } = createAllowListed();
    reader.readKeys('${Name}');

    await assertResolves(resolver, '${Name} $${Db:Password}', 'Ada ${Db:Password}');

    assert.deepEqual(spy.tryGetBytesCalls, ['Name', 'Name']);
  });

  describe("resolve uses the token's escape sequence", () => {
    const cases: [string | undefined, string, string][] = [
      [undefined, '${{Name}} \\{{Name}}', '$Ada \\Ada'],
      ['\\', '${{Name}} \\{{Name}}', '$Ada {{Name}}'],
    ];
    for (const [escape, source, expected] of cases) {
      it(String(escape), async () => {
        const resolver = new ReadingResolver(new CustomToken('{{', '}}', escape), [new DictValueProvider(VALUES)]);

        await assertResolves(resolver, source, expected);
      });
    }
  });

  it('maxResolutionDepth defaults to 1 and must be positive', () => {
    const resolver = new ConfigurationItemResolver(new DefaultToken(), new ConfigurationItemReader(new DefaultToken()), [new DictValueProvider(VALUES)]);

    assert.equal(resolver.maxResolutionDepth, 1);
    assert.throws(
      () => new ConfigurationItemResolver(new DefaultToken(), new ConfigurationItemReader(new DefaultToken()), [new DictValueProvider(VALUES)], { maxResolutionDepth: 0 }),
      (error) => error instanceof InvalidArgumentError && /maxResolutionDepth/.test(error.message),
    );
  });

  describe('resolve: items in values are resolved up to the maximum depth', () => {
    const cases: [number, string, string][] = [
      [1, '${Url}', 'https://${Host}:${Port}/'],
      [2, '${Url}', 'https://${Region}.db.internal:5432/'],
      [3, '${Url}', 'https://eu.db.internal:5432/'],
      [10, 'go ${Url} now', 'go https://eu.db.internal:5432/ now'],
      [1, '${Escaped}', '$${Region}'],
      [2, '${Escaped}', '${Region}'],
      [2, '${Ping}', '${Ping}'],
      [2, '${Port}${Host}', '5432eu.db.internal'],
    ];
    for (const [depth, source, expected] of cases) {
      it(`${depth}: ${JSON.stringify(source)}`, async () => {
        await assertResolves(createNested(depth), source, expected);
      });
    }
  });

  describe('resolve: a value that leads back to its key throws Cycle and clears the destination', () => {
    const cases: [number, string, string, number][] = [
      [2, '${Self}', 'Self', 0],
      [5, 'x ${Self}', 'Self', 2],
      [3, '${Ping}', 'Ping', 0],
      [10, 'ab ${Pong}', 'Pong', 3],
    ];
    for (const [depth, source, key, sourceIndex] of cases) {
      it(`${depth}: ${JSON.stringify(source)}`, async () => {
        const resolver = createNested(depth);

        for (const form of both(source)) {
          const destination = filled(256);

          const error = await rejection(resolver.resolve(form, destination));

          assertKeyError(error, key, ConfigurationKeyErrorCode.cycle, sourceIndex);
          assertZeroed(destination);
        }
      });
    }
  });

  it('resolve: a key in a value must be allowed', async () => {
    const spy = new SpyValueProvider(NESTED);
    const resolver = new ReadingResolver(new DefaultToken(), [spy], { maxResolutionDepth: 3 });

    const error = await rejection(resolveToString(resolver, 'go ${Host}'));

    assertKeyError(error, 'Region', ConfigurationKeyErrorCode.notAllowed, 3);
    assert.deepEqual(spy.tryGetBytesCalls, ['Host']);
  });

  it("resolve: a missing key in a value throws with the source item's index, or is kept when ignored", async () => {
    const strict = createNested(2);
    const lenient = new ReadingResolver(new DefaultToken(), [new DictValueProvider(NESTED)], {
      maxResolutionDepth: 2,
      ignoreUnresolvablePlaceholders: true,
      alsoAllowed: NESTED_KEYS,
    });
    const source = `${E_ACUTE} \${Missing}`;

    const error = await rejection(resolveToString(strict, utf8(source)));

    assertKeyError(error, 'Nope', ConfigurationKeyErrorCode.notFound, 3);
    await assertResolves(lenient, source, `${E_ACUTE} [\${ Nope }]`);
  });

  it('resolve: a value that shrinks when resolved leaves no trace of the raw value', async () => {
    const resolver = createNested(2);
    const rawLength = '${Region}!'.length;

    for (const form of both('${Shrinks}')) {
      const destination = filled(64);

      const written = await resolver.resolve(form, destination);

      assert.deepEqual(Array.from(destination.subarray(0, written)), bytesOf('eu!'));
      assert.ok(!Buffer.from(destination).includes('Region'));
      // The raw value was written, then zeroed, then overwritten by the resolved one.
      assert.deepEqual(Array.from(destination.subarray(written, rawLength)), new Array(rawLength - written).fill(0));
      assert.deepEqual(Array.from(destination.subarray(rawLength)), bytesOf('#'.repeat(64 - rawLength)));
    }
  });

  it('resolve: items in values are written without reading values as strings', async () => {
    const spy = new SpyValueProvider(NESTED);
    const resolver = new ReadingResolver(new DefaultToken(), [spy], { maxResolutionDepth: 3, alsoAllowed: NESTED_KEYS });

    assert.equal(await resolveToString(resolver, '${Url}'), 'https://eu.db.internal:5432/');

    assert.deepEqual(spy.tryGetBytesCalls, ['Url', 'Host', 'Region', 'Port']);
    assert.deepEqual(spy.tryGetValueCalls, []);
  });
});

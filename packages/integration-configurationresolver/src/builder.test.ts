// The port of the Python suite's test_builder.py, itself the port of .NET's
// ConfigurationResolverBuilderTests. addProtectedCache is tested with the protected cache value
// provider.
import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';
import { CustomToken, DictValueProvider, resolveToString } from './core.test-support.js';
import { InvalidOperationError } from './errors.js';
import { ConfigurationResolverBuilder } from './builder.js';
import { ConfigurationItemReader } from './reader.js';
import { ConfigurationItemResolver } from './resolver.js';
import { DefaultToken } from './tokens.js';

const newHigh = () => new DictValueProvider({ Name: 'Grace' });
const newLow = () => new DictValueProvider({ Name: 'Ada', Lang: '${Name}' });

describe('ConfigurationResolverBuilder', () => {
  it('build uses the reader, and the providers in the order added', async () => {
    const reader = new ConfigurationItemReader(new DefaultToken());
    reader.readKeys('${Name} ${Lang}');

    const resolver = new ConfigurationResolverBuilder().withReader(reader).addValueProvider(newHigh()).addValueProvider(newLow()).build();

    assert.ok(resolver instanceof ConfigurationItemResolver);
    assert.equal(await resolveToString(resolver, '${Name} ${Lang} $$${Name}', 256), 'Grace ${Name} $${Name}');
  });

  it('build defaults to the default token and options', async () => {
    const resolver = new ConfigurationResolverBuilder().withReader(new ConfigurationItemReader(new DefaultToken())).addValueProvider(newLow()).build();

    assert.equal(resolver.ignoreUnresolvablePlaceholders, false);
    assert.equal(resolver.maxResolutionDepth, 1);
    assert.equal(await resolveToString(resolver, '$${Name}', 256), '${Name}');
  });

  it('build applies the token and options', async () => {
    const token = new CustomToken('{{', '}}');
    const reader = new ConfigurationItemReader(token);
    reader.readKeys('{{Lang}} {{Name}} {{Missing}}');

    const resolver = new ConfigurationResolverBuilder()
      .withToken(token)
      .withReader(reader)
      .addValueProvider(new DictValueProvider({ Lang: '{{Name}}', Name: 'Ada' }))
      .ignoreUnresolvablePlaceholders()
      .withMaxResolutionDepth(2)
      .build();

    assert.equal(resolver.ignoreUnresolvablePlaceholders, true);
    assert.equal(resolver.maxResolutionDepth, 2);
    assert.equal(await resolveToString(resolver, '{{Lang}} {{Missing}} ${Lang}', 256), 'Ada {{Missing}} ${Lang}');
  });

  it('build returns a new resolver on each call', () => {
    const builder = new ConfigurationResolverBuilder().withReader(new ConfigurationItemReader(new DefaultToken())).addValueProvider(newLow());

    assert.notEqual(builder.build(), builder.build());
  });

  it('build without a reader or a provider throws', () => {
    assert.throws(
      () => new ConfigurationResolverBuilder().addValueProvider(newLow()).build(),
      (error) => error instanceof InvalidOperationError && /reader/.test(error.message),
    );
    assert.throws(
      () => new ConfigurationResolverBuilder().withReader(new ConfigurationItemReader(new DefaultToken())).build(),
      (error) => error instanceof InvalidOperationError && /value provider/.test(error.message),
    );
  });

  it('invalid arguments throw', () => {
    const builder = new ConfigurationResolverBuilder();

    assert.throws(() => builder.withToken(undefined as never), TypeError);
    assert.throws(() => builder.withReader(undefined as never), TypeError);
    assert.throws(() => builder.addValueProvider(undefined as never), TypeError);
    assert.throws(
      () => builder.withMaxResolutionDepth(0),
      (error) => error instanceof InvalidArgumentError && /maxResolutionDepth/.test(error.message),
    );
  });
});

// The port of the Python suite's test_template_scenarios.py: the parts of .NET's
// JsonConfigurationScenarioTests that need only ported code. Only the "dictionary" provider is
// ported - a map-backed ValueProviderBase - so the tests .NET runs over each provider run once here.
// Templates are written to disk as .NET's are, and the resolved JSON is loaded with JSON.parse instead
// of Microsoft.Extensions.Configuration. .NET's ResolveChars reads a template with File.ReadAllText,
// which drops a byte order mark; the string form here drops it to match.
import { strict as assert } from 'node:assert';
import { createReadStream, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import {
  assertZeroed, createTemplateResolver, CustomToken, DictValueProvider, E_ACUTE, filled, O_DIAERESIS, rejection, utf8,
} from './core.test-support.js';
import { ConfigurationKeyError, ConfigurationKeyErrorCode, DestinationTooSmallError } from './errors.js';
import { ConfigurationItemReader } from './reader.js';
import { ConfigurationItemResolver, type ConfigurationResolver } from './resolver.js';
import { DefaultToken, type ConfigurationItemTokenBase } from './tokens.js';

const GREETING = 'h' + E_ACUTE + 'llo';
const WORLD = 'w' + O_DIAERESIS + 'rld';

const TEMPLATE = [
  '{',
  '  "ConnectionStrings": {',
  '    "Default": "Host=${Database:Host};Port=${ Database:Port };Password=${Database:Password}"',
  '  },',
  `  "Greeting": "\${Greeting} ${WORLD}",`,
  '  "Literal": "${} and $ {not an item}"',
  '}',
].join('\n');

const VALUES: Record<string, string> = {
  'Database:Host': 'db.internal',
  'Database:Port': '5432',
  'Database:Password': 's3cr\\"t!',
  Greeting: GREETING,
};

const BUFFER_LENGTH = 4096;
const BOM_UTF8 = [0xef, 0xbb, 0xbf];

const directory = mkdtempSync(join(tmpdir(), 'hkdfguard-templates-'));
after(() => rmSync(directory, { recursive: true, force: true }));

function writeText(fileName: string, content: string, byteOrderMark = false): string {
  const path = join(directory, fileName);
  writeFileSync(path, Buffer.concat([Buffer.from(byteOrderMark ? BOM_UTF8 : []), Buffer.from(utf8(content))]));
  return path;
}

/** The port of File.ReadAllText, which drops a UTF-8 byte order mark. */
function readText(path: string): string {
  return new TextDecoder('utf-8').decode(readFileSync(path));
}

const createProvider = () => new DictValueProvider(VALUES);

const createResolver = (token: ConfigurationItemTokenBase, provider: DictValueProvider, templatePath: string) =>
  createTemplateResolver(token, provider, readText(templatePath));

/** The template resolved as .NET's ResolveChars (a string) and ResolveBytes (the file's bytes) resolve it. */
async function resolveForms(resolver: ConfigurationResolver, path: string): Promise<Uint8Array[]> {
  const resolved: Uint8Array[] = [];
  for (const source of [readText(path), readFileSync(path)]) {
    const destination = new Uint8Array(BUFFER_LENGTH);
    const written = await resolver.resolve(source, destination);
    resolved.push(destination.slice(0, written));
  }
  return resolved;
}

/** The port of TemplateFile.LoadJson. Decoding skips a UTF-8 byte order mark, as .NET's JSON loader does. */
function loadJson(resolved: Uint8Array): any {
  return JSON.parse(new TextDecoder('utf-8').decode(resolved));
}

describe('template scenarios', () => {
  it('a resolved template loads as configuration', async () => {
    const templatePath = writeText('appsettings.template.json', TEMPLATE);
    const resolver = createResolver(new DefaultToken(), createProvider(), templatePath);

    for (const resolved of await resolveForms(resolver, templatePath)) {
      const configuration = loadJson(resolved);

      assert.equal(configuration.ConnectionStrings.Default, 'Host=db.internal;Port=5432;Password=s3cr"t!');
      assert.equal(configuration.Greeting, `${GREETING} ${WORLD}`);
      assert.equal(configuration.Literal, '${} and $ {not an item}');
    }
  });

  it('the reader lists the keys in the template file', async () => {
    const templatePath = writeText('appsettings.template.json', TEMPLATE);
    const reader = new ConfigurationItemReader(new DefaultToken());
    const expected = ['Database:Host', 'Database:Port', 'Database:Password', 'Greeting'];

    assert.deepEqual(await reader.readKeysFrom(createReadStream(templatePath)), expected);

    assert.deepEqual(reader.keys(), expected);
    assert.deepEqual(reader.readKeys(readFileSync(templatePath)), expected);
  });

  it('a custom token resolves only its own items', async () => {
    const templatePath = writeText('custom.template.json', '{ "Host": "{{Database:Host}}", "Kept": "${Database:Host}" }');
    const resolver = createResolver(new CustomToken('{{', '}}'), createProvider(), templatePath);

    for (const resolved of await resolveForms(resolver, templatePath)) {
      const configuration = loadJson(resolved);

      assert.equal(configuration.Host, 'db.internal');
      assert.equal(configuration.Kept, '${Database:Host}');
    }
  });

  it('a template with a byte order mark resolves and loads', async () => {
    const templatePath = writeText('bom.template.json', '{ "Host": "${Database:Host}" }', true);
    const resolver = createResolver(new DefaultToken(), createProvider(), templatePath);
    const destination = new Uint8Array(BUFFER_LENGTH);

    const written = await resolver.resolve(readFileSync(templatePath), destination);

    // The byte order mark is copied like any other text; the JSON loader skips it.
    const resolved = destination.slice(0, written);
    assert.deepEqual(Array.from(resolved.subarray(0, 3)), BOM_UTF8);
    assert.equal(loadJson(resolved).Host, 'db.internal');
  });

  it('a template with a missing value throws', async () => {
    const template = '{ "Value": "${Database:Missing}" }';
    const templatePath = writeText('missing.template.json', template);
    const resolver = createResolver(new DefaultToken(), createProvider(), templatePath);

    for (const source of [readText(templatePath), readFileSync(templatePath)]) {
      const error = await rejection(resolver.resolve(source, new Uint8Array(BUFFER_LENGTH)));

      assert.ok(error instanceof ConfigurationKeyError);
      assert.equal(error.key, 'Database:Missing');
      assert.equal(error.error, ConfigurationKeyErrorCode.notFound);
      assert.equal(error.sourceIndex, template.indexOf('${'));
    }
  });

  it('a destination too small for a value throws and clears the secret', async () => {
    const template = '${Database:Password}${Database:Password}';
    const resolver = createTemplateResolver(new DefaultToken(), createProvider(), template);

    for (const source of [template, utf8(template)]) {
      const destination = filled('s3cr"t!'.length + 3);

      await assert.rejects(resolver.resolve(source, destination), DestinationTooSmallError);

      assertZeroed(destination);
    }
  });

  it('a destination too small for the template text throws and clears the destination', async () => {
    const template = readText(writeText('small.template.json', TEMPLATE));
    const resolver = createTemplateResolver(new DefaultToken(), createProvider(), template);

    for (const source of [template, utf8(template)]) {
      const destination = filled(template.indexOf('${') - 1);

      await assert.rejects(resolver.resolve(source, destination), DestinationTooSmallError);

      assertZeroed(destination);
    }
  });

  it('a template using a key outside the trusted template is rejected', async () => {
    // The trusted template only asks for the host; a substituted template also asks for the password.
    const trustedPath = writeText('trusted.template.json', '{ "Host": "${Database:Host}" }');
    const injectedPath = writeText('injected.template.json', '{ "Host": "${Database:Host}", "Leak": "${Database:Password}" }');
    const resolver = createResolver(new DefaultToken(), createProvider(), trustedPath);

    for (const resolved of await resolveForms(resolver, trustedPath)) {
      assert.equal(loadJson(resolved).Host, 'db.internal');
    }

    const leakIndex = readText(injectedPath).indexOf('${Database:Password}');
    for (const source of [readText(injectedPath), readFileSync(injectedPath)]) {
      const destination = filled(BUFFER_LENGTH);

      const error = await rejection(resolver.resolve(source, destination));

      assert.ok(error instanceof ConfigurationKeyError);
      assert.equal(error.key, 'Database:Password');
      assert.equal(error.error, ConfigurationKeyErrorCode.notAllowed);
      assert.equal(error.sourceIndex, leakIndex);
      assert.ok(!error.message.includes('Database:Password'));
      assertZeroed(destination);
    }
  });

  it('ignoreUnresolvablePlaceholders leaves missing items in the loaded configuration', async () => {
    const templatePath = writeText('optional.template.json', '{ "Host": "${Database:Host}", "Optional": "${ Feature:Flag }" }');
    const reader = new ConfigurationItemReader(new DefaultToken());
    reader.readKeys(readFileSync(templatePath));
    const resolver = new ConfigurationItemResolver(new DefaultToken(), reader, [createProvider()], { ignoreUnresolvablePlaceholders: true });

    for (const resolved of await resolveForms(resolver, templatePath)) {
      const configuration = loadJson(resolved);

      assert.equal(configuration.Host, 'db.internal');
      assert.equal(configuration.Optional, '${ Feature:Flag }');
    }
  });

  it('an unterminated item in JSON runs to the next closing brace', async () => {
    // JSON's own closing brace ends the item, so the key includes the JSON that follows it.
    const template = '{ "Value": "${unterminated" }';
    const templatePath = writeText('unterminated.template.json', template);
    const resolver = createResolver(new DefaultToken(), createProvider(), templatePath);

    for (const source of [readText(templatePath), readFileSync(templatePath)]) {
      const error = await rejection(resolver.resolve(source, new Uint8Array(BUFFER_LENGTH)));

      assert.ok(error instanceof ConfigurationKeyError);
      assert.equal(error.key, 'unterminated"');
      assert.equal(error.error, ConfigurationKeyErrorCode.notFound);
      assert.equal(error.sourceIndex, template.indexOf('${'));
    }
  });

  it('a value that breaks JSON produces invalid configuration', async () => {
    // Values are inserted as they are; the resolver does not escape them for JSON.
    const templatePath = writeText('quote.template.json', '{ "Value": "${Quote}" }');
    const resolver = createResolver(new DefaultToken(), new DictValueProvider({ Quote: 'a"b' }), templatePath);

    for (const resolved of await resolveForms(resolver, templatePath)) {
      assert.equal(new TextDecoder().decode(resolved), '{ "Value": "a"b" }');
      assert.throws(() => loadJson(resolved), SyntaxError);
    }
  });
});

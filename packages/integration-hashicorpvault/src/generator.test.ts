// scripts/generate-vault-client.mjs: what it generates from a spec, and its command line.
import { strict as assert } from 'node:assert';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { before, describe, it } from 'node:test';
import { pathToFileURL } from 'node:url';
import * as ts from 'typescript';

const PACKAGE = resolve(__dirname, '..');
const WORKSPACE = resolve(PACKAGE, '..', '..');

interface Generator {
  generate(spec: string, settings: string | undefined): Record<string, string>;
  run(args: string[], cwd: string, output: { write(text: string): void }, error: { write(text: string): void }): number;
  workspaceRoot(start: string): string | undefined;
  literal(value: string): string;
}

let generator: Generator;
before(async () => {
  // A real dynamic import: the script is an ES module, this test CommonJS.
  generator = await (new Function('url', 'return import(url)') as (url: string) => Promise<Generator>)(
    pathToFileURL(join(WORKSPACE, 'scripts', 'generate-vault-client.mjs')).href);
});

const spec = (paths: Record<string, unknown>, schemas: Record<string, unknown> = {}) =>
  JSON.stringify({ openapi: '3.0.2', info: { title: 'test', version: '9.9.9' }, paths, components: { schemas } });
const operation = (operationId: string, tag = 'secrets', more: Record<string, unknown> = {}) =>
  ({ operationId, tags: [tag], responses: { 200: { description: 'OK' } }, ...more });
const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });
const jsonBody = (name: string) => ({ content: { 'application/json': { schema: ref(name) } } });
const MOUNT = { name: 'kv_mount_path', in: 'path', required: true, schema: { type: 'string', default: 'secret' } };
const read = (name: string) => readFileSync(join(PACKAGE, name), 'utf8');
const flat = (code: string) => code.replace(/\s+/g, ' ');

function syntaxErrors(name: string, code: string): string[] {
  const file = ts.createSourceFile(name, code, ts.ScriptTarget.ES2023, true);
  return ((file as unknown as { parseDiagnostics: ts.Diagnostic[] }).parseDiagnostics ?? []).map((d) => ts.flattenDiagnosticMessageText(d.messageText, '\n'));
}

describe('generate-vault-client', () => {
  it('generated the code on disk from the spec', () => {
    const files = generator.generate(read('openapi.json'), read('generator.json'));
    const output = join(PACKAGE, 'src', 'generated');
    const onDisk = Object.fromEntries(readdirSync(output).filter((f) => f.endsWith('.ts')).sort()
      .map((f) => [f, readFileSync(join(output, f), 'utf8').replace(/\r\n/g, '\n')]));
    assert.deepEqual(Object.keys(onDisk), Object.keys(files));
    for (const name of Object.keys(files)) assert.ok(onDisk[name] === files[name], `${name} is stale: regenerate with node scripts/generate-vault-client.mjs`);
  });

  it('generates the subset generator.json names: 103 operations and 77 models', () => {
    const files = generator.generate(read('openapi.json'), read('generator.json'));
    assert.deepEqual(Object.keys(files), ['apis.ts', 'auth-api.ts', 'index.ts', 'schema.ts', 'secrets-api.ts', 'system-api.ts']);
    const operations = ['auth-api.ts', 'secrets-api.ts', 'system-api.ts'].map((f) => files[f]!.match(/^ {2}async /gm)?.length ?? 0);
    assert.equal(operations.reduce((a, b) => a + b), 103);
    assert.equal(files['schema.ts']!.match(/^export interface /gm)?.length, 77);
    const secrets = files['secrets-api.ts']!;
    assert.ok(secrets.includes('async kvV2Read(') && secrets.includes('async transitEncrypt(') && secrets.includes('async kvV1Read('));
    assert.ok(!secrets.includes('async pki'));
  });

  it('generates TypeScript for the whole spec', () => {
    const files = generator.generate(read('openapi.json'), undefined);
    for (const [name, code] of Object.entries(files)) assert.deepEqual(syntaxErrors(name, code), [], name);
    assert.ok('identity-api.ts' in files);
  });

  it('leaves out duplicates and enterprise stubs, with their schemas', () => {
    const files = generator.generate(spec({
      '/a': { post: operation('thing-write', 'secrets', { requestBody: jsonBody('ThingWriteRequest') }) },
      '/b': { post: operation('thing-write2', 'secrets', { requestBody: jsonBody('ThingWrite2Request') }) },
      '/c': { get: operation('enterprise-stub-read') },
    }, { ThingWriteRequest: { type: 'object', properties: { a: { type: 'string' } } }, ThingWrite2Request: { type: 'object', properties: { a: { type: 'string' } } } }),
    undefined);
    const secrets = files['secrets-api.ts']!;
    assert.ok(secrets.includes('async thingWrite('));
    assert.ok(!secrets.includes('thingWrite2') && !secrets.includes('enterpriseStub'));
    assert.ok(files['schema.ts']!.includes('export interface ThingWriteRequest') && !files['schema.ts']!.includes('ThingWrite2Request'));
  });

  it("keeps prose from breaking out of its comment, in ASCII", () => {
    const nasty = 'Ends */ here \\ and "quoted" ’smart’ — dash';
    const files = generator.generate(spec({ '/a': { get: operation('evil-read', 'secrets', { summary: nasty, description: nasty }) } }), undefined);
    const code = files['secrets-api.ts']!;
    assert.deepEqual(syntaxErrors('x.ts', code), []);
    assert.ok(code.includes('Ends *\\/ here \\ and "quoted" \'smart\' - dash'));
    assert.match(code, /^[\x00-\x7f]*$/);
  });

  it('lets an operation override a path parameter, and types it by its first 2xx response', () => {
    const shared = { name: 'name', in: 'path', description: 'shared', schema: { type: 'string' } };
    const own = { name: 'name', in: 'path', description: 'its own', schema: { type: 'string' } };
    const files = generator.generate(spec({ '/{kv_mount_path}/things/{name}': {
      parameters: [MOUNT, shared],
      get: operation('thing-read', 'secrets', { parameters: [own], responses: { default: { description: 'error' },
        200: { content: { 'application/json': { schema: ref('ThingReadResponse') } } }, 204: { description: 'none' } } }),
    } }, { ThingReadResponse: { type: 'object', properties: { when: { type: 'string', format: 'date-time' }, n: { type: 'integer' },
      tags: { type: 'array', items: { type: 'string' } }, extra: { type: 'object' } } } }), undefined);
    const api = files['secrets-api.ts']!;
    assert.ok(api.includes('@param name its own'));
    assert.ok(api.includes('VaultResponse<ThingReadResponse>') && api.includes('ThingReadResponse.read'));
    assert.ok(flat(api).includes("const requestPath = '/v1/' + escapePathSegment(mountPathOr(options, 'secret')) + '/things/' + escapePathSegment(name);"));
    const schema = files['schema.ts']!;
    for (const text of ['readonly when?: Date;', 'readonly tags?: string[];', 'readonly extra?: Record<string, JsonValue>;',
      "when: json.member('when').readDate(),", "tags: json.member('tags').readArray((v0) => v0.readString()),"]) {
      assert.ok(schema.includes(text), text);
    }
  });

  it('keeps names TypeScript, and clear of each other and of the options', () => {
    const query = ['options', 'class', 'list', 'signal'].map((name) => ({ name, in: 'query', required: name === 'class', schema: { type: 'boolean' } }));
    const files = generator.generate(spec({ '/x': { get: operation('odd-names', 'secrets', { parameters: query }) } },
      { OddRequest: { type: 'object', properties: { from: { type: 'string' }, 'a-b': { type: 'string' }, a_b: { type: 'string' } } } }), undefined);
    const api = files['secrets-api.ts']!;
    assert.ok(api.includes('classParameter: boolean'), api);
    assert.ok(api.includes('readonly options?: boolean') && api.includes('readonly signalParameter?: boolean'));
    assert.ok(api.includes("query.push(['list', 'true']);"));
    const schema = files['schema.ts']!;
    for (const field of ['readonly from?: string;', 'readonly aB?: string;', 'readonly aB2?: string;']) assert.ok(schema.includes(field), field);
    for (const [name, code] of Object.entries(files)) assert.deepEqual(syntaxErrors(name, code), [], name);
  });

  it('keeps, with an include list, only its operations, the schemas they use, and their classes', () => {
    const document = spec({
      '/a': { post: operation('kv-write', 'secrets', { requestBody: jsonBody('KvWriteRequest') }) },
      '/b': { post: operation('app-login', 'auth', { requestBody: jsonBody('AppLoginRequest') }) },
    }, { KvWriteRequest: { type: 'object', properties: { nested: ref('Nested') } }, Nested: { type: 'object', properties: {} },
      AppLoginRequest: { type: 'object', properties: {} }, Unused: { type: 'object', properties: {} } });
    const files = generator.generate(document, JSON.stringify({ description: 'd', include: ['^Kv'] }));
    assert.deepEqual(Object.keys(files), ['apis.ts', 'index.ts', 'schema.ts', 'secrets-api.ts']);
    assert.ok(files['schema.ts']!.includes('export interface KvWriteRequest') && files['schema.ts']!.includes('export interface Nested'));
    assert.ok(!files['schema.ts']!.includes('AppLoginRequest') && !files['schema.ts']!.includes('Unused'));
    assert.ok(files['schema.ts']!.includes('Nested.write(writer, value.nested);'));
    const everything = generator.generate(document, undefined);
    assert.ok('auth-api.ts' in everything && everything['schema.ts']!.includes('export interface Unused'));
  });

  for (const [settings, message] of [['not json', /aren't JSON/], ['[]', /JSON object/], ['{"exclude": []}', /Unknown generator setting/],
    ['{"include": []}', /non-empty/], ['{"include": ["("]}', /isn't a regular expression/], ['{"include": ["^Nothing"]}', /matches no operation/]] as const) {
    it(`refuses the settings ${settings}`, () => {
      assert.throws(() => generator.generate(spec({ '/a': { get: operation('a-read') } }), settings), message);
    });
  }

  it("refuses an included operation's missing schema", () => {
    assert.throws(() => generator.generate(spec({ '/a': { post: operation('a-write', 'secrets', { requestBody: jsonBody('Missing') }) } }), undefined),
      /Missing is used by a generated operation/);
  });

  it("escapes in a literal what a string can't hold as it is", () => {
    for (const value of ['quote \' back \\ nl \n tab \t nul \0', 'é\u{1f600}']) {
      assert.equal(new Function(`return ${generator.literal(value)};`)(), value);
      assert.match(generator.literal(value), /^[\x20-\x7e]*$/);
    }
  });

  it('writes only the files that changed, and deletes stale ones', () => {
    const directory = mkdtempSync(join(tmpdir(), 'hkdfguard-generator-'));
    try {
      const document = join(directory, 'openapi.json');
      writeFileSync(document, spec({ '/a': { get: operation('a-read') } }));
      writeFileSync(join(directory, 'generator.json'), '{"include": ["^A"]}');
      const output = join(directory, 'out');
      mkdirSync(output);
      writeFileSync(join(output, 'stale.ts'), 'old');
      let out = '';
      assert.equal(generator.run(['--spec', document, '--output', output], directory, { write: (t) => { out += t; } }, { write: () => undefined }), 0);
      assert.match(out, /4 written, 0 unchanged, 1 stale deleted/);
      assert.match(out, / with /);
      assert.ok(!existsSync(join(output, 'stale.ts')));
      out = '';
      generator.run(['--spec', document, '--output', output, '--settings', join(directory, 'none.json')], directory, { write: (t) => { out += t; } },
        { write: () => undefined });
      assert.match(out, /0 written, 4 unchanged, 0 stale deleted/);
      assert.ok(!out.includes(' with '));
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('refuses unknown arguments, and needs the workspace', () => {
    let error = '';
    assert.equal(generator.run(['--bogus'], tmpdir(), { write: () => undefined }, { write: (t) => { error += t; } }), 2);
    assert.match(error, /Usage/);
    const directory = mkdtempSync(join(tmpdir(), 'hkdfguard-generator-'));
    try {
      error = '';
      assert.equal(generator.run([], directory, { write: () => undefined }, { write: (t) => { error += t; } }), 2);
      assert.match(error, /workspace root/);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("finds the workspace root from inside it, for the library's own spec and output", () => {
    assert.equal(generator.workspaceRoot(join(PACKAGE, 'src')), WORKSPACE);
  });
});

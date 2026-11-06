#!/usr/bin/env node
// Generates @runsecure/hkdfguard-integration-hashicorpvault's typed API from Vault's OpenAPI document:
// what vault-client-go's generate/templates produce through openapi-generator, in TypeScript - and
// what the .NET, Java and Python generators produce in theirs. One class per tag (AuthApi,
// IdentityApi, SecretsApi, SystemApi) with one async method per operation, the VaultApis base class
// whose getters reach them from a VaultClient, and one model per schema in schema.ts: an interface,
// and a constant of the same name that reads and writes it.
//
// As vault-client-go, operations whose id ends in 2, 3 or 4 (duplicates Vault's spec lists for
// alternative paths) or starts EnterpriseStub are left out, and so are their schemas.
//
// Settings can narrow that further: an "include" list of regular expressions, matched against each
// operation's name in PascalCase (KvV2Read, AppRoleLogin - the .NET method name without Async).
// Only operations one of them matches are generated, only the schemas those operations use
// (directly, or through another schema), and only the classes that still have an operation. Each
// expression must match at least one operation, so a typo or an operation the spec has dropped is
// noticed rather than silently generating less.
//
// The command line: [--spec <openapi.json>] [--settings <generator.json>] [--output <directory>].
// The spec and output default to the library's own, found from the workspace root - the directory
// holding hkdfguard-node's package.json, at or above the current one - and the settings to
// generator.json beside the spec, if there is one. Files are only rewritten when they change, and
// .ts files under the output that the spec no longer produces are deleted. Run it from
// hkdfguard-node, with no dependency but Node:
//
//   node scripts/generate-vault-client.mjs
//
// The spec isn't fetched: pull a newer openapi.json from Vault yourself (`vault read
// sys/internal/specs/openapi` on the Vault version to target) and regenerate.

import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

/** The library's directory under packages/. */
export const LIBRARY = 'integration-hashicorpvault';

/** The settings file looked for beside the spec. */
export const SETTINGS_FILE_NAME = 'generator.json';

// The tags in the order vault-client-go lists them, and what each class holds.
const KNOWN_TAGS = new Map([
  ['auth', "Vault's auth methods and tokens."],
  ['identity', "Vault's identity store: entities, groups, aliases, OIDC and MFA."],
  ['secrets', "Vault's secrets engines."],
  ['system', "Vault's system backend (sys/)."],
]);

// Names generated code uses itself, so a parameter can't take them.
const RESERVED_PARAMETER_NAMES = new Set(['options', 'request', 'requestPath', 'query', 'sender']);
// VaultRequestOptions' own members, so an optional query parameter - one of the options too - can't take them.
const RESERVED_OPTION_NAMES = new Set([
  'token', 'namespace', 'mfaCredentials', 'responseWrappingTtlMs', 'customHeaders', 'requestCallbacks', 'responseCallbacks', 'mountPath',
  'queryParameters', 'replicationForwardingMode', 'signal',
]);
// Words an identifier can't be, in strict-mode TypeScript.
const KEYWORDS = new Set([
  'arguments', 'await', 'break', 'case', 'catch', 'class', 'const', 'continue', 'debugger', 'default', 'delete', 'do', 'else', 'enum', 'eval',
  'export', 'extends', 'false', 'finally', 'for', 'function', 'if', 'implements', 'import', 'in', 'instanceof', 'interface', 'let', 'new',
  'null', 'package', 'private', 'protected', 'public', 'return', 'static', 'super', 'switch', 'this', 'throw', 'true', 'try', 'typeof',
  'var', 'void', 'while', 'with', 'yield',
]);
// vault-client-go's .openapi-generator-ignore: model_*2_request.go, ..., model_enterprise_stub*.
const isExcludedSchema = (name) => name.startsWith('EnterpriseStub')
  || ['Request', 'Response'].some((suffix) => name.endsWith(suffix) && /^[234]$/.test(name.charAt(name.length - suffix.length - 1)));
const PLACEHOLDER = /([^{]*)\{([^}]*)\}/g;
const NON_ALPHANUMERIC = /[^A-Za-z0-9]+/;
const METHODS = ['get', 'put', 'post', 'delete', 'patch'];
const SCHEMA_PREFIX = '#/components/schemas/';
const WIDTH = 150;
const DOC_WIDTH = 100;
// Prose the spec writes with typographic characters, in ASCII.
const ASCII = new Map([
  [0x2018, "'"], [0x2019, "'"], [0x201c, '"'], [0x201d, '"'], [0x2013, '-'], [0x2014, '-'], [0x2026, '...'], [0x00a0, ' '], [0x00b5, 'u'],
  [0x03bc, 'u'],
]);

// --- The spec ------------------------------------------------------------------------------------

const member = (element, name) => (isObject(element) ? element[name] : undefined);
const members = (element) => (isObject(element) ? element : {});
const string = (element, name) => {
  const value = member(element, name);
  return typeof value === 'string' ? value : undefined;
};
const bool = (element, name) => member(element, name) === true;
const has = (element, name) => isObject(element) && Object.hasOwn(element, name);

function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parameters(element) {
  const list = member(element, 'parameters');
  if (!Array.isArray(list)) return [];
  return list.map((p) => ({
    name: string(p, 'name') ?? '',
    location: string(p, 'in') ?? '',
    description: string(p, 'description'),
    schema: member(p, 'schema'),
    required: bool(p, 'required'),
  }));
}

const isMountPath = (parameter) => parameter.location === 'path' && parameter.name.endsWith('_mount_path');

function requestSchema(operationId, operation) {
  if (!has(operation, 'requestBody')) return undefined;
  const content = members(member(member(operation, 'requestBody'), 'content'));
  if (!Object.hasOwn(content, 'application/json') || Object.keys(content).length !== 1) {
    throw new Error(`Operation ${operationId} has a request body that isn't only application/json.`);
  }
  return member(content['application/json'], 'schema');
}

function responseSchema(operation) {
  // The first 2xx response's JSON schema, if it has one.
  for (const [status, response] of Object.entries(members(member(operation, 'responses')))) {
    if (!status.startsWith('2')) continue;
    const content = member(member(response, 'content'), 'application/json');
    return has(content, 'schema') ? member(content, 'schema') : undefined;
  }
  return undefined;
}

/** What the generator needs from Vault's OpenAPI document `root`, in document order. */
export function readSpec(root) {
  const version = string(member(root, 'info'), 'version');
  const operations = [];
  for (const [path, item] of Object.entries(members(member(root, 'paths')))) {
    const shared = parameters(item);
    for (const [method, operation] of Object.entries(members(item))) {
      if (!METHODS.includes(method)) continue;
      const id = string(operation, 'operationId');
      if (id === undefined) throw new Error(`${method} ${path} has no operationId.`);
      const tags = Array.isArray(member(operation, 'tags')) ? member(operation, 'tags') : [];
      if (tags.length !== 1) throw new Error(`Operation ${id} has ${tags.length} tags; the generator expects exactly one.`);
      // Operation parameters first, then the path's that it doesn't override - as openapi-generator orders them.
      const own = parameters(operation);
      const every = [...own, ...shared.filter((s) => !own.some((o) => o.name === s.name && o.location === s.location))];
      operations.push({
        id, tag: tags[0], method: method.toUpperCase(), path,
        summary: string(operation, 'summary'), description: string(operation, 'description'), pathDescription: string(item, 'description'),
        deprecated: bool(operation, 'deprecated'),
        unauthenticated: bool(operation, 'x-vault-unauthenticated') || bool(item, 'x-vault-unauthenticated'),
        sudo: bool(operation, 'x-vault-sudo') || bool(item, 'x-vault-sudo'),
        parameters: every, requestSchema: requestSchema(id, operation), responseSchema: responseSchema(operation),
      });
    }
  }
  return { apiVersion: version ?? '', operations, schemas: members(member(member(root, 'components'), 'schemas')) };
}

/** The schema a $ref names, without its "#/components/schemas/" prefix; undefined if `schema` isn't a $ref. */
export function refName(schema) {
  const reference = string(schema, '$ref');
  if (reference === undefined) return undefined;
  if (!reference.startsWith(SCHEMA_PREFIX)) throw new Error(`Unsupported $ref '${reference}': only ${SCHEMA_PREFIX}... is handled.`);
  return reference.slice(SCHEMA_PREFIX.length);
}

// --- Names and prose -----------------------------------------------------------------------------

/**
 * `name` in PascalCase: split at anything but letters and digits, each part's first letter
 * capitalized - "kv-v2-read" is KvV2Read, as openapi-generator (and the .NET generator) names it.
 */
export function pascal(name) {
  const result = name.split(NON_ALPHANUMERIC).filter((p) => p !== '').map((p) => p[0].toUpperCase() + p.slice(1)).join('');
  if (result === '') return 'Value';
  // Letters and digits only: one can't start with a digit.
  return /^[A-Za-z]/.test(result) ? result : `_${result}`;
}

/** `name` in camelCase: "kv-v2-read" is kvV2Read, "kv_mount_path" kvMountPath, "tokenTTL" tokenTTL. */
export function camel(name) {
  const result = pascal(name);
  return result.startsWith('_') ? result : result[0].toLowerCase() + result.slice(1);
}

/** `value` as a TypeScript string literal, in ASCII. */
export function literal(value) {
  let text = "'";
  for (const c of value) {
    const code = c.codePointAt(0);
    if (c === "'" || c === '\\') text += `\\${c}`;
    else if (c === '\n') text += '\\n';
    else if (c === '\r') text += '\\r';
    else if (c === '\t') text += '\\t';
    else if (code < 0x20 || code > 0x7e) text += code > 0xffff ? `\\u{${code.toString(16)}}` : `\\u${code.toString(16).padStart(4, '0')}`;
    else text += c;
  }
  return `${text}'`;
}

/**
 * `text` for a doc comment: in ASCII, whitespace collapsed to single spaces, and any "*\/" broken
 * up, so prose can never end the comment.
 */
export function doc(text) {
  let ascii = '';
  for (const c of text) ascii += ASCII.get(c.codePointAt(0)) ?? c;
  ascii = ascii.normalize('NFKD').replace(/[^\x00-\x7f]/g, '');
  return ascii.replace(/\s+/g, ' ').trim().replaceAll('*/', '*\\/');
}

function wrap(line, width, hanging) {
  const words = line.split(' ');
  const lines = [];
  let current = '';
  for (const word of words) {
    const prefix = lines.length === 0 ? '' : hanging;
    if (current !== '' && prefix.length + current.length + 1 + word.length > width) {
      lines.push(prefix + current);
      current = word;
    } else {
      current = current === '' ? word : `${current} ${word}`;
    }
  }
  lines.push((lines.length === 0 ? '' : hanging) + current);
  return lines;
}

/**
 * `text` (already {@link doc}-escaped) as a doc comment at `indent`: paragraphs separated by "\n\n",
 * each line of one wrapped on its own - an "@" line with a hanging indent.
 */
export function jsdoc(text, indent) {
  const paragraphs = text.split('\n\n').filter((p) => p !== '')
    .map((p) => p.split('\n').flatMap((line) => wrap(line, DOC_WIDTH - indent.length - 3, line.startsWith('@') ? '  ' : '')));
  if (paragraphs.length === 1 && paragraphs[0].length === 1 && indent.length + paragraphs[0][0].length + 7 <= WIDTH) {
    return `${indent}/** ${paragraphs[0][0]} */\n`;
  }
  const body = paragraphs.map((lines) => lines.map((l) => `${indent} * ${l}`.trimEnd()).join('\n')).join(`\n${indent} *\n`);
  return `${indent}/**\n${body}\n${indent} */\n`;
}

// --- Generating ----------------------------------------------------------------------------------

/**
 * The generated files for the OpenAPI document `openApiJson`, by path relative to the output
 * directory ('/'-separated), each with '\n' line endings.
 * @param settingsJson the generator's settings - {"include": ["^KvV2", ...]} - or undefined to
 *   generate every operation vault-client-go does
 * @throws Error the document uses something the generator doesn't handle, the settings aren't
 *   valid, or an include pattern matches no operation
 */
export function generate(openApiJson, settingsJson) {
  const include = readInclude(settingsJson);
  let root;
  try {
    root = JSON.parse(openApiJson);
  } catch (error) {
    throw new Error(`The spec isn't JSON: ${error.message}`);
  }
  const spec = readSpec(root);
  let operations = spec.operations.filter((o) => !isExcluded(pascal(o.id)));
  if (include !== undefined) {
    for (const pattern of include) {
      if (!operations.some((o) => pattern.test(pascal(o.id)))) throw new Error(`The include pattern '${pattern.source}' matches no operation.`);
    }
    operations = operations.filter((o) => include.some((p) => p.test(pascal(o.id))));
  }

  let schemaNames = new Set(Object.keys(spec.schemas).filter((name) => !isExcludedSchema(name)));
  // Which operations send or return each schema, for its summary and how it's typed.
  const requestUses = new Map();
  const responseUses = new Map();
  const use = (uses, name, operation) => uses.set(name, [...(uses.get(name) ?? []), operation]);
  for (const operation of operations) {
    const requestName = operation.requestSchema === undefined ? undefined : refName(operation.requestSchema);
    if (requestName !== undefined) use(requestUses, requestName, operation);
    const responseName = operation.responseSchema === undefined ? undefined : refName(operation.responseSchema);
    if (responseName !== undefined) use(responseUses, responseName, operation);
  }
  const used = [...requestUses.keys(), ...responseUses.keys()];
  for (const name of used) {
    if (!schemaNames.has(name)) throw new Error(`Schema ${name} is used by a generated operation but is missing or excluded.`);
  }
  // Narrowed, only the schemas the operations use are generated: those they send or return, and
  // those those refer to.
  if (include !== undefined) schemaNames = referenced(spec, used);

  const byType = new Map();
  for (const name of [...schemaNames].sort(byCodeUnits)) byType.set(pascal(name), [...(byType.get(pascal(name)) ?? []), name]);
  for (const [typeName, names] of byType) {
    if (names.length > 1) throw new Error(`Schemas ${names.join(', ')} would all be named ${typeName}.`);
  }

  const tags = orderTags([...new Set(operations.map((o) => o.tag))]);
  const files = { 'index.ts': indexFile(spec, tags), 'apis.ts': apisFile(spec, tags) };
  for (const tag of tags) files[`${kebab(tag)}-api.ts`] = apiFile(spec, tag, operations.filter((o) => o.tag === tag));
  const sortedSchemas = [...schemaNames].sort((a, b) => compare(pascal(a), pascal(b)));
  const models = sortedSchemas.map((name) => model(name, spec.schemas[name], requestUses.get(name) ?? [], responseUses.get(name) ?? []));
  files['schema.ts'] = schemaFile(spec, models);
  // Prose from the spec can carry its own line endings.
  const result = {};
  for (const path of Object.keys(files).sort(compare)) result[path] = files[path].replace(/\r\n?/g, '\n');
  return result;
}

const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

function readInclude(settingsJson) {
  // The settings' include patterns; undefined without settings or an include list.
  if (settingsJson === undefined || settingsJson === null) return undefined;
  let settings;
  try {
    settings = JSON.parse(settingsJson);
  } catch (error) {
    throw new Error(`The generator's settings aren't JSON: ${error.message}`);
  }
  if (!isObject(settings)) throw new Error("The generator's settings must be a JSON object.");
  let include;
  for (const [name, value] of Object.entries(settings)) {
    if (name === 'description') continue;
    if (name !== 'include') throw new Error(`Unknown generator setting '${name}': only "include" and "description" are.`);
    if (!Array.isArray(value) || value.length === 0 || !value.every((p) => typeof p === 'string')) {
      throw new Error('The generator\'s "include" setting must be a non-empty array of regular expressions.');
    }
    try {
      include = value.map((p) => new RegExp(p));
    } catch (error) {
      throw new Error(`An include pattern isn't a regular expression: ${error.message}`);
    }
  }
  return include;
}

function referenced(spec, roots) {
  // roots, and every schema they refer to, however indirectly.
  const found = new Set();
  const pending = [...roots];
  while (pending.length > 0) {
    const name = pending.pop();
    if (found.has(name)) continue;
    found.add(name);
    if (!Object.hasOwn(spec.schemas, name)) throw new Error(`Schema ${name} is referred to but missing.`);
    references(spec.schemas[name], pending);
  }
  return found;
}

function references(element, found) {
  if (Array.isArray(element)) {
    for (const value of element) references(value, found);
  } else if (isObject(element)) {
    const reference = refName(element);
    if (reference !== undefined) {
      found.push(reference);
      return;
    }
    for (const value of Object.values(element)) references(value, found);
  }
}

// vault-client-go's partial_filter_operation.
const isExcluded = (operationName) => /[234]$/.test(operationName) || operationName.startsWith('EnterpriseStub');

function orderTags(tags) {
  return [...[...KNOWN_TAGS.keys()].filter((t) => tags.includes(t)), ...tags.filter((t) => !KNOWN_TAGS.has(t)).sort(compare)];
}

const kebab = (tag) => camel(tag).replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);

/** The class holding `tag`'s operations: AuthApi for "auth". */
export const apiClass = (tag) => `${pascal(tag)}Api`;

/** The method an operation is generated as: kvV2Read for kv-v2-read. */
export const methodName = (operation) => camel(operation.id);

const tagSummary = (tag) => KNOWN_TAGS.get(tag) ?? `Vault's "${tag}" endpoints.`;

function header(spec) {
  return `// Generated by scripts/generate-vault-client.mjs from openapi.json (HashiCorp Vault API ${spec.apiVersion}).\n`
    + "// Don't edit: change the generator or the spec, and regenerate (docs/how-to/use-hashicorp-vault-client.md).\n";
}

function indexFile(spec, tags) {
  let code = header(spec) + "// The typed API generated from Vault's OpenAPI spec: the groups a VaultClient reaches, and their models.\n\n";
  code += "export { VaultApis } from './apis.js';\n";
  for (const tag of tags) code += `export { ${apiClass(tag)} } from './${kebab(tag)}-api.js';\n`;
  code += "export * from './schema.js';\n";
  return code;
}

function apisFile(spec, tags) {
  let code = header(spec) + "import type { VaultRequestOptions } from '../client-options.js';\n";
  code += "import type { JsonValue, JsonWriter } from '../json.js';\n";
  code += "import type { VaultResponse } from '../response.js';\n";
  code += "import { SEND, type Query, type VaultSender } from '../sender.js';\n";
  for (const tag of tags) code += `import { ${apiClass(tag)} } from './${kebab(tag)}-api.js';\n`;
  code += '\n' + jsdoc("The typed groups of Vault's API a VaultClient reaches, generated from Vault's OpenAPI spec.", '');
  code += 'export abstract class VaultApis implements VaultSender {\n';
  code += jsdoc('Sends one request; what the generated methods call.', '  ');
  code += '  abstract [SEND]<T>(\n'
    + '    method: string, path: string, body: ((writer: JsonWriter) => void) | undefined, query: Query, options: VaultRequestOptions | undefined,\n'
    + '    reader: (json: JsonValue) => T | undefined,\n  ): Promise<VaultResponse<T> | undefined>;\n';
  for (const tag of tags) {
    code += '\n' + jsdoc(`${doc(tagSummary(tag))} The ${doc(tag)} endpoints, through this client.`, '  ');
    code += `  get ${camel(tag)}(): ${apiClass(tag)} {\n    return new ${apiClass(tag)}(this);\n  }\n`;
  }
  return code + '}\n';
}

function apiFile(spec, tag, operations) {
  const schemas = new Set();
  const body = operations.map((o) => '\n' + method(o, schemas)).join('');
  let code = header(spec);
  code += "import type { VaultRequestOptions } from '../client-options.js';\n";
  if (body.includes('JsonValue')) code += "import type { JsonValue } from '../json.js';\n";
  code += "import type { VaultResponse } from '../response.js';\n";
  const helpers = ['SEND', 'type VaultSender', 'escapePathSegment', 'queryParameters'];
  if (body.includes('formatQueryValue(')) helpers.push('formatQueryValue');
  if (body.includes('mountPathOr(')) helpers.push('mountPathOr');
  code += importNames('../sender.js', helpers.sort((a, b) => compare(a.replace('type ', ''), b.replace('type ', ''))));
  if (schemas.size > 0) code += importNames('./schema.js', [...schemas].sort(compare));
  code += '\n' + jsdoc(`${doc(tagSummary(tag))} Reached through \`VaultClient.${camel(tag)}\`.`, '');
  code += `export class ${apiClass(tag)} {\n  readonly #sender: VaultSender;\n\n`;
  code += `  constructor(sender: VaultSender) {\n    this.#sender = sender;\n  }\n`;
  return code + body + '}\n';
}

function importNames(module, names) {
  const line = `import { ${names.join(', ')} } from '${module}';\n`;
  if (line.length <= WIDTH) return line;
  return `import {\n${names.map((n) => `  ${n},\n`).join('')}} from '${module}';\n`;
}

function method(operation, schemas) {
  let mount;
  const pathParameters = [];
  const queryParameters = [];
  let lists = false;
  for (const parameter of operation.parameters) {
    if (parameter.location === 'path') {
      if (isMountPath(parameter)) mount ??= parameter;
      else pathParameters.push(parameter);
    } else if (parameter.location === 'query') {
      if (parameter.name === 'list') lists = true;
      else queryParameters.push(parameter);
    } else {
      throw new Error(`Operation ${operation.id} has a ${parameter.location} parameter, ${parameter.name}; only path and query parameters are handled.`);
    }
  }

  // TypeScript names for the parameters, kept clear of each other and of the generated code's own.
  const names = new Set();
  const paths = pathParameters.map((p) => param(operation, p, names, RESERVED_PARAMETER_NAMES));
  const required = queryParameters.filter((p) => p.required).map((p) => param(operation, p, names, RESERVED_PARAMETER_NAMES));
  const optional = queryParameters.filter((p) => !p.required).map((p) => param(operation, p, names, RESERVED_OPTION_NAMES));

  const responseName = operation.responseSchema === undefined ? undefined : refName(operation.responseSchema);
  let responseType;
  let reader;
  if (responseName !== undefined) {
    responseType = pascal(responseName);
    reader = `${responseType}.read`;
    schemas.add(responseType);
  } else {
    responseType = 'Record<string, JsonValue>';
    reader = '(json) => json.readJsonRecord()';
  }

  let requestType;
  let writer;
  if (operation.requestSchema !== undefined) {
    const requestName = refName(operation.requestSchema);
    if (requestName !== undefined) {
      requestType = pascal(requestName);
      writer = `(writer) => ${requestType}.write(writer, request)`;
      schemas.add(requestType);
    } else if (isFreeForm(operation.requestSchema)) {
      requestType = 'Readonly<Record<string, unknown>>';
      writer = '(writer) => writer.value(request)';
    } else {
      throw new Error(`Operation ${operation.id}'s request body is neither a $ref nor a free-form object.`);
    }
  }

  const optionsType = optional.length === 0
    ? 'VaultRequestOptions'
    : `VaultRequestOptions & { ${optional.map((q) => `readonly ${q.name}?: ${q.type}`).join('; ')} }`;
  const signature = [...paths.map((p) => `${p.name}: ${p.type}`)];
  if (requestType !== undefined) signature.push(`request: ${requestType}`);
  signature.push(...required.map((q) => `${q.name}: ${q.type}`));
  signature.push(`options?: ${optionsType}`);

  let description = operation.description;
  const summary = operation.summary ?? description ?? operation.pathDescription;
  if (operation.summary === undefined) description = undefined;
  let remarks = `\`${operation.method} /v1${operation.path}\`${lists ? ' with `list=true`' : ''}.`;
  if (description !== undefined) remarks += ` ${doc(description)}`;
  if (operation.unauthenticated) remarks += ' Needs no token.';
  if (operation.sudo) remarks += ' Needs a token with sudo capability.';
  if (operation.deprecated) remarks += ' Deprecated by Vault.';
  const parameterDocs = paths.map((p) => `@param ${p.name} ${parameterDoc(p.parameter)}`);
  if (requestType !== undefined) parameterDocs.push('@param request The request body.');
  parameterDocs.push(...required.map((q) => `@param ${q.name} ${parameterDoc(q.parameter)}`));
  let optionsDoc = 'Settings for this request; omitted for none.';
  if (mount !== undefined) {
    const engine = operation.tag === 'auth' ? 'auth method' : 'secrets engine';
    optionsDoc += ` Its \`mountPath\` is where the ${engine} is mounted, "${doc(mountDefault(operation, mount))}" by default.`;
  }
  optionsDoc += optional.map((q) => ` Its \`${q.name}\`: ${parameterDoc(q.parameter)}`).join('');
  parameterDocs.push(`@param options ${optionsDoc}`);
  parameterDocs.push("@returns Vault's response; undefined if it has no body", '@throws VaultResponseError Vault refuses the request');
  const summaryDoc = summary ? doc(summary) : `${operation.method} /v1${operation.path}.`;

  let text = jsdoc(`${summaryDoc}\n\n${remarks}\n\n${parameterDocs.join('\n')}`, '  ');
  text += def(`  async ${methodName(operation)}`, signature, `Promise<VaultResponse<${responseType}> | undefined>`);
  if (requestType !== undefined) text += "    if (request === undefined || request === null) throw new TypeError('request must not be undefined.');\n";
  text += assignment('const requestPath', pathExpression(operation, mount, paths));
  text += `    const query = queryParameters(options);\n`;
  if (lists) text += "    query.push(['list', 'true']);\n";
  for (const q of required) text += `    query.push([${literal(q.parameter.name)}, formatQueryValue(${q.name})]);\n`;
  for (const q of optional) {
    text += `    if (options?.${q.name} !== undefined) query.push([${literal(q.parameter.name)}, formatQueryValue(options.${q.name})]);\n`;
  }
  const call = `this.#sender[SEND](${literal(operation.method)}, requestPath, ${writer ?? 'undefined'}, query, options, ${reader})`;
  text += `    return ${call};\n  }\n`;
  return text;
}

function def(start, parameterList, returnType) {
  const line = `${start}(${parameterList.join(', ')}): ${returnType} {\n`;
  if (line.length <= WIDTH) return line;
  return `${start}(\n${parameterList.map((p) => `    ${p},\n`).join('')}  ): ${returnType} {\n`;
}

function assignment(target, parts) {
  const line = `    ${target} = ${parts.join(' + ')};\n`;
  if (line.length <= WIDTH) return line;
  return `    ${target} = ${parts[0]}\n${parts.slice(1).map((p) => `      + ${p}`).join('\n')};\n`;
}

function param(operation, parameter, names, reserved) {
  let name = camel(parameter.name);
  if (KEYWORDS.has(name)) name += 'Parameter';
  while (reserved.has(name) || names.has(name)) name += 'Parameter';
  names.add(name);
  return { parameter, name, type: parameterType(operation, parameter) };
}

function pathExpression(operation, mount, paths) {
  // "/v1" + the path, its placeholders filled in - each escaped as one segment, the mount path
  // with options' or the default - as vault-client-go's strings.Replace(..., url.PathEscape(...)).
  const parts = [];
  let text = '/v1';
  for (const match of `${operation.path}{}`.matchAll(PLACEHOLDER)) {
    text += match[1];
    const placeholder = match[2];
    if (placeholder === '') break;
    if (text !== '') parts.push(literal(text));
    text = '';
    if (mount !== undefined && placeholder === mount.name) {
      parts.push(`escapePathSegment(mountPathOr(options, ${literal(mountDefault(operation, mount))}))`);
      continue;
    }
    const parameter = paths.find((p) => p.parameter.name === placeholder);
    if (parameter === undefined) throw new Error(`Operation ${operation.id}'s path ${operation.path} has a placeholder {${placeholder}} with no parameter.`);
    parts.push(`escapePathSegment(${parameter.name})`);
  }
  if (text !== '') parts.push(literal(text));
  return parts;
}

function mountDefault(operation, mount) {
  const value = string(mount.schema, 'default');
  if (!value) throw new Error(`Operation ${operation.id}'s mount path parameter ${mount.name} has no default.`);
  return value;
}

function parameterType(operation, parameter) {
  const type = string(parameter.schema, 'type');
  switch (type) {
    case 'string': return 'string';
    case 'integer': return 'number';
    case 'boolean': return 'boolean';
    default:
      throw new Error(`Operation ${operation.id}'s parameter ${parameter.name} is a ${type ?? 'typeless'}; only string, integer and boolean are handled.`);
  }
}

function parameterDoc(parameter) {
  let text = doc(parameter.description ?? `The ${parameter.name} ${parameter.location} parameter.`);
  // parameterType has already refused a parameter without a schema.
  if (has(parameter.schema, 'default')) text += ` Vault's default: ${doc(JSON.stringify(member(parameter.schema, 'default')))}.`;
  return text;
}

const isFreeForm = (schema) => string(schema, 'type') === 'object' && !has(schema, 'properties');

// --- Models --------------------------------------------------------------------------------------

// A property's TypeScript type, how a value of it is read from a JsonValue expression, and how one
// is written - each at the lambda depth given, so nested lambdas' parameters don't collide.
function scalar(name, readMethod) {
  return { name, read: (e) => `${e}.${readMethod}()`, write: (e) => `writer.value(${e})` };
}

function container(name, readMethod, writeMethod, item) {
  return {
    name,
    read: (e, depth) => `${e}.${readMethod}((v${depth}) => ${item.read(`v${depth}`, depth + 1)})`,
    write: (e, depth) => `writer.${writeMethod}(${e}, (v${depth}) => ${item.write(`v${depth}`, depth + 1)})`,
  };
}

/**
 * The TypeScript type a property's schema maps to: vault-client-go's type mapping, but with
 * free-form values as `unknown` (sent) or `JsonValue` (returned) where Go has interface{}.
 */
export function typeOf(where, schema, isRequest) {
  const reference = refName(schema);
  if (reference !== undefined) {
    const model = pascal(reference);
    return { name: model, model, read: (e) => `${e}.readModel(${model}.read)`, write: (e) => `${model}.write(writer, ${e})` };
  }
  const free = isRequest
    ? { name: 'unknown', read: (e) => `${e}.readUnknown()`, write: (e) => `writer.value(${e})` }
    : { name: 'JsonValue', read: (e) => `${e}.readJson()`, write: (e) => `writer.value(${e})` };
  const type = string(schema, 'type');
  switch (type) {
    case undefined:
      return free;
    case 'string':
      return string(schema, 'format') === 'date-time' ? scalar('Date', 'readDate') : scalar('string', 'readString');
    case 'integer':
      return scalar('number', 'readInteger');
    case 'number':
      return scalar('number', 'readNumber');
    case 'boolean':
      return scalar('boolean', 'readBoolean');
    case 'array': {
      const items = has(schema, 'items') ? typeOf(where, member(schema, 'items'), isRequest) : free;
      if (items.name === 'JsonValue') return { name: 'JsonValue[]', read: (e) => `${e}.readJsonArray()`, write: (e) => `writer.value(${e})` };
      if (items.name === 'unknown') return { name: 'unknown[]', read: (e) => `${e}.readUnknownArray()`, write: (e) => `writer.value(${e})` };
      return { ...container(`${items.name}[]`, 'readArray', 'array', items), model: items.model };
    }
    case 'object': {
      if (has(schema, 'properties')) throw new Error(`${where} is an object with properties of its own; only free-form objects are handled inline.`);
      const values = member(schema, 'additionalProperties');
      const value = isObject(values) ? typeOf(where, values, isRequest) : free;
      if (value.name === 'JsonValue') {
        return { name: 'Record<string, JsonValue>', read: (e) => `${e}.readJsonRecord()`, write: (e) => `writer.value(${e})` };
      }
      if (value.name === 'unknown') {
        return { name: 'Record<string, unknown>', read: (e) => `${e}.readUnknownRecord()`, write: (e) => `writer.value(${e})` };
      }
      return { ...container(`Record<string, ${value.name}>`, 'readRecord', 'record', value), model: value.model };
    }
    default:
      throw new Error(`${where} has type '${type}', which the generator doesn't handle.`);
  }
}

function model(name, schema, sentBy, returnedBy) {
  if (string(schema, 'type') !== 'object') throw new Error(`Schema ${name} isn't an object; only object schemas are handled.`);
  // Sent, it's written: free-form values are anything, and required members are required.
  // Returned, it's read: free-form values are JSON, and nothing is relied on being there.
  const isRequest = sentBy.length > 0 || (returnedBy.length === 0 && name.endsWith('Request'));
  // As openapi-generator names models: Vault's spec has a few with underscores.
  const typeName = pascal(name);
  const requiredList = member(schema, 'required');
  const required = new Set(Array.isArray(requiredList) ? requiredList : []);

  const properties = [];
  const used = new Set();
  for (const [jsonName, property] of Object.entries(members(member(schema, 'properties')))) {
    const fieldName = camel(jsonName);
    let unique = fieldName;
    for (let i = 2; used.has(unique); i++) unique = `${fieldName}${i}`;
    used.add(unique);
    properties.push({
      jsonName, field: unique, type: typeOf(`${name}.${jsonName}`, property, isRequest), required: isRequest && required.has(jsonName),
      deprecated: bool(property, 'deprecated'), schema: property,
    });
  }

  let code = jsdoc(modelSummary(name, schema, sentBy, returnedBy), '');
  code += `export interface ${typeName} {\n`;
  properties.forEach((p, i) => {
    if (i > 0) code += '\n';
    code += jsdoc(propertyDoc(p), '  ');
    code += `  readonly ${p.field}${p.required ? '' : '?'}: ${p.type.name};\n`;
  });
  code += '}\n\n';

  code += jsdoc(`Reads and writes {@link ${typeName}}.`, '');
  code += `export const ${typeName}: VaultModel<${typeName}> = {\n`;
  code += `  name: ${literal(typeName)},\n\n`;
  code += `  read(json: JsonValue): ${typeName} {\n`;
  code += `    json.requireObject(${literal(typeName)});\n`;
  if (properties.length === 0) {
    code += '    return {};\n';
  } else {
    code += '    return {\n';
    for (const p of properties) code += `      ${p.field}: ${p.type.read(`json.member(${literal(p.jsonName)})`, 0)},\n`;
    // A required member is required of what is sent; what is read may lack it.
    code += properties.some((p) => p.required) ? `    } as ${typeName};\n` : '    };\n';
  }
  code += '  },\n\n';
  const valueName = properties.length === 0 ? '_value' : 'value';
  code += `  write(writer: JsonWriter, ${valueName}: ${typeName}): void {\n`;
  for (const p of properties.filter((p) => p.required)) {
    code += `    if (value.${p.field} === undefined || value.${p.field} === null) throw new TypeError(${literal(`${typeName} needs its ${p.jsonName}.`)});\n`;
  }
  code += '    writer.beginObject();\n';
  for (const p of properties) {
    const write = p.type.write(`value.${p.field}`, 0);
    const name = `writer.name(${literal(p.jsonName)})`;
    // A write through the writer chains onto its name; a model's own write follows it.
    code += write.startsWith('writer.')
      ? `    if (value.${p.field} !== undefined) ${name}${write.slice('writer'.length)};\n`
      : `    if (value.${p.field} !== undefined) {\n      ${name};\n      ${write};\n    }\n`;
  }
  code += '    writer.endObject();\n  },\n};\n';
  return { name: typeName, code };
}

function modelSummary(name, schema, sentBy, returnedBy) {
  const description = string(schema, 'description');
  if (description) return doc(description);
  if (sentBy.length > 0) return `The request body of ${methods(sentBy)}.`;
  if (returnedBy.length > 0) return `The data ${methods(returnedBy)} return${returnedBy.length === 1 ? 's' : ''}.`;
  return `The ${doc(name)} schema.`;
}

const methods = (operations) => operations.map((o) => `{@link ${apiClass(o.tag)}.${methodName(o)}}`).join(', ');

function propertyDoc(p) {
  let text = doc(string(p.schema, 'description') || 'Not described by Vault\'s spec.');
  const remarks = [];
  if (string(p.schema, 'format') === 'duration') remarks.push('A duration: seconds, or a Go duration such as "24h".');
  const values = member(p.schema, 'enum');
  if (Array.isArray(values)) remarks.push(`One of: ${values.map((v) => JSON.stringify(v)).join(', ')}.`);
  if (has(p.schema, 'default')) remarks.push(`Vault's default: ${JSON.stringify(member(p.schema, 'default'))}.`);
  if (p.required) remarks.push('Required.');
  if (p.deprecated) remarks.push('Deprecated by Vault.');
  if (remarks.length > 0) text += `\n\n${doc(remarks.join(' '))}`;
  return text;
}

function schemaFile(spec, models) {
  let code = header(spec) + '// The models of the request and response bodies the generated methods send and return: an interface each,\n'
    + '// and a constant of the same name that reads and writes it.\n';
  code += "import type { JsonValue, JsonWriter, VaultModel } from '../json.js';\n";
  return code + models.map((m) => `\n${m.code}`).join('');
}

// --- The command line ----------------------------------------------------------------------------

/** The directory at or above `start` holding the workspace's package.json (name hkdfguard-node); undefined if there is none. */
export function workspaceRoot(start) {
  for (let directory = resolve(start); ; directory = dirname(directory)) {
    const packageJson = join(directory, 'package.json');
    if (existsSync(packageJson)) {
      try {
        if (JSON.parse(readFileSync(packageJson, 'utf8')).name === 'hkdfguard-node') return directory;
      } catch {
        // Not JSON: not the workspace's.
      }
    }
    if (dirname(directory) === directory) return undefined;
  }
}

function listTs(directory) {
  const found = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) found.push(...listTs(path));
    else if (entry.isFile() && entry.name.endsWith('.ts')) found.push(path);
  }
  return found.sort(compare);
}

/**
 * Runs the command.
 * @param output, error where to write its messages: anything with write(text)
 * @returns 0 on success, 2 for bad arguments or no workspace root
 * @throws Error the spec or settings are refused by the generator
 */
export function run(args, currentDirectory, output, error) {
  const options = {};
  for (let i = 0; i < args.length; i += 2) {
    const argument = args[i];
    if (!['--spec', '--settings', '--output'].includes(argument) || i + 1 >= args.length) {
      error.write(`Unknown argument '${argument}'. Usage: [--spec <openapi.json>] [--settings <generator.json>] [--output <directory>]\n`);
      return 2;
    }
    options[argument.slice(2)] = resolve(currentDirectory, args[i + 1]);
  }

  let spec = options.spec;
  let outputDirectory = options.output;
  if (spec === undefined || outputDirectory === undefined) {
    const root = workspaceRoot(currentDirectory);
    if (root === undefined) {
      error.write("Couldn't find the workspace root (hkdfguard-node's package.json) at or above the current directory; run from inside it, "
        + 'or pass --spec and --output.\n');
      return 2;
    }
    const library = join(root, 'packages', LIBRARY);
    spec ??= join(library, 'openapi.json');
    outputDirectory ??= join(library, 'src', 'generated');
  }
  const settings = options.settings ?? join(dirname(spec), SETTINGS_FILE_NAME);

  const hasSettings = existsSync(settings) && statSync(settings).isFile();
  const files = generate(readFileSync(spec, 'utf8'), hasSettings ? readFileSync(settings, 'utf8') : undefined);
  let written = 0;
  const expected = new Set();
  for (const [relative, content] of Object.entries(files)) {
    const path = resolve(outputDirectory, ...relative.split('/'));
    expected.add(path);
    if (existsSync(path) && readFileSync(path, 'utf8').replace(/\r\n/g, '\n') === content) continue;
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content, 'utf8');
    written++;
  }
  let deleted = 0;
  if (existsSync(outputDirectory) && statSync(outputDirectory).isDirectory()) {
    for (const path of listTs(outputDirectory)) {
      if (!expected.has(resolve(path))) {
        unlinkSync(path);
        deleted++;
      }
    }
  }
  const withSettings = hasSettings ? ` with ${settings}` : '';
  const count = Object.keys(files).length;
  output.write(`${count} files from ${spec}${withSettings}: ${written} written, ${count - written} unchanged, ${deleted} stale deleted, `
    + `in ${outputDirectory}.\n`);
  return 0;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    process.exitCode = run(process.argv.slice(2), process.cwd(), process.stdout, process.stderr);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}

// Ordinal order, UTF-16 code unit by code unit, so the generated code is the same on every machine.
function byCodeUnits(a, b) {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

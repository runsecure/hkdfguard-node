import { strict as assert } from 'node:assert';
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { describe, it } from 'node:test';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import type { ProtectedReadOnlyCache } from '@runsecure/hkdfguard-abstractions';
import { KeyRing } from '@runsecure/hkdfguard-dek';
import { RecordingKey } from '@runsecure/hkdfguard-test-support';
import { AwsSecretsManagerSecretCache } from './cache.js';

/*
 * Real calls against a secret the caller provides, named in aws.test.properties at the repository
 * root (or the environment; see setting), as the principal whose access keys are in the environment
 * or the shared credentials file (see credentials); the region comes from the SDK's usual chain
 * (AWS_REGION, the profile's region in ~/.aws/config):
 *
 *   aws configure
 *   HKDFGUARD_TEST_AWS_SECRET_NAME=hkdfguard-test/key-value npm test --workspace packages/cache-awssecretsmanager
 *
 * Without HKDFGUARD_TEST_AWS_SECRET_NAME every test here is reported as skipped - never as passed -
 * the same variable the .NET, Java and Python integration tests read. Once it names a secret, a
 * failing call - or a value that isn't a secret name - is a test failure. To check what the secret
 * holds, not just that it holds something, also set HKDFGUARD_TEST_AWS_SECRET_JSON to the JSON object
 * its SecretString is expected to hold (a key/value secret, as the console stores one): the whole
 * value and each key, read as "name#key", are then compared with it. The principal needs only
 * secretsmanager:GetSecretValue on that secret's folder (and kms:Decrypt on its key, if it isn't the
 * AWS managed one); the tests never list, create, alter or delete a secret. See
 * docs/how-to/run-aws-secrets-manager-cache-integration-tests.md.
 */

const SECRET_NAME_VARIABLE = 'HKDFGUARD_TEST_AWS_SECRET_NAME';
const EXPECTED_JSON_VARIABLE = 'HKDFGUARD_TEST_AWS_SECRET_JSON';
const SETTINGS_FILE = 'aws.test.properties';
const HOW_TO = 'docs/how-to/run-aws-secrets-manager-cache-integration-tests.md';

/**
 * The settings file at the repository root - the nearest directory above this file that holds
 * package-lock.json - as NAME=value lines, '#' and '!' starting a comment; empty if there is none.
 * The same file as hkdfguard-java's and hkdfguard-python's: a local file, ignored by git, naming the
 * secret (and its expected content) only - credentials come from {@link credentials}, so no
 * credential ever goes in it.
 */
function settings(): Map<string, string> {
  const values = new Map<string, string>();
  for (let directory = __dirname; ; directory = dirname(directory)) {
    if (existsSync(join(directory, 'package-lock.json'))) {
      const file = join(directory, SETTINGS_FILE);
      if (!existsSync(file)) return values;
      for (const raw of readFileSync(file, 'utf8').split(/\r?\n/)) {
        const line = raw.trim();
        const equals = line.indexOf('=');
        if (line !== '' && !line.startsWith('#') && !line.startsWith('!') && equals > 0) {
          values.set(line.slice(0, equals).trim(), line.slice(equals + 1).trim());
        }
      }
      return values;
    }
    if (dirname(directory) === directory) return values;
  }
}

const file = settings();

/** `variable` from the environment, else from the settings file; undefined if neither sets it. */
function setting(variable: string): string | undefined {
  return process.env[variable] || file.get(variable) || undefined;
}

const secretName = setting(SECRET_NAME_VARIABLE);
const expectedJson = setting(EXPECTED_JSON_VARIABLE);

/** The test principal's access keys, as a SecretsManagerClient's `credentials`. */
interface AccessKeys {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

/**
 * The test principal's access keys: from AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY (and
 * AWS_SESSION_TOKEN), else from the shared credentials file's profile (AWS_PROFILE, or default) -
 * the file aws configure writes (AWS_SHARED_CREDENTIALS_FILE, or ~/.aws/credentials), read on its
 * own, as hkdfguard-java's and hkdfguard-python's tests read it. The SDK's default chain merges
 * ~/.aws/config into that profile, and a login_session there (from aws login) would take precedence
 * over its keys, running the tests as whoever signed in rather than as the test principal. No
 * message here ever quotes a key.
 */
function credentials(): AccessKeys {
  const fromEnvironment = { id: process.env['AWS_ACCESS_KEY_ID'], secret: process.env['AWS_SECRET_ACCESS_KEY'] };
  if (fromEnvironment.id && fromEnvironment.secret) {
    return keys(fromEnvironment.id, fromEnvironment.secret, process.env['AWS_SESSION_TOKEN']);
  }

  const path = process.env['AWS_SHARED_CREDENTIALS_FILE'] || join(homedir(), '.aws', 'credentials');
  if (!existsSync(path)) assert.fail(`There is no AWS credentials file at ${path}; run aws configure, or set AWS_ACCESS_KEY_ID. See ${HOW_TO}.`);
  const profileName = process.env['AWS_PROFILE'] || 'default';
  const profile = readProfile(readFileSync(path, 'utf8'), profileName);
  const id = profile.get('aws_access_key_id');
  const secret = profile.get('aws_secret_access_key');
  if (!id || !secret) {
    assert.fail(`The [${profileName}] profile in ${path} has no aws_access_key_id and aws_secret_access_key; run aws configure. See ${HOW_TO}.`);
  }
  return keys(id, secret, profile.get('aws_session_token'));
}

function keys(accessKeyId: string, secretAccessKey: string, sessionToken: string | undefined): AccessKeys {
  return sessionToken ? { accessKeyId, secretAccessKey, sessionToken } : { accessKeyId, secretAccessKey };
}

// One [section] of an INI file - the credentials file's format - as name = value pairs; ';' and
// '#' start a comment line.
function readProfile(text: string, section: string): Map<string, string> {
  const values = new Map<string, string>();
  let current: string | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#') || line.startsWith(';')) continue;
    if (line.startsWith('[') && line.endsWith(']')) {
      current = line.slice(1, -1).trim();
      continue;
    }
    const equals = line.indexOf('=');
    if (current === section && equals > 0) values.set(line.slice(0, equals).trim(), line.slice(equals + 1).trim());
  }
  return values;
}

// A value the cache would report missing without a call (a placeholder or an ARN, say) fails with a
// message naming the variable, rather than as a secret that isn't there.
function checkedName(): string {
  const name = secretName!;
  if (!AwsSecretsManagerSecretCache.isValidSecretName(name)) {
    assert.fail(`${SECRET_NAME_VARIABLE} is ${JSON.stringify(name)}, which isn't a secret's name: 1-${AwsSecretsManagerSecretCache.MAX_SECRET_NAME_LENGTH} `
      + `ASCII letters, digits and /_+=.@- (not an ARN). See ${HOW_TO}.`);
  }
  return name;
}

/**
 * Runs `test` with a cache over a client the test owns, as an application would: created here with
 * the test principal's keys, destroyed afterwards.
 */
async function withCache(test: (cache: AwsSecretsManagerSecretCache, name: string) => Promise<void>): Promise<void> {
  const name = checkedName();
  const client = new SecretsManagerClient({ credentials: credentials() });
  try {
    const ring = new KeyRing();
    ring.add(1, new RecordingKey());
    await test(new AwsSecretsManagerSecretCache(client, ring), name);
  } finally {
    client.destroy();
  }
}

// --- The expected secret (hkdfguard-dotnet's ExpectedSecret) ---------------------------------------

/** HKDFGUARD_TEST_AWS_SECRET_JSON's JSON object, parsed with `reviver`. */
function expected(reviver?: (key: string, value: unknown, context?: { source?: string }) => unknown): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(expectedJson!, reviver as never);
  } catch {
    assert.fail(`${EXPECTED_JSON_VARIABLE} isn't JSON.`);
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) assert.fail(`${EXPECTED_JSON_VARIABLE} isn't a JSON object.`);
  return value as Record<string, unknown>;
}

/** A JSON number, kept as the text it was written as. */
class JsonNumber {
  constructor(readonly text: string) {}
}

/**
 * Each member as the cache reveals it under "name#key": a string as its text, a number, true or
 * false as its JSON text (a number exactly as written); null, objects and arrays aren't keys.
 */
function members(): [key: string, value: string][] {
  const object = expected((_key, value, context) => (typeof value === 'number' && context?.source !== undefined ? new JsonNumber(context.source) : value));
  const found: [string, string][] = [];
  for (const [key, value] of Object.entries(object)) {
    if (typeof value === 'string') found.push([key, value]);
    else if (typeof value === 'boolean') found.push([key, String(value)]);
    else if (value instanceof JsonNumber) found.push([key, value.text]);
  }
  return found;
}

/** The value stored under `name`, as text; fails the test if there is none. */
async function decrypt(cache: ProtectedReadOnlyCache, name: string): Promise<string> {
  const length = await cache.maxDecryptedLength(name);
  if (length === undefined || length === 0) assert.fail(`Nothing is stored under ${JSON.stringify(name)}.`);
  const result = new Uint8Array(length);
  return new TextDecoder().decode(result.subarray(0, await cache.decrypt(name, result)));
}

/**
 * Asserts `whole` is HKDFGUARD_TEST_AWS_SECRET_JSON's object, compared as JSON, so whitespace the
 * store added or removed doesn't matter. Never quotes either value.
 */
function assertWholeValue(whole: string): void {
  let actual: unknown;
  try {
    actual = JSON.parse(whole);
  } catch {
    actual = undefined;
  }
  if (!isDeepStrictEqual(actual, expected())) assert.fail('The secret\'s whole value isn\'t the expected JSON object.');
}

// Never quotes either value, as assert.equal's message would.
function assertKey(actual: string, expectedValue: string, key: string): void {
  if (actual !== expectedValue) assert.fail(`Key ${JSON.stringify(key)} isn't the expected value.`);
}

describe('AWS Secrets Manager cache integration', {
  skip: secretName === undefined
    && `Set ${SECRET_NAME_VARIABLE} to a secret's name, in the environment or ${SETTINGS_FILE}, to run AWS Secrets Manager cache integration tests.`,
}, () => {
  const contentSkip = expectedJson === undefined
    && `Set ${SECRET_NAME_VARIABLE} and ${EXPECTED_JSON_VARIABLE}, in the environment or ${SETTINGS_FILE}, to check a secret's contents.`;

  it('reveals the secret through decrypt, after finding it through maxDecryptedLength', () => withCache(async (cache, name) => {
    const length = await cache.maxDecryptedLength(name);
    assert.ok(length !== undefined && length > 0);
    assert.ok(await cache.decrypt(name, new Uint8Array(length)) > 0);
  }));

  it('reveals the secret through a first lookup that is decrypt', () => withCache(async (cache, name) => {
    // A size no AWS secret exceeds (64 KiB), so decrypt fetches it with nothing looked up before.
    assert.ok(await cache.decrypt(name, new Uint8Array(64 * 1024)) > 0);
    assert.ok((await cache.maxDecryptedLength(name))! > 0);
  }));

  it('reveals the expected whole value, and every key', { skip: contentSkip }, () => withCache(async (cache, name) => {
    const keys = members();

    assertWholeValue(await decrypt(cache, name));
    for (const [key, value] of keys) assertKey(await decrypt(cache, `${name}#${key}`), value, key);
    assert.equal(await cache.decrypt(`${name}#no-such-key`, new Uint8Array(16)), 0);
  }));

  it('reveals every key, and the expected whole value, when a key is looked up first', { skip: contentSkip }, () => withCache(async (cache, name) => {
    const keys = members();

    for (const [key, value] of keys) assertKey(await decrypt(cache, `${name}#${key}`), value, key);
    assertWholeValue(await decrypt(cache, name));
    assert.equal(await cache.decrypt(`${name}#no-such-key`, new Uint8Array(16)), 0);
  }));

  it('returns 0 for a secret that doesn\'t exist', () => withCache(async (cache, name) => {
    // Beside the configured secret, so a policy granting GetSecretValue on its folder covers it:
    // without permission, Secrets Manager answers AccessDeniedException even for a secret that
    // doesn't exist.
    const folder = name.slice(0, name.lastIndexOf('/') + 1);
    assert.equal(await cache.decrypt(`${folder}hkdfguard-missing-${randomUUID().replaceAll('-', '')}`, new Uint8Array(16)), 0);
  }));
});

import { strict as assert } from 'node:assert';
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { isDeepStrictEqual } from 'node:util';
import type { PipelinePolicy } from '@azure/core-rest-pipeline';
import { DefaultAzureCredential } from '@azure/identity';
import type { ProtectedReadOnlyCache } from '@runsecure/hkdfguard-abstractions';
import { KeyRing } from '@runsecure/hkdfguard-dek';
import { RecordingKey } from '@runsecure/hkdfguard-test-support';
import { AzureKeyVaultSecretCache } from './cache.js';

/*
 * Real calls against a secret the caller provides, named in azure.test.properties at the repository
 * root (or the environment; see setting). Credentials come from DefaultAzureCredential (environment,
 * workload or managed identity, Azure CLI, ...):
 *
 *   az login
 *   npm test --workspace packages/cache-azurekeyvault
 *
 * Without the secret every test here is reported as skipped - never as passed - the same variables
 * the .NET, Java and Python integration tests read. Once it is named, a failing call - or a value
 * that isn't a secret identifier - is a test failure. The identity needs only get on secrets (the
 * Key Vault Secrets User role); the tests never list, create, change or delete a secret.
 *
 * To check what the secret holds, not just that it holds something, set
 * HKDFGUARD_TEST_AZURE_SECRET_JSON to the JSON object it is expected to hold: the whole value and
 * each member, read as "name#key", are then compared with it. Set
 * HKDFGUARD_TEST_AZURE_SEPARATE_SECRETS=true as well when the vault also holds each member as a
 * secret of its own, named by its key; those are then read and compared too. No assertion here ever
 * prints a value. See docs/how-to/run-azure-key-vault-secret-cache-integration-tests.md.
 */

const SECRET_ID_VARIABLE = 'HKDFGUARD_TEST_AZURE_SECRET_ID';
const EXPECTED_JSON_VARIABLE = 'HKDFGUARD_TEST_AZURE_SECRET_JSON';
const SEPARATE_SECRETS_VARIABLE = 'HKDFGUARD_TEST_AZURE_SEPARATE_SECRETS';
const SETTINGS_FILE = 'azure.test.properties';
const HOW_TO = 'docs/how-to/run-azure-key-vault-secret-cache-integration-tests.md';

/**
 * The settings file at the repository root - the nearest directory above this file that holds
 * package-lock.json - as NAME=value lines, '#' and '!' starting a comment; empty if there is none.
 * The same local file, ignored by git, that the key wrapping integration tests and hkdfguard-java's
 * and hkdfguard-python's read: it names a secret only - DefaultAzureCredential signs in with az
 * login, so no credential ever goes in it.
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

/**
 * The variable from the environment - where setting it, even to empty, overrides the file - else
 * from the settings file; undefined if it is unset or empty.
 */
function setting(variable: string): string | undefined {
  const value = (variable in process.env ? process.env[variable] : file.get(variable)) ?? '';
  return value.trim() || undefined;
}

/**
 * The configured secret's vault URL and name. A value that isn't a secret identifier without a
 * version (a placeholder left in place, say) fails with a message naming the variable.
 */
function secretId(): { vaultUrl: string; name: string } {
  const value = setting(SECRET_ID_VARIABLE)!;
  const url = URL.canParse(value) ? new URL(value) : undefined;
  const segments = url?.pathname.replace(/^\/+|\/+$/g, '').split('/') ?? [];
  if (url === undefined || url.protocol !== 'https:' || url.host === '' || url.search !== '' || segments.length !== 2 || segments[0] !== 'secrets'
    || !AzureKeyVaultSecretCache.isValidSecretName(segments[1])) {
    assert.fail(`${SECRET_ID_VARIABLE} is ${JSON.stringify(value)}, which isn't a secret identifier without a version: `
      + `https://{vault}.vault.azure.net/secrets/{name}. See ${HOW_TO}.`);
  }
  return { vaultUrl: `https://${url.host}/`, name: segments[1]! };
}

/**
 * Each member of the expected JSON object as the cache reveals it under "name#key": a string as its
 * text, a number, true or false as its JSON text as written; null, an object or an array not at all.
 */
function expectedMembers(): [key: string, value: string][] {
  const text = setting(EXPECTED_JSON_VARIABLE)!;
  // The reviver's context holds each primitive's source text (V8's JSON.parse source text access).
  type Reviver = (key: string, value: unknown, context?: { source?: string }) => unknown;
  const reviver: Reviver = (_key, value, context) => (typeof value === 'number' ? context?.source ?? String(value) : value);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text, reviver as (key: string, value: unknown) => unknown);
  } catch {
    assert.fail(`${EXPECTED_JSON_VARIABLE} isn't JSON. See ${HOW_TO}.`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) assert.fail(`${EXPECTED_JSON_VARIABLE} isn't a JSON object. See ${HOW_TO}.`);

  const members: [string, string][] = [];
  for (const [key, value] of Object.entries(parsed)) {
    // Numbers are already their source text.
    if (typeof value === 'string' || typeof value === 'boolean') members.push([key, String(value)]);
  }
  return members;
}

/**
 * Asserts `whole` is the expected object, compared as JSON - structurally, numbers by value - so
 * whitespace the store added or removed doesn't matter. The message never quotes either.
 */
function assertWholeValue(whole: string): void {
  let actual: unknown;
  try {
    actual = JSON.parse(whole);
  } catch {
    assert.fail('The secret\'s whole value isn\'t JSON.');
  }
  assert.ok(isDeepStrictEqual(actual, JSON.parse(setting(EXPECTED_JSON_VARIABLE)!)), 'The secret\'s whole value isn\'t the expected JSON object.');
}

function newRing(): KeyRing {
  // The ring's key is local: only the secret comes from Azure.
  const ring = new KeyRing();
  ring.add(1, new RecordingKey());
  return ring;
}

/** The value stored under `name`, as text; fails the test if there is none. */
async function decrypt(cache: ProtectedReadOnlyCache, name: string): Promise<string> {
  const length = await cache.maxDecryptedLength(name);
  assert.ok(length !== undefined, `Nothing is stored under '${name}'.`);
  const result = new Uint8Array(length);
  return new TextDecoder().decode(result.subarray(0, await cache.decrypt(name, result)));
}

const hasSecret = setting(SECRET_ID_VARIABLE) !== undefined;
const hasJson = hasSecret && setting(EXPECTED_JSON_VARIABLE) !== undefined;
const hasSeparateSecrets = hasJson && setting(SEPARATE_SECRETS_VARIABLE)?.toLowerCase() === 'true';

describe('Azure Key Vault secret cache integration', {
  skip: !hasSecret && `Set ${SECRET_ID_VARIABLE} to a secret's identifier, in the environment or ${SETTINGS_FILE}, to run Azure Key Vault secret cache integration tests.`,
}, () => {
  const credential = new DefaultAzureCredential();
  const cache = (options: ConstructorParameters<typeof AzureKeyVaultSecretCache>[4] = {}) =>
    new AzureKeyVaultSecretCache(secretId().vaultUrl, credential, newRing(), undefined, options);
  const skipWithoutJson = !hasJson && `Set ${SECRET_ID_VARIABLE} and ${EXPECTED_JSON_VARIABLE} to check a secret's contents.`;

  it('reveals the secret', async () => {
    const { name } = secretId();
    const secrets = cache();

    const length = await secrets.maxDecryptedLength(name);
    assert.ok(length !== undefined, `Nothing is stored under '${name}'.`);
    assert.ok(await secrets.decrypt(name, new Uint8Array(length)) > 0);
  });

  it('gives SecretClient only the response with the value blanked', async () => {
    const { name } = secretId();
    const bodies: string[] = [];
    const recorder: PipelinePolicy = {
      name: 'bodyRecorder',
      async sendRequest(request, next) {
        const response = await next(request);
        if (response.status === 200) bodies.push(response.bodyAsText ?? '');
        return response;
      },
    };
    const secrets = cache({ clientOptions: { additionalPolicies: [{ policy: recorder, position: 'perCall' }] } });

    const value = await decrypt(secrets, name);
    assert.equal(bodies.length, 1, 'One Get Secret response was expected.');
    assert.ok(/"value"\s*:\s*""/.test(bodies[0]!), 'The response SecretClient was given doesn\'t hold a blank value.');
    assert.ok(!bodies[0]!.includes(value), 'The response SecretClient was given holds the secret\'s value.');
  });

  it('reveals the expected whole value', { skip: skipWithoutJson }, async () => {
    assertWholeValue(await decrypt(cache(), secretId().name));
  });

  it('reveals every key the secret holds, and nothing for a key it doesn\'t', { skip: skipWithoutJson }, async () => {
    const { name } = secretId();
    const secrets = cache();

    for (const [key, value] of expectedMembers()) {
      assert.ok(await decrypt(secrets, `${name}#${key}`) === value, `'${name}#${key}' doesn't hold the expected value.`);
    }
    assert.equal(await secrets.decrypt(`${name}#no-such-key`, new Uint8Array(16)), 0);
    // Every key came from the one fetch: the whole value is cached too.
    assertWholeValue(await decrypt(secrets, name));
  });

  it('reads each key as a secret of its own, holding the same value', {
    skip: !hasSeparateSecrets && `Set ${SEPARATE_SECRETS_VARIABLE}=true, with ${SECRET_ID_VARIABLE} and ${EXPECTED_JSON_VARIABLE}, when the vault `
      + 'holds each expected key as a secret of its own.',
  }, async () => {
    const secrets = cache();

    for (const [key, value] of expectedMembers()) {
      assert.ok(AzureKeyVaultSecretCache.isValidSecretName(key), `'${key}' can't be a Key Vault secret name.`);
      assert.ok(await decrypt(secrets, key) === value, `The secret '${key}' doesn't hold the expected value.`);
      // Key Vault matches secret names ignoring case, so the cache does too.
      assert.ok(await decrypt(secrets, key.toUpperCase()) === value, `The secret '${key.toUpperCase()}' doesn't hold the expected value.`);
    }
  });

  it('reports a secret that doesn\'t exist as 0', async () => {
    assert.equal(await cache().decrypt(`hkdfguard-missing-${randomUUID().replaceAll('-', '')}`, new Uint8Array(16)), 0);
  });
});

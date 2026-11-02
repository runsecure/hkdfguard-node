import { strict as assert } from 'node:assert';
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { after, describe, it } from 'node:test';
import { isDeepStrictEqual } from 'node:util';
import { SecretManagerServiceClient } from '@google-cloud/secret-manager';
import type { ProtectedReadOnlyCache } from '@runsecure/hkdfguard-abstractions';
import { KeyRing } from '@runsecure/hkdfguard-dek';
import { RecordingKey } from '@runsecure/hkdfguard-test-support';
import { GoogleSecretManagerSecretCache } from './cache.js';

/*
 * Real calls against a Secret Manager secret the caller provides, named in google.test.properties at
 * the repository root (or the environment; see configured). Credentials come from Application
 * Default Credentials (an attached service account, workload identity federation, or gcloud):
 *
 *   gcloud auth application-default login
 *   npm test --workspace packages/cache-googlesecretmanager
 *
 * Without HKDFGUARD_TEST_GOOGLE_SECRET_NAME every test here is reported as skipped - never as passed -
 * the same variable the .NET, Java and Python integration tests read. Once it is named, a failing
 * call - or a value that isn't a secret's resource name - is a test failure. To check what the secret
 * holds, not just that it holds something, set HKDFGUARD_TEST_GOOGLE_SECRET_JSON to the JSON object
 * its latest version's payload is expected to hold: the whole value and each member, read as
 * "id#key", are then compared with it. No value is ever printed, matching or not. The principal needs
 * only secretmanager.versions.access on the secret (the Secret Manager Secret Accessor role); the
 * tests never list, create, alter or delete a secret. See
 * docs/how-to/run-google-secret-manager-cache-integration-tests.md.
 */

const SECRET_NAME_VARIABLE = 'HKDFGUARD_TEST_GOOGLE_SECRET_NAME';
const EXPECTED_JSON_VARIABLE = 'HKDFGUARD_TEST_GOOGLE_SECRET_JSON';
const SETTINGS_FILE = 'google.test.properties';

/**
 * The settings file at the repository root - the nearest directory above this file that holds
 * package-lock.json - as NAME=value lines, '#' and '!' starting a comment; empty if there is none.
 * This repository's counterpart of hkdfguard-dotnet's google.runsettings, and the same file as
 * hkdfguard-java's and hkdfguard-python's: a local file, ignored by git, naming the secret only -
 * Application Default Credentials sign in with gcloud, so no credential ever goes in it.
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

/** The variable's value from the environment, else from the settings file; undefined if neither gives one. */
function configured(variable: string): string | undefined {
  return process.env[variable] || settings().get(variable) || undefined;
}

/**
 * The configured secret's project and ID. A value that isn't a secret's resource name (a placeholder
 * left in place, say) fails with a message naming the variable, rather than as an argument error from
 * the cache.
 */
function secret(): { projectId: string; id: string } {
  const value = configured(SECRET_NAME_VARIABLE)!;
  const match = /^projects\/([^/[\]{}<>]+)\/secrets\/([^/[\]{}<>]+)$/.exec(value);
  if (match === null) {
    assert.fail(`${SECRET_NAME_VARIABLE} is ${JSON.stringify(value)}, which isn't a secret's resource name: projects/{project}/secrets/{secret}. `
      + `Replace the placeholders in ${SETTINGS_FILE} (docs/how-to/run-google-secret-manager-cache-integration-tests.md).`);
  }
  return { projectId: match[1]!, id: match[2]! };
}

/**
 * Each member of the expected JSON object as the cache reveals it under "id#key": a string as its
 * text, a number as its JSON text, true or false as theirs. Null, objects and arrays are left out, as
 * the cache leaves them out.
 */
function expectedMembers(): [string, string][] {
  const seen: { holder: unknown; key: string; value: unknown; source: string | undefined }[] = [];
  // The reviver's third argument holds a primitive's source text, so a number keeps its JSON text.
  const top: unknown = JSON.parse(configured(EXPECTED_JSON_VARIABLE)!, function (this: unknown, key: string, value: unknown, context?: { source?: string }) {
    seen.push({ holder: this, key, value, source: context?.source });
    return value;
  } as (this: unknown, key: string, value: unknown) => unknown);
  if (typeof top !== 'object' || top === null || Array.isArray(top)) assert.fail(`${EXPECTED_JSON_VARIABLE} isn't a JSON object.`);
  return seen
    .filter((s) => s.holder === top && (typeof s.value === 'string' || typeof s.value === 'number' || typeof s.value === 'boolean'))
    .map((s) => [s.key, typeof s.value === 'string' ? s.value : s.source ?? String(s.value)]);
}

/** Asserts `whole` is the expected object, compared as JSON (so whitespace doesn't matter), never printing either. */
function assertWholeValue(whole: string): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(whole);
  } catch {
    assert.fail('The secret\'s whole value isn\'t JSON.');
  }
  assert.ok(isDeepStrictEqual(parsed, JSON.parse(configured(EXPECTED_JSON_VARIABLE)!)), 'The secret\'s whole value isn\'t the expected JSON object.');
}

/** The value stored under `name`, as text; fails the test if there is none. */
async function decrypt(cache: ProtectedReadOnlyCache, name: string): Promise<string> {
  const length = await cache.maxDecryptedLength(name);
  assert.ok(length !== undefined && length > 0, `Nothing is stored under '${name}'.`);
  const result = new Uint8Array(length);
  return new TextDecoder().decode(result.subarray(0, await cache.decrypt(name, result)));
}

/** A ring whose one key is made up locally: these tests check the cache's Secret Manager calls, not wrapping. */
function newRing(): KeyRing {
  const ring = new KeyRing();
  ring.add(1, new RecordingKey());
  return ring;
}

const secretName = configured(SECRET_NAME_VARIABLE);
const expectedJson = configured(EXPECTED_JSON_VARIABLE);
const needsExpectedJson = expectedJson === undefined && `Set ${SECRET_NAME_VARIABLE} and ${EXPECTED_JSON_VARIABLE} to check a secret's contents.`;

describe('Google Secret Manager cache integration', {
  skip: secretName === undefined && `Set ${SECRET_NAME_VARIABLE} to a secret's resource name (projects/{project}/secrets/{secret}), in the environment or `
    + `${SETTINGS_FILE}, to run Google Secret Manager cache integration tests.`,
}, () => {
  const caches: GoogleSecretManagerSecretCache[] = [];
  after(() => Promise.all(caches.map((c) => c.close())));
  // A cache over a client of its own, signed in with Application Default Credentials.
  const created = () => {
    const cache = GoogleSecretManagerSecretCache.create(secret().projectId, newRing());
    caches.push(cache);
    return cache;
  };

  it('reveals the secret through a client of its own', async () => {
    const { id } = secret();
    const cache = created();
    const length = await cache.maxDecryptedLength(id);
    assert.ok(length !== undefined && length > 0);
    assert.ok(await cache.decrypt(id, new Uint8Array(length)) > 0);
  });

  it('reveals the secret through the application\'s own client', async () => {
    const { projectId, id } = secret();
    const client = new SecretManagerServiceClient();
    try {
      const cache = new GoogleSecretManagerSecretCache(client, projectId, newRing());
      assert.ok((await decrypt(cache, id)).length > 0);
    } finally {
      await client.close();
    }
  });

  it('reveals the expected whole value, then every key', { skip: needsExpectedJson }, async () => {
    const { id } = secret();
    const cache = created();
    assertWholeValue(await decrypt(cache, id));
    for (const [key, value] of expectedMembers()) assert.ok(await decrypt(cache, `${id}#${key}`) === value, `'${id}#${key}' isn't the expected value.`);
    assert.equal(await cache.decrypt(`${id}#no-such-key`, new Uint8Array(16)), 0);
  });

  it('reveals every key, then the expected whole value', { skip: needsExpectedJson }, async () => {
    const { id } = secret();
    const cache = created();
    for (const [key, value] of expectedMembers()) assert.ok(await decrypt(cache, `${id}#${key}`) === value, `'${id}#${key}' isn't the expected value.`);
    assertWholeValue(await decrypt(cache, id));
    assert.equal(await cache.decrypt(`${id}#no-such-key`, new Uint8Array(16)), 0);
  });

  it('reports a secret that doesn\'t exist missing', async () => {
    const cache = created();
    assert.equal(await cache.decrypt(`hkdfguard-missing-${randomUUID().replaceAll('-', '')}`, new Uint8Array(16)), 0);
  });
});

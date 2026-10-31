import { strict as assert } from 'node:assert';
import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { Agent as HttpsAgent } from 'node:https';
import { dirname, join } from 'node:path';
import { after, describe, it } from 'node:test';
import type { ProtectedReadOnlyCache } from '@runsecure/hkdfguard-abstractions';
import { KeyRing } from '@runsecure/hkdfguard-dek';
import { RecordingKey } from '@runsecure/hkdfguard-test-support';
import { HashiCorpVaultSecretCache } from './cache.js';
import { VaultRequestError } from './errors.js';
import { StaticVaultToken } from './token.js';

/*
 * Real reads of a secret the caller provides, in a KV version 2 engine mounted at "secret" (a dev
 * server's default), with a token the caller provides:
 *
 *   vault kv put secret/hkdfguard/test value=s3cret port=5432
 *   HKDFGUARD_TEST_VAULT_ADDR=http://127.0.0.1:8200 HKDFGUARD_TEST_VAULT_TOKEN=... \
 *   HKDFGUARD_TEST_VAULT_SECRET_NAME=hkdfguard/test#value \
 *   HKDFGUARD_TEST_VAULT_SECRET_JSON='{"value":"s3cret","port":"5432"}' \
 *   npm test --workspace packages/cache-hashicorpvault
 *
 * Without HKDFGUARD_TEST_VAULT_SECRET_NAME every test here is reported as skipped - never as passed -
 * the same variables the .NET, Java and Python integration tests read; once it is set, a failing
 * read is a test failure. HKDFGUARD_TEST_VAULT_CACERT is needed only for a server certificate Node
 * doesn't trust; it is then the only CA trusted. To check what the secret holds, not just that it
 * holds something, set HKDFGUARD_TEST_VAULT_SECRET_JSON to the JSON object of keys it is expected to
 * hold: each is then read as "path#key", the path being HKDFGUARD_TEST_VAULT_SECRET_NAME's without
 * its key, and compared with it. The token needs only read on that secret's path (and the path of
 * a missing secret beside it, hkdfguard/missing-<random>); the tests never list, write or delete.
 * See docs/how-to/run-hashicorp-vault-cache-integration-tests.md.
 *
 * The secret's name, Vault's address and its CA certificate are read from the environment, else
 * from vault.test.properties at the repository root - the same file as hkdfguard-java's and
 * hkdfguard-python's: a local file, ignored by git. The token and the expected JSON, which hold
 * secrets, are read from the environment only, never from a file, and never printed.
 */

const SECRET_NAME_VARIABLE = 'HKDFGUARD_TEST_VAULT_SECRET_NAME';
const ADDRESS_VARIABLE = 'HKDFGUARD_TEST_VAULT_ADDR';
const TOKEN_VARIABLE = 'HKDFGUARD_TEST_VAULT_TOKEN';
const CA_CERTIFICATE_VARIABLE = 'HKDFGUARD_TEST_VAULT_CACERT';
const EXPECTED_JSON_VARIABLE = 'HKDFGUARD_TEST_VAULT_SECRET_JSON';
const SETTINGS_FILE = 'vault.test.properties';
const DEFAULT_ADDRESS = 'https://127.0.0.1:8200';

/**
 * The settings file at the repository root - the nearest directory above this file that holds
 * package-lock.json - as NAME=value lines, '#' and '!' starting a comment; empty if there is none.
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

/** `variable` from the environment, else from the settings file; undefined if neither sets it. */
function configured(variable: string): string | undefined {
  return process.env[variable] || settings().get(variable) || undefined;
}

const secretName = configured(SECRET_NAME_VARIABLE);
// The secret's path: the configured name without its key, if it has one.
const secretPath = secretName?.split('#', 1)[0];

/**
 * Each member of the expected JSON object as the cache reveals it under "path#key": a string as its
 * text, a number, true or false as its JSON text; a null, object or array is left out.
 */
function expectedMembers(): [string, string][] {
  let expected: unknown;
  try {
    // A number is kept as the text it was written as, where the reviver is given it.
    expected = JSON.parse(process.env[EXPECTED_JSON_VARIABLE] ?? '', (_key, value: unknown, context?: { source?: string }) =>
      (typeof value === 'number' ? context?.source ?? String(value) : value));
  } catch {
    expected = undefined;
  }
  if (typeof expected !== 'object' || expected === null || Array.isArray(expected)) {
    // Never quoting it: it holds the secret's values.
    assert.fail(`${EXPECTED_JSON_VARIABLE} isn't a JSON object.`);
  }

  const members: [string, string][] = [];
  for (const [key, value] of Object.entries(expected)) {
    if (typeof value === 'boolean') members.push([key, value ? 'true' : 'false']);
    else if (typeof value === 'string') members.push([key, value]);
  }
  return members;
}

/** An agent trusting HKDFGUARD_TEST_VAULT_CACERT, and only it, when set; otherwise the cache's own. */
function agent(): HttpsAgent | undefined {
  const caCertificate = configured(CA_CERTIFICATE_VARIABLE);
  return caCertificate === undefined ? undefined : new HttpsAgent({ ca: readFileSync(caCertificate), keepAlive: true });
}

async function reveal(cache: ProtectedReadOnlyCache, name: string): Promise<string> {
  const maximum = await cache.maxDecryptedLength(name);
  assert.ok(maximum !== undefined, `Nothing is stored under '${name}'.`);
  const result = new Uint8Array(maximum);
  return new TextDecoder().decode(result.subarray(0, await cache.decrypt(name, result)));
}

describe('HashiCorp Vault cache integration', {
  skip: secretName === undefined && `Set ${SECRET_NAME_VARIABLE} to a secret's path#key (with ${ADDRESS_VARIABLE} and ${TOKEN_VARIABLE}), in the `
    + `environment or ${SETTINGS_FILE}, to run Vault cache integration tests.`,
}, () => {
  const ring = new KeyRing();
  ring.add(1, new RecordingKey());
  const protector = ring.createProtector(HashiCorpVaultSecretCache.TOKEN_PURPOSE);
  const tls = agent();
  const caches: HashiCorpVaultSecretCache[] = [];
  after(() => {
    for (const cache of caches) cache.close();
    tls?.destroy();
  });

  /** A cache reading with `token`, or with HKDFGUARD_TEST_VAULT_TOKEN's, protected as soon as it is read. */
  function newCache(token?: string): HashiCorpVaultSecretCache {
    const provider = token !== undefined ? StaticVaultToken.protect(protector, token) : (() => {
      const fromEnvironment = process.env[TOKEN_VARIABLE];
      if (!fromEnvironment) {
        assert.fail(`Set ${TOKEN_VARIABLE} in the environment (never in ${SETTINGS_FILE}) to a token allowed to read ${SECRET_NAME_VARIABLE}.`);
      }
      return StaticVaultToken.protect(protector, fromEnvironment);
    })();
    const cache = new HashiCorpVaultSecretCache(configured(ADDRESS_VARIABLE) ?? DEFAULT_ADDRESS, provider, protector, ring, { agent: tls });
    caches.push(cache);
    return cache;
  }

  it('decrypt reveals the secret', async () => {
    const cache = newCache();
    const maximum = await cache.maxDecryptedLength(secretName!);
    assert.ok(maximum !== undefined && maximum > 0, `Nothing is stored under '${secretName}'.`);

    assert.ok(await cache.decrypt(secretName!, new Uint8Array(maximum)) > 0);
  });

  it('decrypt reveals every key the secret holds', {
    skip: !process.env[EXPECTED_JSON_VARIABLE] && `Set ${SECRET_NAME_VARIABLE} and ${EXPECTED_JSON_VARIABLE} to check a secret's keys.`,
  }, async () => {
    const cache = newCache();
    for (const [key, value] of expectedMembers()) {
      // Compared without letting the assertion print either side: they are the secret's values.
      const matches = await reveal(cache, `${secretPath}#${key}`) === value;
      assert.ok(matches, `'${secretPath}#${key}' doesn't hold the expected value.`);
    }
  });

  it('decrypt of a key the secret doesn\'t hold returns 0', async () => {
    const cache = newCache();
    assert.equal(await cache.decrypt(`${secretPath}#no-such-key-${randomUUID()}`, new Uint8Array(16)), 0);
  });

  it('decrypt of a secret that doesn\'t exist returns 0', async () => {
    const cache = newCache();
    assert.equal(await cache.decrypt(`hkdfguard/missing-${randomUUID().replaceAll('-', '')}`, new Uint8Array(16)), 0);
  });

  it('a token Vault doesn\'t know is refused with 403', async () => {
    const cache = newCache(`hvs.not-a-token-${randomUUID()}`);
    await assert.rejects(cache.decrypt(secretName!, new Uint8Array(16)), (e: unknown) => e instanceof VaultRequestError && e.statusCode === 403);
  });
});

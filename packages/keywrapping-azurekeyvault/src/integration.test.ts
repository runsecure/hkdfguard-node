import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { DefaultAzureCredential } from '@azure/identity';
import { InvalidArgumentError, isZero, MAX_WRAPPED_KEY_BYTES } from '@runsecure/hkdfguard-abstractions';
import { AzureKeyVaultError } from './errors.js';
import { KeyVaultKeyId } from './keyId.js';
import { AzureKeyVaultKeyWrapper } from './wrapper.js';

/*
 * Real calls against an RSA wrapping key and an EC P-256 signing key the caller provides, named in
 * azure.test.properties at the repository root (or the environment; see configuredKeys). Credentials
 * come from DefaultAzureCredential (environment, workload or managed identity, Azure CLI, ...):
 *
 *   az login
 *   npm test --workspace packages/keywrapping-azurekeyvault
 *
 * Without both keys every test here is reported as skipped - never as passed - the same variables
 * the .NET, Java and Python integration tests read. Once they are named, a failing call - or a value
 * that isn't a key identifier - is a test failure. The identity needs get, wrapKey, unwrapKey, sign
 * and verify on the keys; the tests never create, change or delete a key. See
 * docs/how-to/run-azure-key-vault-integration-tests.md.
 */

const WRAPPING_KEY_VARIABLE = 'HKDFGUARD_TEST_AZURE_WRAP_KEY_ID';
const SIGNING_KEY_VARIABLE = 'HKDFGUARD_TEST_AZURE_SIGN_KEY_ID';
const SETTINGS_FILE = 'azure.test.properties';
const CONTEXT = 'hkdfguard.integrationtest';

/**
 * The settings file at the repository root - the nearest directory above this file that holds
 * package-lock.json - as NAME=value lines, '#' and '!' starting a comment; empty if there is none.
 * This repository's counterpart of hkdfguard-dotnet's azure.runsettings, and the same file as
 * hkdfguard-java's and hkdfguard-python's: a local file, ignored by git, naming keys only -
 * DefaultAzureCredential signs in with az login, so no credential ever goes in it.
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

/** The real wrapping and signing keys, each from the environment, else from the settings file; undefined unless both are given. */
function configuredKeys(): [string, string] | undefined {
  const file = settings();
  const [wrapping, signing] = [WRAPPING_KEY_VARIABLE, SIGNING_KEY_VARIABLE].map((name) => process.env[name] || file.get(name) || undefined);
  return wrapping !== undefined && signing !== undefined ? [wrapping, signing] : undefined;
}

// A value that isn't a key identifier (a placeholder left in place, say) fails with a message naming
// the variable, rather than as an argument error from the wrapper.
function checked(variable: string, value: string): string {
  try {
    KeyVaultKeyId.parse(value);
  } catch (error) {
    assert.ok(error instanceof InvalidArgumentError);
    assert.fail(`${variable} is ${JSON.stringify(value)}, which isn't a key identifier. See docs/how-to/run-azure-key-vault-integration-tests.md.`);
  }
  return value;
}

const keys = configuredKeys();

describe('Azure Key Vault integration', {
  skip: keys === undefined
    && `Set ${WRAPPING_KEY_VARIABLE} to an RSA key and ${SIGNING_KEY_VARIABLE} to an EC P-256 key, in the environment or ${SETTINGS_FILE}, to run Azure Key Vault integration tests.`,
}, () => {
  const credential = new DefaultAzureCredential();
  const wrapper = (context: string = CONTEXT) =>
    new AzureKeyVaultKeyWrapper(checked(WRAPPING_KEY_VARIABLE, keys![0]), checked(SIGNING_KEY_VARIABLE, keys![1]), credential, { context });

  it('round-trips a 32-byte DEK through wrap and unwrap', async () => {
    const azure = wrapper();
    const dek = new Uint8Array(randomBytes(32));
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await azure.wrap(dek, wrapped);
    const revealed = new Uint8Array(32);

    assert.equal(await azure.unwrap(wrapped.subarray(0, length), revealed), 32);
    assert.deepEqual(revealed, dek);
  });

  it('generates a wrapped DEK that reveals', async () => {
    const azure = wrapper();
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await azure.generateAndWrap(wrapped);
    const revealed = new Uint8Array(32);

    assert.equal(await azure.unwrap(wrapped.subarray(0, length), revealed), 32);
    assert.ok(!isZero(revealed));
  });

  it('refuses to unwrap under another context', async () => {
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await wrapper().generateAndWrap(wrapped);

    await assert.rejects(wrapper('hkdfguard.integrationtest.other').unwrap(wrapped.subarray(0, length), new Uint8Array(32)),
      (e: unknown) => e instanceof AzureKeyVaultError && e.message.includes('signature doesn\'t verify'));
  });

  it('refuses to unwrap a tampered DEK', async () => {
    const azure = wrapper();
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await azure.generateAndWrap(wrapped);
    wrapped[length - 1]! ^= 1;

    await assert.rejects(azure.unwrap(wrapped.subarray(0, length), new Uint8Array(32)), AzureKeyVaultError);
  });
});

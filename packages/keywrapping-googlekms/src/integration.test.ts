import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { after, describe, it } from 'node:test';
import { KeyManagementServiceClient } from '@google-cloud/kms';
import { isZero, MAX_WRAPPED_KEY_BYTES } from '@runsecure/hkdfguard-abstractions';
import { GoogleKmsError } from './errors.js';
import { GoogleKmsKeyWrapper } from './wrapper.js';

/*
 * Real calls against a symmetric Cloud KMS key the caller provides, named in google.test.properties
 * at the repository root (or the environment; see configuredKey). Credentials come from Application
 * Default Credentials (an attached service account, workload identity federation, or gcloud):
 *
 *   gcloud auth application-default login
 *   npm test --workspace packages/keywrapping-googlekms
 *
 * Without the key every test here is reported as skipped - never as passed - the same variable the
 * .NET, Java and Python integration tests read. Once it is named, a failing call - or a value that
 * isn't a key's resource name - is a test failure. The identity needs
 * roles/cloudkms.cryptoKeyEncrypterDecrypter on the key; the tests never create, change or destroy a
 * key. See docs/how-to/run-google-kms-integration-tests.md.
 */

const KEY_NAME_VARIABLE = 'HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME';
const SETTINGS_FILE = 'google.test.properties';
const CONTEXT = 'hkdfguard.integrationtest';

/**
 * The settings file at the repository root - the nearest directory above this file that holds
 * package-lock.json - as NAME=value lines, '#' and '!' starting a comment; empty if there is none.
 * This repository's counterpart of hkdfguard-dotnet's google.runsettings, and the same file as
 * hkdfguard-java's and hkdfguard-python's: a local file, ignored by git, naming the key only -
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

/** The real key, from the environment, else from the settings file; undefined if neither names it. */
function configuredKey(): string | undefined {
  return process.env[KEY_NAME_VARIABLE] || settings().get(KEY_NAME_VARIABLE) || undefined;
}

// A value that isn't a key's resource name (a placeholder left in place, say) fails with a message
// naming the variable, rather than as an argument error from the wrapper.
function checked(value: string): string {
  if (!/^projects\/[^/[]+\/locations\/[^/[]+\/keyRings\/[^/[]+\/cryptoKeys\/[^/[]+$/.test(value)) {
    assert.fail(`${KEY_NAME_VARIABLE} is ${JSON.stringify(value)}, which isn't a key's resource name. Replace the placeholders in ${SETTINGS_FILE} `
      + 'with your project, key ring and key. See docs/how-to/run-google-kms-integration-tests.md.');
  }
  return value;
}

const keyName = configuredKey();

describe('Google Cloud KMS integration', {
  skip: keyName === undefined && `Set ${KEY_NAME_VARIABLE} to a symmetric Cloud KMS key, in the environment or ${SETTINGS_FILE}, to run Google Cloud KMS integration tests.`,
}, () => {
  const client = new KeyManagementServiceClient();
  after(() => client.close());
  const wrapper = (context: string = CONTEXT) => new GoogleKmsKeyWrapper(client, checked(keyName!), { context });

  it('round-trips a 32-byte DEK through wrap and unwrap', async () => {
    const kms = wrapper();
    const dek = new Uint8Array(randomBytes(32));
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await kms.wrap(dek, wrapped);
    const revealed = new Uint8Array(32);

    assert.equal(await kms.unwrap(wrapped.subarray(0, length), revealed), 32);
    assert.deepEqual(revealed, dek);
  });

  it('generates a wrapped DEK that reveals', async () => {
    const kms = wrapper();
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await kms.generateAndWrap(wrapped);
    const revealed = new Uint8Array(32);

    assert.equal(await kms.unwrap(wrapped.subarray(0, length), revealed), 32);
    assert.ok(!isZero(revealed));
  });

  it('refuses to unwrap under another context', async () => {
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await wrapper().generateAndWrap(wrapped);

    await assert.rejects(wrapper('hkdfguard.integrationtest.other').unwrap(wrapped.subarray(0, length), new Uint8Array(32)),
      (e: unknown) => e instanceof GoogleKmsError && e.message.includes('INVALID_ARGUMENT'));
  });

  it('refuses to unwrap a tampered DEK', async () => {
    const kms = wrapper();
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await kms.generateAndWrap(wrapped);
    wrapped[length - 1]! ^= 1;

    await assert.rejects(kms.unwrap(wrapped.subarray(0, length), new Uint8Array(32)), GoogleKmsError);
  });
});

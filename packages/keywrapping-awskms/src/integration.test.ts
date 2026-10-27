import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import { KMSClient } from '@aws-sdk/client-kms';
import { isZero, MAX_WRAPPED_KEY_BYTES } from '@runsecure/hkdfguard-abstractions';
import { AwsKmsError } from './errors.js';
import { AwsKmsKeyWrapper } from './wrapper.js';

/*
 * Real calls against a symmetric AWS KMS key the caller provides. The SDK resolves credentials and
 * region the usual way (environment, shared config and credentials files, container or instance role):
 *
 *   HKDFGUARD_TEST_AWS_KMS_KEY_ID=arn:aws:kms:... AWS_REGION=us-east-1 npm test --workspace packages/keywrapping-awskms
 *
 * Without HKDFGUARD_TEST_AWS_KMS_KEY_ID every test here is reported as skipped - never as passed -
 * the same variable the .NET, Java and Python integration tests read. Once it names a key, a failing
 * call is a test failure. The principal needs kms:Encrypt, kms:Decrypt and
 * kms:GenerateDataKeyWithoutPlaintext on the key; the tests never create, alter or schedule deletion
 * of a key.
 */

const KEY_ID_VARIABLE = 'HKDFGUARD_TEST_AWS_KMS_KEY_ID';
const CONTEXT = { purpose: 'hkdfguard.integrationtest' };
const keyId = process.env[KEY_ID_VARIABLE] || undefined;

describe('AWS KMS integration', { skip: keyId === undefined && `Set ${KEY_ID_VARIABLE} to a symmetric KMS key to run the AWS KMS integration tests.` }, () => {
  /** Runs `test` with a client the test owns, as an application would: created here, destroyed afterwards. */
  async function withClient(test: (client: KMSClient, key: string) => Promise<void>): Promise<void> {
    const client = new KMSClient({});
    try {
      await test(client, keyId!);
    } finally {
      client.destroy();
    }
  }

  it('round-trips a 32-byte DEK through wrap and unwrap', () => withClient(async (client, key) => {
    const wrapper = new AwsKmsKeyWrapper(client, key, { encryptionContext: CONTEXT });
    const dek = new Uint8Array(randomBytes(32));
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await wrapper.wrap(dek, wrapped);
    const revealed = new Uint8Array(32);

    assert.equal(await wrapper.unwrap(wrapped.subarray(0, length), revealed), 32);
    assert.deepEqual(revealed, dek);
  }));

  it('generates a wrapped DEK that reveals', () => withClient(async (client, key) => {
    const wrapper = new AwsKmsKeyWrapper(client, key, { encryptionContext: CONTEXT });
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await wrapper.generateAndWrap(wrapped);
    const revealed = new Uint8Array(32);

    assert.equal(await wrapper.unwrap(wrapped.subarray(0, length), revealed), 32);
    assert.ok(!isZero(revealed));
  }));

  it('refuses to unwrap under another encryption context', () => withClient(async (client, key) => {
    const wrapper = new AwsKmsKeyWrapper(client, key, { encryptionContext: CONTEXT });
    const other = new AwsKmsKeyWrapper(client, key, { encryptionContext: { purpose: 'hkdfguard.integrationtest.other' } });
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await wrapper.generateAndWrap(wrapped);

    await assert.rejects(other.unwrap(wrapped.subarray(0, length), new Uint8Array(32)), AwsKmsError);
  }));

  it('refuses to unwrap a tampered DEK', () => withClient(async (client, key) => {
    const wrapper = new AwsKmsKeyWrapper(client, key, { encryptionContext: CONTEXT });
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await wrapper.generateAndWrap(wrapped);
    wrapped[length - 1]! ^= 1;

    await assert.rejects(wrapper.unwrap(wrapped.subarray(0, length), new Uint8Array(32)), AwsKmsError);
  }));
});

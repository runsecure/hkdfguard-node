import { strict as assert } from 'node:assert';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, type TestContext } from 'node:test';
import {
  DecryptCommand, EncryptCommand, GenerateDataKeyWithoutPlaintextCommand, IncorrectKeyException, InvalidCiphertextException, KMSClient,
  KMSInternalException, KMSServiceException, type DecryptCommandInput, type EncryptCommandInput, type GenerateDataKeyWithoutPlaintextCommandInput,
} from '@aws-sdk/client-kms';
import { InvalidArgumentError, isZero, MAX_WRAPPED_KEY_BYTES, type KeyWrapper } from '@runsecure/hkdfguard-abstractions';
import { AesGcmCryptoProviderFactory } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { keyFileDirectory, windowsCurrentUserSid } from '@runsecure/hkdfguard-test-support';
import { AwsKmsError } from './errors.js';
import { KeyFileError, KeyFileTrust } from './index.js';
import { AwsKmsKeyWrapper, GENERATED_KEY_LENGTH, MAX_PLAINTEXT_LENGTH, type KmsClient, type KmsCommand } from './wrapper.js';

const KEY_ARN = 'arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab';
const CONTEXT = { purpose: 'hkdfguard.test' };
const isWindows = process.platform === 'win32';
const isUnix = process.platform === 'linux' || (process.platform === 'darwin' && process.arch === 'arm64');

type Handler = (input: Record<string, unknown>) => unknown;

/**
 * An in-process stand-in for KMS, implementing only the three commands AwsKmsKeyWrapper sends,
 * through `send` as the SDK's client takes them. By default it behaves like a symmetric KMS key:
 * ciphertext is AES-GCM under a local key, binding the key ID and encryption context, so Decrypt
 * fails unless both match. Each command can be answered by a handler instead, which returns or throws
 * what a test needs. Every input is recorded as received; Encrypt's plaintext is also copied when it
 * arrives, since the wrapper zeroes the buffer it sent once the call completes.
 */
class FakeKms implements KmsClient {
  private readonly key = randomBytes(32);
  onEncrypt: Handler | undefined;
  onDecrypt: Handler | undefined;
  onGenerate: Handler | undefined;
  readonly encryptRequests: EncryptCommandInput[] = [];
  readonly encryptPlaintexts: Uint8Array[] = [];
  readonly decryptRequests: DecryptCommandInput[] = [];
  readonly generateRequests: GenerateDataKeyWithoutPlaintextCommandInput[] = [];
  readonly options: unknown[] = [];

  async send(command: KmsCommand, options?: { abortSignal?: AbortSignal }): Promise<unknown> {
    this.options.push(options);
    if (command instanceof EncryptCommand) {
      const input = command.input;
      this.encryptRequests.push(input);
      this.encryptPlaintexts.push(Uint8Array.from(input.Plaintext!));
      if (this.onEncrypt !== undefined) return this.onEncrypt(input as unknown as Record<string, unknown>);
      return { KeyId: input.KeyId, CiphertextBlob: this.seal(input.Plaintext!, input.KeyId!, input.EncryptionContext) };
    }
    if (command instanceof DecryptCommand) {
      const input = command.input;
      this.decryptRequests.push(input);
      if (this.onDecrypt !== undefined) return this.onDecrypt(input as unknown as Record<string, unknown>);
      return { KeyId: input.KeyId, Plaintext: this.open(input.CiphertextBlob!, input.KeyId!, input.EncryptionContext) };
    }
    if (command instanceof GenerateDataKeyWithoutPlaintextCommand) {
      const input = command.input;
      this.generateRequests.push(input);
      if (this.onGenerate !== undefined) return this.onGenerate(input as unknown as Record<string, unknown>);
      return { KeyId: input.KeyId, CiphertextBlob: this.seal(randomBytes(32), input.KeyId!, input.EncryptionContext) };
    }
    throw new Error(`FakeKms does not implement ${(command as object).constructor.name}`);
  }

  private seal(plaintext: Uint8Array, keyId: string, context: Record<string, string> | undefined): Uint8Array {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, nonce).setAAD(aad(keyId, context));
    return new Uint8Array(Buffer.concat([nonce, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]));
  }

  private open(sealed: Uint8Array, keyId: string, context: Record<string, string> | undefined): Uint8Array {
    if (sealed.length < 28) throw serviceError(InvalidCiphertextException, 400);
    try {
      const decipher = createDecipheriv('aes-256-gcm', this.key, sealed.subarray(0, 12)).setAAD(aad(keyId, context));
      decipher.setAuthTag(sealed.subarray(sealed.length - 16));
      return new Uint8Array(Buffer.concat([decipher.update(sealed.subarray(12, sealed.length - 16)), decipher.final()]));
    } catch {
      // Real KMS reports a key mismatch as IncorrectKeyException and a context mismatch or tampering
      // as InvalidCiphertextException; one is enough for a fake.
      throw serviceError(InvalidCiphertextException, 400);
    }
  }
}

function aad(keyId: string, context: Record<string, string> | undefined): Buffer {
  const entries = Object.entries(context ?? {}).sort(([a], [b]) => (a < b ? -1 : 1));
  return Buffer.from(keyId + entries.map(([k, v]) => `\0${k}=${v}`).join(''), 'utf8');
}

type ServiceExceptionClass = new (options: { message: string; $metadata: { httpStatusCode?: number } }) => Error;

/** The exception the SDK throws for a KMS error response: its modeled class, with the response metadata. */
function serviceError(type: ServiceExceptionClass, status: number | undefined): Error {
  return new type({ message: `${type.name} from FakeKms.`, $metadata: status === undefined ? {} : { httpStatusCode: status } });
}

/**
 * What the SDK throws for an error KMS answers with but its model doesn't name, such as
 * AccessDeniedException: a KMSServiceException carrying the error's name.
 */
function unmodeledError(name: string, status: number): Error {
  return new KMSServiceException({ name, $fault: 'client', message: `${name} from FakeKms.`, $metadata: { httpStatusCode: status } });
}

const raise = (error: unknown): Handler => () => { throw error; };

async function wrapWith(wrapper: AwsKmsKeyWrapper, dek: Uint8Array): Promise<Uint8Array> {
  const result = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
  const length = await wrapper.wrap(dek, result);
  return result.slice(0, length);
}

const dek = () => new Uint8Array(randomBytes(32));
const filled = (length: number) => new Uint8Array(length).fill(0xaa);

/** A predicate for assert.rejects: an AwsKmsError whose message is `message` exactly, or holds it. */
function kmsError(message: string | RegExp): (e: unknown) => boolean {
  return (e: unknown) => {
    assert.ok(e instanceof AwsKmsError, String(e));
    assert.equal(e.code, 'ERR_HKDFGUARD_AWS_KMS');
    if (typeof message === 'string') assert.equal(e.message, message);
    else assert.match(e.message, message);
    return true;
  };
}

describe('constructing an AwsKmsKeyWrapper', () => {
  it('refuses missing or invalid arguments', () => {
    const kms = new FakeKms();
    for (const [client, keyId, options] of [
      [null, KEY_ARN, {}], [{}, KEY_ARN, {}], [kms, undefined, {}], [kms, 42, {}], [kms, '', {}], [kms, ' ', {}], [kms, '\t ', {}],
      [kms, KEY_ARN, null], [kms, KEY_ARN, { encryptionContext: { '': 'x' } }], [kms, KEY_ARN, { encryptionContext: { k: null } }],
      [kms, KEY_ARN, { encryptionContext: { k: 1 } }], [kms, KEY_ARN, { encryptionContext: [['k', 'v']] }],
      [kms, KEY_ARN, { encryptionContext: new Map([[1, 'v']]) }], [kms, KEY_ARN, { encryptionContext: 'purpose=x' }],
      [kms, KEY_ARN, { keyFileTrust: 'S-1-5-18' }], [kms, KEY_ARN, { keyFileTrust: { windowsPrincipals: [] } }],
    ] as const) {
      assert.throws(() => new AwsKmsKeyWrapper(client as never, keyId as never, options as never), InvalidArgumentError, String(keyId));
    }
  });

  it('is a KeyWrapper over any client with send, a real KMSClient included', () => {
    const client = new KMSClient({ region: 'us-east-1', credentials: { accessKeyId: 'testing', secretAccessKey: 'testing' } });
    try {
      const wrapper: KeyWrapper = new AwsKmsKeyWrapper(client, KEY_ARN);
      assert.ok(wrapper instanceof AwsKmsKeyWrapper);
    } finally {
      client.destroy();
    }
    assert.equal(new AwsKmsKeyWrapper(new FakeKms(), KEY_ARN).keyId, KEY_ARN);
    assert.equal(GENERATED_KEY_LENGTH, 32);
    assert.equal(MAX_PLAINTEXT_LENGTH, 4096);
  });
});

describe('wrap, unwrap and generate-and-wrap', () => {
  it('round-trips a DEK', async () => {
    const wrapper = new AwsKmsKeyWrapper(new FakeKms(), KEY_ARN, { encryptionContext: CONTEXT });
    const key = dek();
    const revealed = new Uint8Array(32);
    assert.equal(await wrapper.unwrap(await wrapWith(wrapper, key), revealed), 32);
    assert.deepEqual(revealed, key);
  });

  it('sends the key, context and algorithm, and zeroes its copy of the plaintext once the call completes', async () => {
    const kms = new FakeKms();
    const key = dek();
    await wrapWith(new AwsKmsKeyWrapper(kms, KEY_ARN, { encryptionContext: CONTEXT }), key);

    assert.equal(kms.encryptRequests.length, 1);
    const request = kms.encryptRequests[0]!;
    assert.deepEqual(Object.keys(request).sort(), ['EncryptionAlgorithm', 'EncryptionContext', 'KeyId', 'Plaintext']);
    assert.equal(request.KeyId, KEY_ARN);
    assert.deepEqual(request.EncryptionContext, CONTEXT);
    assert.equal(request.EncryptionAlgorithm, 'SYMMETRIC_DEFAULT');
    assert.deepEqual(kms.encryptPlaintexts[0], key);
    // The buffer sent is the wrapper's own copy, zeroed once the call completed; the caller's is the caller's to zero.
    assert.notEqual(request.Plaintext, key);
    assert.ok(isZero(request.Plaintext!));
    assert.ok(!isZero(key));
  });

  it('zeroes its copy of the plaintext when KMS refuses', async () => {
    const kms = new FakeKms();
    kms.onEncrypt = raise(unmodeledError('AccessDeniedException', 400));
    await assert.rejects(wrapWith(new AwsKmsKeyWrapper(kms, KEY_ARN), dek()), AwsKmsError);
    assert.ok(isZero(kms.encryptRequests[0]!.Plaintext!));
  });

  it('wraps a view into a larger buffer', async () => {
    const wrapper = new AwsKmsKeyWrapper(new FakeKms(), KEY_ARN);
    const backing = new Uint8Array(randomBytes(64));
    const revealed = new Uint8Array(32);
    await wrapper.unwrap(await wrapWith(wrapper, backing.subarray(16, 48)), revealed);
    assert.deepEqual(revealed, backing.subarray(16, 48));
  });

  it('sends no context when given none, or an empty one', async () => {
    const kms = new FakeKms();
    for (const options of [undefined, {}, { encryptionContext: {} }, { encryptionContext: new Map<string, string>() }]) {
      const wrapper = new AwsKmsKeyWrapper(kms, KEY_ARN, options);
      const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
      const length = await wrapper.generateAndWrap(wrapped);
      await wrapper.unwrap(wrapped.subarray(0, length), new Uint8Array(32));
      await wrapWith(wrapper, dek());
    }
    for (const request of [...kms.generateRequests, ...kms.decryptRequests, ...kms.encryptRequests]) {
      assert.ok(!('EncryptionContext' in request), JSON.stringify(Object.keys(request)));
    }
  });

  it('copies the context at construction and for every request', async () => {
    const kms = new FakeKms();
    const context: Record<string, string> = { ...CONTEXT };
    const wrapper = new AwsKmsKeyWrapper(kms, KEY_ARN, { encryptionContext: context });
    context['purpose'] = 'changed';

    await wrapper.generateAndWrap(new Uint8Array(MAX_WRAPPED_KEY_BYTES));
    kms.generateRequests[0]!.EncryptionContext!['purpose'] = 'changed by a middleware';
    await wrapper.generateAndWrap(new Uint8Array(MAX_WRAPPED_KEY_BYTES));

    assert.deepEqual(kms.generateRequests[1]!.EncryptionContext, CONTEXT);
  });

  it('takes the context from a Map, sends it sorted by key, and keeps a "__proto__" key as an ordinary entry', async () => {
    const kms = new FakeKms();
    await new AwsKmsKeyWrapper(kms, KEY_ARN, { encryptionContext: new Map([['b', '2'], ['a', '1'], ['B', '3'], ['__proto__', '4']]) })
      .generateAndWrap(new Uint8Array(MAX_WRAPPED_KEY_BYTES));
    const sent = kms.generateRequests[0]!.EncryptionContext!;
    assert.deepEqual(Object.keys(sent), ['B', '__proto__', 'a', 'b']);
    assert.equal(Object.getPrototypeOf(sent), Object.prototype);
    assert.equal(Object.getOwnPropertyDescriptor(sent, '__proto__')?.value, '4');
  });

  it('asks KMS for a wrapped AES-256 key only when generating', async () => {
    const kms = new FakeKms();
    const wrapper = new AwsKmsKeyWrapper(kms, KEY_ARN, { encryptionContext: CONTEXT });
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await wrapper.generateAndWrap(wrapped);
    const revealed = new Uint8Array(32);

    assert.equal(await wrapper.unwrap(wrapped.subarray(0, length), revealed), GENERATED_KEY_LENGTH);
    assert.deepEqual(kms.generateRequests, [{ KeyId: KEY_ARN, KeySpec: 'AES_256', EncryptionContext: CONTEXT }]);
    assert.deepEqual(kms.encryptRequests, []);
    assert.ok(!isZero(revealed));
  });

  it('pins the key on unwrap, sending its own copy of the wrapped DEK', async () => {
    const kms = new FakeKms();
    const wrapper = new AwsKmsKeyWrapper(kms, KEY_ARN, { encryptionContext: CONTEXT });
    const wrapped = await wrapWith(wrapper, dek());

    await wrapper.unwrap(wrapped, new Uint8Array(32));

    assert.deepEqual(kms.decryptRequests, [{ KeyId: KEY_ARN, CiphertextBlob: wrapped, EncryptionContext: CONTEXT, EncryptionAlgorithm: 'SYMMETRIC_DEFAULT' }]);
    assert.notEqual(kms.decryptRequests[0]!.CiphertextBlob, wrapped);
  });

  it('refuses a DEK wrapped under another key, zeroing the result', async () => {
    const kms = new FakeKms();
    const wrapped = await wrapWith(new AwsKmsKeyWrapper(kms, 'alias/other', { encryptionContext: CONTEXT }), dek());
    const result = filled(32);

    await assert.rejects(new AwsKmsKeyWrapper(kms, KEY_ARN, { encryptionContext: CONTEXT }).unwrap(wrapped, result), (e: unknown) => {
      kmsError(`AWS KMS unwrap failed for key '${KEY_ARN}': InvalidCiphertextException (HTTP 400).`)(e);
      const error = e as AwsKmsError;
      assert.ok(error.cause instanceof InvalidCiphertextException);
      assert.equal(error.operation, 'unwrap');
      assert.equal(error.keyId, KEY_ARN);
      return true;
    });
    assert.ok(isZero(result));
  });

  it('refuses a DEK wrapped under another context, or none', async () => {
    const kms = new FakeKms();
    const wrapped = await wrapWith(new AwsKmsKeyWrapper(kms, KEY_ARN, { encryptionContext: CONTEXT }), dek());
    await assert.rejects(new AwsKmsKeyWrapper(kms, KEY_ARN, { encryptionContext: { purpose: 'other' } }).unwrap(wrapped, new Uint8Array(32)), AwsKmsError);
    await assert.rejects(new AwsKmsKeyWrapper(kms, KEY_ARN).unwrap(wrapped, new Uint8Array(32)), AwsKmsError);
  });

  it('refuses a tampered DEK', async () => {
    const wrapper = new AwsKmsKeyWrapper(new FakeKms(), KEY_ARN, { encryptionContext: CONTEXT });
    const wrapped = await wrapWith(wrapper, dek());
    wrapped[wrapped.length - 1]! ^= 1;
    await assert.rejects(wrapper.unwrap(wrapped, new Uint8Array(32)), AwsKmsError);
  });

  it('refuses a wrapped DEK out of bounds without calling KMS, zeroing the result', async () => {
    for (const size of [0, MAX_WRAPPED_KEY_BYTES + 1]) {
      const kms = new FakeKms();
      const result = filled(32);
      await assert.rejects(new AwsKmsKeyWrapper(kms, KEY_ARN).unwrap(new Uint8Array(size), result), kmsError(new RegExp(`got ${size}\\.$`)));
      assert.deepEqual(kms.decryptRequests, []);
      assert.ok(isZero(result));
    }
  });

  it('refuses a result too small for the revealed key, zeroing it and the SDK\'s plaintext', async () => {
    const kms = new FakeKms();
    const wrapper = new AwsKmsKeyWrapper(kms, KEY_ARN);
    const wrapped = await wrapWith(wrapper, dek());
    const revealed = filled(32);
    kms.onDecrypt = () => ({ KeyId: KEY_ARN, Plaintext: revealed });

    const result = filled(16);
    await assert.rejects(wrapper.unwrap(wrapped, result), (e: unknown) => e instanceof InvalidArgumentError && e.message.includes('result holds 16'));
    assert.ok(isZero(result));
    assert.ok(isZero(revealed));
  });

  it('zeroes the plaintext the SDK decoded once it is copied into the result', async () => {
    const kms = new FakeKms();
    const key = dek();
    const decoded = Uint8Array.from(key);
    kms.onDecrypt = () => ({ KeyId: KEY_ARN, Plaintext: decoded });

    const result = new Uint8Array(32);
    assert.equal(await new AwsKmsKeyWrapper(kms, KEY_ARN).unwrap(new Uint8Array(64), result), 32);
    assert.deepEqual(result, key);
    assert.ok(isZero(decoded));
  });

  it('writes the revealed key into a view of a larger buffer', async () => {
    const wrapper = new AwsKmsKeyWrapper(new FakeKms(), KEY_ARN);
    const key = dek();
    const backing = new Uint8Array(64);
    assert.equal(await wrapper.unwrap(await wrapWith(wrapper, key), backing.subarray(16)), 32);
    assert.deepEqual(backing.subarray(16, 48), key);
    assert.ok(isZero(backing.subarray(0, 16)) && isZero(backing.subarray(48)));
  });

  it('fails, zeroing the result, when KMS returns no plaintext', async () => {
    for (const response of [{ KeyId: KEY_ARN }, { Plaintext: undefined }, { Plaintext: new Uint8Array(0) }, { Plaintext: 'AAAA' }]) {
      const kms = new FakeKms();
      kms.onDecrypt = () => response;
      const result = filled(32);
      await assert.rejects(new AwsKmsKeyWrapper(kms, KEY_ARN).unwrap(new Uint8Array(64), result), kmsError(/returned no plaintext/));
      assert.ok(isZero(result));
    }
  });

  it('zeroes the result whatever the failure', async () => {
    const kms = new FakeKms();
    kms.onDecrypt = raise(new TypeError('a bug in a test double'));
    const result = filled(32);
    await assert.rejects(new AwsKmsKeyWrapper(kms, KEY_ARN).unwrap(new Uint8Array(64), result), TypeError);
    assert.ok(isZero(result));
  });

  it('refuses a plaintext KMS would refuse, without calling it', async () => {
    for (const size of [0, MAX_PLAINTEXT_LENGTH + 1]) {
      const kms = new FakeKms();
      await assert.rejects(new AwsKmsKeyWrapper(kms, KEY_ARN).wrap(new Uint8Array(size), new Uint8Array(MAX_WRAPPED_KEY_BYTES)),
        (e: unknown) => e instanceof InvalidArgumentError && e.message.includes(`got ${size}`));
      assert.deepEqual(kms.encryptRequests, []);
    }
  });

  it('accepts the largest plaintext KMS does', async () => {
    const kms = new FakeKms();
    kms.onEncrypt = () => ({ CiphertextBlob: new Uint8Array(200) });
    assert.equal(await new AwsKmsKeyWrapper(kms, KEY_ARN).wrap(new Uint8Array(MAX_PLAINTEXT_LENGTH), new Uint8Array(MAX_WRAPPED_KEY_BYTES)), 200);
  });

  it('refuses a result too small for the wrapped DEK', async () => {
    await assert.rejects(new AwsKmsKeyWrapper(new FakeKms(), KEY_ARN).wrap(dek(), new Uint8Array(8)),
      (e: unknown) => e instanceof InvalidArgumentError && e.message.includes('result holds 8'));
  });

  it('refuses a ciphertext over the key-file limit', async () => {
    for (const operation of ['wrap', 'generate-and-wrap']) {
      const kms = new FakeKms();
      kms.onEncrypt = kms.onGenerate = () => ({ CiphertextBlob: new Uint8Array(MAX_WRAPPED_KEY_BYTES + 1) });
      const wrapper = new AwsKmsKeyWrapper(kms, KEY_ARN);
      const result = new Uint8Array(2 * MAX_WRAPPED_KEY_BYTES);
      await assert.rejects(operation === 'wrap' ? wrapper.wrap(dek(), result) : wrapper.generateAndWrap(result),
        kmsError(`AWS KMS ${operation} for key '${KEY_ARN}' returned 513 bytes; a wrapped DEK is at most 512.`));
    }
  });

  it('fails when KMS returns no ciphertext', async () => {
    for (const response of [{}, { CiphertextBlob: undefined }, { CiphertextBlob: new Uint8Array(0) }, { CiphertextBlob: 'Y2lwaGVy' }]) {
      const kms = new FakeKms();
      kms.onGenerate = () => response;
      await assert.rejects(new AwsKmsKeyWrapper(kms, KEY_ARN).generateAndWrap(new Uint8Array(MAX_WRAPPED_KEY_BYTES)), kmsError(/returned no ciphertext/));
    }
  });

  it('refuses buffers that are not Uint8Arrays', async () => {
    const wrapper = new AwsKmsKeyWrapper(new FakeKms(), KEY_ARN);
    await assert.rejects(wrapper.wrap('key' as never, new Uint8Array(MAX_WRAPPED_KEY_BYTES)), InvalidArgumentError);
    await assert.rejects(wrapper.unwrap(new Uint8Array(64), [] as never), InvalidArgumentError);
    await assert.rejects(wrapper.generateAndWrap(undefined as never), InvalidArgumentError);
  });
});

describe('cancellation', () => {
  it('rejects an aborted signal without calling KMS', async () => {
    const kms = new FakeKms();
    const wrapper = new AwsKmsKeyWrapper(kms, KEY_ARN);
    const result = filled(32);
    await assert.rejects(wrapper.wrap(dek(), new Uint8Array(MAX_WRAPPED_KEY_BYTES), AbortSignal.abort()), { name: 'AbortError' });
    await assert.rejects(wrapper.unwrap(new Uint8Array(64), result, AbortSignal.abort()), { name: 'AbortError' });
    await assert.rejects(wrapper.generateAndWrap(new Uint8Array(MAX_WRAPPED_KEY_BYTES), AbortSignal.abort()), { name: 'AbortError' });
    await assert.rejects(wrapper.readKeyFile('v1.key', AbortSignal.abort()), { name: 'AbortError' });
    assert.deepEqual(kms.options, []);
    assert.ok(isZero(result));
  });

  it('passes the signal to the SDK, and leaves its abort as it is', async () => {
    const kms = new FakeKms();
    const controller = new AbortController();
    await new AwsKmsKeyWrapper(kms, KEY_ARN).generateAndWrap(new Uint8Array(MAX_WRAPPED_KEY_BYTES), controller.signal);
    await new AwsKmsKeyWrapper(kms, KEY_ARN).generateAndWrap(new Uint8Array(MAX_WRAPPED_KEY_BYTES));
    assert.deepEqual(kms.options, [{ abortSignal: controller.signal }, undefined]);

    const aborted = Object.assign(new Error('Request aborted'), { name: 'AbortError', $metadata: { attempts: 1 } });
    kms.onDecrypt = raise(aborted);
    const result = filled(32);
    await assert.rejects(new AwsKmsKeyWrapper(kms, KEY_ARN).unwrap(new Uint8Array(64), result, controller.signal), (e: unknown) => e === aborted);
    assert.ok(isZero(result));
  });
});

describe('failures', () => {
  it('turn a service refusal into an AwsKmsError naming the error and the HTTP status', async () => {
    const kms = new FakeKms();
    const refusal = unmodeledError('AccessDeniedException', 400);
    kms.onEncrypt = raise(refusal);
    await assert.rejects(new AwsKmsKeyWrapper(kms, KEY_ARN).wrap(dek(), new Uint8Array(MAX_WRAPPED_KEY_BYTES)), (e: unknown) => {
      kmsError(`AWS KMS wrap failed for key '${KEY_ARN}': AccessDeniedException (HTTP 400).`)(e);
      assert.equal((e as AwsKmsError).cause, refusal);
      return true;
    });
  });

  it('name a server fault the same way', async () => {
    const kms = new FakeKms();
    kms.onDecrypt = raise(serviceError(KMSInternalException, 500));
    await assert.rejects(new AwsKmsKeyWrapper(kms, KEY_ARN).unwrap(new Uint8Array(64), new Uint8Array(32)),
      kmsError(`AWS KMS unwrap failed for key '${KEY_ARN}': KMSInternalException (HTTP 500).`));
  });

  it('say so when a refusal has no HTTP status', async () => {
    const kms = new FakeKms();
    kms.onGenerate = raise(serviceError(IncorrectKeyException, undefined));
    await assert.rejects(new AwsKmsKeyWrapper(kms, KEY_ARN).generateAndWrap(new Uint8Array(MAX_WRAPPED_KEY_BYTES)), kmsError(/IncorrectKeyException \(HTTP unknown\)\.$/));
  });

  it('turn a failure on the way to KMS into an AwsKmsError', async () => {
    const refused = Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:443'), { code: 'ECONNREFUSED', $metadata: { attempts: 1, totalRetryDelay: 0 } });
    const noCredentials = Object.assign(new Error('Could not load credentials from any providers'), { name: 'CredentialsProviderError' });
    for (const failure of [refused, noCredentials]) {
      const kms = new FakeKms();
      kms.onGenerate = raise(failure);
      await assert.rejects(new AwsKmsKeyWrapper(kms, KEY_ARN).generateAndWrap(new Uint8Array(MAX_WRAPPED_KEY_BYTES)), (e: unknown) => {
        kmsError(`AWS KMS generate-and-wrap failed for key '${KEY_ARN}': ${failure.message}`)(e);
        assert.equal((e as AwsKmsError).cause, failure);
        return true;
      });
    }
  });

  it('leave what is not an SDK failure as it is', async () => {
    for (const failure of [new RangeError('a bug in a middleware'), 'a string']) {
      const kms = new FakeKms();
      kms.onGenerate = raise(failure);
      await assert.rejects(new AwsKmsKeyWrapper(kms, KEY_ARN).generateAndWrap(new Uint8Array(MAX_WRAPPED_KEY_BYTES)), (e: unknown) => e === failure);
    }
  });

  it('refuse a client that returns no response', async () => {
    const kms = new FakeKms();
    kms.onGenerate = () => undefined;
    await assert.rejects(new AwsKmsKeyWrapper(kms, KEY_ARN).generateAndWrap(new Uint8Array(MAX_WRAPPED_KEY_BYTES)), kmsError(/returned no response/));
  });
});

/** What a fake HTTP handler received: each request's target, and its JSON body. */
interface Exchange {
  target: string;
  body: Record<string, unknown>;
}

/**
 * A real KMSClient whose HTTP handler answers in-process: every request is built, signed and
 * serialized by the SDK exactly as it would be sent, and every answer deserialized as it would be
 * received - so the requests are checked against the KMS model and its wire format.
 */
function clientAnswering(answer: (exchange: Exchange) => { status: number; headers?: Record<string, string>; body: unknown }): { client: KMSClient; exchanges: Exchange[] } {
  const exchanges: Exchange[] = [];
  const handler = {
    async handle(request: { headers: Record<string, string>; body?: unknown }) {
      // The SDK hands over the JSON body as bytes - a Uint8Array subclass that warns when used as a
      // string - or, in older versions, a string.
      const text = request.body instanceof Uint8Array ? new TextDecoder().decode(request.body) : String(request.body);
      const exchange = { target: request.headers['x-amz-target'] ?? '', body: JSON.parse(text) as Record<string, unknown> };
      exchanges.push(exchange);
      const { status, headers = {}, body } = answer(exchange);
      return {
        response: {
          statusCode: status,
          reason: undefined,
          headers: { 'content-type': 'application/x-amz-json-1.1', 'x-amzn-requestid': 'fake-request-id', ...headers },
          body: new Uint8Array(Buffer.from(JSON.stringify(body))),
        },
      };
    },
    updateHttpClientConfig() {},
    httpHandlerConfigs() {
      return {};
    },
  };
  const client = new KMSClient({ region: 'us-east-1', credentials: { accessKeyId: 'testing', secretAccessKey: 'testing' }, requestHandler: handler as never, maxAttempts: 1 });
  return { client, exchanges };
}

const base64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');

describe('through a real KMSClient', () => {
  it('sends every request as the KMS model and wire format define it', async (t) => {
    const key = dek();
    const ciphertext = new Uint8Array(184).fill(0x63);
    const generated = new Uint8Array(184).fill(0x67);
    const { client, exchanges } = clientAnswering(({ target }) => ({
      status: 200,
      body: target === 'TrentService.Decrypt' ? { KeyId: KEY_ARN, Plaintext: base64(key), EncryptionAlgorithm: 'SYMMETRIC_DEFAULT' }
        : { KeyId: KEY_ARN, CiphertextBlob: base64(target === 'TrentService.Encrypt' ? ciphertext : generated) },
    }));
    t.after(() => client.destroy());
    const wrapper = new AwsKmsKeyWrapper(client, KEY_ARN, { encryptionContext: CONTEXT });

    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    assert.equal(await wrapper.wrap(key, wrapped), 184);
    const revealed = new Uint8Array(32);
    assert.equal(await wrapper.unwrap(wrapped.subarray(0, 184), revealed), 32);
    assert.equal(await wrapper.generateAndWrap(wrapped), 184);

    assert.deepEqual(revealed, key);
    assert.deepEqual(wrapped.subarray(0, 184), generated);
    assert.deepEqual(exchanges, [
      { target: 'TrentService.Encrypt', body: { KeyId: KEY_ARN, Plaintext: base64(key), EncryptionContext: CONTEXT, EncryptionAlgorithm: 'SYMMETRIC_DEFAULT' } },
      { target: 'TrentService.Decrypt', body: { KeyId: KEY_ARN, CiphertextBlob: base64(ciphertext), EncryptionContext: CONTEXT, EncryptionAlgorithm: 'SYMMETRIC_DEFAULT' } },
      { target: 'TrentService.GenerateDataKeyWithoutPlaintext', body: { KeyId: KEY_ARN, KeySpec: 'AES_256', EncryptionContext: CONTEXT } },
    ]);
  });

  it('names a modeled KMS error by its name', async (t) => {
    const { client } = clientAnswering(() => ({
      status: 400,
      headers: { 'x-amzn-errortype': 'IncorrectKeyException' },
      body: { __type: 'IncorrectKeyException', message: 'The key ID in the request does not identify a CMK that can perform this operation.' },
    }));
    t.after(() => client.destroy());
    const result = filled(32);

    await assert.rejects(new AwsKmsKeyWrapper(client, KEY_ARN).unwrap(new Uint8Array(184).fill(0x63), result), (e: unknown) => {
      kmsError(`AWS KMS unwrap failed for key '${KEY_ARN}': IncorrectKeyException (HTTP 400).`)(e);
      assert.ok((e as AwsKmsError).cause instanceof IncorrectKeyException);
      return true;
    });
    assert.ok(isZero(result));
  });

  it('reports a refused connection as an AwsKmsError', async (t) => {
    // A client-side failure end to end: a port this machine just stopped listening on, so the
    // connection is refused locally and no request leaves it.
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as { port: number };
    await new Promise<void>((resolve) => server.close(() => resolve()));
    const client = new KMSClient({ region: 'us-east-1', endpoint: `http://127.0.0.1:${port}`, credentials: { accessKeyId: 'testing', secretAccessKey: 'testing' }, maxAttempts: 1 });
    t.after(() => client.destroy());

    await assert.rejects(new AwsKmsKeyWrapper(client, KEY_ARN).generateAndWrap(new Uint8Array(MAX_WRAPPED_KEY_BYTES)), (e: unknown) => {
      kmsError(new RegExp(`^AWS KMS generate-and-wrap failed for key '${KEY_ARN.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}': .*ECONNREFUSED`))(e);
      assert.equal(((e as AwsKmsError).cause as NodeJS.ErrnoException).code, 'ECONNREFUSED');
      return true;
    });
  });
});

describe('with the rest of HkdfGuard', () => {
  it('lets a crypto provider generate and reveal its DEK through KMS', async () => {
    const kms = new FakeKms();
    const provider = await new AesGcmCryptoProviderFactory().createEphemeral(new AwsKmsKeyWrapper(kms, KEY_ARN, { encryptionContext: CONTEXT }), { expirySeconds: 60 });
    try {
      const expected = new TextEncoder().encode('hello, kms');
      // encrypt zeroes the plaintext it is given, so it gets a copy.
      const encrypted = new Uint8Array(provider.encryptedAllocationLength(expected.length));
      const encryptedLength = provider.encrypt(Uint8Array.from(expected), encrypted);
      const decrypted = new Uint8Array(provider.decryptedAllocationLength(encryptedLength));
      const decryptedLength = provider.decrypt(encrypted.subarray(0, encryptedLength), decrypted);
      assert.deepEqual(decrypted.subarray(0, decryptedLength), expected);
      assert.equal(kms.generateRequests.length, 1);
      assert.ok(kms.decryptRequests.length >= 1);
    } finally {
      await provider.close();
    }
  });
});

/**
 * A key file in a folder the user running the tests could replace: under the user's temp folder
 * (Windows) or the shared /tmp (Linux and macOS) - neither somewhere only administrators can write.
 */
function userWritableKeyFile(t: TestContext): string {
  const directory = mkdtempSync(join(isWindows ? tmpdir() : '/tmp', 'hkdfguard-keys-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, 'v1.key');
  writeFileSync(path, randomBytes(184));
  return path;
}

const notTrusted = (e: unknown) => e instanceof KeyFileError && e.code === 'EACCES' && e.message.includes('not trusted');

describe('reading key files', () => {
  it('refuses by default a file the current user could have replaced', { skip: !isWindows && !isUnix && 'Windows, Linux and Apple silicon macOS only.' }, async (t) => {
    await assert.rejects(new AwsKmsKeyWrapper(new FakeKms(), KEY_ARN, { encryptionContext: CONTEXT }).readKeyFile(userWritableKeyFile(t)), notTrusted);
  });

  it('trusts administrators only when given no trust', { skip: !isWindows && !isUnix && 'Windows, Linux and Apple silicon macOS only.' }, async (t) => {
    // The same refusal as the default: an omitted trust is administratorsOnly, never "anyone".
    await assert.rejects(new AwsKmsKeyWrapper(new FakeKms(), KEY_ARN, { keyFileTrust: undefined }).readKeyFile(userWritableKeyFile(t)), notTrusted);
  });

  it('refuses a missing path', async () => {
    for (const path of ['', undefined]) {
      await assert.rejects(new AwsKmsKeyWrapper(new FakeKms(), KEY_ARN).readKeyFile(path as string), InvalidArgumentError);
    }
  });

  it('reads a file the writer\'s account is trusted for, and it reveals (Windows)', { skip: !isWindows && 'Windows only.' }, async (t) => {
    const wrapper = new AwsKmsKeyWrapper(new FakeKms(), KEY_ARN, { encryptionContext: CONTEXT, keyFileTrust: new KeyFileTrust({ windowsPrincipals: [windowsCurrentUserSid()] }) });
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await wrapper.generateAndWrap(wrapped);
    const path = userWritableKeyFile(t);
    writeFileSync(path, wrapped.subarray(0, length));

    const read = await wrapper.readKeyFile(path);
    assert.deepEqual(read, wrapped.subarray(0, length));
    assert.equal(await wrapper.unwrap(read, new Uint8Array(32)), 32);
  });

  it('refuses to trust everyone (Windows)', { skip: !isWindows && 'Windows only.' }, async (t) => {
    const wrapper = new AwsKmsKeyWrapper(new FakeKms(), KEY_ARN, { keyFileTrust: new KeyFileTrust({ windowsPrincipals: ['S-1-1-0'] }) });
    await assert.rejects(wrapper.readKeyFile(userWritableKeyFile(t)), (e: unknown) => e instanceof InvalidArgumentError && e.message.includes('every account'));
  });

  it('reads a file in a directory only its trusted owner can write, and it reveals (Linux and macOS)', { skip: !isUnix && 'Linux and Apple silicon macOS only.' }, async (t) => {
    const directory = keyFileDirectory(t, 'hkdfguard-awskms-');
    if (directory === undefined) return;
    const wrapper = new AwsKmsKeyWrapper(new FakeKms(), KEY_ARN, { keyFileTrust: new KeyFileTrust({ unixUserIds: [process.geteuid!()] }) });
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await wrapper.generateAndWrap(wrapped);
    const path = join(directory, 'v1.key');
    writeFileSync(path, wrapped.subarray(0, length), { mode: 0o600 });

    const read = await wrapper.readKeyFile(path);
    assert.deepEqual(read, wrapped.subarray(0, length));
    assert.equal(await wrapper.unwrap(read, new Uint8Array(32)), 32);
  });
});

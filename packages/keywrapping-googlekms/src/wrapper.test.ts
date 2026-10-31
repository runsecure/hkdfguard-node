import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { createCipheriv, createDecipheriv, generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, type TestContext } from 'node:test';
import { KeyManagementServiceClient, protos } from '@google-cloud/kms';
import * as grpc from '@grpc/grpc-js';
import { InvalidArgumentError, isZero, MAX_WRAPPED_KEY_BYTES, type KeyWrapper } from '@runsecure/hkdfguard-abstractions';
import { crc32c } from '@runsecure/hkdfguard-abstractions/internal';
import { AesGcmCryptoProviderFactory } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { keyFileDirectory, windowsCurrentUserSid } from '@runsecure/hkdfguard-test-support';
import { GoogleKmsError } from './errors.js';
import { KeyFileError, KeyFileTrust } from './index.js';
import {
  GENERATED_KEY_LENGTH, GoogleKmsKeyWrapper, MAX_CONTEXT_LENGTH, MAX_PLAINTEXT_LENGTH, type CloudKmsClient, type DecryptRequest, type EncryptRequest,
} from './wrapper.js';

const KEY_NAME = 'projects/test-project/locations/us-east1/keyRings/hkdfguard/cryptoKeys/wrap';
const OTHER_KEY_NAME = 'projects/test-project/locations/us-east1/keyRings/hkdfguard/cryptoKeys/other';
const CONTEXT = 'hkdfguard.test';
const LABEL = Buffer.from('HkdfGuard-GoogleKms-wrap-v1\0');
const isWindows = process.platform === 'win32';
const isUnix = process.platform === 'linux' || (process.platform === 'darwin' && process.arch === 'arm64');

const v1 = protos.google.cloud.kms.v1;
type EncryptResponse = protos.google.cloud.kms.v1.IEncryptResponse;
type DecryptResponse = protos.google.cloud.kms.v1.IDecryptResponse;

/** A refusal the fake answers with: a gRPC status and its details, as Cloud KMS sends them. */
class StatusError extends Error {
  constructor(readonly code: grpc.status, readonly details: string) {
    super(details);
  }
}

/** A request as the fake received it, decoded from the wire: bytes as Buffers, checksums as numbers. */
interface Received {
  name: string;
  data: Buffer;
  dataCrc32c: number | undefined;
  aad: Buffer;
  aadCrc32c: number | undefined;
}

const int64 = (field: { value?: unknown } | null | undefined) => (field?.value == null ? undefined : Number(String(field.value)));

/**
 * Cloud KMS on the loopback address: a gRPC server implementing Encrypt and Decrypt of
 * google.cloud.kms.v1.KeyManagementService, reached through a real KeyManagementServiceClient - so
 * every request is serialized, sent and checked, and every answer received and decoded, as it would
 * be against Google. By default it behaves like a symmetric Cloud KMS key: a ciphertext is AES-GCM
 * under a local key, names the version that made it, and binds the key name, that version and the
 * additional authenticated data, so Decrypt fails unless all three match; it verifies the request's
 * checksums as Cloud KMS does. Either call can be answered by a handler instead, which returns or
 * throws (a StatusError) what a test needs.
 */
class FakeCloudKms {
  private readonly key = randomBytes(32);
  private version = 1;
  onEncrypt: ((request: Received) => EncryptResponse) | undefined;
  onDecrypt: ((request: Received) => DecryptResponse) | undefined;
  readonly encryptRequests: Received[] = [];
  readonly decryptRequests: Received[] = [];

  /** Makes a new primary version, as rotating the key does; ciphertexts made under earlier ones still decrypt. */
  rotate(): void {
    this.version++;
  }

  /** What Encrypt answers by default. */
  encryptNormally(request: Received): EncryptResponse {
    verifyChecksum(request.data, request.dataCrc32c, 'plaintext');
    verifyChecksum(request.aad, request.aadCrc32c, 'additional_authenticated_data');
    if (request.name.includes('/cryptoKeyVersions/')) throw new StatusError(grpc.status.INVALID_ARGUMENT, 'Encrypt takes a key, not a key version.');
    const ciphertext = this.seal(request.data, request.name, this.version, request.aad);
    return {
      name: `${request.name}/cryptoKeyVersions/${this.version}`, ciphertext, ciphertextCrc32c: { value: crc32c(ciphertext) },
      verifiedPlaintextCrc32c: request.dataCrc32c !== undefined, verifiedAdditionalAuthenticatedDataCrc32c: request.aadCrc32c !== undefined,
      protectionLevel: 'SOFTWARE',
    };
  }

  /** What Decrypt answers by default. */
  decryptNormally(request: Received): DecryptResponse {
    verifyChecksum(request.data, request.dataCrc32c, 'ciphertext');
    verifyChecksum(request.aad, request.aadCrc32c, 'additional_authenticated_data');
    const plaintext = this.open(request.data, request.name, request.aad);
    return { plaintext, plaintextCrc32c: { value: crc32c(plaintext) }, usedPrimary: request.data[0] === this.version, protectionLevel: 'SOFTWARE' };
  }

  /** Encrypts as Cloud KMS would for any caller, not through the wrapper: under this key, with exactly this AAD. */
  sealDirectly(plaintext: Uint8Array, keyName: string, aad: Uint8Array): Uint8Array {
    return this.seal(plaintext, keyName, this.version, aad);
  }

  private seal(plaintext: Uint8Array, keyName: string, version: number, aad: Uint8Array): Uint8Array {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, nonce).setAAD(binding(keyName, version, aad));
    return new Uint8Array(Buffer.concat([Buffer.of(version), nonce, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]));
  }

  private open(sealed: Uint8Array, keyName: string, aad: Uint8Array): Uint8Array {
    // Cloud KMS says no more than this whatever is wrong: another key, other AAD, or tampering.
    const refused = new StatusError(grpc.status.INVALID_ARGUMENT, 'Decryption failed.');
    if (sealed.length < 29) throw refused;
    try {
      const decipher = createDecipheriv('aes-256-gcm', this.key, sealed.subarray(1, 13)).setAAD(binding(keyName, sealed[0]!, aad));
      decipher.setAuthTag(sealed.subarray(sealed.length - 16));
      return new Uint8Array(Buffer.concat([decipher.update(sealed.subarray(13, sealed.length - 16)), decipher.final()]));
    } catch {
      throw refused;
    }
  }

  /** The service implementation the server runs. */
  service(): grpc.UntypedServiceImplementation {
    const answer = <Q, P>(handle: (request: Q) => P) => (call: grpc.ServerUnaryCall<Q, P>, callback: grpc.sendUnaryData<P>) => {
      try {
        callback(null, handle(call.request));
      } catch (error) {
        if (!(error instanceof StatusError)) throw error;
        callback({ code: error.code, details: error.details });
      }
    };
    return {
      Encrypt: answer((wire: protos.google.cloud.kms.v1.EncryptRequest) => {
        const request = received(wire.name, wire.plaintext as Uint8Array, wire.plaintextCrc32c, wire.additionalAuthenticatedData as Uint8Array, wire.additionalAuthenticatedDataCrc32c);
        this.encryptRequests.push(request);
        return v1.EncryptResponse.create((this.onEncrypt ?? ((r) => this.encryptNormally(r)))(request));
      }),
      Decrypt: answer((wire: protos.google.cloud.kms.v1.DecryptRequest) => {
        const request = received(wire.name, wire.ciphertext as Uint8Array, wire.ciphertextCrc32c, wire.additionalAuthenticatedData as Uint8Array, wire.additionalAuthenticatedDataCrc32c);
        this.decryptRequests.push(request);
        return v1.DecryptResponse.create((this.onDecrypt ?? ((r) => this.decryptNormally(r)))(request));
      }),
    };
  }
}

function received(name: string, data: Uint8Array, dataCrc32c: { value?: unknown } | null | undefined, aad: Uint8Array,
  aadCrc32c: { value?: unknown } | null | undefined): Received {
  return { name, data: Buffer.from(data), dataCrc32c: int64(dataCrc32c), aad: Buffer.from(aad), aadCrc32c: int64(aadCrc32c) };
}

function verifyChecksum(data: Uint8Array, checksum: number | undefined, field: string): void {
  if (checksum !== undefined && checksum !== crc32c(data)) {
    throw new StatusError(grpc.status.INVALID_ARGUMENT, `The checksum in field ${field}_crc32c did not match the data in field ${field}.`);
  }
}

function binding(keyName: string, version: number, aad: Uint8Array): Buffer {
  return Buffer.concat([Buffer.from(`${keyName}\0`), Buffer.of(version), aad]);
}

const method = <Q, P>(name: string, request: { encode(m: Q): { finish(): Uint8Array }; decode(b: Uint8Array): Q },
  response: { encode(m: P): { finish(): Uint8Array }; decode(b: Uint8Array): P }) => ({
  path: `/google.cloud.kms.v1.KeyManagementService/${name}`, requestStream: false, responseStream: false,
  requestSerialize: (m: Q) => Buffer.from(request.encode(m).finish()), requestDeserialize: (b: Buffer) => request.decode(b),
  responseSerialize: (m: P) => Buffer.from(response.encode(m).finish()), responseDeserialize: (b: Buffer) => response.decode(b),
});

const SERVICE = {
  Encrypt: method('Encrypt', v1.EncryptRequest, v1.EncryptResponse),
  Decrypt: method('Decrypt', v1.DecryptRequest, v1.DecryptResponse),
} as unknown as grpc.ServiceDefinition;

/**
 * Options for a real client that reaches only the loopback address, over an insecure channel. A
 * throwaway service account is its credential: never used, as the channel carries no call
 * credentials, but without one the client spends seconds looking for the machine's own.
 */
const FAKE_CREDENTIALS = {
  client_email: 'hkdfguard-test@test-project.iam.gserviceaccount.com',
  private_key: generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
};
const loopback = (port: number) => ({ apiEndpoint: '127.0.0.1', port, sslCreds: grpc.credentials.createInsecure(), credentials: FAKE_CREDENTIALS, projectId: 'test-project' });

/** A fake Cloud KMS, and a real client connected to it; both shut down when the test ends. */
async function fakeCloudKms(t: TestContext): Promise<{ kms: FakeCloudKms; client: KeyManagementServiceClient }> {
  const kms = new FakeCloudKms();
  const server = new grpc.Server();
  server.addService(SERVICE, kms.service());
  const port = await new Promise<number>((resolve, reject) =>
    server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (error, bound) => (error ? reject(error) : resolve(bound))));
  const client = new KeyManagementServiceClient(loopback(port));
  t.after(async () => {
    await client.close();
    server.forceShutdown();
  });
  return { kms, client };
}

/**
 * A client that never reaches the network: each call records the request object it is given - the
 * wrapper's own buffers, not copies - and answers with what `onEncrypt` or `onDecrypt` returns
 * (resolving to [response, ...], as the real client does) or throws.
 */
class StubClient implements CloudKmsClient {
  readonly encryptRequests: EncryptRequest[] = [];
  readonly decryptRequests: DecryptRequest[] = [];
  readonly calls: string[] = [];
  onEncrypt: (request: EncryptRequest) => unknown = (request) => [encrypted(request)];
  onDecrypt: (request: DecryptRequest) => unknown = () => [revealedKey(new Uint8Array(32).fill(7))];
  initialize: (() => Promise<unknown>) | undefined = async () => {
    this.calls.push('initialize');
    return {};
  };

  async encrypt(request: EncryptRequest): Promise<unknown> {
    this.calls.push('encrypt');
    this.encryptRequests.push(request);
    return this.onEncrypt(request);
  }

  async decrypt(request: DecryptRequest): Promise<unknown> {
    this.calls.push('decrypt');
    this.decryptRequests.push(request);
    return this.onDecrypt(request);
  }
}

/** An Encrypt response for `request` that passes every check, with `ciphertext` (by default 113 bytes). */
function encrypted(request: EncryptRequest, ciphertext: Uint8Array = new Uint8Array(113).fill(0x63)): EncryptResponse {
  return {
    name: `${request.name}/cryptoKeyVersions/1`, ciphertext, ciphertextCrc32c: { value: String(crc32c(ciphertext)) },
    verifiedPlaintextCrc32c: true, verifiedAdditionalAuthenticatedDataCrc32c: true,
  };
}

/** A Decrypt response revealing `plaintext`, its checksum as the client decodes it: decimal text. */
function revealedKey(plaintext: Uint8Array): DecryptResponse {
  return { plaintext, plaintextCrc32c: { value: String(crc32c(plaintext)) } };
}

async function wrapWith(wrapper: GoogleKmsKeyWrapper, key: Uint8Array): Promise<Uint8Array> {
  const result = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
  const length = await wrapper.wrap(key, result);
  return result.slice(0, length);
}

async function generate(wrapper: GoogleKmsKeyWrapper): Promise<Uint8Array> {
  const result = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
  const length = await wrapper.generateAndWrap(result);
  return result.slice(0, length);
}

const dek = () => new Uint8Array(randomBytes(32));
const filled = (length: number) => new Uint8Array(length).fill(0xaa);
const aadOf = (context: string) => Buffer.concat([LABEL, Buffer.from(context, 'utf8')]);
const escape = (text: string) => text.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

/** A predicate for assert.rejects: a GoogleKmsError whose message is `message` exactly, or matches it. */
function kmsError(message: string | RegExp, operation?: string): (e: unknown) => boolean {
  return (e: unknown) => {
    assert.ok(e instanceof GoogleKmsError, String(e));
    assert.equal(e.code, 'ERR_HKDFGUARD_GOOGLE_KMS');
    if (typeof message === 'string') assert.equal(e.message, message);
    else assert.match(e.message, message);
    if (operation !== undefined) assert.equal(e.operation, operation);
    assert.equal(e.keyName, KEY_NAME);
    return true;
  };
}

describe('constructing a GoogleKmsKeyWrapper', () => {
  it('refuses a missing or invalid client, options or key file trust', () => {
    const stub = new StubClient();
    for (const [client, options] of [
      [null, {}], [undefined, {}], [{}, {}], [{ encrypt() {} }, {}], [{ decrypt() {} }, {}], ['client', {}],
      [stub, null], [stub, 'options'], [stub, { keyFileTrust: 'S-1-5-18' }], [stub, { keyFileTrust: { windowsPrincipals: [] } }],
    ] as const) {
      assert.throws(() => new GoogleKmsKeyWrapper(client as never, KEY_NAME, options as never), InvalidArgumentError, JSON.stringify(options));
    }
  });

  it('refuses a name that isn\'t a key\'s resource name, a key version\'s included', () => {
    for (const name of [
      undefined, null, 42, '', ' ', 'wrap', `${KEY_NAME}/cryptoKeyVersions/1`, `/${KEY_NAME}`, `${KEY_NAME}/`, `${KEY_NAME}/x`,
      'projects/p/locations/l/keyRings/r', 'projects/p/locations/l/keyRings/r/cryptoKeys/', 'projects//locations/l/keyRings/r/cryptoKeys/k',
      'projects/p/locations/l/keyRings//cryptoKeys/k', 'projects/p/locations/l/keyRings/r/cryptokeys/k', 'projects/p/keyRings/r/cryptoKeys/k',
      `//cloudkms.googleapis.com/${KEY_NAME}`, `https://cloudkms.googleapis.com/v1/${KEY_NAME}`,
    ]) {
      assert.throws(() => new GoogleKmsKeyWrapper(new StubClient(), name as never), (e: unknown) =>
        e instanceof InvalidArgumentError && e.message.includes('isn\'t a Cloud KMS key\'s resource name'), String(name));
    }
  });

  it('accepts any key name Cloud KMS could have made', () => {
    for (const name of [KEY_NAME, 'projects/my-project-123/locations/global/keyRings/ring_1/cryptoKeys/key-2', 'projects/p/locations/l/keyRings/r/cryptoKeys/k']) {
      assert.equal(new GoogleKmsKeyWrapper(new StubClient(), name).keyName, name);
    }
  });

  it('refuses a context that isn\'t a string, isn\'t well-formed text, or is too long', () => {
    for (const context of [42, {}, ['a'], 'a\uD800', '\uDC00b', 'x'.repeat(MAX_CONTEXT_LENGTH + 1), '\u20AC'.repeat(Math.floor(MAX_CONTEXT_LENGTH / 3) + 1)]) {
      assert.throws(() => new GoogleKmsKeyWrapper(new StubClient(), KEY_NAME, { context: context as never }), InvalidArgumentError,
        typeof context === 'string' ? `${context.length} chars` : String(context));
    }
  });

  it('accepts the longest context', async () => {
    const stub = new StubClient();
    await generate(new GoogleKmsKeyWrapper(stub, KEY_NAME, { context: 'x'.repeat(MAX_CONTEXT_LENGTH) }));
    assert.equal((stub.encryptRequests[0]!.additionalAuthenticatedData as Uint8Array).length, LABEL.length + MAX_CONTEXT_LENGTH);
  });

  it('is a KeyWrapper over a real KeyManagementServiceClient, or any client with encrypt and decrypt', async () => {
    const client = new KeyManagementServiceClient(loopback(1));
    try {
      const wrapper: KeyWrapper = new GoogleKmsKeyWrapper(client, KEY_NAME);
      assert.ok(wrapper instanceof GoogleKmsKeyWrapper);
    } finally {
      await client.close();
    }
    const stub = new StubClient();
    stub.initialize = undefined;
    assert.equal(new GoogleKmsKeyWrapper(stub, KEY_NAME).keyName, KEY_NAME);
    assert.equal(GENERATED_KEY_LENGTH, 32);
    assert.equal(MAX_PLAINTEXT_LENGTH, 65536);
    assert.equal(MAX_CONTEXT_LENGTH, 65504);
  });
});

describe('wrap, unwrap and generate-and-wrap', () => {
  it('round-trip a DEK through Cloud KMS', async (t) => {
    const { client } = await fakeCloudKms(t);
    const wrapper = new GoogleKmsKeyWrapper(client, KEY_NAME, { context: CONTEXT });
    const key = dek();
    const wrapped = await wrapWith(wrapper, key);
    const revealed = new Uint8Array(32);

    assert.equal(wrapped.length, 1 + 12 + 32 + 16);
    assert.equal(await wrapper.unwrap(wrapped, revealed), 32);
    assert.deepEqual(revealed, key);
  });

  it('send the key, the plaintext, the label and context as AAD, and a checksum of each', async (t) => {
    const { kms, client } = await fakeCloudKms(t);
    const wrapper = new GoogleKmsKeyWrapper(client, KEY_NAME, { context: CONTEXT });
    const key = dek();
    const wrapped = await wrapWith(wrapper, key);
    await wrapper.unwrap(wrapped, new Uint8Array(32));

    const aad = aadOf(CONTEXT);
    assert.deepEqual(kms.encryptRequests, [{ name: KEY_NAME, data: Buffer.from(key), dataCrc32c: crc32c(key), aad, aadCrc32c: crc32c(aad) }]);
    assert.deepEqual(kms.decryptRequests, [{ name: KEY_NAME, data: Buffer.from(wrapped), dataCrc32c: crc32c(wrapped), aad, aadCrc32c: crc32c(aad) }]);
  });

  it('zero the wrapper\'s copy of the plaintext once the call completes, and leave the caller\'s alone', async () => {
    for (const fail of [false, true]) {
      const stub = new StubClient();
      if (fail) stub.onEncrypt = () => { throw Object.assign(new Error('7 PERMISSION_DENIED: no'), { code: 7, details: 'no' }); };
      const key = dek();
      const result = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
      const wrapping = new GoogleKmsKeyWrapper(stub, KEY_NAME).wrap(key, result);
      if (fail) await assert.rejects(wrapping, GoogleKmsError);
      else await wrapping;

      const sent = stub.encryptRequests[0]!.plaintext as Uint8Array;
      assert.notEqual(sent, key);
      assert.ok(isZero(sent));
      assert.ok(!isZero(key));
    }
  });

  it('wrap a view into a larger buffer', async (t) => {
    const { client } = await fakeCloudKms(t);
    const wrapper = new GoogleKmsKeyWrapper(client, KEY_NAME);
    const backing = new Uint8Array(randomBytes(64));
    const revealed = new Uint8Array(32);
    await wrapper.unwrap(await wrapWith(wrapper, backing.subarray(16, 48)), revealed);
    assert.deepEqual(revealed, backing.subarray(16, 48));
  });

  it('treat an omitted, undefined and empty context alike, binding the label alone', async (t) => {
    const { kms, client } = await fakeCloudKms(t);
    const wrappers = [new GoogleKmsKeyWrapper(client, KEY_NAME), new GoogleKmsKeyWrapper(client, KEY_NAME, { context: undefined }),
      new GoogleKmsKeyWrapper(client, KEY_NAME, { context: '' }), new GoogleKmsKeyWrapper(client, KEY_NAME, { context: null as never })];
    for (const writer of wrappers) {
      const wrapped = await generate(writer);
      for (const reader of wrappers) assert.equal(await reader.unwrap(wrapped, new Uint8Array(32)), 32);
    }
    for (const request of [...kms.encryptRequests, ...kms.decryptRequests]) assert.deepEqual(request.aad, LABEL);
  });

  it('encode the context as UTF-8 after the label', async (t) => {
    const { kms, client } = await fakeCloudKms(t);
    const context = 'caf\u00e9 \u20AC \u{1F600}';
    await generate(new GoogleKmsKeyWrapper(client, KEY_NAME, { context }));
    assert.deepEqual(kms.encryptRequests[0]!.aad, Buffer.concat([LABEL, Buffer.from([0x63, 0x61, 0x66, 0xc3, 0xa9, 0x20, 0xe2, 0x82, 0xac, 0x20, 0xf0, 0x9f, 0x98, 0x80])]));
  });

  it('send a fresh copy of the AAD with every request', async () => {
    const stub = new StubClient();
    const wrapper = new GoogleKmsKeyWrapper(stub, KEY_NAME, { context: CONTEXT });
    await generate(wrapper);
    (stub.encryptRequests[0]!.additionalAuthenticatedData as Uint8Array).fill(0);
    await generate(wrapper);
    assert.deepEqual(Buffer.from(stub.encryptRequests[1]!.additionalAuthenticatedData as Uint8Array), aadOf(CONTEXT));
    assert.notEqual(stub.encryptRequests[0]!.additionalAuthenticatedData, stub.encryptRequests[1]!.additionalAuthenticatedData);
  });

  it('generate a 32-byte DEK in the process, wrap it, and zero it once the call completes', async (t) => {
    const { kms, client } = await fakeCloudKms(t);
    const wrapper = new GoogleKmsKeyWrapper(client, KEY_NAME, { context: CONTEXT });
    const revealed = new Uint8Array(32);
    assert.equal(await wrapper.unwrap(await generate(wrapper), revealed), GENERATED_KEY_LENGTH);
    assert.deepEqual(kms.encryptRequests[0]!.data, Buffer.from(revealed));
    assert.ok(!isZero(revealed));
    const second = new Uint8Array(32);
    await wrapper.unwrap(await generate(wrapper), second);
    assert.notDeepEqual(second, revealed);

    const stub = new StubClient();
    await generate(new GoogleKmsKeyWrapper(stub, KEY_NAME));
    assert.equal((stub.encryptRequests[0]!.plaintext as Uint8Array).length, GENERATED_KEY_LENGTH);
    assert.ok(isZero(stub.encryptRequests[0]!.plaintext as Uint8Array));
  });

  it('keep unwrapping key files made before the key rotated', async (t) => {
    const { kms, client } = await fakeCloudKms(t);
    const wrapper = new GoogleKmsKeyWrapper(client, KEY_NAME, { context: CONTEXT });
    const key = dek();
    const before = await wrapWith(wrapper, key);
    kms.rotate();
    const after = await wrapWith(wrapper, key);

    assert.equal(before[0], 1);
    assert.equal(after[0], 2);
    for (const wrapped of [before, after]) {
      const revealed = new Uint8Array(32);
      await wrapper.unwrap(wrapped, revealed);
      assert.deepEqual(revealed, key);
    }
  });

  it('resend the same plaintext when the client retries', async (t) => {
    const { kms, client } = await fakeCloudKms(t);
    let failures = 1;
    kms.onEncrypt = (request) => {
      if (failures-- > 0) throw new StatusError(grpc.status.UNAVAILABLE, 'Try again.');
      return kms.encryptNormally(request);
    };
    const key = dek();
    const wrapped = await wrapWith(new GoogleKmsKeyWrapper(client, KEY_NAME), key);

    assert.equal(kms.encryptRequests.length, 2);
    assert.deepEqual(kms.encryptRequests[0]!.data, Buffer.from(key));
    assert.deepEqual(kms.encryptRequests[1]!.data, Buffer.from(key));
    const revealed = new Uint8Array(32);
    await new GoogleKmsKeyWrapper(client, KEY_NAME).unwrap(wrapped, revealed);
    assert.deepEqual(revealed, key);
  });

  it('write the revealed key into a view of a larger buffer, and zero what the client decoded once copied', async () => {
    const stub = new StubClient();
    const key = dek();
    const decoded = Uint8Array.from(key);
    stub.onDecrypt = () => [revealedKey(decoded)];
    const backing = new Uint8Array(64);

    assert.equal(await new GoogleKmsKeyWrapper(stub, KEY_NAME).unwrap(new Uint8Array(61), backing.subarray(16)), 32);
    assert.deepEqual(backing.subarray(16, 48), key);
    assert.ok(isZero(backing.subarray(0, 16)) && isZero(backing.subarray(48)));
    assert.ok(isZero(decoded));
  });

  it('accept the largest plaintext Cloud KMS does', async (t) => {
    const { client } = await fakeCloudKms(t);
    const result = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    assert.equal(await new GoogleKmsKeyWrapper(new StubClient(), KEY_NAME).wrap(new Uint8Array(MAX_PLAINTEXT_LENGTH).fill(1), result), 113);
    // Through the wire too: the ciphertext is too long for a key file, which is refused after Cloud KMS accepted the plaintext.
    await assert.rejects(new GoogleKmsKeyWrapper(client, KEY_NAME).wrap(new Uint8Array(MAX_PLAINTEXT_LENGTH).fill(1), result),
      kmsError(`Cloud KMS wrap for key '${KEY_NAME}' returned ${1 + 12 + MAX_PLAINTEXT_LENGTH + 16} bytes; a wrapped DEK is at most 512.`, 'wrap'));
  });
});

describe('refusals', () => {
  it('refuse a DEK wrapped under another key, naming the status Cloud KMS answered with, and zero the result', async (t) => {
    const { client } = await fakeCloudKms(t);
    const wrapped = await wrapWith(new GoogleKmsKeyWrapper(client, OTHER_KEY_NAME, { context: CONTEXT }), dek());
    const result = filled(32);

    await assert.rejects(new GoogleKmsKeyWrapper(client, KEY_NAME, { context: CONTEXT }).unwrap(wrapped, result), (e: unknown) => {
      kmsError(`Cloud KMS unwrap failed for key '${KEY_NAME}': INVALID_ARGUMENT: Decryption failed.`, 'unwrap')(e);
      assert.equal(((e as GoogleKmsError).cause as { code?: unknown }).code, grpc.status.INVALID_ARGUMENT);
      return true;
    });
    assert.ok(isZero(result));
  });

  it('refuse a DEK wrapped under another context, or none', async (t) => {
    const { client } = await fakeCloudKms(t);
    const wrapped = await generate(new GoogleKmsKeyWrapper(client, KEY_NAME, { context: CONTEXT }));
    for (const options of [{ context: 'hkdfguard.other' }, { context: `${CONTEXT} ` }, {}]) {
      await assert.rejects(new GoogleKmsKeyWrapper(client, KEY_NAME, options).unwrap(wrapped, new Uint8Array(32)), kmsError(/INVALID_ARGUMENT: Decryption failed\.$/));
    }
  });

  it('refuse a ciphertext the key made without the HkdfGuard label', async (t) => {
    const { kms, client } = await fakeCloudKms(t);
    const ciphertext = kms.sealDirectly(dek(), KEY_NAME, Buffer.from(CONTEXT));
    await assert.rejects(new GoogleKmsKeyWrapper(client, KEY_NAME, { context: CONTEXT }).unwrap(ciphertext, new Uint8Array(32)), kmsError(/Decryption failed/));
    // With the label it is accepted: the label is all that differs.
    const labelled = kms.sealDirectly(dek(), KEY_NAME, aadOf(CONTEXT));
    assert.equal(await new GoogleKmsKeyWrapper(client, KEY_NAME, { context: CONTEXT }).unwrap(labelled, new Uint8Array(32)), 32);
  });

  it('refuse a tampered DEK', async (t) => {
    const { client } = await fakeCloudKms(t);
    const wrapper = new GoogleKmsKeyWrapper(client, KEY_NAME, { context: CONTEXT });
    const wrapped = await generate(wrapper);
    for (const index of [0, 1, 20, wrapped.length - 1]) {
      const tampered = Uint8Array.from(wrapped);
      tampered[index]! ^= 1;
      await assert.rejects(wrapper.unwrap(tampered, new Uint8Array(32)), GoogleKmsError);
    }
  });

  it('refuse a wrapped DEK out of bounds without calling Cloud KMS, zeroing the result', async () => {
    for (const size of [0, MAX_WRAPPED_KEY_BYTES + 1]) {
      const stub = new StubClient();
      const result = filled(32);
      await assert.rejects(new GoogleKmsKeyWrapper(stub, KEY_NAME).unwrap(new Uint8Array(size), result),
        kmsError(`A wrapped DEK is 1-${MAX_WRAPPED_KEY_BYTES} bytes; got ${size}.`, 'unwrap'));
      assert.deepEqual(stub.calls, []);
      assert.ok(isZero(result));
    }
  });

  it('refuse a result too small for the revealed key, zeroing it and the client\'s plaintext', async () => {
    const stub = new StubClient();
    const revealed = filled(32);
    stub.onDecrypt = () => [revealedKey(revealed)];
    const result = filled(16);
    await assert.rejects(new GoogleKmsKeyWrapper(stub, KEY_NAME).unwrap(new Uint8Array(61), result),
      (e: unknown) => e instanceof InvalidArgumentError && e.message.includes('result holds 16'));
    assert.ok(isZero(result));
    assert.ok(isZero(revealed));
  });

  it('refuse a response with no plaintext, or one that doesn\'t match its checksum, zeroing the result', async () => {
    const key = filled(32);
    for (const [response, message] of [
      [{}, /returned no plaintext\.$/], [{ plaintext: null }, /returned no plaintext\.$/], [{ plaintext: new Uint8Array(0) }, /returned no plaintext\.$/],
      [{ plaintext: Buffer.from(key).toString('base64') }, /returned no plaintext\.$/],
      [{ plaintext: key }, /doesn't match its checksum: it was corrupted in transit\.$/],
      [{ plaintext: key, plaintextCrc32c: null }, /doesn't match its checksum/],
      [{ plaintext: key, plaintextCrc32c: { value: String(crc32c(key) ^ 1) } }, /doesn't match its checksum/],
      [{ plaintext: key, plaintextCrc32c: { value: `${crc32c(key)}.0` } }, /doesn't match its checksum/],
      [{ plaintext: key, plaintextCrc32c: { value: String(crc32c(key) + 2 ** 32) } }, /doesn't match its checksum/],
    ] as const) {
      const stub = new StubClient();
      const decoded = Uint8Array.from(key);
      stub.onDecrypt = () => [{ ...response, ...('plaintext' in response && response.plaintext === key ? { plaintext: decoded } : {}) }];
      const result = filled(32);
      await assert.rejects(new GoogleKmsKeyWrapper(stub, KEY_NAME).unwrap(new Uint8Array(61), result), kmsError(message, 'unwrap'), JSON.stringify(response));
      assert.ok(isZero(result));
      if ('plaintext' in response && response.plaintext === key) assert.ok(isZero(decoded));
    }
  });

  it('accept a checksum as a number, a bigint or a Long-like object, as other decoders give it', async () => {
    const key = dek();
    for (const value of [crc32c(key), BigInt(crc32c(key)), { toString: () => String(crc32c(key)) }]) {
      const stub = new StubClient();
      stub.onDecrypt = () => [{ plaintext: Uint8Array.from(key), plaintextCrc32c: { value } }];
      const result = new Uint8Array(32);
      assert.equal(await new GoogleKmsKeyWrapper(stub, KEY_NAME).unwrap(new Uint8Array(61), result), 32);
      assert.deepEqual(result, key);
    }
  });

  it('refuse a plaintext Cloud KMS would refuse, without calling it', async () => {
    for (const size of [0, MAX_PLAINTEXT_LENGTH + 1]) {
      const stub = new StubClient();
      await assert.rejects(new GoogleKmsKeyWrapper(stub, KEY_NAME).wrap(new Uint8Array(size), new Uint8Array(MAX_WRAPPED_KEY_BYTES)),
        (e: unknown) => e instanceof InvalidArgumentError && e.message === `Cloud KMS wraps 1-65536 bytes; got ${size}.`);
      assert.deepEqual(stub.calls, []);
    }
  });

  it('refuse a result too small for the wrapped DEK', async (t) => {
    const { client } = await fakeCloudKms(t);
    await assert.rejects(new GoogleKmsKeyWrapper(client, KEY_NAME).wrap(dek(), new Uint8Array(60)),
      (e: unknown) => e instanceof InvalidArgumentError && e.message === 'The wrapped DEK is 61 bytes; result holds 60.');
  });

  it('refuse a response naming a version of another key, or no version', async () => {
    for (const name of [
      `${OTHER_KEY_NAME}/cryptoKeyVersions/1`, `${OTHER_KEY_NAME}/cryptoKeyVersions/123456`, `${KEY_NAME}x/cryptoKeyVersions/1`, KEY_NAME,
      `${KEY_NAME}/cryptoKeyVersions/`, `${KEY_NAME}/cryptoKeyVersions/1/x`, `${KEY_NAME}/cryptoKeyVersions//`, `${KEY_NAME}/1`, '', undefined, null, 1,
    ]) {
      const stub = new StubClient();
      stub.onEncrypt = (request) => [{ ...encrypted(request), name }];
      await assert.rejects(generate(new GoogleKmsKeyWrapper(stub, KEY_NAME)),
        kmsError(`Cloud KMS wrap for key '${KEY_NAME}' reported key version '${String(name)}' instead.`, 'wrap'), String(name));
    }
  });

  it('accept any version of this key', async () => {
    for (const version of ['1', '123456', 'v2']) {
      const stub = new StubClient();
      stub.onEncrypt = (request) => [{ ...encrypted(request), name: `${KEY_NAME}/cryptoKeyVersions/${version}` }];
      assert.equal((await generate(new GoogleKmsKeyWrapper(stub, KEY_NAME))).length, 113);
    }
  });

  it('refuse a response that didn\'t verify the request\'s checksums', async (t) => {
    for (const unverified of [{ verifiedPlaintextCrc32c: false }, { verifiedAdditionalAuthenticatedDataCrc32c: false },
      { verifiedPlaintextCrc32c: undefined }, { verifiedAdditionalAuthenticatedDataCrc32c: 'true' }]) {
      const stub = new StubClient();
      stub.onEncrypt = (request) => [{ ...encrypted(request), ...unverified }];
      await assert.rejects(generate(new GoogleKmsKeyWrapper(stub, KEY_NAME)),
        kmsError(`Cloud KMS wrap for key '${KEY_NAME}' didn't verify the request's checksums: it was corrupted in transit.`), JSON.stringify(unverified));
    }
    // Over the wire: a service that ignores the checksums leaves both flags false.
    const { kms, client } = await fakeCloudKms(t);
    kms.onEncrypt = (request) => ({ ...kms.encryptNormally(request), verifiedAdditionalAuthenticatedDataCrc32c: false });
    await assert.rejects(generate(new GoogleKmsKeyWrapper(client, KEY_NAME)), kmsError(/didn't verify the request's checksums/));
  });

  it('refuse a ciphertext that doesn\'t match its checksum', async (t) => {
    const ciphertext = new Uint8Array(113).fill(0x63);
    for (const checksum of [null, undefined, { value: null }, { value: String(crc32c(ciphertext) ^ 0x80000000) }, { value: '-1' }, { value: 'abc' }]) {
      const stub = new StubClient();
      stub.onEncrypt = (request) => [{ ...encrypted(request, ciphertext), ciphertextCrc32c: checksum }];
      await assert.rejects(generate(new GoogleKmsKeyWrapper(stub, KEY_NAME)),
        kmsError(`Cloud KMS wrap for key '${KEY_NAME}' returned a ciphertext that doesn't match its checksum: it was corrupted in transit.`), JSON.stringify(checksum));
    }
    const { kms, client } = await fakeCloudKms(t);
    kms.onEncrypt = (request) => {
      const response = kms.encryptNormally(request);
      (response.ciphertext as Uint8Array)[5]! ^= 1;
      return response;
    };
    await assert.rejects(generate(new GoogleKmsKeyWrapper(client, KEY_NAME)), kmsError(/doesn't match its checksum/));
  });

  it('refuse a response with no ciphertext, or one over the key-file limit', async () => {
    for (const ciphertext of [undefined, null, new Uint8Array(0), 'Y2lwaGVy']) {
      const stub = new StubClient();
      stub.onEncrypt = (request) => [{ ...encrypted(request), ciphertext }];
      await assert.rejects(generate(new GoogleKmsKeyWrapper(stub, KEY_NAME)), kmsError(`Cloud KMS wrap for key '${KEY_NAME}' returned no ciphertext.`));
    }
    const stub = new StubClient();
    stub.onEncrypt = (request) => [encrypted(request, new Uint8Array(MAX_WRAPPED_KEY_BYTES + 1))];
    await assert.rejects(new GoogleKmsKeyWrapper(stub, KEY_NAME).wrap(dek(), new Uint8Array(1024)),
      kmsError(`Cloud KMS wrap for key '${KEY_NAME}' returned 513 bytes; a wrapped DEK is at most 512.`));
    stub.onEncrypt = (request) => [encrypted(request, new Uint8Array(MAX_WRAPPED_KEY_BYTES).fill(1))];
    assert.equal(await new GoogleKmsKeyWrapper(stub, KEY_NAME).wrap(dek(), new Uint8Array(1024)), MAX_WRAPPED_KEY_BYTES);
  });

  it('refuse buffers that are not Uint8Arrays', async () => {
    const wrapper = new GoogleKmsKeyWrapper(new StubClient(), KEY_NAME);
    await assert.rejects(wrapper.wrap('key' as never, new Uint8Array(MAX_WRAPPED_KEY_BYTES)), InvalidArgumentError);
    await assert.rejects(wrapper.wrap(dek(), [] as never), InvalidArgumentError);
    await assert.rejects(wrapper.unwrap(new Uint8Array(61), [] as never), InvalidArgumentError);
    const result = filled(32);
    await assert.rejects(wrapper.unwrap([1, 2] as never, result), InvalidArgumentError);
    assert.ok(isZero(result));
    await assert.rejects(wrapper.generateAndWrap(undefined as never), InvalidArgumentError);
  });
});

describe('cancellation', () => {
  it('rejects an aborted signal without calling Cloud KMS', async () => {
    const stub = new StubClient();
    const wrapper = new GoogleKmsKeyWrapper(stub, KEY_NAME);
    const result = filled(32);
    await assert.rejects(wrapper.wrap(dek(), new Uint8Array(MAX_WRAPPED_KEY_BYTES), AbortSignal.abort()), { name: 'AbortError' });
    await assert.rejects(wrapper.unwrap(new Uint8Array(61), result, AbortSignal.abort()), { name: 'AbortError' });
    await assert.rejects(wrapper.generateAndWrap(new Uint8Array(MAX_WRAPPED_KEY_BYTES), AbortSignal.abort()), { name: 'AbortError' });
    await assert.rejects(wrapper.readKeyFile('v1.key', AbortSignal.abort()), { name: 'AbortError' });
    assert.deepEqual(stub.calls, []);
    assert.ok(isZero(result));
  });

  it('stops waiting when the signal aborts, rejecting with its reason, and zeroes the key sent once the call ends', async () => {
    const stub = new StubClient();
    let answer!: (value: unknown) => void;
    stub.onEncrypt = (request) => new Promise((resolve) => { answer = () => resolve([encrypted(request)]); });
    const controller = new AbortController();
    const reason = new Error('the caller gave up');
    const wrapping = new GoogleKmsKeyWrapper(stub, KEY_NAME).wrap(dek(), new Uint8Array(MAX_WRAPPED_KEY_BYTES), controller.signal);
    await new Promise((resolve) => setImmediate(resolve));

    controller.abort(reason);
    await assert.rejects(wrapping, (e: unknown) => e === reason);
    // The client may still be sending the request: the key stays as it is until the call ends.
    const sent = stub.encryptRequests[0]!.plaintext as Uint8Array;
    assert.ok(!isZero(sent));
    answer(undefined);
    await new Promise((resolve) => setImmediate(resolve));
    assert.ok(isZero(sent));
  });

  it('zeroes a key revealed after the signal aborted, and the result', async () => {
    const stub = new StubClient();
    let answer!: () => void;
    const decoded = filled(32);
    stub.onDecrypt = () => new Promise((resolve) => { answer = () => resolve([revealedKey(decoded)]); });
    const controller = new AbortController();
    const result = filled(32);
    const unwrapping = new GoogleKmsKeyWrapper(stub, KEY_NAME).unwrap(new Uint8Array(61), result, controller.signal);
    await new Promise((resolve) => setImmediate(resolve));

    controller.abort();
    await assert.rejects(unwrapping, { name: 'AbortError' });
    assert.ok(isZero(result));
    answer();
    await new Promise((resolve) => setImmediate(resolve));
    assert.ok(isZero(decoded));
  });

  it('finishes normally when the signal doesn\'t abort, and leaves an abort the client reports as it is', async () => {
    const stub = new StubClient();
    const controller = new AbortController();
    assert.equal((await generate(new GoogleKmsKeyWrapper(stub, KEY_NAME))).length, 113);
    const result = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    assert.equal(await new GoogleKmsKeyWrapper(stub, KEY_NAME).generateAndWrap(result, controller.signal), 113);

    const aborted = Object.assign(new Error('The operation was aborted'), { name: 'AbortError' });
    stub.onDecrypt = () => { throw aborted; };
    await assert.rejects(new GoogleKmsKeyWrapper(stub, KEY_NAME).unwrap(new Uint8Array(61), filled(32), controller.signal), (e: unknown) => e === aborted);
  });
});

describe('failures', () => {
  it('name the gRPC status and Google\'s description, with the client\'s error as the cause', async (t) => {
    const { kms, client } = await fakeCloudKms(t);
    for (const [code, name] of [[grpc.status.PERMISSION_DENIED, 'PERMISSION_DENIED'], [grpc.status.NOT_FOUND, 'NOT_FOUND'],
      [grpc.status.FAILED_PRECONDITION, 'FAILED_PRECONDITION'], [grpc.status.UNAUTHENTICATED, 'UNAUTHENTICATED']] as const) {
      const details = `Permission 'cloudkms.cryptoKeyVersions.useToEncrypt' denied (${name}).`;
      kms.onEncrypt = () => { throw new StatusError(code, details); };
      kms.onDecrypt = kms.onEncrypt;
      await assert.rejects(generate(new GoogleKmsKeyWrapper(client, KEY_NAME)), (e: unknown) => {
        kmsError(`Cloud KMS wrap failed for key '${KEY_NAME}': ${name}: ${details}`, 'wrap')(e);
        assert.equal(((e as GoogleKmsError).cause as { code?: unknown }).code, code);
        return true;
      });
      await assert.rejects(new GoogleKmsKeyWrapper(client, KEY_NAME).unwrap(new Uint8Array(61), filled(32)),
        kmsError(`Cloud KMS unwrap failed for key '${KEY_NAME}': ${name}: ${details}`, 'unwrap'));
    }
  });

  it('report a checksum Cloud KMS found didn\'t match', async (t) => {
    const { client } = await fakeCloudKms(t);
    const corrupting: CloudKmsClient = {
      encrypt: (request) => client.encrypt({ ...request, plaintextCrc32c: { value: 1 } }),
      decrypt: (request) => client.decrypt(request),
    };
    await assert.rejects(generate(new GoogleKmsKeyWrapper(corrupting, KEY_NAME)),
      kmsError(`Cloud KMS wrap failed for key '${KEY_NAME}': INVALID_ARGUMENT: The checksum in field plaintext_crc32c did not match the data in field plaintext.`));
  });

  it('use the message when a status has no details, without repeating the status', async () => {
    for (const [failure, text] of [
      [Object.assign(new Error('Total timeout of API google.cloud.kms.v1.KeyManagementService exceeded 60000 milliseconds retrying error'), { code: 4 }),
        'DEADLINE_EXCEEDED: Total timeout of API google.cloud.kms.v1.KeyManagementService exceeded 60000 milliseconds retrying error'],
      [Object.assign(new Error('14 UNAVAILABLE: No connection established.'), { code: 14, details: '' }), 'UNAVAILABLE: No connection established.'],
      [Object.assign(new Error('Internal error.'), { code: 13, details: 42 }), 'INTERNAL: Internal error.'],
    ] as const) {
      const stub = new StubClient();
      stub.onEncrypt = () => { throw failure; };
      await assert.rejects(generate(new GoogleKmsKeyWrapper(stub, KEY_NAME)), (e: unknown) => {
        kmsError(`Cloud KMS wrap failed for key '${KEY_NAME}': ${text}`)(e);
        assert.equal((e as GoogleKmsError).cause, failure);
        return true;
      });
    }
  });

  it('use the message of a failure that carries no gRPC status', async () => {
    for (const failure of [
      new Error('Could not load the default credentials. Browse to https://cloud.google.com/docs/authentication/getting-started for more information.'),
      Object.assign(new Error('Unable to read the credential file specified by the GOOGLE_APPLICATION_CREDENTIALS environment variable.'), { code: 'ENOENT' }),
      Object.assign(new Error('Out of range'), { code: 17 }), Object.assign(new Error('Negative'), { code: -1 }), new TypeError('a bug in a test double'),
    ]) {
      const stub = new StubClient();
      stub.onDecrypt = () => { throw failure; };
      const result = filled(32);
      await assert.rejects(new GoogleKmsKeyWrapper(stub, KEY_NAME).unwrap(new Uint8Array(61), result), (e: unknown) => {
        kmsError(`Cloud KMS unwrap failed for key '${KEY_NAME}': ${failure.message}`, 'unwrap')(e);
        assert.equal((e as GoogleKmsError).cause, failure);
        return true;
      });
      assert.ok(isZero(result));
    }
    const stub = new StubClient();
    stub.onEncrypt = () => { throw 'a string'; };
    await assert.rejects(generate(new GoogleKmsKeyWrapper(stub, KEY_NAME)), kmsError(`Cloud KMS wrap failed for key '${KEY_NAME}': a string`));
  });

  it('initialize the client before every call, and fail the call without making it when that fails', async () => {
    const stub = new StubClient();
    const wrapper = new GoogleKmsKeyWrapper(stub, KEY_NAME);
    await wrapper.unwrap(await generate(wrapper), new Uint8Array(32));
    assert.deepEqual(stub.calls, ['initialize', 'encrypt', 'initialize', 'decrypt']);

    const noCredentials = new Error('Could not load the default credentials.');
    const failing = new StubClient();
    failing.initialize = () => Promise.reject(noCredentials);
    const key = dek();
    await assert.rejects(new GoogleKmsKeyWrapper(failing, KEY_NAME).wrap(key, new Uint8Array(MAX_WRAPPED_KEY_BYTES)), (e: unknown) => {
      kmsError(`Cloud KMS wrap failed for key '${KEY_NAME}': Could not load the default credentials.`, 'wrap')(e);
      assert.equal((e as GoogleKmsError).cause, noCredentials);
      return true;
    });
    const result = filled(32);
    await assert.rejects(new GoogleKmsKeyWrapper(failing, KEY_NAME).unwrap(new Uint8Array(61), result), kmsError(/Could not load the default credentials/, 'unwrap'));
    assert.deepEqual(failing.calls, []);
    assert.ok(isZero(result));
  });

  it('don\'t end the process when the real client finds no credential', () => {
    // Google's client, called with no credential, rejects the call and also raises an unhandled
    // rejection of its own, which ends the process - unless it was initialized, and failed, first.
    const script = `
      const { KeyManagementServiceClient } = require('@google-cloud/kms');
      const { GoogleKmsKeyWrapper, GoogleKmsError } = require(${JSON.stringify(join(__dirname, 'index.js'))});
      (async () => {
        const client = new KeyManagementServiceClient();
        const wrapper = new GoogleKmsKeyWrapper(client, ${JSON.stringify(KEY_NAME)});
        for (let i = 0; i < 2; i++) {
          try { await wrapper.generateAndWrap(new Uint8Array(512)); console.log('wrapped'); }
          catch (e) { console.log(e instanceof GoogleKmsError ? 'refused: ' + e.message : 'other: ' + e); }
        }
        await new Promise((resolve) => setTimeout(resolve, 300));
        console.log('alive');
      })();`;
    const child = spawnSync(process.execPath, ['-e', script], {
      cwd: __dirname, encoding: 'utf8', timeout: 60_000,
      env: { ...process.env, GOOGLE_APPLICATION_CREDENTIALS: join(tmpdir(), 'hkdfguard-no-such-credential.json'), GOOGLE_SDK_NODE_LOGGING: '' },
    });
    assert.equal(child.status, 0, child.stderr);
    const lines = child.stdout.trim().split(/\r?\n/);
    assert.equal(lines.length, 3, child.stdout);
    for (const line of lines.slice(0, 2)) {
      assert.match(line, new RegExp(`^refused: Cloud KMS wrap failed for key '${escape(KEY_NAME)}': Unable to read the credential file`));
    }
    assert.equal(lines[2], 'alive');
  });

  it('refuse a client that returns no response', async () => {
    for (const reply of [undefined, null, [], [null], [undefined, {}], {}, 'response', [42]]) {
      const stub = new StubClient();
      stub.onEncrypt = () => reply;
      stub.onDecrypt = () => reply;
      await assert.rejects(generate(new GoogleKmsKeyWrapper(stub, KEY_NAME)), kmsError(`Cloud KMS wrap for key '${KEY_NAME}' returned no response.`), JSON.stringify(reply));
      await assert.rejects(new GoogleKmsKeyWrapper(stub, KEY_NAME).unwrap(new Uint8Array(61), filled(32)),
        kmsError(`Cloud KMS unwrap for key '${KEY_NAME}' returned no response.`));
    }
  });
});

describe('CRC32C', () => {
  it('matches the standard check values', () => {
    // RFC 3720, B.4, and the catalogue's check value for "123456789".
    assert.equal(crc32c(new Uint8Array(0)), 0);
    assert.equal(crc32c(Buffer.from('123456789')), 0xe3069283);
    assert.equal(crc32c(new Uint8Array(32)), 0x8a9136aa);
    assert.equal(crc32c(new Uint8Array(32).fill(0xff)), 0x62a8ab43);
    assert.equal(crc32c(Uint8Array.from({ length: 32 }, (_, i) => i)), 0x46dd794e);
    assert.equal(crc32c(Uint8Array.from({ length: 32 }, (_, i) => 31 - i)), 0x113fdb5c);
    assert.equal(crc32c(Buffer.from('123456789').subarray(2, 5)), crc32c(Buffer.from('345')));
  });
});

describe('with the rest of HkdfGuard', () => {
  it('lets a crypto provider generate and reveal its DEK through Cloud KMS', async (t) => {
    const { kms, client } = await fakeCloudKms(t);
    const provider = await new AesGcmCryptoProviderFactory().createEphemeral(new GoogleKmsKeyWrapper(client, KEY_NAME, { context: CONTEXT }), { expirySeconds: 60 });
    try {
      const expected = new TextEncoder().encode('hello, cloud kms');
      // encrypt zeroes the plaintext it is given, so it gets a copy.
      const encrypted = new Uint8Array(provider.encryptedAllocationLength(expected.length));
      const encryptedLength = provider.encrypt(Uint8Array.from(expected), encrypted);
      const decrypted = new Uint8Array(provider.decryptedAllocationLength(encryptedLength));
      const decryptedLength = provider.decrypt(encrypted.subarray(0, encryptedLength), decrypted);
      assert.deepEqual(decrypted.subarray(0, decryptedLength), expected);
      assert.equal(kms.encryptRequests.length, 1);
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
  writeFileSync(path, randomBytes(113));
  return path;
}

const notTrusted = (e: unknown) => e instanceof KeyFileError && e.code === 'EACCES' && e.message.includes('not trusted');

describe('reading key files', () => {
  it('refuses by default a file the current user could have replaced', { skip: !isWindows && !isUnix && 'Windows, Linux and Apple silicon macOS only.' }, async (t) => {
    await assert.rejects(new GoogleKmsKeyWrapper(new StubClient(), KEY_NAME, { context: CONTEXT }).readKeyFile(userWritableKeyFile(t)), notTrusted);
  });

  it('trusts administrators only when given no trust', { skip: !isWindows && !isUnix && 'Windows, Linux and Apple silicon macOS only.' }, async (t) => {
    // The same refusal as the default: an omitted trust is administratorsOnly, never "anyone".
    await assert.rejects(new GoogleKmsKeyWrapper(new StubClient(), KEY_NAME, { keyFileTrust: undefined }).readKeyFile(userWritableKeyFile(t)), notTrusted);
  });

  it('refuses a missing path', async () => {
    for (const path of ['', undefined]) {
      await assert.rejects(new GoogleKmsKeyWrapper(new StubClient(), KEY_NAME).readKeyFile(path as string), InvalidArgumentError);
    }
  });

  it('reads a file the writer\'s account is trusted for, and it reveals (Windows)', { skip: !isWindows && 'Windows only.' }, async (t) => {
    const { client } = await fakeCloudKms(t);
    const wrapper = new GoogleKmsKeyWrapper(client, KEY_NAME, { context: CONTEXT, keyFileTrust: new KeyFileTrust({ windowsPrincipals: [windowsCurrentUserSid()] }) });
    const wrapped = await generate(wrapper);
    const path = userWritableKeyFile(t);
    writeFileSync(path, wrapped);

    const read = await wrapper.readKeyFile(path);
    assert.deepEqual(read, wrapped);
    assert.equal(await wrapper.unwrap(read, new Uint8Array(32)), 32);
  });

  it('refuses to trust everyone (Windows)', { skip: !isWindows && 'Windows only.' }, async (t) => {
    const wrapper = new GoogleKmsKeyWrapper(new StubClient(), KEY_NAME, { keyFileTrust: new KeyFileTrust({ windowsPrincipals: ['S-1-1-0'] }) });
    await assert.rejects(wrapper.readKeyFile(userWritableKeyFile(t)), (e: unknown) => e instanceof InvalidArgumentError && e.message.includes('every account'));
  });

  it('reads a file in a directory only its trusted owner can write, and it reveals (Linux and macOS)', { skip: !isUnix && 'Linux and Apple silicon macOS only.' }, async (t) => {
    const directory = keyFileDirectory(t, 'hkdfguard-googlekms-');
    if (directory === undefined) return;
    const { client } = await fakeCloudKms(t);
    const wrapper = new GoogleKmsKeyWrapper(client, KEY_NAME, { keyFileTrust: new KeyFileTrust({ unixUserIds: [process.geteuid!()] }) });
    const wrapped = await generate(wrapper);
    const path = join(directory, 'v1.key');
    writeFileSync(path, wrapped, { mode: 0o600 });

    const read = await wrapper.readKeyFile(path);
    assert.deepEqual(read, wrapped);
    assert.equal(await wrapper.unwrap(read, new Uint8Array(32)), 32);
  });
});

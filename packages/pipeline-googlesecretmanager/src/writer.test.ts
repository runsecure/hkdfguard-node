import { strict as assert } from 'node:assert';
import { generateKeyPairSync } from 'node:crypto';
import { describe, it, type TestContext } from 'node:test';
import { protos, SecretManagerServiceClient } from '@google-cloud/secret-manager';
import * as grpc from '@grpc/grpc-js';
import { InvalidArgumentError, isZero } from '@runsecure/hkdfguard-abstractions';
import { crc32c } from '@runsecure/hkdfguard-abstractions/internal';
import { AesGcmPipelineDataProtector } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { DefaultFormatProvider } from '@runsecure/hkdfguard-dek';
import { decryptPipelineValue, PIPELINE_FORMAT_LIMIT, secretPipelineWriterContract } from '@runsecure/hkdfguard-test-support';
import { ResponseCapture, type AccessedSecretVersion } from './capture.js';
import { retrySettings } from './writer.js';
import { GoogleSecretManagerSecretPipelineWriter, InvalidSecretDataError, SecretsNotFoundError } from './index.js';

const v1 = protos.google.cloud.secretmanager.v1;
type AccessResponse = protos.google.cloud.secretmanager.v1.IAccessSecretVersionResponse;
type AccessRequest = protos.google.cloud.secretmanager.v1.AccessSecretVersionRequest;

const PROJECT_ID = 'hkdfguard-test';
// Google answers with the project's number, not the ID it was asked with.
const PROJECT_NUMBER = '123456789012';
const METHOD = '/google.cloud.secretmanager.v1.SecretManagerService/AccessSecretVersion';
const VERSION_NAME = /^projects\/([^/]+)\/secrets\/([^/]+)\/versions\/([^/]+)$/;
const utf8 = (s: string) => new TextEncoder().encode(s);

/**
 * Secret Manager on the loopback address: a gRPC server implementing only AccessSecretVersion,
 * reached through a real SecretManagerServiceClient, so the client's stub, channel and status errors
 * are as they would be against Google. Secret IDs are matched exactly, as Google matches them, and
 * responses name the project by its number and carry a CRC32C, as Google's do for payloads added with
 * one. Every call's resource name and metadata are recorded.
 */
class FakeSecretManager {
  readonly secrets = new Map<string, Uint8Array>();
  readonly accesses: string[] = [];
  readonly metadata: grpc.Metadata[] = [];
  /** When set, every call fails with this status instead of answering. */
  failure: { code: grpc.status; details: string } | undefined;
  /** Statuses the next calls fail with, one each, before failure and the secrets are consulted. */
  nextFailures: grpc.status[] = [];
  /** Rewrites a response before it is sent. */
  tamper: ((response: AccessResponse) => AccessResponse) | undefined;

  set(id: string, value: string | Uint8Array): void {
    this.secrets.set(id, typeof value === 'string' ? utf8(value) : value);
  }

  /** The secret ID of every access, in order. */
  gets(): string[] {
    return this.accesses.map((a) => VERSION_NAME.exec(a)?.[2] ?? a);
  }

  service(): grpc.UntypedServiceImplementation {
    return {
      AccessSecretVersion: (call: grpc.ServerUnaryCall<AccessRequest, Buffer>, callback: grpc.sendUnaryData<Buffer>) => {
        const name = call.request.name;
        this.accesses.push(name);
        this.metadata.push(call.metadata);
        const next = this.nextFailures.shift();
        if (next !== undefined) return callback({ code: next, details: 'Failing once in a test.' });
        if (this.failure !== undefined) return callback(this.failure);

        const match = VERSION_NAME.exec(name);
        if (match === null || match[1] !== PROJECT_ID || match[3] !== 'latest') {
          return callback({ code: grpc.status.INVALID_ARGUMENT, details: `Unexpected resource name ${name}.` });
        }
        const id = match[2]!;
        const value = this.secrets.get(id);
        if (value === undefined) {
          return callback({ code: grpc.status.NOT_FOUND, details: `Secret [projects/${PROJECT_NUMBER}/secrets/${id}] not found or has no versions.` });
        }

        let response: AccessResponse = { name: `projects/${PROJECT_NUMBER}/secrets/${id}/versions/1`, payload: { data: value, dataCrc32c: crc32c(value) } };
        if (this.tamper !== undefined) response = this.tamper(response);
        callback(null, Buffer.from(v1.AccessSecretVersionResponse.encode(response).finish()));
      },
    };
  }
}

const SERVICE = {
  AccessSecretVersion: {
    path: METHOD, requestStream: false, responseStream: false,
    requestSerialize: (m: AccessRequest) => Buffer.from(v1.AccessSecretVersionRequest.encode(m).finish()),
    requestDeserialize: (b: Buffer) => v1.AccessSecretVersionRequest.decode(b),
    responseSerialize: (raw: Buffer) => raw,
    responseDeserialize: (b: Buffer) => b,
  },
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

/** A fake Secret Manager, and a real client connected to it; shut down when the test ends. */
async function startFake(t: TestContext): Promise<{ google: FakeSecretManager; client: SecretManagerServiceClient; port: number }> {
  const google = new FakeSecretManager();
  const server = new grpc.Server();
  server.addService(SERVICE, google.service());
  const port = await new Promise<number>((resolve, reject) =>
    server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (error, bound) => (error ? reject(error) : resolve(bound))));
  const client = new SecretManagerServiceClient(loopback(port));
  t.after(async () => {
    await client.close();
    server.forceShutdown();
  });
  return { google, client, port };
}

const newProtector = () => new AesGcmPipelineDataProtector(new DefaultFormatProvider(PIPELINE_FORMAT_LIMIT), 3);

/** A fake, a client, a protector, and writers over them - all closed when the test ends. */
async function setUp(t: TestContext) {
  const { google, client, port } = await startFake(t);
  const protector = newProtector();
  t.after(() => protector.close());
  const create = (secretNames: readonly string[]) => {
    const writer = new GoogleSecretManagerSecretPipelineWriter(client, PROJECT_ID, protector, secretNames);
    t.after(() => writer.close());
    return writer;
  };
  const decrypt = (encrypted: string | undefined, fileName: string) => decryptPipelineValue(protector, encrypted!, fileName);
  return { google, client, port, protector, create, decrypt };
}

/** Every response the writer's deserializer parsed, and every message gRPC handed it, to check they were zeroed. */
function recordParsed(t: TestContext): { versions: AccessedSecretVersion[]; received: Uint8Array[] } {
  const parsed = { versions: [] as AccessedSecretVersion[], received: [] as Uint8Array[] };
  const deserialize = ResponseCapture.prototype.deserialize;
  t.mock.method(ResponseCapture.prototype, 'deserialize', function (this: ResponseCapture, raw: Uint8Array) {
    parsed.received.push(raw);
    const version = deserialize.call(this, raw);
    parsed.versions.push(version);
    return version;
  });
  return parsed;
}

function assertTheOneResponseWasZeroed(parsed: { versions: AccessedSecretVersion[]; received: Uint8Array[] }): void {
  assert.equal(parsed.versions.length, 1);
  assert.ok(parsed.versions[0]!.data.length > 0);
  assert.ok(isZero(parsed.versions[0]!.data));
  assert.equal(parsed.received.length, 1);
  assert.ok(isZero(parsed.received[0]!));
}

secretPipelineWriterContract('GoogleSecretManagerSecretPipelineWriter over a fake Secret Manager', {
  newProtector,
  setUp: async (t) => {
    const { google, client } = await startFake(t);
    return {
      // No key ring anywhere: the only key is the protector's.
      createWriter: (protector, secretNames) => new GoogleSecretManagerSecretPipelineWriter(client, PROJECT_ID, protector, secretNames),
      setText: (name, text) => google.set(name, text),
      setKeys: (name, json) => google.set(name, json),
      failReads: () => {
        google.failure = { code: grpc.status.PERMISSION_DENIED, details: 'Denied in a test.' };
      },
      isReadFailure: (error) => (error as { code?: unknown }).code === grpc.status.PERMISSION_DENIED,
      reads: () => google.gets(),
    };
  },
});

describe('GoogleSecretManagerSecretPipelineWriter', () => {
  it('reads each secret\'s latest version, with the routing header', async (t) => {
    const { google, create } = await setUp(t);
    google.set('api-key', 'value');
    const writer = create(['api-key']);

    await writer.pullSecrets();

    assert.deepEqual(google.accesses, ['projects/hkdfguard-test/secrets/api-key/versions/latest']);
    assert.deepEqual(google.metadata[0]!.get('x-goog-request-params'), ['name=projects%2Fhkdfguard-test%2Fsecrets%2Fapi-key%2Fversions%2Flatest']);
  });

  it('reads the whole payload for a name without a key, and its keys from the one call', async (t) => {
    const { google, create, decrypt } = await setUp(t);
    google.set('db_login', '{"user":"app"}');
    const writer = create(['db_login', 'db_login#user']);

    await writer.pullSecrets();

    assert.equal(decrypt(writer.protectedSecrets.get('db_login'), 'db_login'), '{"user":"app"}');
    assert.equal(decrypt(writer.protectedSecrets.get('db_login__user'), 'db_login__user'), 'app');
    assert.deepEqual(google.gets(), ['db_login']);
  });

  it('zeroes the deserialized payload and the message gRPC received', async (t) => {
    const { google, create } = await setUp(t);
    const parsed = recordParsed(t);
    google.set('item', 's3cret');

    await create(['item']).pullSecrets();

    assertTheOneResponseWasZeroed(parsed);
  });

  it('refuses a payload that isn\'t UTF-8 text, and zeroes it', async (t) => {
    const { google, create } = await setUp(t);
    const parsed = recordParsed(t);
    google.set('binary', new Uint8Array([0xff, 0xfe, 0x00, 0x80]));
    const writer = create(['binary']);

    await assert.rejects(writer.pullSecrets(), InvalidSecretDataError);

    assert.equal(writer.protectedSecrets.size, 0);
    assertTheOneResponseWasZeroed(parsed);
  });

  it('refuses a payload not matching its checksum, and zeroes it', async (t) => {
    const { google, create } = await setUp(t);
    const parsed = recordParsed(t);
    google.set('item', 's3cret');
    google.tamper = (r) => ({ ...r, payload: { ...r.payload, dataCrc32c: Number(r.payload!.dataCrc32c) + 1 } });
    const writer = create(['item']);

    await assert.rejects(writer.pullSecrets(), InvalidSecretDataError);

    assert.equal(writer.protectedSecrets.size, 0);
    assertTheOneResponseWasZeroed(parsed);
  });

  for (const name of [`projects/${PROJECT_NUMBER}/secrets/other/versions/1`, 'not a resource name']) {
    it(`refuses a response naming '${name}'`, async (t) => {
      const { google, create } = await setUp(t);
      google.set('item', 's3cret');
      google.tamper = (r) => ({ ...r, name });

      await assert.rejects(create(['item']).pullSecrets(), InvalidSecretDataError);
    });
  }

  it('finds nothing in a response without a payload, and accepts one without a checksum', async (t) => {
    const { google, create, decrypt } = await setUp(t);
    google.set('none', 'x');
    google.set('unchecked', 's3cret');
    google.tamper = (r) => (r.name!.includes('/none/') ? { name: r.name } : { name: r.name, payload: { data: r.payload!.data } });
    const writer = create(['none', 'unchecked']);

    await assert.rejects(writer.pullSecrets(), (error: unknown) => error instanceof SecretsNotFoundError && error.secretNames.join() === 'none');

    assert.equal(decrypt(writer.protectedSecrets.get('unchecked'), 'unchecked'), 's3cret');
  });

  it('retries UNAVAILABLE, as the client does', async (t) => {
    const original = retrySettings.initialDelayMs;
    retrySettings.initialDelayMs = 1;
    t.after(() => { retrySettings.initialDelayMs = original; });
    const { google, create, decrypt } = await setUp(t);
    google.set('item', 's3cret');
    google.nextFailures.push(grpc.status.UNAVAILABLE);
    const writer = create(['item']);

    await writer.pullSecrets();

    assert.equal(decrypt(writer.protectedSecrets.get('item'), 'item'), 's3cret');
    assert.equal(google.accesses.length, 2);
  });

  it('makes a client of its own with create, and closes it on close', async (t) => {
    const { google, port, protector, decrypt } = await setUp(t);
    google.set('item', 's3cret');
    const close = t.mock.method(SecretManagerServiceClient.prototype, 'close');
    const writer = GoogleSecretManagerSecretPipelineWriter.create(PROJECT_ID, protector, ['item'], { clientOptions: loopback(port) });

    await writer.pullSecrets();
    assert.equal(decrypt(writer.protectedSecrets.get('item'), 'item'), 's3cret');
    await writer.close();
    assert.equal(close.mock.callCount(), 1);

    assert.throws(() => GoogleSecretManagerSecretPipelineWriter.create('bad/project', protector, ['item']), InvalidArgumentError);
    assert.throws(() => GoogleSecretManagerSecretPipelineWriter.create(PROJECT_ID, protector, ['item'], { clientOptions: { fallback: true } }),
      InvalidArgumentError);
    assert.throws(() => GoogleSecretManagerSecretPipelineWriter.create(PROJECT_ID, protector, ['a.b'], { clientOptions: loopback(port) }),
      InvalidArgumentError);
    assert.equal(close.mock.callCount(), 2);
  });

  it('leaves a client passed in open', async (t) => {
    const { create } = await setUp(t);
    const close = t.mock.method(SecretManagerServiceClient.prototype, 'close');
    await create(['item']).close();
    assert.equal(close.mock.callCount(), 0);
  });

  for (const secretName of ['prod/app', 'db.login']) {
    it(`refuses '${secretName}', which Secret Manager can't hold`, async (t) => {
      const { create } = await setUp(t);
      assert.throws(() => create([secretName]), InvalidArgumentError);
    });
  }

  it('applies Secret Manager\'s name rule', () => {
    const max = GoogleSecretManagerSecretPipelineWriter.MAX_SECRET_NAME_LENGTH;
    assert.equal(GoogleSecretManagerSecretPipelineWriter.isValidSecretName('db_login-2'), true);
    assert.equal(GoogleSecretManagerSecretPipelineWriter.isValidSecretName('a'.repeat(max)), true);
    assert.equal(GoogleSecretManagerSecretPipelineWriter.isValidSecretName('a'.repeat(max + 1)), false);
    assert.equal(GoogleSecretManagerSecretPipelineWriter.isValidSecretName(''), false);
    assert.equal(GoogleSecretManagerSecretPipelineWriter.isValidSecretName(undefined), false);
  });

  it('checks the client, the project and the options', async (t) => {
    const { client, protector } = await setUp(t);
    const create = (c: unknown, project: unknown, options?: object) =>
      new GoogleSecretManagerSecretPipelineWriter(c as SecretManagerServiceClient, project as string, protector, ['item'], options);
    assert.throws(() => create(undefined, PROJECT_ID), InvalidArgumentError);
    assert.throws(() => create({}, PROJECT_ID), InvalidArgumentError);
    assert.throws(() => create(client, undefined), InvalidArgumentError);
    assert.throws(() => create(client, ''), InvalidArgumentError);
    assert.throws(() => create(client, 'projects/x'), InvalidArgumentError);
    assert.throws(() => create(client, PROJECT_ID, { timeoutMs: 0 }), InvalidArgumentError);
    assert.throws(() => create(client, PROJECT_ID, null as unknown as object), InvalidArgumentError);
  });
});

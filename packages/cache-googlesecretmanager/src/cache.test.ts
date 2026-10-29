import { strict as assert } from 'node:assert';
import { generateKeyPairSync } from 'node:crypto';
import { describe, it, type TestContext } from 'node:test';
import { SpanStatusCode } from '@opentelemetry/api';
import { protos, SecretManagerServiceClient } from '@google-cloud/secret-manager';
import * as grpc from '@grpc/grpc-js';
import { InvalidArgumentError, isZero, type ProtectedReadOnlyCache } from '@runsecure/hkdfguard-abstractions';
import { InvalidSecretDataError, ProtectedCache, ProtectedCacheCollection } from '@runsecure/hkdfguard-cache';
import { KeyRing } from '@runsecure/hkdfguard-dek';
import { AttributeNames, HkdfGuardTelemetry, MetricNames, SpanNames } from '@runsecure/hkdfguard-diagnostics';
import { capturingLogger, RecordingKey, useMetricRecorder, useSpanRecorder } from '@runsecure/hkdfguard-test-support';
import { GoogleSecretManagerSecretCache, retrySettings, type GoogleSecretManagerSecretCacheOptions } from './cache.js';
import { ResponseCapture, type AccessedSecretVersion } from './capture.js';
import { crc32c } from './crc32c.js';

const v1 = protos.google.cloud.secretmanager.v1;
type AccessResponse = protos.google.cloud.secretmanager.v1.IAccessSecretVersionResponse;
type AccessRequest = protos.google.cloud.secretmanager.v1.AccessSecretVersionRequest;

const PROJECT_ID = 'hkdfguard-test';
// Google answers with the project's number, not the ID it was asked with.
const PROJECT_NUMBER = '123456789012';
const METHOD = '/google.cloud.secretmanager.v1.SecretManagerService/AccessSecretVersion';

// A key/value secret as AWS Secrets Manager's console stores one.
const KEY_VALUE_SECRET = `{
  "test-credential-1": "This is my first credential",
  "service-credential-3": "This is my third credential",
  "api-credential-21": "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==",
  "domain-credential-17": "fakedomain/thiscredential",
  "port": 5432
}`;

const VERSION_NAME = /^projects\/([^/]+)\/secrets\/([^/]+)\/versions\/([^/]+)$/;
const utf8 = (s: string) => new TextEncoder().encode(s);

/**
 * Secret Manager on the loopback address: a gRPC server implementing only AccessSecretVersion (any
 * other call is answered UNIMPLEMENTED), reached through a real SecretManagerServiceClient, so the
 * client's stub, channel and status errors are as they would be against Google. Secret IDs are
 * matched exactly, as Google matches them, and responses name the project by its number and carry a
 * CRC32C, as Google's do for payloads added with one. Every call's resource name and metadata are
 * recorded.
 */
class FakeSecretManager {
  readonly secrets = new Map<string, Uint8Array>();
  readonly accesses: string[] = [];
  readonly metadata: grpc.Metadata[] = [];
  /** When set, every call fails with this status instead of answering. */
  failure: { code: grpc.status; details: string } | undefined;
  /** Statuses the next calls fail with, one each, before failure and the secrets are consulted. */
  nextFailures: grpc.status[] = [];
  /** Awaited inside every call before it answers, e.g. to hold it open. */
  onAccess: (() => Promise<void>) | undefined;
  /** Rewrites a response before it is sent. */
  tamper: ((response: AccessResponse) => AccessResponse) | undefined;
  /** Sent as the response's bytes instead, when set. */
  raw: Buffer | undefined;
  /** Never answer; the call ends only when the client cancels it or its deadline passes. */
  hang = false;
  readonly cancelled = Promise.withResolvers<void>();
  #waiters: (() => void)[] = [];

  set(id: string, value: string | Uint8Array): void {
    this.secrets.set(id, typeof value === 'string' ? utf8(value) : value);
  }

  /** The secret ID of every access, in order. */
  gets(): string[] {
    return this.accesses.map((a) => VERSION_NAME.exec(a)?.[2] ?? a);
  }

  /** Resolves when the next call arrives. */
  received(): Promise<void> {
    return new Promise((resolve) => this.#waiters.push(resolve));
  }

  service(): grpc.UntypedServiceImplementation {
    return {
      AccessSecretVersion: (call: grpc.ServerUnaryCall<AccessRequest, Buffer>, callback: grpc.sendUnaryData<Buffer>) => {
        void this.#access(call, callback);
      },
    };
  }

  async #access(call: grpc.ServerUnaryCall<AccessRequest, Buffer>, callback: grpc.sendUnaryData<Buffer>): Promise<void> {
    const name = call.request.name;
    this.accesses.push(name);
    this.metadata.push(call.metadata);
    for (const resolve of this.#waiters.splice(0)) resolve();
    if (this.hang) {
      call.on('cancelled', () => this.cancelled.resolve());
      return;
    }

    if (this.onAccess !== undefined) await this.onAccess();
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
    callback(null, this.raw ?? Buffer.from(v1.AccessSecretVersionResponse.encode(response).finish()));
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

interface Fixture {
  google: FakeSecretManager;
  client: SecretManagerServiceClient;
  port: number;
  ring: KeyRing;
  cache: GoogleSecretManagerSecretCache;
}

/** A fake Secret Manager, a real client connected to it, and a cache over it; shut down when the test ends. */
async function fixture(t: TestContext, options?: GoogleSecretManagerSecretCacheOptions): Promise<Fixture> {
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
  const ring = newRing();
  return { google, client, port, ring, cache: new GoogleSecretManagerSecretCache(client, PROJECT_ID, ring, options) };
}

function newRing(): KeyRing {
  const ring = new KeyRing();
  ring.add(1, new RecordingKey());
  return ring;
}

interface Parsed {
  versions: AccessedSecretVersion[];
  received: Uint8Array[];
}

/** Every response the cache's deserializer parsed, and every message gRPC handed it, to check they were zeroed. */
function recordParsed(t: TestContext): Parsed {
  const parsed: Parsed = { versions: [], received: [] };
  const deserialize = ResponseCapture.prototype.deserialize;
  t.mock.method(ResponseCapture.prototype, 'deserialize', function (this: ResponseCapture, raw: Uint8Array) {
    parsed.received.push(raw);
    const version = deserialize.call(this, raw);
    parsed.versions.push(version);
    return version;
  });
  return parsed;
}

function assertTheOneResponseWasZeroed(parsed: Parsed): void {
  assert.equal(parsed.versions.length, 1);
  assert.ok(isZero(parsed.versions[0]!.data));
  assert.equal(parsed.received.length, 1);
  assert.ok(isZero(parsed.received[0]!));
}

async function decryptString(cache: ProtectedReadOnlyCache, name: string, size = 512, signal?: AbortSignal): Promise<string> {
  const result = new Uint8Array(size);
  return new TextDecoder().decode(result.subarray(0, await cache.decrypt(name, result, signal)));
}

const missing = async (cache: ProtectedReadOnlyCache, name: string) => assert.equal(await cache.decrypt(name, new Uint8Array(16)), 0);

/** A predicate for assert.rejects: the gRPC error a call fails with, carrying `code`. */
const grpcError = (code: grpc.status) => (e: unknown) => {
  assert.ok(e instanceof Error, String(e));
  assert.equal((e as { code?: unknown }).code, code, e.message);
  return true;
};

function withSensitiveLogging(): () => void {
  const original = HkdfGuardTelemetry.cache.enableSensitiveLogging;
  HkdfGuardTelemetry.cache.enableSensitiveLogging = true;
  return () => { HkdfGuardTelemetry.cache.enableSensitiveLogging = original; };
}

/** Shortens the wait before a retry for the rest of the test. */
function fastRetries(t: TestContext, initialDelayMs = 10): void {
  const original = retrySettings.initialDelayMs;
  retrySettings.initialDelayMs = initialDelayMs;
  t.after(() => { retrySettings.initialDelayMs = original; });
}

describe('GoogleSecretManagerSecretCache: fetching', () => {
  it('fetches the one secret\'s latest version on a miss, then serves it from the cache', async (t) => {
    const { google, cache } = await fixture(t);
    google.set('Db-Password', 's3cret');

    assert.equal(await decryptString(cache, 'Db-Password'), 's3cret');
    assert.equal(await decryptString(cache, 'Db-Password'), 's3cret');

    assert.deepEqual(google.accesses, ['projects/hkdfguard-test/secrets/Db-Password/versions/latest']);
  });

  it('zeroes the parsed payload once encrypted, and the message gRPC received once read', async (t) => {
    const { google, cache } = await fixture(t);
    const parsed = recordParsed(t);
    google.set('item', 'value');

    assert.equal(await decryptString(cache, 'item'), 'value');

    assertTheOneResponseWasZeroed(parsed);
    assert.equal(parsed.versions[0]!.data.length, 5);
  });

  it('never builds the client\'s own message: the call is made on its stub with the cache\'s deserializer', async (t) => {
    const { google, client, cache } = await fixture(t);
    type Stub = { makeUnaryRequest: (...args: unknown[]) => unknown; accessSecretVersion?: unknown };
    const stub = await client.initialize() as unknown as Stub;
    const definition = (stub.constructor as unknown as { service: grpc.ServiceDefinition }).service;
    const deserializers: unknown[] = [];
    const makeUnaryRequest = stub.makeUnaryRequest;
    // On the instance, shadowing the generated client's prototype; the stub is closed with the client.
    stub.makeUnaryRequest = function (this: Stub, ...args: unknown[]) {
      assert.equal(args[0], METHOD);
      deserializers.push(args[2]);
      return Reflect.apply(makeUnaryRequest, this, args);
    };
    const never = () => { throw new Error('The client\'s own AccessSecretVersion was called.'); };
    t.mock.method(client, 'accessSecretVersion', never);
    stub.accessSecretVersion = never;
    google.set('a', 'value');

    assert.equal(await decryptString(cache, 'a'), 'value');
    await missing(cache, 'b');

    assert.equal(deserializers.length, 2);
    for (const deserialize of deserializers) assert.notEqual(deserialize, definition['AccessSecretVersion']!.responseDeserialize);
  });

  it('sends the routing header and the client header the client would', async (t) => {
    const { google, cache } = await fixture(t);
    google.set('item', 'value');

    assert.equal(await decryptString(cache, 'item'), 'value');
    await missing(cache, 'absent');

    assert.equal(google.metadata.length, 2);
    assert.deepEqual(google.metadata[0]!.get('x-goog-request-params'), ['name=projects%2Fhkdfguard-test%2Fsecrets%2Fitem%2Fversions%2Flatest']);
    for (const metadata of google.metadata) {
      const client = String(metadata.get('x-goog-api-client')[0]);
      assert.match(client, /gl-node\//);
      assert.match(client, /gapic\//);
    }
  });

  it('caches a JSON payload whole and by key from one call, and zeroes it', async (t) => {
    const { google, cache } = await fixture(t);
    const parsed = recordParsed(t);
    google.set('App-Credentials', KEY_VALUE_SECRET);

    assert.equal(await decryptString(cache, 'App-Credentials#api-credential-21'),
      '0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==');
    assert.equal(await decryptString(cache, 'App-Credentials#service-credential-3'), 'This is my third credential');
    assert.equal(await decryptString(cache, 'App-Credentials#port'), '5432');
    assert.equal(await decryptString(cache, 'App-Credentials'), KEY_VALUE_SECRET);

    assert.deepEqual(google.gets(), ['App-Credentials']);
    assertTheOneResponseWasZeroed(parsed);
  });

  it('fetches on maxDecryptedLength\'s miss too', async (t) => {
    const { google, cache } = await fixture(t);
    google.set('api-key', 'value');

    assert.ok((await cache.maxDecryptedLength('api-key'))! >= 5);
    assert.equal(await cache.maxDecryptedLength('absent'), undefined);
    assert.equal(await decryptString(cache, 'api-key'), 'value');
    assert.equal(google.accesses.length, 2);
  });

  it('treats names differing only in case as different secrets and different entries', async (t) => {
    const { google, cache } = await fixture(t);
    google.set('Db', 'upper');
    google.set('db', 'lower');

    assert.equal(await decryptString(cache, 'Db'), 'upper');
    assert.equal(await decryptString(cache, 'db'), 'lower');
    await missing(cache, 'DB');
    assert.equal(await decryptString(cache, 'Db'), 'upper');

    assert.deepEqual(google.gets(), ['Db', 'db', 'DB']);
  });

  it('reports a missing secret (NOT_FOUND) missing, and looks it up again until it exists', async (t) => {
    const { google, cache } = await fixture(t);
    await missing(cache, 'later');
    assert.equal(await cache.maxDecryptedLength('later'), undefined);

    google.set('later', 'now here');
    assert.equal(await decryptString(cache, 'later'), 'now here');
    assert.equal(google.accesses.length, 3);
  });

  it('reports an empty or absent payload missing', async (t) => {
    const { google, cache } = await fixture(t);
    google.set('empty', new Uint8Array(0));
    await missing(cache, 'empty');

    google.tamper = (r) => ({ name: r.name });
    google.set('no-payload', 'value');
    await missing(cache, 'no-payload');
  });

  it('caches a binary secret as its bytes', async (t) => {
    const { google, cache } = await fixture(t);
    google.set('binary', Uint8Array.of(0, 1, 254, 255));

    const result = new Uint8Array(16);
    const written = await cache.decrypt('binary', result);

    assert.deepEqual(result.subarray(0, written), Uint8Array.of(0, 1, 254, 255));
  });

  it('accepts a payload without a checksum', async (t) => {
    const { google, cache } = await fixture(t);
    google.set('item', 'value');
    google.tamper = (r) => ({ name: r.name, payload: { data: r.payload!.data } });

    assert.equal(await decryptString(cache, 'item'), 'value');
  });

  it('refuses and zeroes a payload that doesn\'t match its checksum, caching nothing', async (t) => {
    const { google, cache } = await fixture(t);
    const parsed = recordParsed(t);
    google.set('item', 'value');
    google.tamper = (r) => ({ name: r.name, payload: { data: r.payload!.data, dataCrc32c: Number(r.payload!.dataCrc32c) ^ 1 } });

    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), (e: unknown) => {
      assert.ok(e instanceof InvalidSecretDataError);
      assert.equal(e.message, 'The payload of secret \'item\' doesn\'t match its CRC32C: it was corrupted in transit.');
      return true;
    });

    assertTheOneResponseWasZeroed(parsed);
    // Nothing was cached: the next lookup asks again.
    google.tamper = undefined;
    assert.equal(await decryptString(cache, 'item'), 'value');
  });

  for (const reported of ['projects/123456789012/secrets/other/versions/1', 'not a resource name', '', 'projects/123456789012/secrets/item',
    'projects/123456789012/secrets/item/versions/1/extra', 'projects/123456789012/secrets/ITEM/versions/1']) {
    it(`refuses and zeroes a response naming ${JSON.stringify(reported)}`, async (t) => {
      const { google, cache } = await fixture(t);
      const parsed = recordParsed(t);
      google.set('item', 'value');
      google.tamper = (r) => ({ name: reported, payload: r.payload });

      await assert.rejects(cache.decrypt('item', new Uint8Array(16)), InvalidSecretDataError);
      assertTheOneResponseWasZeroed(parsed);
    });
  }

  it('accepts a response from a regional secret of the same name', async (t) => {
    const { google, cache } = await fixture(t);
    google.set('item', 'value');
    google.tamper = (r) => ({ name: 'projects/123456789012/locations/us-east1/secrets/item/versions/3', payload: r.payload });

    assert.equal(await decryptString(cache, 'item'), 'value');
  });

  it('fails a malformed response as INTERNAL, without quoting it, and caches nothing', async (t) => {
    const { google, cache } = await fixture(t);
    const parsed = recordParsed(t);
    google.set('item', 'value');
    google.raw = Buffer.of(0x12, 0x06, 0x0a, 0x05, ...utf8('s3cr'));

    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), (e: unknown) => {
      grpcError(grpc.status.INTERNAL)(e);
      assert.match((e as Error).message, /Response message parsing error: The response's payload data runs past the end of its message\./);
      assert.ok(!(e as Error).message.includes('s3cr'));
      return true;
    });
    assert.ok(isZero(parsed.received[0]!));

    google.raw = undefined;
    assert.equal(await decryptString(cache, 'item'), 'value');
  });

  for (const name of ['', 'ConnectionStrings:Admin', 'prod/db', 'db.password', 'has space', 'café', 'bang!', 'x'.repeat(256)]) {
    it(`reports ${name.length > 40 ? 'a too-long name' : JSON.stringify(name)} missing without calling Google`, async (t) => {
      const { google, cache } = await fixture(t);
      await missing(cache, name);
      assert.equal(await cache.maxDecryptedLength(name), undefined);
      assert.deepEqual(google.accesses, []);
    });
  }

  it('isValidSecretName accepts ASCII letters, digits, hyphens and underscores, up to 255', () => {
    assert.ok(GoogleSecretManagerSecretCache.isValidSecretName('a'));
    assert.ok(GoogleSecretManagerSecretCache.isValidSecretName('Db_Password-2'));
    assert.ok(GoogleSecretManagerSecretCache.isValidSecretName('x'.repeat(GoogleSecretManagerSecretCache.MAX_SECRET_NAME_LENGTH)));
    assert.ok(!GoogleSecretManagerSecretCache.isValidSecretName('x'.repeat(GoogleSecretManagerSecretCache.MAX_SECRET_NAME_LENGTH + 1)));
    for (const name of [undefined, null, '', '１２', 'a\n', 'a.b']) assert.ok(!GoogleSecretManagerSecretCache.isValidSecretName(name), String(name));
  });

  it('caches a large secret, and zeroes it', async (t) => {
    const { google, cache } = await fixture(t);
    const parsed = recordParsed(t);
    const large = 'é-秘密-'.repeat(1500);
    assert.ok(utf8(large).length > 4096);
    google.set('large', large);

    const result = new Uint8Array((await cache.maxDecryptedLength('large')) ?? 0);
    assert.equal(new TextDecoder().decode(result.subarray(0, await cache.decrypt('large', result))), large);
    assertTheOneResponseWasZeroed(parsed);
  });

  it('shares one fetch among concurrent misses on one name', async (t) => {
    const { google, cache } = await fixture(t);
    google.set('shared', 'value');
    const release = Promise.withResolvers<void>();
    google.onAccess = () => release.promise;

    const lookups = Array.from({ length: 8 }, () => decryptString(cache, 'shared'));
    await google.received();
    release.resolve();

    assert.deepEqual(await Promise.all(lookups), new Array(8).fill('value'));
    assert.equal(google.accesses.length, 1);
  });

  it('still decrypts a cached secret after the ring rotates', async (t) => {
    const { google, cache, ring } = await fixture(t);
    google.set('before', 'v1 value');
    google.set('after', 'v2 value');

    assert.equal(await decryptString(cache, 'before'), 'v1 value');
    ring.add(2, new RecordingKey());

    assert.equal(await decryptString(cache, 'after'), 'v2 value');
    assert.equal(await decryptString(cache, 'before'), 'v1 value');
  });

  it('in a collection, is reached only by names the earlier sources miss', async (t) => {
    const { google, cache, ring } = await fixture(t);
    google.set('from-google', 'google value');
    const local = new ProtectedCache(ring);
    local.add('ConnectionStrings:Admin', utf8('local value'));
    const collection = new ProtectedCacheCollection(local, cache);

    assert.equal(await decryptString(collection, 'ConnectionStrings:Admin'), 'local value');
    assert.equal(await decryptString(collection, 'from-google'), 'google value');
    assert.deepEqual(google.gets(), ['from-google']);
  });
});

describe('GoogleSecretManagerSecretCache: failures, retries and cancellation', () => {
  // Codes the client doesn't retry: FAILED_PRECONDITION is a disabled or destroyed latest version.
  for (const status of [grpc.status.PERMISSION_DENIED, grpc.status.FAILED_PRECONDITION, grpc.status.INTERNAL, grpc.status.UNAUTHENTICATED]) {
    it(`propagates ${grpc.status[status]} and fetches again on the next lookup`, async (t) => {
      const { google, cache } = await fixture(t);
      google.set('item', 'value');
      google.failure = { code: status, details: 'refused' };

      await assert.rejects(cache.decrypt('item', new Uint8Array(16)), grpcError(status));

      google.failure = undefined;
      assert.equal(await decryptString(cache, 'item'), 'value');
      assert.equal(google.accesses.length, 2);
    });
  }

  for (const status of [grpc.status.UNAVAILABLE, grpc.status.RESOURCE_EXHAUSTED]) {
    it(`retries ${grpc.status[status]} as the client retries it`, async (t) => {
      fastRetries(t);
      const { google, cache } = await fixture(t);
      google.set('a', 'first');
      google.set('b', 'second');

      google.nextFailures = [status, status];
      assert.equal(await decryptString(cache, 'a'), 'first');
      google.nextFailures = [status];
      assert.equal(await decryptString(cache, 'b'), 'second');

      assert.deepEqual(google.gets(), ['a', 'a', 'a', 'b', 'b']);
    });
  }

  it('stops retrying at the timeout, failing with the last error', async (t) => {
    fastRetries(t, 50);
    const { google, cache } = await fixture(t, { timeoutMs: 300 });
    google.set('item', 'value');
    google.failure = { code: grpc.status.UNAVAILABLE, details: 'Down in a test.' };

    // The last error is UNAVAILABLE, or DEADLINE_EXCEEDED when the timeout lands during the last
    // attempt rather than before a retry; which one depends on timing.
    const started = Date.now();
    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), (e: unknown) => {
      assert.ok(e instanceof Error, String(e));
      assert.ok([grpc.status.UNAVAILABLE, grpc.status.DEADLINE_EXCEEDED].includes((e as { code?: grpc.status }).code!), e.message);
      return true;
    });
    assert.ok(Date.now() - started < 2_000);
    assert.ok(google.accesses.length > 1);
  });

  it('fails a fetch that outlasts the timeout as DEADLINE_EXCEEDED', async (t) => {
    const { google, cache } = await fixture(t, { timeoutMs: 300 });
    google.set('item', 'value');
    google.hang = true;

    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), grpcError(grpc.status.DEADLINE_EXCEEDED));
  });

  it('cancels the call when the lookup that started the fetch is aborted, and a later lookup fetches again', async (t) => {
    const { google, cache } = await fixture(t);
    google.set('item', 'value');
    google.hang = true;
    const controller = new AbortController();
    const reason = new Error('Aborted in a test.');

    const lookup = cache.decrypt('item', new Uint8Array(16), controller.signal);
    await google.received();
    controller.abort(reason);

    await assert.rejects(lookup, (e: unknown) => e === reason);
    await google.cancelled.promise;
    google.hang = false;
    assert.equal(await decryptString(cache, 'item'), 'value');
    assert.equal(google.accesses.length, 2);
  });

  it('stops waiting to retry when the lookup is aborted', async (t) => {
    fastRetries(t, 30_000);
    const { google, cache } = await fixture(t);
    google.set('item', 'value');
    google.nextFailures = [grpc.status.UNAVAILABLE];
    const controller = new AbortController();

    const lookup = cache.decrypt('item', new Uint8Array(16), controller.signal);
    await google.received();
    await new Promise((resolve) => setTimeout(resolve, 50));
    const started = Date.now();
    controller.abort();

    await assert.rejects(lookup, (e: unknown) => e instanceof Error && e.name === 'AbortError');
    assert.ok(Date.now() - started < 1_000);
    assert.equal(google.accesses.length, 1);
  });
});

describe('GoogleSecretManagerSecretCache: telemetry', () => {
  it('logs, with sensitive logging, the secret\'s name for each fetch - never its value - and every failure', async (t) => {
    const restore = withSensitiveLogging();
    try {
      const { logger, entries, withEventId } = capturingLogger();
      const { google, client, ring } = await fixture(t);
      const cache = new GoogleSecretManagerSecretCache(client, PROJECT_ID, ring, { logger });
      google.set('Item', 'never-logged');

      assert.equal(await decryptString(cache, 'Item'), 'never-logged');
      google.failure = { code: grpc.status.INTERNAL, details: 'boom' };
      await assert.rejects(cache.decrypt('other', new Uint8Array(16)), grpcError(grpc.status.INTERNAL));

      // The secret's own name, not its escaped entry name.
      assert.ok(withEventId(1).some((e) => e.level === 'debug' && e.message === 'hkdfguard.cache.populate completed for Item.'));
      const failures = withEventId(2);
      assert.equal(failures.length, 1);
      assert.equal((failures[0]!.attributes.error as { code?: unknown }).code, grpc.status.INTERNAL);
      assert.ok(!entries.some((e) => JSON.stringify(e.attributes).includes('never-logged') || e.message.includes('never-logged')));
    } finally {
      restore();
    }
  });

  for (const sensitive of [false, true]) {
    it(`works without a logger, with sensitive logging ${sensitive ? 'on' : 'off'}`, async (t) => {
      const original = HkdfGuardTelemetry.cache.enableSensitiveLogging;
      HkdfGuardTelemetry.cache.enableSensitiveLogging = sensitive;
      try {
        const { google, cache } = await fixture(t);
        google.set('item', 'value');
        assert.equal(await decryptString(cache, 'item'), 'value');
        google.failure = { code: grpc.status.PERMISSION_DENIED, details: 'refused' };
        await assert.rejects(cache.decrypt('other', new Uint8Array(16)), grpcError(grpc.status.PERMISSION_DENIED));
      } finally {
        HkdfGuardTelemetry.cache.enableSensitiveLogging = original;
      }
    });
  }

  it('makes each fetch a populate span, counted as success, not_found or error', async (t) => {
    const restore = withSensitiveLogging();
    const spans = useSpanRecorder();
    const metrics = useMetricRecorder();
    try {
      const { google, cache } = await fixture(t);
      google.set('Found', 'value');
      assert.equal(await decryptString(cache, 'Found'), 'value');
      await missing(cache, 'missing');
      google.failure = { code: grpc.status.PERMISSION_DENIED, details: 'refused' };
      await assert.rejects(cache.decrypt('failing', new Uint8Array(16)), grpcError(grpc.status.PERMISSION_DENIED));

      const [found, notFound, failed, ...rest] = spans.spans().filter((s) => s.name === SpanNames.cache.populate);
      assert.equal(rest.length, 0);
      assert.ok(found?.events.some((e) => e.attributes?.[AttributeNames.name] === 'Found'));
      assert.notEqual(found?.status.code, SpanStatusCode.ERROR);
      assert.notEqual(notFound?.status.code, SpanStatusCode.ERROR);
      assert.equal(failed?.status.code, SpanStatusCode.ERROR);

      const points = await metrics.collect();
      for (const result of ['success', 'not_found', 'error']) {
        const key = `HkdfGuard.Cache|${MetricNames.cacheOperations}|{operation}|${AttributeNames.operationName}=${SpanNames.cache.populate},${AttributeNames.result}=${result}`;
        assert.equal(points.get(key), 1, result);
      }
    } finally {
      await metrics.dispose();
      await spans.dispose();
      restore();
    }
  });
});

describe('GoogleSecretManagerSecretCache: construction and closing', () => {
  it('leaves a caller\'s own client open on close', async (t) => {
    const { google, client, ring } = await fixture(t);
    google.set('item', 'value');
    const first = new GoogleSecretManagerSecretCache(client, PROJECT_ID, ring);
    assert.equal(await decryptString(first, 'item'), 'value');
    await first.close();

    assert.equal(await decryptString(new GoogleSecretManagerSecretCache(client, PROJECT_ID, ring), 'item'), 'value');
  });

  it('refuses a missing client, ring or project, a project ID that could change the resource path, and a bad timeout', async (t) => {
    const { client, ring } = await fixture(t);
    const create = (...args: unknown[]) => () => Reflect.construct(GoogleSecretManagerSecretCache, args);

    for (const bad of [undefined, null, {}, 'client']) assert.throws(create(bad, PROJECT_ID, ring), InvalidArgumentError);
    assert.throws(create(client, PROJECT_ID, undefined), TypeError);
    for (const projectId of [undefined, null, 7, '', 'p/secrets/other', 'my project', 'projé', 'p?x', 'p#x', 'p%2Fx']) {
      assert.throws(create(client, projectId, ring), InvalidArgumentError, String(projectId));
    }
    for (const timeoutMs of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, true, '100']) {
      assert.throws(create(client, PROJECT_ID, ring, { timeoutMs }), InvalidArgumentError, String(timeoutMs));
    }
    assert.throws(create(client, PROJECT_ID, ring, null), InvalidArgumentError);

    // A project number, and a legacy domain-scoped ID, are both fine.
    new GoogleSecretManagerSecretCache(client, '123456789012', ring);
    new GoogleSecretManagerSecretCache(client, 'example.com:my-project', ring, { timeoutMs: 1 });
  });

  it('create checks its arguments before creating a client', () => {
    const ring = newRing();
    assert.throws(() => GoogleSecretManagerSecretCache.create('p/x', ring), InvalidArgumentError);
    assert.throws(() => GoogleSecretManagerSecretCache.create(undefined as unknown as string, ring), InvalidArgumentError);
    assert.throws(() => GoogleSecretManagerSecretCache.create('p', undefined as unknown as KeyRing), TypeError);
    assert.throws(() => GoogleSecretManagerSecretCache.create('p', ring, { timeoutMs: 0 }), InvalidArgumentError);
    assert.throws(() => GoogleSecretManagerSecretCache.create('p', ring, { clientOptions: { fallback: true } }), /gRPC/);
  });

  it('refuses a REST client at the first fetch', async (t) => {
    const client = new SecretManagerServiceClient({ fallback: true, credentials: FAKE_CREDENTIALS, projectId: 'test-project' });
    t.after(() => client.close());
    const cache = new GoogleSecretManagerSecretCache(client, PROJECT_ID, newRing());

    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), (e: unknown) => e instanceof InvalidArgumentError && /gRPC/.test(e.message));
  });

  it('create makes a client of its own, calling nothing until a secret is looked up, and close closes it', async (t) => {
    const { google, port } = await fixture(t);
    google.set('item', 'value');
    const cache = GoogleSecretManagerSecretCache.create(PROJECT_ID, newRing(), { clientOptions: loopback(port), timeoutMs: 5_000 });

    // A name Secret Manager can't hold never reaches the client.
    await missing(cache, 'not:a:secret');
    assert.deepEqual(google.accesses, []);
    assert.equal(await decryptString(cache, 'item'), 'value');

    await cache.close();
    await assert.rejects(cache.decrypt('other', new Uint8Array(16)), /Channel has been shut down/);
    assert.equal(google.accesses.length, 1);
  });
});

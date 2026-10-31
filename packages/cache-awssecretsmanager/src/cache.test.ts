import { strict as assert } from 'node:assert';
import { createServer } from 'node:net';
import { Readable } from 'node:stream';
import { describe, it, type TestContext } from 'node:test';
import { SpanStatusCode } from '@opentelemetry/api';
import {
  DecryptionFailure, GetSecretValueCommand, InternalServiceError, InvalidParameterException, InvalidRequestException, ResourceNotFoundException,
  SecretsManagerClient, SecretsManagerServiceException, type SecretsManagerClientConfig,
} from '@aws-sdk/client-secrets-manager';
import { HkdfGuardError, isZero, type ProtectedReadOnlyCache } from '@runsecure/hkdfguard-abstractions';
import { InvalidSecretDataError, ProtectedCache, ProtectedCacheCollection, SecretJsonBody } from '@runsecure/hkdfguard-cache';
import { AttributeNames, HkdfGuardTelemetry, MetricNames, SpanNames } from '@runsecure/hkdfguard-diagnostics';
import { KeyRing } from '@runsecure/hkdfguard-dek';
import { capturingLogger, RecordingKey, useMetricRecorder, useSpanRecorder } from '@runsecure/hkdfguard-test-support';
import { AwsSecretsManagerSecretCache, type GetSecretValueClient } from './index.js';

/*
 * The cache through a real SecretsManagerClient - its serializer, middleware stack, retry,
 * deserializer and logger included - answered by FakeSecretsManager's request handler instead of
 * the network.
 */

// A key/value secret as AWS Secrets Manager's console stores one.
const KEY_VALUE_SECRET = `{
  "test-credential-1": "This is my first credential",
  "service-credential-3": "This is my third credential",
  "api-credential-21": "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==",
  "domain-credential-17": "fakedomain/thiscredential",
  "port": 5432
}`;

const utf8 = (s: string) => new TextEncoder().encode(s);
const base64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');

interface HttpRequest {
  method: string;
  headers: Record<string, string>;
  body?: unknown;
}

/** What the request handler hands the SDK: the shape of its HttpResponse. */
interface HttpResponse {
  statusCode: number;
  reason?: string;
  headers: Record<string, string>;
  body: unknown;
}

/**
 * Secrets Manager's JSON 1.1 endpoint, as the request handler of a real SecretsManagerClient - no
 * network. A GetSecretValue is answered with the secret (names matched exactly, as AWS matches them)
 * or ResourceNotFoundException; any other operation - ListSecrets and BatchGetSecretValue among
 * them - is recorded in `unexpectedOperations` and refused. A successful body is sent as a Node
 * Readable of small chunks, as an http.IncomingMessage streams one, and every chunk is kept, to check
 * it was zeroed.
 */
class FakeSecretsManager {
  private readonly secrets = new Map<string, string>();
  /** Every SecretId GetSecretValue was called with, in order. */
  readonly gets: string[] = [];
  /** Every other operation called. */
  readonly unexpectedOperations: string[] = [];
  /** Every chunk of every successful body handed to the SDK. */
  readonly chunks: Uint8Array[] = [];
  /** When set, GetSecretValue fails with this AWS error type and HTTP status. */
  failWith: [type: string, status: number] | undefined;
  /** When set, GetSecretValue is answered with this body (bytes, or a stream of chunks) as it is. */
  rawBody: (() => unknown) | undefined;
  /** Runs inside every GetSecretValue before it answers, e.g. to hold it open; given the SecretId. */
  onGet: ((name: string) => Promise<void> | void) | undefined;
  chunkLength = 7;

  readonly requestHandler = {
    handle: (request: HttpRequest, options?: { abortSignal?: AbortSignal }) => this.answer(request, options?.abortSignal),
    updateHttpClientConfig() {},
    httpHandlerConfigs() {
      return {};
    },
  };

  setString(name: string, value: string): void {
    this.secrets.set(name, `"SecretString":${JSON.stringify(value)},`);
  }

  setBinary(name: string, value: Uint8Array): void {
    this.secrets.set(name, `"SecretBinary":"${base64(value)}",`);
  }

  setEmpty(name: string): void {
    this.secrets.set(name, '');
  }

  /** A client sending every request here, without retries. */
  client(t: TestContext, config: SecretsManagerClientConfig = {}): SecretsManagerClient {
    const client = new SecretsManagerClient({
      region: 'us-east-1', credentials: { accessKeyId: 'testing', secretAccessKey: 'testing' }, requestHandler: this.requestHandler as never,
      maxAttempts: 1, ...config,
    });
    t.after(() => client.destroy());
    return client;
  }

  private async answer(request: HttpRequest, signal: AbortSignal | undefined): Promise<{ response: HttpResponse }> {
    const operation = request.headers['x-amz-target'] ?? '';
    if (operation !== 'secretsmanager.GetSecretValue') {
      this.unexpectedOperations.push(operation);
      return this.error('AccessDeniedException', 400);
    }

    assert.equal(request.method, 'POST');
    assert.ok(request.headers['content-type']?.startsWith('application/x-amz-json-1.1'));
    const text = request.body instanceof Uint8Array ? new TextDecoder().decode(request.body) : String(request.body);
    const body = JSON.parse(text) as Record<string, unknown>;
    // No VersionId or VersionStage: AWSCURRENT.
    assert.deepEqual(Object.keys(body), ['SecretId']);
    const name = body['SecretId'] as string;
    this.gets.push(name);

    // As the SDK's HTTP handler does: an abort rejects the request with an AbortError.
    const hold = this.onGet?.(name);
    if (hold !== undefined) await abortable(hold, signal);

    if (this.failWith !== undefined) return this.error(...this.failWith);
    if (this.rawBody !== undefined) return respond(200, this.rawBody());
    const value = this.secrets.get(name);
    if (value === undefined) return this.error('ResourceNotFoundException', 400);

    const response = `{"ARN":${JSON.stringify(`arn:aws:secretsmanager:us-east-1:123456789012:secret:${name}-AbCdEf`)},"Name":${JSON.stringify(name)},${value}`
      + '"VersionId":"a1b2c3d4-5678-90ab-cdef-EXAMPLE11111","VersionStages":["AWSCURRENT"],"CreatedDate":1700000000.0}';
    return respond(200, this.stream(utf8(response)));
  }

  private stream(body: Uint8Array): Readable {
    const chunks: Buffer[] = [];
    for (let i = 0; i < body.length; i += this.chunkLength) chunks.push(Buffer.from(body.subarray(i, i + this.chunkLength)));
    this.chunks.push(...chunks);
    return Readable.from(chunks);
  }

  private error(type: string, status: number): { response: HttpResponse } {
    return respond(status, utf8(JSON.stringify({ __type: type, Message: `${type} in a test.` })), { 'x-amzn-errortype': type });
  }
}

function respond(status: number, body: unknown, headers: Record<string, string> = {}): { response: HttpResponse } {
  return {
    response: {
      statusCode: status, reason: undefined,
      headers: { 'content-type': 'application/x-amz-json-1.1', 'x-amzn-requestid': 'request-1', ...headers },
      body,
    },
  };
}

function abortable<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (signal === undefined) return promise;
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(Object.assign(new Error('Request aborted'), { name: 'AbortError' }));
    if (signal.aborted) onAbort();
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(resolve, reject);
  });
}

/** A middleware's shape, as the SDK calls it. */
type RecordingMiddleware = (next: (args: unknown) => Promise<{ response: unknown; output: unknown }>)
  => (args: unknown) => Promise<{ response: unknown; output: unknown }>;

/**
 * What every GetSecretValue response held as the application's own middleware on the client saw
 * it: the body in the deserialize step - one middleware right after the SDK's deserializer, one at
 * low priority, as an application would add them - and the parsed output, in the initialize step.
 * Added to the client before the cache is created, as an application would.
 */
class Recorded {
  readonly bodies: Uint8Array[] = [];
  readonly lowPriorityBodies: Uint8Array[] = [];
  readonly outputs: Record<string, unknown>[] = [];

  constructor(client: SecretsManagerClient) {
    const recordBody: RecordingMiddleware = (next) => async (args) => {
      const result = await next(args);
      this.record(result.response, this.bodies);
      return result;
    };
    client.middlewareStack.addRelativeTo(recordBody as never, { relation: 'after', toMiddleware: 'deserializerMiddleware', name: 'applicationBodyRecorder' });
    client.middlewareStack.add((next) => async (args) => {
      const result = await next(args);
      this.record(result.response, this.lowPriorityBodies);
      return result;
    }, { step: 'deserialize', priority: 'low', name: 'applicationLowPriorityBodyRecorder' });
    client.middlewareStack.add((next) => async (args) => {
      const result = await next(args);
      this.outputs.push(result.output as unknown as Record<string, unknown>);
      return result;
    }, { step: 'initialize', name: 'applicationOutputRecorder' });
  }

  // A successful body of bytes is recorded; a stream - the application's own calls - isn't read.
  private record(response: unknown, into: Uint8Array[]): void {
    const { statusCode, body } = response as HttpResponse;
    if (statusCode < 300 && body instanceof Uint8Array) into.push(Uint8Array.from(body));
  }
}

/** Every message the SDK's logger was given, as text. */
function sdkLogger(): { logger: Record<'trace' | 'debug' | 'info' | 'warn' | 'error', (...content: unknown[]) => void>; messages: string[] } {
  const messages: string[] = [];
  const at = (...content: unknown[]) => { messages.push(content.map((c) => (typeof c === 'string' ? c : JSON.stringify(c))).join(' ')); };
  return { logger: { trace: at, debug: at, info: at, warn: at, error: at }, messages };
}

function newRing(): KeyRing {
  const ring = new KeyRing();
  ring.add(1, new RecordingKey());
  return ring;
}

/** A fake, a client sending to it, the application's recorder on that client, and a cache over it. */
function setUp(t: TestContext, config: SecretsManagerClientConfig = {}) {
  const aws = new FakeSecretsManager();
  const client = aws.client(t, config);
  const recorded = new Recorded(client);
  const ring = newRing();
  const cache = new AwsSecretsManagerSecretCache(client, ring);
  return { aws, client, recorded, ring, cache };
}

async function decryptString(cache: ProtectedReadOnlyCache, name: string, size = 512, signal?: AbortSignal): Promise<string> {
  const result = new Uint8Array(size);
  return new TextDecoder().decode(result.subarray(0, await cache.decrypt(name, result, signal)));
}

const missing = async (cache: ProtectedReadOnlyCache, name: string) => assert.equal(await cache.decrypt(name, new Uint8Array(16)), 0);

/** A predicate for assert.rejects: the SDK's error for an AWS error response of `type` and `status`. */
function awsError(type: string, status: number): (e: unknown) => boolean {
  return (e: unknown) => {
    assert.ok(e instanceof SecretsManagerServiceException, String(e));
    assert.equal(e.name, type);
    assert.equal(e.$metadata.httpStatusCode, status);
    return true;
  };
}

/** Resolves once `condition` holds, polling. */
async function eventually(condition: () => boolean): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error('The condition never held.');
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

function withSensitiveLogging(): () => void {
  const original = HkdfGuardTelemetry.cache.enableSensitiveLogging;
  HkdfGuardTelemetry.cache.enableSensitiveLogging = true;
  return () => { HkdfGuardTelemetry.cache.enableSensitiveLogging = original; };
}

describe('fetching', () => {
  it('fetches the one secret on a miss, then serves it from the cache', async (t) => {
    const { aws, cache } = setUp(t);
    aws.setString('prod/Db-Password', 's3cret');

    assert.equal(await decryptString(cache, 'prod/Db-Password'), 's3cret');
    assert.equal(await decryptString(cache, 'prod/Db-Password'), 's3cret');

    assert.deepEqual(aws.gets, ['prod/Db-Password']);
    assert.deepEqual(aws.unexpectedOperations, []);
  });

  it('leaves the value blanked in the parsed output', async (t) => {
    const { aws, cache, recorded } = setUp(t);
    aws.setString('text', 's3cret');
    aws.setBinary('binary', new Uint8Array([1, 2, 3]));

    assert.equal(await decryptString(cache, 'text'), 's3cret');
    assert.equal(await cache.decrypt('binary', new Uint8Array(16)), 3);

    assert.equal(recorded.outputs.length, 2);
    for (const output of recorded.outputs) {
      assert.equal(output['SecretString'] ?? '', '');
      assert.equal((output['SecretBinary'] as Uint8Array | undefined)?.length ?? 0, 0);
      assert.match(output['ARN'] as string, /^arn:aws:secretsmanager:/);
      assert.deepEqual(output['VersionStages'], ['AWSCURRENT']);
    }
  });

  it('shows every middleware the application added, and the SDK\'s logger, only the redacted body', async (t) => {
    const { logger, messages } = sdkLogger();
    const { aws, cache, recorded } = setUp(t, { logger });
    aws.setString('text', 's3cret-value-spanning-several-chunks');
    aws.setBinary('binary', utf8('binary-value-spanning-several-chunks'));

    assert.equal(await decryptString(cache, 'text'), 's3cret-value-spanning-several-chunks');
    assert.ok(await cache.decrypt('binary', new Uint8Array(64)) > 0);

    // The application's middleware was added before the cache existed, yet runs outside its capture.
    for (const bodies of [recorded.bodies, recorded.lowPriorityBodies]) {
      assert.equal(bodies.length, 2);
      for (const body of bodies) {
        const parsed = JSON.parse(new TextDecoder().decode(body)) as Record<string, unknown>;
        assert.equal(parsed['SecretString'] ?? '', '');
        assert.equal(parsed['SecretBinary'] ?? '', '');
        assert.ok(!Buffer.from(body).includes('spanning'));
      }
    }
    assert.ok(messages.length > 0);
    const encoded = base64(utf8('binary-value-spanning-several-chunks'));
    assert.ok(!messages.some((m) => m.includes('s3cret') || m.includes(encoded)));
  });

  it('zeroes every chunk of the response stream', async (t) => {
    const { aws, cache } = setUp(t);
    aws.setString('prod/App', KEY_VALUE_SECRET);

    assert.equal(await decryptString(cache, 'prod/App#port'), '5432');

    assert.ok(aws.chunks.length > 10);
    for (const chunk of aws.chunks) assert.ok(isZero(chunk));
  });

  it('leaves the application\'s own calls on the client as they are', async (t) => {
    const { aws, client, ring, cache } = setUp(t);
    aws.setString('a', '1');
    aws.setString('b', '2');

    assert.equal(await decryptString(cache, 'a'), '1');
    // The capture is on the cache's own commands: the application's are parsed as usual.
    assert.equal((await client.send(new GetSecretValueCommand({ SecretId: 'b' }))).SecretString, '2');

    // A second cache on the same client captures too, and the client is unchanged by either.
    const other = new AwsSecretsManagerSecretCache(client, ring);
    assert.equal(await decryptString(other, 'b'), '2');
    assert.equal(await decryptString(cache, 'b'), '2');
    assert.equal((await client.send(new GetSecretValueCommand({ SecretId: 'a' }))).SecretString, '1');
    assert.ok(!client.middlewareStack.identify().some((name) => name.includes('hkdfguard')));
  });

  it('captures on a client that caches its middleware, without capturing the application\'s calls', async (t) => {
    const { aws, client, cache } = setUp(t, { cacheMiddleware: true });
    aws.setString('a', '1');
    aws.setString('b', '2');

    // The application's call first, so its handler is the one cached for GetSecretValueCommand.
    assert.equal((await client.send(new GetSecretValueCommand({ SecretId: 'b' }))).SecretString, '2');
    assert.equal(await decryptString(cache, 'a'), '1');
    assert.equal(await decryptString(cache, 'b'), '2');
    assert.equal((await client.send(new GetSecretValueCommand({ SecretId: 'a' }))).SecretString, '1');
  });

  it('captures only its own response in each of many concurrent fetches on one shared client', async (t) => {
    const { aws, client, cache } = setUp(t);
    const count = 12;
    for (let i = 0; i < count; i++) aws.setString(`secret-${i}`, `value-${i}`);
    aws.setString('plain', 'the application\'s');
    // Every call - the cache's twelve and the application's own - is in flight before any answers.
    const allIn = Promise.withResolvers<void>();
    aws.onGet = () => {
      if (aws.gets.length === count + 1) allIn.resolve();
      return allIn.promise;
    };

    const lookups = Array.from({ length: count }, (_, i) => decryptString(cache, `secret-${i}`));
    const plain = client.send(new GetSecretValueCommand({ SecretId: 'plain' }));

    assert.deepEqual(await Promise.all(lookups), Array.from({ length: count }, (_, i) => `value-${i}`));
    assert.equal((await plain).SecretString, 'the application\'s');
  });

  it('unescapes a value with JSON escapes exactly', async (t) => {
    const { aws, cache } = setUp(t);
    const secret = 'p"a\\ss/wörd\n\u0001秘密';
    aws.setString('escaped', secret);

    assert.equal(await decryptString(cache, 'escaped'), secret);
  });

  it('caches a binary secret as its bytes', async (t) => {
    const { aws, cache } = setUp(t);
    aws.setBinary('binary', new Uint8Array([0, 1, 254, 255]));

    const result = new Uint8Array(16);
    const written = await cache.decrypt('binary', result);

    assert.deepEqual(result.subarray(0, written), new Uint8Array([0, 1, 254, 255]));
  });

  it('caches a key/value secret whole and by key from one call, and the SDK never sees it', async (t) => {
    const { aws, cache, recorded } = setUp(t);
    aws.setString('prod/App', KEY_VALUE_SECRET);

    assert.equal(await decryptString(cache, 'prod/App#api-credential-21'),
      '0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==');
    assert.equal(await decryptString(cache, 'prod/App#test-credential-1'), 'This is my first credential');
    assert.equal(await decryptString(cache, 'prod/App#service-credential-3'), 'This is my third credential');
    assert.equal(await decryptString(cache, 'prod/App#domain-credential-17'), 'fakedomain/thiscredential');
    assert.equal(await decryptString(cache, 'prod/App#port'), '5432');
    assert.equal(await decryptString(cache, 'prod/App'), KEY_VALUE_SECRET);
    await missing(cache, 'prod/app#port');

    assert.deepEqual(aws.gets, ['prod/App', 'prod/app']);
    assert.equal(recorded.outputs[0]!['SecretString'], '');
  });

  it('never splits a binary secret holding JSON', async (t) => {
    const { aws, cache } = setUp(t);
    aws.setBinary('binary', utf8('{"k":"v"}'));

    assert.equal(await decryptString(cache, 'binary'), '{"k":"v"}');
    await missing(cache, 'binary#k');
  });

  it('fetches on a miss through maxDecryptedLength', async (t) => {
    const { aws, cache } = setUp(t);
    aws.setString('api-key', 'value');

    assert.ok((await cache.maxDecryptedLength('api-key'))! >= 5);
    assert.equal(await decryptString(cache, 'api-key'), 'value');
    assert.equal(aws.gets.length, 1);
  });

  it('treats names differing only in case as different secrets and different entries', async (t) => {
    const { aws, cache } = setUp(t);
    aws.setString('prod/Db', 'upper');
    aws.setString('prod/db', 'lower');

    assert.equal(await decryptString(cache, 'prod/Db'), 'upper');
    assert.equal(await decryptString(cache, 'prod/db'), 'lower');
    await missing(cache, 'PROD/DB');
    assert.equal(await decryptString(cache, 'prod/Db'), 'upper');

    assert.deepEqual(aws.gets, ['prod/Db', 'prod/db', 'PROD/DB']);
  });

  it('reports a missing secret as 0 and looks it up again until it exists', async (t) => {
    const { aws, cache } = setUp(t);
    await missing(cache, 'later');
    assert.equal(await cache.maxDecryptedLength('later'), undefined);

    aws.setString('later', 'now here');
    assert.equal(await decryptString(cache, 'later'), 'now here');
    assert.equal(aws.gets.length, 3);
  });

  it('reports an empty secret missing', async (t) => {
    const { aws, cache } = setUp(t);
    aws.setEmpty('none');
    aws.setString('empty-string', '');
    aws.setBinary('empty-binary', new Uint8Array(0));

    await missing(cache, 'none');
    await missing(cache, 'empty-string');
    await missing(cache, 'empty-binary');
  });

  for (const body of ['{"SecretString":"a","SecretBinary":"Yg=="}', '{"SecretBinary":"not base64!"}', 'not json', '']) {
    it(`refuses a response that can't be trusted: ${JSON.stringify(body)}`, async (t) => {
      const { aws, cache, recorded } = setUp(t);
      aws.rawBody = () => Readable.from([Buffer.from(body)]);

      await assert.rejects(cache.decrypt('item', new Uint8Array(16)), (e: unknown) => e instanceof InvalidSecretDataError && e.cause === undefined);
      // Refused before the SDK parsed it, so nothing outside the capture saw it.
      assert.deepEqual(recorded.bodies, []);
      assert.deepEqual(recorded.outputs, []);
    });
  }

  it('refuses a missing body', async (t) => {
    const { aws, cache } = setUp(t);
    aws.rawBody = () => undefined;

    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), InvalidSecretDataError);
  });

  it('refuses a response body over the limit without reading it all', async (t) => {
    const { aws, cache, recorded } = setUp(t);
    const chunkLength = 64 * 1024;
    const chunks = 2 * SecretJsonBody.MAX_BODY_LENGTH / chunkLength;
    let produced = 0;
    aws.rawBody = () => (async function* () {
      yield utf8('{"SecretString":"');
      for (; produced < chunks; produced++) yield new Uint8Array(chunkLength).fill(0x61);
    })();

    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), InvalidSecretDataError);
    assert.ok(produced <= SecretJsonBody.MAX_BODY_LENGTH / chunkLength + 1, String(produced));
    assert.deepEqual(recorded.outputs, []);
  });

  it('doesn\'t retry a response it refused', async (t) => {
    const { aws, cache } = setUp(t, { maxAttempts: 3 });
    aws.rawBody = () => utf8('not json');

    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), InvalidSecretDataError);
    assert.equal(aws.gets.length, 1);
  });

  it('captures a retried call\'s successful attempt', async (t) => {
    const { aws, cache } = setUp(t, { maxAttempts: 3, retryStrategy: undefined });
    aws.setString('item', 'value');
    aws.failWith = ['InternalServiceError', 500];
    aws.onGet = () => {
      if (aws.gets.length === 2) aws.failWith = undefined;
    };

    assert.equal(await decryptString(cache, 'item'), 'value');
    assert.equal(aws.gets.length, 2);
  });
});

describe('cancellation', () => {
  it('aborts the call when the lookup is aborted, and the next lookup fetches again', async (t) => {
    const { aws, cache } = setUp(t);
    aws.setString('item', 'value');
    const release = Promise.withResolvers<void>();
    aws.onGet = () => release.promise;
    const controller = new AbortController();

    const lookup = cache.decrypt('item', new Uint8Array(16), controller.signal);
    await eventually(() => aws.gets.length === 1);
    controller.abort();
    await assert.rejects(lookup, (e: unknown) => (e as Error).name === 'AbortError');

    aws.onGet = undefined;
    assert.equal(await cache.decrypt('item', new Uint8Array(16)), 5);
    assert.equal(aws.gets.length, 2);
    release.resolve();
  });

  it('makes no call for a lookup already aborted', async (t) => {
    const { aws, cache } = setUp(t);
    aws.setString('item', 'value');

    await assert.rejects(cache.decrypt('item', new Uint8Array(16), AbortSignal.abort()));
    assert.deepEqual(aws.gets, []);
  });
});

describe('names', () => {
  for (const name of ['', 'ConnectionStrings:Admin', 'arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf', 'has space', 'café',
    'bang!', 'prod/Db!x', 'x'.repeat(513)]) {
    it(`reports ${JSON.stringify(name.length > 40 ? `${name.slice(0, 10)}...` : name)}, which Secrets Manager can't hold, missing without calling AWS`,
      async (t) => {
        const { aws, cache } = setUp(t);
        await missing(cache, name);
        assert.equal(await cache.maxDecryptedLength(name), undefined);
        assert.deepEqual(aws.gets, []);
        assert.deepEqual(aws.unexpectedOperations, []);
      });
  }

  it('accepts the Secrets Manager character set, up to 512 characters, as a secret name', () => {
    const max = AwsSecretsManagerSecretCache.MAX_SECRET_NAME_LENGTH;
    assert.equal(max, 512);
    for (const name of ['a', 'prod/app_1+x=y.z@w-v', 'AZaz09', 'x'.repeat(max)]) assert.ok(AwsSecretsManagerSecretCache.isValidSecretName(name), name);
    for (const name of ['x'.repeat(max + 1), '', undefined, null, 42, 'prod#key', 'ｆｕｌｌ', 'tab\t', 'new\nline']) {
      assert.ok(!AwsSecretsManagerSecretCache.isValidSecretName(name as string), String(name));
    }
  });

  it('reads a key after the name from the named secret', async (t) => {
    const { aws, cache } = setUp(t);
    aws.setString('prod/app', '{"user":"admin"}');

    assert.equal(await decryptString(cache, 'prod/app#user'), 'admin');
    await missing(cache, 'prod/app#bad key');
    assert.deepEqual(aws.gets, ['prod/app']);
  });

  it('rejects a name that isn\'t a string', async (t) => {
    const { aws, cache } = setUp(t);
    await assert.rejects(cache.decrypt(42 as never, new Uint8Array(16)), TypeError);
    assert.deepEqual(aws.gets, []);
  });
});

describe('failures', () => {
  it('propagates an AWS failure, and fetches again on the next lookup', async (t) => {
    const { aws, cache } = setUp(t);
    aws.setString('item', 'value');
    aws.failWith = ['InvalidRequestException', 400];

    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), awsError('InvalidRequestException', 400));

    aws.failWith = undefined;
    assert.equal(await decryptString(cache, 'item'), 'value');
    assert.equal(aws.gets.length, 2);
  });

  for (const [type, status, modeled] of [
    ['AccessDeniedException', 400, undefined], ['InvalidRequestException', 400, InvalidRequestException],
    ['DecryptionFailure', 400, DecryptionFailure], ['InvalidParameterException', 400, InvalidParameterException],
    ['InternalServiceError', 500, InternalServiceError],
  ] as const) {
    it(`rejects with the SDK's own error for ${type}`, async (t) => {
      const { aws, cache } = setUp(t);
      aws.failWith = [type, status];

      await assert.rejects(cache.decrypt('item', new Uint8Array(16)), (e: unknown) => {
        awsError(type, status)(e);
        if (modeled !== undefined) assert.ok(e instanceof modeled);
        return true;
      });
    });
  }

  it('reports ResourceNotFoundException as missing, not as an error', async (t) => {
    const { client, cache } = setUp(t);
    await assert.rejects(client.send(new GetSecretValueCommand({ SecretId: 'missing' })), ResourceNotFoundException);

    await missing(cache, 'missing');
    assert.equal(await cache.maxDecryptedLength('missing'), undefined);
  });

  it('propagates a credential failure', async (t) => {
    const aws = new FakeSecretsManager();
    const noCredentials = Object.assign(new Error('Could not load credentials from any providers'), { name: 'CredentialsProviderError' });
    const cache = new AwsSecretsManagerSecretCache(aws.client(t, { credentials: () => Promise.reject(noCredentials) }), newRing());

    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), (e: unknown) => e === noCredentials);
    assert.deepEqual(aws.gets, []);
  });

  it('propagates a refused connection', async (t) => {
    // A port this machine just stopped listening on, so the connection is refused locally.
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as { port: number };
    await new Promise<void>((resolve) => server.close(() => resolve()));
    const client = new SecretsManagerClient({
      region: 'us-east-1', endpoint: `http://127.0.0.1:${port}`, credentials: { accessKeyId: 'testing', secretAccessKey: 'testing' }, maxAttempts: 1,
    });
    t.after(() => client.destroy());

    await assert.rejects(new AwsSecretsManagerSecretCache(client, newRing()).decrypt('item', new Uint8Array(16)),
      (e: unknown) => (e as NodeJS.ErrnoException).code === 'ECONNREFUSED');
  });

  it('refuses a response that never passed through the capture', async () => {
    // A double that answers by itself, never running the command's middleware: the value is a string already.
    const sent: GetSecretValueCommand[] = [];
    const double: GetSecretValueClient = {
      async send(command) {
        sent.push(command);
        return { ARN: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:item-AbCdEf', Name: 'item', SecretString: 's3cret' };
      },
    };

    await assert.rejects(new AwsSecretsManagerSecretCache(double, newRing()).decrypt('item', new Uint8Array(16)),
      (e: unknown) => e instanceof HkdfGuardError && e.code === 'ERR_HKDFGUARD_INVALID_STATE' && e.message.includes('wasn\'t captured'));
    assert.equal(sent.length, 1);
    assert.deepEqual(sent[0]!.input, { SecretId: 'item' });
  });

  it('passes the lookup\'s signal to send, and always some options', async () => {
    const options: unknown[] = [];
    const double: GetSecretValueClient = {
      async send(_command, sendOptions) {
        options.push(sendOptions);
        throw Object.assign(new Error('not found'), { name: 'ResourceNotFoundException' });
      },
    };
    const cache = new AwsSecretsManagerSecretCache(double, newRing());
    const controller = new AbortController();

    await missing(cache, 'item');
    assert.equal(await cache.decrypt('item', new Uint8Array(16), controller.signal), 0);

    assert.deepEqual(options, [{}, { abortSignal: controller.signal }]);
  });
});

describe('the cache', () => {
  it('shares one fetch among concurrent misses on one name', async (t) => {
    const { aws, cache } = setUp(t);
    aws.setString('shared', 'value');
    const release = Promise.withResolvers<void>();
    aws.onGet = () => release.promise;

    const lookups = Array.from({ length: 8 }, () => decryptString(cache, 'shared'));
    lookups.push(cache.maxDecryptedLength('shared').then((length) => (length! >= 5 ? 'value' : 'too short')));
    await eventually(() => aws.gets.length === 1);
    await new Promise((resolve) => setTimeout(resolve, 50));
    release.resolve();

    assert.deepEqual(await Promise.all(lookups), Array(9).fill('value'));
    assert.equal(aws.gets.length, 1);
  });

  it('round-trips a large secret', async (t) => {
    const { aws, cache } = setUp(t);
    aws.chunkLength = 1000;
    const large = 'é-秘密-'.repeat(3000);
    assert.ok(utf8(large).length > 16 * 1024);
    aws.setString('large', large);

    const length = await cache.maxDecryptedLength('large');
    assert.ok(length !== undefined);
    assert.equal(await decryptString(cache, 'large', length), large);
  });

  it('still decrypts a cached secret after the ring rotates', async (t) => {
    const { aws, cache, ring } = setUp(t);
    aws.setString('before', 'v1 value');
    aws.setString('after', 'v2 value');

    assert.equal(await decryptString(cache, 'before'), 'v1 value');
    ring.add(2, new RecordingKey());

    assert.equal(await decryptString(cache, 'after'), 'v2 value');
    assert.equal(await decryptString(cache, 'before'), 'v1 value');
  });

  it('is asked, in a collection, only for the names the earlier sources miss', async (t) => {
    const { aws, cache, ring } = setUp(t);
    aws.setString('from-aws', 'aws value');
    const local = new ProtectedCache(ring);
    local.add('ConnectionStrings:Admin', utf8('local value'));
    const collection = new ProtectedCacheCollection().add(local).add(cache);

    assert.equal(await decryptString(collection, 'ConnectionStrings:Admin'), 'local value');
    assert.equal(await decryptString(collection, 'from-aws'), 'aws value');
    assert.deepEqual(aws.gets, ['from-aws']);
  });

  it('logs, with sensitive logging, the name only for a fetch, and an error for a failure', async (t) => {
    const restore = withSensitiveLogging();
    try {
      const aws = new FakeSecretsManager();
      const { logger, entries, withEventId } = capturingLogger();
      const cache = new AwsSecretsManagerSecretCache(aws.client(t), newRing(), logger);
      aws.setString('prod/Item', 'never-logged');

      assert.equal(await decryptString(cache, 'prod/Item'), 'never-logged');
      aws.failWith = ['InternalServiceError', 500];
      await assert.rejects(cache.decrypt('other', new Uint8Array(16)), InternalServiceError);

      // The secret's own name, not its escaped entry name.
      assert.ok(withEventId(1).some((e) => e.level === 'debug' && e.message === 'hkdfguard.cache.populate completed for prod/Item.'));
      const failures = withEventId(2);
      assert.equal(failures.length, 1);
      assert.ok(failures[0]!.attributes.error instanceof InternalServiceError);
      assert.ok(!entries.some((e) => e.message.includes('never-logged')));
    } finally {
      restore();
    }
  });

  it('makes each fetch a populate span, counted as success, not_found or error', async (t) => {
    const restore = withSensitiveLogging();
    const spans = useSpanRecorder();
    const metrics = useMetricRecorder();
    try {
      const { aws, cache } = setUp(t);
      aws.setString('Found', 'value');
      assert.equal(await decryptString(cache, 'Found'), 'value');
      await missing(cache, 'missing');
      aws.failWith = ['AccessDeniedException', 400];
      await assert.rejects(cache.decrypt('denied', new Uint8Array(16)), SecretsManagerServiceException);

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

  it('makes no call until a secret is requested', (t) => {
    const aws = new FakeSecretsManager();
    new AwsSecretsManagerSecretCache(aws.client(t), newRing());
    assert.deepEqual(aws.gets, []);
    assert.deepEqual(aws.unexpectedOperations, []);
  });

  it('refuses a missing client or ring, or a client without send, and accepts a missing logger', async (t) => {
    const aws = new FakeSecretsManager();
    const client = aws.client(t);
    for (const bad of [undefined, null, {}, { send: 'not a function' }, 'client']) {
      assert.throws(() => new AwsSecretsManagerSecretCache(bad as never, newRing()), TypeError);
    }
    assert.throws(() => new AwsSecretsManagerSecretCache(client, undefined as never), TypeError);
    assert.throws(() => new AwsSecretsManagerSecretCache(client, null as never), TypeError);
    await missing(new AwsSecretsManagerSecretCache(client, newRing(), undefined), 'missing');
  });
});

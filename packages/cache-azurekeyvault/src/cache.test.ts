import { strict as assert } from 'node:assert';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Readable } from 'node:stream';
import { describe, it, type TestContext } from 'node:test';
import { gzipSync } from 'node:zlib';
import { SpanStatusCode } from '@opentelemetry/api';
import {
  createDefaultHttpClient, createEmptyPipeline, createHttpHeaders, createPipelineRequest, defaultRetryPolicy,
  type HttpClient, type Pipeline, type PipelinePolicy, type PipelineRequest, type PipelineResponse,
} from '@azure/core-rest-pipeline';
import { DefaultAzureCredential } from '@azure/identity';
import { SecretClient, type KeyVaultSecret, type SecretClientOptions } from '@azure/keyvault-secrets';
import { InvalidArgumentError, isZero, type KeyRing as KeyRingContract, type ProtectedReadOnlyCache } from '@runsecure/hkdfguard-abstractions';
import {
  InvalidSecretDataError, ProtectedCache, ProtectedCacheCollection, RemoteSecretCache, SecretNameMatching, type SecretValueSink,
} from '@runsecure/hkdfguard-cache';
import { AttributeNames, HkdfGuardTelemetry, MetricNames, SpanNames, type Logger } from '@runsecure/hkdfguard-diagnostics';
import { KeyRing } from '@runsecure/hkdfguard-dek';
import { capturingLogger, RecordingKey, useMetricRecorder, useSpanRecorder } from '@runsecure/hkdfguard-test-support';
import { AzureKeyVaultSecretCache, type AzureKeyVaultSecretCacheOptions, type KeyVaultCredential } from './cache.js';
import { Capture, captureWithin, SECRET_CAPTURE_POLICY_NAME, secretCapturePolicy } from './capture.js';

const HOST = 'hkdfguard-test.vault.azure.net';
const VAULT = `https://${HOST}`;
const TOKEN = 'stub-token';
const CHALLENGE = 'Bearer authorization="https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000", resource="https://vault.azure.net"';
// The bytes the fake vault writes at a time, so a body of any size reaches the client in several chunks.
const CHUNK_LENGTH = 1000;

// A key/value secret as AWS Secrets Manager's console stores one.
const KEY_VALUE_SECRET = `{
  "test-credential-1": "This is my first credential",
  "service-credential-3": "This is my third credential",
  "api-credential-21": "0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==",
  "domain-credential-17": "fakedomain/thiscredential",
  "port": 5432
}`;

const utf8 = (s: string) => new TextEncoder().encode(s);

/**
 * Key Vault's secrets endpoint, as a loopback HTTP server reached through the Azure SDK's own Node
 * HTTP client (createDefaultHttpClient), behind a real SecretClient with no network: the
 * {@link httpClient} it gives SecretClient sends each https://hkdfguard-test.vault.azure.net request
 * to the server instead, so the body arrives as a real response stream, decompressed by the SDK. A
 * request without a bearer token gets Key Vault's 401 challenge, and an authorized Get Secret is
 * answered with the secret's JSON (names compared ignoring case, as Key Vault does) or a 404. Any
 * other request - listing secrets or versions among them - is recorded in `unexpectedRequests` and
 * refused.
 *
 * Like the SDK's client, it hands a 200 body over unread only when the request asks to stream it,
 * unless `alwaysBuffer` is set. {@link clientOptions} also installs a per-call policy recording
 * every 200 body SecretClient was given to deserialize, so a test can check the secret never
 * reached it.
 */
class FakeKeyVault {
  readonly secrets = new Map<string, string>();
  /** The name of every authorized Get Secret, in order. */
  readonly gets: string[] = [];
  /** Whether each authorized Get Secret asked for a 200's body unread. */
  readonly streams: boolean[] = [];
  /** Every other request, as "METHOD path". */
  readonly unexpectedRequests: string[] = [];
  /** Every 200 body SecretClient deserialized. */
  readonly bodiesSeenBySecretClient: string[] = [];
  /** When set, an authorized Get Secret is answered with this status and an error body - failuresLeft times, or every time while that is undefined. */
  failWith: number | undefined;
  failuresLeft: number | undefined;
  /** When set, an authorized Get Secret is answered with this body as it is. */
  rawBody: string | undefined;
  /** Runs inside every authorized Get Secret before it answers, e.g. to hold it open. */
  onGet: ((name: string) => void | Promise<void>) | undefined;
  /** Hands every body over already read, as bodyAsText, whatever the request asks. */
  alwaysBuffer = false;
  /** Compresses every 200 body with gzip, when the request accepts it. */
  gzip = false;
  /** How many bodies were compressed. */
  compressed = 0;
  readonly httpClient: HttpClient = { sendRequest: (request) => this.#send(request) };
  readonly #transport = createDefaultHttpClient();
  readonly #server: Server;
  #port = 0;

  private constructor() {
    this.#server = createServer((request, response) => {
      response.on('error', () => undefined);
      this.#handle(request, response).catch(() => response.destroy());
    });
  }

  /** A vault listening on a loopback port, closed when the test ends. */
  static async start(t: TestContext): Promise<FakeKeyVault> {
    const vault = new FakeKeyVault();
    await new Promise<void>((resolve) => vault.#server.listen(0, '127.0.0.1', resolve));
    vault.#port = (vault.#server.address() as AddressInfo).port;
    t.after(() => {
      vault.#server.closeAllConnections();
      vault.#server.close();
    });
    return vault;
  }

  set(name: string, value: string): void {
    this.secrets.set(name.toLowerCase(), value);
  }

  /** A per-call policy - outermost - recording each 200 body exactly as SecretClient will deserialize it. */
  readonly bodyRecorder: PipelinePolicy = {
    name: 'bodyRecorder',
    sendRequest: async (request, next) => {
      const response = await next(request);
      if (response.status === 200) this.bodiesSeenBySecretClient.push(response.bodyAsText ?? '');
      return response;
    },
  };

  /** SecretClient options that send every request here, never retry, and record the bodies SecretClient sees. */
  clientOptions(extra: SecretClientOptions = {}): SecretClientOptions {
    return {
      httpClient: this.httpClient,
      retryOptions: { maxRetries: 0 },
      ...extra,
      additionalPolicies: [{ policy: this.bodyRecorder, position: 'perCall' }, ...(extra.additionalPolicies ?? [])],
    };
  }

  async #send(request: PipelineRequest): Promise<PipelineResponse> {
    const url = new URL(request.url);
    assert.equal(url.host, HOST);
    if (request.headers.get('authorization') === `Bearer ${TOKEN}` && url.pathname.startsWith('/secrets/')) {
      this.streams.push(request.streamResponseStatusCodes?.has(200) === true);
    }

    const { url: original, allowInsecureConnection, streamResponseStatusCodes } = request;
    request.url = `http://127.0.0.1:${this.#port}${url.pathname}${url.search}`;
    request.allowInsecureConnection = true;
    if (this.alwaysBuffer) request.streamResponseStatusCodes = undefined;
    try {
      return await this.#transport.sendRequest(request);
    } finally {
      request.url = original;
      request.allowInsecureConnection = allowInsecureConnection;
      request.streamResponseStatusCodes = streamResponseStatusCodes;
    }
  }

  async #handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const url = new URL(request.url!, 'http://localhost');
    const authorization = request.headers.authorization;
    if (authorization === undefined) return respond(response, 401, Buffer.alloc(0), { 'WWW-Authenticate': CHALLENGE });
    if (authorization !== `Bearer ${TOKEN}`) return error(response, 401, 'Unauthorized');

    const path = /^\/secrets\/([^/]+)\/?$/.exec(url.pathname);
    if (request.method !== 'GET' || path === null) {
      this.unexpectedRequests.push(`${request.method} ${url.pathname}`);
      return error(response, 403, 'Forbidden');
    }

    const name = decodeURIComponent(path[1]!);
    this.gets.push(name);
    await this.onGet?.(name);

    if (this.failWith !== undefined && (this.failuresLeft === undefined || this.failuresLeft > 0)) {
      if (this.failuresLeft !== undefined) this.failuresLeft--;
      return error(response, this.failWith, this.failWith === 403 ? 'Forbidden' : 'InternalServerError');
    }
    if (this.rawBody !== undefined) return this.#ok(request, response, this.rawBody);

    const value = this.secrets.get(name.toLowerCase());
    if (value === undefined) return error(response, 404, 'SecretNotFound');
    return this.#ok(request, response, JSON.stringify({
      value,
      id: `${VAULT}/secrets/${name}/0123456789abcdef0123456789abcdef`,
      attributes: { enabled: true, created: 1700000000, updated: 1700000000, recoveryLevel: 'Recoverable+Purgeable' },
      tags: { value: 'a tag, not the secret' },
    }));
  }

  #ok(request: IncomingMessage, response: ServerResponse, body: string): void {
    let content = Buffer.from(body);
    const headers: Record<string, string> = {};
    if (this.gzip && (request.headers['accept-encoding'] ?? '').includes('gzip')) {
      content = gzipSync(content);
      this.compressed++;
      headers['Content-Encoding'] = 'gzip';
    }
    respond(response, 200, content, headers);
  }
}

function error(response: ServerResponse, status: number, code: string): void {
  respond(response, status, Buffer.from(JSON.stringify({ error: { code, message: `${code} from the fake vault.` } })));
}

function respond(response: ServerResponse, status: number, content: Buffer, headers: Record<string, string> = {}): void {
  // A request the client aborted while it was held has no one to answer.
  if (response.destroyed) return;
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': String(content.length), ...headers });
  for (let offset = 0; offset < content.length; offset += CHUNK_LENGTH) response.write(content.subarray(offset, offset + CHUNK_LENGTH));
  response.end();
}

/** A credential that hands out the fake vault's token, or fails as one that can't get a token does. */
function credential(failure?: Error): KeyVaultCredential {
  return {
    async getToken() {
      if (failure !== undefined) throw failure;
      return { token: TOKEN, expiresOnTimestamp: Date.now() + 3_600_000 };
    },
  };
}

function newRing(): KeyRing {
  const ring = new KeyRing();
  ring.add(1, new RecordingKey());
  return ring;
}

function create(vault: FakeKeyVault, ring: KeyRingContract = newRing(), options: { logger?: Logger; clientOptions?: SecretClientOptions } = {}): AzureKeyVaultSecretCache {
  return new AzureKeyVaultSecretCache(VAULT, credential(), ring, options.logger, { clientOptions: vault.clientOptions(options.clientOptions) });
}

async function decryptString(cache: ProtectedReadOnlyCache, name: string, size = 512, signal?: AbortSignal): Promise<string> {
  const result = new Uint8Array(size);
  return new TextDecoder().decode(result.subarray(0, await cache.decrypt(name, result, signal)));
}

const missing = async (cache: ProtectedReadOnlyCache, name: string) => assert.equal(await cache.decrypt(name, new Uint8Array(16)), 0);

/** A promise and its resolver: a gate a held request waits at. */
function gate(): { promise: Promise<void>; open: () => void } {
  const { promise, resolve } = Promise.withResolvers<void>();
  return { promise, open: () => resolve() };
}

/** A predicate for assert.rejects: the SDK's RestError with this HTTP status. */
const restError = (status: number) => (e: unknown) => {
  assert.equal((e as { name?: unknown }).name, 'RestError', String(e));
  assert.equal((e as { statusCode?: unknown }).statusCode, status);
  return true;
};

function withSensitiveLogging(): () => void {
  const original = HkdfGuardTelemetry.cache.enableSensitiveLogging;
  HkdfGuardTelemetry.cache.enableSensitiveLogging = true;
  return () => { HkdfGuardTelemetry.cache.enableSensitiveLogging = original; };
}

/**
 * A RemoteSecretCache whose fetch is a test's: the way to get a real SecretValueSink, which only a
 * cache creates, into a request made through the capture policy directly.
 */
class SinkProbeCache extends RemoteSecretCache {
  constructor(ring: KeyRingContract, private readonly probe: (name: string, sink: SecretValueSink) => Promise<void>) {
    super(ring, SecretNameMatching.ignoreAsciiCase);
  }

  protected override isValidName(name: string): boolean {
    return AzureKeyVaultSecretCache.isValidSecretName(name);
  }

  protected override fetch(name: string, sink: SecretValueSink): Promise<void> {
    return this.probe(name, sink);
  }
}

describe('AzureKeyVaultSecretCache: fetching and caching', () => {
  it('fetches the one secret on a miss, then serves it from the cache', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const cache = create(vault);
    vault.set('Db-Password', 's3cret');

    assert.equal(await decryptString(cache, 'Db-Password'), 's3cret');
    assert.equal(await decryptString(cache, 'Db-Password'), 's3cret');

    assert.deepEqual(vault.gets, ['Db-Password']);
    assert.deepEqual(vault.unexpectedRequests, []);
  });

  it('caches a JSON secret whole and by key from one call, and SecretClient never sees it', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const cache = create(vault);
    vault.set('App-Credentials', KEY_VALUE_SECRET);

    assert.equal(await decryptString(cache, 'App-Credentials#api-credential-21'),
      '0k4sBPf0vQw6SDn6r7g4lMODn9bB5JrXyYVkvhFl3f0oM2xVhW3vXKz6u4Fuw2VwCs+6xXK8WaF9JUYg9l0L8Q==');
    assert.equal(await decryptString(cache, 'app-credentials#test-credential-1'), 'This is my first credential');
    assert.equal(await decryptString(cache, 'APP-CREDENTIALS#domain-credential-17'), 'fakedomain/thiscredential');
    assert.equal(await decryptString(cache, 'App-Credentials#port'), '5432');
    assert.equal(await decryptString(cache, 'App-Credentials'), KEY_VALUE_SECRET);

    // Secret names ignore case; keys don't - a key the secret doesn't hold costs a fetch.
    await missing(cache, 'App-Credentials#PORT');

    assert.deepEqual(vault.gets, ['App-Credentials', 'App-Credentials']);
    assert.ok(vault.bodiesSeenBySecretClient.length > 0);
    assert.ok(!vault.bodiesSeenBySecretClient.some((body) => body.includes('credential')));
  });

  it('gives SecretClient only the body with the value blanked', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const cache = create(vault);
    vault.set('Db-Password', 's3cret');

    assert.equal(await decryptString(cache, 'Db-Password'), 's3cret');

    const [body, ...rest] = vault.bodiesSeenBySecretClient;
    assert.equal(rest.length, 0);
    assert.ok(!body!.includes('s3cret'));
    assert.ok(body!.includes('"value":""'));
    // Only the top-level value is taken: a nested property of the same name is left alone.
    assert.ok(body!.includes('a tag, not the secret'));
  });

  it('asks for the body of each of its fetches unread', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const cache = create(vault);
    vault.set('Db-Password', 's3cret');

    assert.equal(await decryptString(cache, 'Db-Password'), 's3cret');
    assert.deepEqual(vault.streams, [true]);
  });

  it('still captures and redacts a body the HTTP client read anyway', async (t) => {
    // The string the HTTP client decoded it into can't be zeroed; the bytes captured from it are.
    const vault = await FakeKeyVault.start(t);
    const cache = create(vault);
    vault.set('Db-Password', 's3cret');
    vault.alwaysBuffer = true;

    assert.equal(await decryptString(cache, 'Db-Password'), 's3cret');
    const [body] = vault.bodiesSeenBySecretClient;
    assert.ok(!body!.includes('s3cret') && body!.includes('"value":""'));
  });

  it('decompresses a compressed body before it is captured', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const cache = create(vault);
    vault.set('Db-Password', 's3cret');
    vault.gzip = true;

    assert.equal(await decryptString(cache, 'Db-Password'), 's3cret');
    assert.equal(vault.compressed, 1);
    const [body] = vault.bodiesSeenBySecretClient;
    assert.ok(!body!.includes('s3cret') && body!.includes('"value":""'));
  });

  it('unescapes a value with JSON escapes exactly', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const cache = create(vault);
    const secret = 'p"a\\ss/wörd\n\u0001秘密';
    vault.set('escaped', secret);

    assert.equal(await decryptString(cache, 'escaped'), secret);
    assert.ok(!vault.bodiesSeenBySecretClient[0]!.includes('wörd'));
  });

  it('fetches the secret when maxDecryptedLength misses', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const cache = create(vault);
    vault.set('api-key', 'value');

    assert.ok((await cache.maxDecryptedLength('api-key'))! >= 5);
    assert.equal(await decryptString(cache, 'api-key'), 'value');
    assert.equal(vault.gets.length, 1);
  });

  it('treats names differing in case as one entry and one fetch', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const cache = create(vault);
    vault.set('Db-Password', 's3cret');

    assert.equal(await decryptString(cache, 'db-password'), 's3cret');
    assert.equal(await decryptString(cache, 'DB-PASSWORD'), 's3cret');
    assert.deepEqual(vault.gets, ['db-password']);
  });

  it('reports a missing secret as 0, and looks it up again until it exists', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const cache = create(vault);

    await missing(cache, 'later');
    assert.equal(await cache.maxDecryptedLength('later'), undefined);

    vault.set('later', 'now here');
    assert.equal(await decryptString(cache, 'later'), 'now here');
    assert.equal(vault.gets.length, 3);
  });

  it('reports an empty secret missing', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const cache = create(vault);
    vault.set('empty', '');

    await missing(cache, 'empty');
    assert.equal(vault.gets.length, 1);
  });

  for (const name of ['', 'ConnectionStrings:Admin', 'db_password', '../keys/other', 'name/version', 'name?api-version=1', 'café',
    'has space', 'x'.repeat(128), '١٢٣']) {
    it(`reports ${name.length > 40 ? `a ${name.length}-character name` : JSON.stringify(name)}, which Key Vault can't hold, missing without calling the vault`, async (t) => {
      const vault = await FakeKeyVault.start(t);
      const cache = create(vault);

      await missing(cache, name);
      assert.equal(await cache.maxDecryptedLength(name), undefined);
      assert.deepEqual(vault.gets, []);
      assert.deepEqual(vault.unexpectedRequests, []);
    });
  }

  it('isValidSecretName accepts ASCII letters, digits and hyphens, up to 127', () => {
    assert.ok(AzureKeyVaultSecretCache.isValidSecretName('a'));
    assert.ok(AzureKeyVaultSecretCache.isValidSecretName('Db-Password-2'));
    assert.ok(AzureKeyVaultSecretCache.isValidSecretName('x'.repeat(AzureKeyVaultSecretCache.MAX_SECRET_NAME_LENGTH)));
    assert.ok(!AzureKeyVaultSecretCache.isValidSecretName('x'.repeat(AzureKeyVaultSecretCache.MAX_SECRET_NAME_LENGTH + 1)));
    assert.ok(!AzureKeyVaultSecretCache.isValidSecretName(''));
    assert.ok(!AzureKeyVaultSecretCache.isValidSecretName(undefined));
    assert.ok(!AzureKeyVaultSecretCache.isValidSecretName(null));
    assert.ok(!AzureKeyVaultSecretCache.isValidSecretName(42 as unknown as string));
    // A Unicode-aware test would accept these; Key Vault doesn't.
    assert.ok(!AzureKeyVaultSecretCache.isValidSecretName('café'));
    assert.ok(!AzureKeyVaultSecretCache.isValidSecretName('x١'));
    assert.ok(!AzureKeyVaultSecretCache.isValidSecretName('name\n'));
  });

  for (const status of [401, 403, 429, 500, 503]) {
    it(`propagates a Key Vault failure (HTTP ${status}) and retries it on the next lookup`, async (t) => {
      const vault = await FakeKeyVault.start(t);
      const cache = create(vault);
      vault.set('item', 'value');
      vault.failWith = status;

      await assert.rejects(cache.decrypt('item', new Uint8Array(16)), restError(status));

      vault.failWith = undefined;
      assert.equal(await decryptString(cache, 'item'), 'value');
      assert.equal(vault.gets.length, 2);
    });
  }

  it('captures a retried attempt once it succeeds', async (t) => {
    // The policy runs per attempt: the 503 is left for the retry policy, and the 200 that follows is captured.
    const vault = await FakeKeyVault.start(t);
    const cache = create(vault, newRing(), { clientOptions: { retryOptions: { maxRetries: 2, retryDelayInMs: 1, maxRetryDelayInMs: 1 } } });
    vault.set('item', 'value');
    vault.failWith = 503;
    vault.failuresLeft = 1;

    assert.equal(await decryptString(cache, 'item'), 'value');
    assert.deepEqual(vault.gets, ['item', 'item']);
    assert.deepEqual(vault.streams, [true, true]);
    const [body, ...rest] = vault.bodiesSeenBySecretClient;
    assert.equal(rest.length, 0);
    assert.ok(body!.includes('"value":""'));
  });

  it('refuses a response that is not JSON', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const cache = create(vault);
    vault.rawBody = 'not json';

    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), InvalidSecretDataError);
    // Nothing was handed over: the next lookup fetches again.
    vault.rawBody = undefined;
    vault.set('item', 'value');
    assert.equal(await decryptString(cache, 'item'), 'value');
  });

  it('propagates a credential failure', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const failure = new Error('no token');
    const cache = new AzureKeyVaultSecretCache(VAULT, credential(failure), newRing(), undefined, { clientOptions: vault.clientOptions() });

    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), (e: unknown) => e === failure);
    assert.deepEqual(vault.gets, []);
  });

  it('aborts the request when the lookup is aborted, caches nothing, and fetches again on the next lookup', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const cache = create(vault);
    vault.set('slow', 'value');
    const entered = gate();
    const release = gate();
    vault.onGet = async () => {
      entered.open();
      await release.promise;
    };

    const controller = new AbortController();
    const lookup = cache.decrypt('slow', new Uint8Array(16), controller.signal);
    await entered.promise;
    controller.abort();
    await assert.rejects(lookup, { name: 'AbortError' });
    release.open();

    vault.onGet = undefined;
    assert.equal(await decryptString(cache, 'slow'), 'value');
    assert.deepEqual(vault.gets, ['slow', 'slow']);
  });

  it('makes no request for a lookup aborted before it starts', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const cache = create(vault);
    vault.set('item', 'value');

    await assert.rejects(cache.decrypt('item', new Uint8Array(16), AbortSignal.abort()), { name: 'AbortError' });
    assert.deepEqual(vault.gets, []);
  });

  it('shares one fetch between concurrent misses on one name', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const cache = create(vault);
    vault.set('shared', 'value');
    const entered = gate();
    const release = gate();
    vault.onGet = async () => {
      entered.open();
      await release.promise;
    };

    const lookups = Array.from({ length: 8 }, (_, i) => decryptString(cache, i % 2 === 0 ? 'shared' : 'SHARED'));
    await entered.promise;
    release.open();

    assert.deepEqual(await Promise.all(lookups), Array(8).fill('value'));
    assert.equal(vault.gets.length, 1);
  });

  it('captures each value into its own fetch when fetches of different secrets run through the one client at once', async (t) => {
    // Every request in flight at once, so each response must reach its own fetch's sink.
    const vault = await FakeKeyVault.start(t);
    const names = Array.from({ length: 6 }, (_, i) => `secret-${i}`);
    for (const name of names) vault.set(name, `value of ${name}`);
    const together = gate();
    let arrived = 0;
    vault.onGet = async () => {
      if (++arrived === names.length) together.open();
      await together.promise;
    };
    const cache = create(vault);

    assert.deepEqual(await Promise.all(names.map((name) => decryptString(cache, name))), names.map((name) => `value of ${name}`));
    assert.deepEqual([...vault.gets].sort(), names);
  });

  it('round-trips a large secret', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const cache = create(vault);
    const large = 'é-秘密-'.repeat(3000);
    assert.ok(utf8(large).length > 16 * 1024);
    vault.set('large', large);

    const length = await cache.maxDecryptedLength('large');
    assert.notEqual(length, undefined);
    assert.equal(await decryptString(cache, 'large', length), large);
  });

  it('still decrypts a cached secret after the ring rotates', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const ring = newRing();
    const cache = create(vault, ring);
    vault.set('before', 'v1 value');
    vault.set('after', 'v2 value');

    assert.equal(await decryptString(cache, 'before'), 'v1 value');
    ring.add(2, new RecordingKey());

    assert.equal(await decryptString(cache, 'after'), 'v2 value');
    assert.equal(await decryptString(cache, 'before'), 'v1 value');
  });

  it('in a collection, receives only the names the sources before it miss', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const ring = newRing();
    const vaultCache = create(vault, ring);
    vault.set('from-vault', 'vault value');
    const local = new ProtectedCache(ring);
    local.add('ConnectionStrings:Admin', utf8('local value'));
    const collection = new ProtectedCacheCollection(local, vaultCache);

    assert.equal(await decryptString(collection, 'ConnectionStrings:Admin'), 'local value');
    assert.equal(await decryptString(collection, 'from-vault'), 'vault value');
    assert.deepEqual(vault.gets, ['from-vault']);
  });
});

describe('AzureKeyVaultSecretCache: logging and telemetry', () => {
  it('with sensitive logging, logs a fetch\'s name only, and a failure as an error', async (t) => {
    const restore = withSensitiveLogging();
    try {
      const vault = await FakeKeyVault.start(t);
      const { logger, entries, withEventId } = capturingLogger();
      const cache = create(vault, newRing(), { logger });
      vault.set('item', 'never-logged');

      assert.equal(await decryptString(cache, 'item'), 'never-logged');
      vault.failWith = 500;
      await assert.rejects(cache.decrypt('other', new Uint8Array(16)), restError(500));

      assert.ok(withEventId(1).some((e) => e.level === 'debug' && e.message.includes('item')));
      const failures = withEventId(2);
      assert.equal(failures.length, 1);
      assert.equal(failures[0]!.level, 'error');
      assert.equal((failures[0]!.attributes.error as { statusCode?: unknown }).statusCode, 500);
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
      const vault = await FakeKeyVault.start(t);
      const cache = create(vault);
      vault.set('Found', 'value');
      assert.equal(await decryptString(cache, 'Found'), 'value');
      await missing(cache, 'missing');
      vault.failWith = 500;
      await assert.rejects(cache.decrypt('failing', new Uint8Array(16)), restError(500));

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

describe('AzureKeyVaultSecretCache: construction', () => {
  for (const option of ['pipeline', 'endpoint', 'baseUrl']) {
    it(`refuses the client option ${option}, which would bypass the capture or send it elsewhere`, async (t) => {
      const vault = await FakeKeyVault.start(t);
      const clientOptions = { ...vault.clientOptions(), [option]: option === 'pipeline' ? createEmptyPipeline() : 'https://elsewhere.vault.azure.net' };
      assert.throws(() => new AzureKeyVaultSecretCache(VAULT, credential(), newRing(), undefined, { clientOptions }),
        (e: unknown) => e instanceof InvalidArgumentError && e.message.includes(`must not set ${option}`));
    });
  }

  it('shows a policy of the application\'s, per call or per retry, only the redacted body', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const seen: string[] = [];
    const peek = (name: string): PipelinePolicy => ({
      name,
      async sendRequest(request, next) {
        const response = await next(request);
        if (response.status === 200) seen.push(`${name}: ${response.bodyAsText}`);
        return response;
      },
    });
    const cache = create(vault, newRing(), {
      clientOptions: { additionalPolicies: [{ policy: peek('perRetry'), position: 'perRetry' }, { policy: peek('perCall'), position: 'perCall' }] },
    });
    vault.set('item', 's3cret');

    assert.equal(await decryptString(cache, 'item'), 's3cret');
    assert.equal(seen.length, 2);
    for (const body of seen) assert.ok(!body.includes('s3cret') && body.includes('"value":""'), body);
  });

  it('leaves the caller\'s client options alone, and another client built from them reads secrets as usual', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const options = vault.clientOptions();
    const additional = options.additionalPolicies!;
    const snapshot = { ...options };
    const additionalSnapshot = [...additional];
    const cache = new AzureKeyVaultSecretCache(VAULT, credential(), newRing(), undefined, { clientOptions: options });
    vault.set('Db-Password', 's3cret');

    assert.equal(await decryptString(cache, 'Db-Password'), 's3cret');
    assert.deepEqual(options, snapshot);
    assert.equal(options.additionalPolicies, additional);
    assert.deepEqual(additional, additionalSnapshot);
    assert.equal((await new SecretClient(VAULT, credential(), options).getSecret('Db-Password')).value, 's3cret');
  });

  it('makes no call from the public constructor until a secret is requested', async () => {
    const cache = new AzureKeyVaultSecretCache('https://example.vault.azure.net/', new DefaultAzureCredential(), newRing());
    // An invalid name never reaches the client, so this needs no network or credential.
    await missing(cache, 'not:a:secret');
  });

  it('refuses missing or invalid arguments', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const ring = newRing();
    const ok = credential();
    for (const [url, cred, keyRing, options, error] of [
      [undefined, ok, ring, {}, TypeError], [42, ok, ring, {}, TypeError], [VAULT, undefined, ring, {}, TypeError], [VAULT, null, ring, {}, TypeError],
      [VAULT, {}, ring, {}, TypeError], [VAULT, { getToken: 'token' }, ring, {}, TypeError], [VAULT, ok, undefined, {}, TypeError],
      [VAULT, ok, ring, null, TypeError], [VAULT, ok, ring, { clientOptions: 'retry' }, TypeError],
      [VAULT, ok, ring, { clientOptions: { ...vault.clientOptions(), additionalPolicies: secretCapturePolicy } }, TypeError],
      ['', ok, ring, {}, InvalidArgumentError], ['not a url', ok, ring, {}, InvalidArgumentError],
    ] as const) {
      assert.throws(() => new AzureKeyVaultSecretCache(url as string, cred as KeyVaultCredential, keyRing as KeyRing, undefined,
        options as AzureKeyVaultSecretCacheOptions), error, JSON.stringify([url, options]));
    }
  });
});

describe('the secret capture policy on its own', () => {
  const getSecret = (name: string) => createPipelineRequest({
    // The fake vault's own token, so the request needs no authentication policy.
    url: `${VAULT}/secrets/${name}/?api-version=2025-07-01`, headers: createHttpHeaders({ authorization: `Bearer ${TOKEN}` }),
  });

  function pipeline(...policies: PipelinePolicy[]): Pipeline {
    const built = createEmptyPipeline();
    for (const policy of policies) built.addPolicy(policy, policy.name === 'defaultRetryPolicy' ? { phase: 'Retry' } : {});
    built.addPolicy(secretCapturePolicy, { afterPhase: 'Retry' });
    return built;
  }

  it('is named', () => {
    assert.equal(secretCapturePolicy.name, SECRET_CAPTURE_POLICY_NAME);
  });

  it('leaves the value SecretClient returns empty, and the rest of the secret as it was', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const client = new SecretClient(VAULT, credential(), vault.clientOptions({ additionalPolicies: [{ policy: secretCapturePolicy, position: 'perRetry' }] }));
    vault.set('Db-Password', 's3cret');
    const returned: KeyVaultSecret[] = [];
    const cache = new SinkProbeCache(newRing(), async (name, sink) => {
      returned.push(await captureWithin(new Capture(sink), () => client.getSecret(name)));
    });

    assert.equal(await decryptString(cache, 'Db-Password'), 's3cret');

    const [secret] = returned;
    assert.equal(secret!.value, '');
    assert.deepEqual(secret!.properties.tags, { value: 'a tag, not the secret' });
    assert.equal(secret!.name, 'Db-Password');
  });

  it('captures the value and hands on the body with it blanked', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const run = pipeline();
    vault.set('Db-Password', 's3cret');
    const responses: PipelineResponse[] = [];
    const captures: Capture[] = [];
    const cache = new SinkProbeCache(newRing(), async (name, sink) => {
      const capture = new Capture(sink);
      captures.push(capture);
      responses.push(await captureWithin(capture, () => run.sendRequest(vault.httpClient, getSecret(name))));
    });

    assert.equal(await decryptString(cache, 'Db-Password'), 's3cret');

    assert.ok(captures[0]!.captured);
    assert.equal(responses[0]!.readableStreamBody, undefined);
    assert.ok(responses[0]!.bodyAsText!.includes('"value":""') && !responses[0]!.bodyAsText!.includes('s3cret'));
    assert.deepEqual(vault.streams, [true]);
  });

  it('leaves an error response read for the client, and captures nothing from it', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const run = pipeline();
    const seen: [number, string | null | undefined, boolean][] = [];
    const cache = new SinkProbeCache(newRing(), async (name, sink) => {
      const capture = new Capture(sink);
      const response = await captureWithin(capture, () => run.sendRequest(vault.httpClient, getSecret(name)));
      seen.push([response.status, response.bodyAsText, capture.captured]);
    });

    await missing(cache, 'missing');

    const [[status, body, captured]] = seen as [[number, string, boolean]];
    assert.equal(status, 404);
    assert.ok(body.includes('SecretNotFound'));
    assert.equal(captured, false);
  });

  it('refuses a body that is not JSON', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const run = pipeline();
    vault.rawBody = 'not json';
    const cache = new SinkProbeCache(newRing(), async (name, sink) => {
      await captureWithin(new Capture(sink), () => run.sendRequest(vault.httpClient, getSecret(name)));
    });

    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), InvalidSecretDataError);
  });

  it('passes a request made outside a capture through untouched', async (t) => {
    const vault = await FakeKeyVault.start(t);
    vault.set('item', 'value');

    const response = await pipeline().sendRequest(vault.httpClient, getSecret('item'));

    assert.ok(response.bodyAsText!.includes('"value":"value"'));
    assert.deepEqual(vault.streams, [false]);
  });

  it('streams and captures every attempt a retry policy before it makes', async (t) => {
    const vault = await FakeKeyVault.start(t);
    const run = pipeline(defaultRetryPolicy({ maxRetries: 1, retryDelayInMs: 1, maxRetryDelayInMs: 1 }));
    vault.set('item', 'value');
    vault.failWith = 500;
    vault.failuresLeft = 1;
    const cache = new SinkProbeCache(newRing(), async (name, sink) => {
      await captureWithin(new Capture(sink), () => run.sendRequest(vault.httpClient, getSecret(name)));
    });

    assert.equal(await decryptString(cache, 'item'), 'value');
    assert.deepEqual(vault.streams, [true, true]);
  });

  for (const kind of ['Node Readable', 'web ReadableStream'] as const) {
    it(`zeroes every chunk of a ${kind} body once it is read`, async () => {
      const chunks = [Buffer.from('{"value":"s3'), Buffer.from('cret","id":"x"'), Buffer.from('}')];
      const asked: boolean[] = [];
      const client: HttpClient = {
        async sendRequest(request) {
          asked.push(request.streamResponseStatusCodes?.has(200) === true);
          const response: PipelineResponse = { request, status: 200, headers: createHttpHeaders() };
          if (kind === 'Node Readable') response.readableStreamBody = Readable.from(chunks);
          else response.browserStreamBody = ReadableStream.from(chunks);
          return response;
        },
      };
      const responses: PipelineResponse[] = [];
      const cache = new SinkProbeCache(newRing(), async (name, sink) => {
        responses.push(await captureWithin(new Capture(sink), () => pipeline().sendRequest(client, getSecret(name))));
      });

      assert.equal(await decryptString(cache, 'item'), 's3cret');
      assert.deepEqual(asked, [true]);
      assert.ok(chunks.every((chunk) => isZero(chunk)));
      assert.equal(responses[0]!.bodyAsText, '{"value":"","id":"x"}');
      assert.equal(responses[0]!.readableStreamBody, undefined);
      assert.equal(responses[0]!.browserStreamBody, undefined);
    });
  }

  it('refuses a 200 without a body', async () => {
    const client: HttpClient = { sendRequest: async (request) => ({ request, status: 200, headers: createHttpHeaders() }) };
    const cache = new SinkProbeCache(newRing(), async (name, sink) => {
      await captureWithin(new Capture(sink), () => pipeline().sendRequest(client, getSecret(name)));
    });

    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), InvalidSecretDataError);
  });

  it('refuses a capture that has no sink, or isn\'t a Capture', () => {
    assert.throws(() => new Capture(undefined as unknown as SecretValueSink), TypeError);
    assert.throws(() => new Capture({} as SecretValueSink), TypeError);
    assert.throws(() => captureWithin({ sink: undefined, captured: false } as unknown as Capture, async () => undefined), TypeError);
  });
});

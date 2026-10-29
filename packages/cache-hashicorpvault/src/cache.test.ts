import { strict as assert } from 'node:assert';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { Agent as HttpsAgent } from 'node:https';
import { createServer as createNetServer, type Socket } from 'node:net';
import { afterEach, describe, it } from 'node:test';
import { SpanStatusCode } from '@opentelemetry/api';
import { ClosedError, HkdfGuardError, InvalidArgumentError, type DataProtector, type ProtectedReadOnlyCache } from '@runsecure/hkdfguard-abstractions';
import { InvalidSecretDataError, ProtectedCache, ProtectedCacheCollection } from '@runsecure/hkdfguard-cache';
import { AttributeNames, HkdfGuardTelemetry, MetricNames, SpanNames, type Logger } from '@runsecure/hkdfguard-diagnostics';
import { KeyRing } from '@runsecure/hkdfguard-dek';
import { capturingLogger, RecordingKey, useMetricRecorder, useSpanRecorder } from '@runsecure/hkdfguard-test-support';
import { HashiCorpVaultSecretCache, retryDelay } from './cache.js';
import { VaultRequestError } from './errors.js';
import { HashiCorpVaultSecretCacheOptions, VaultKvVersion } from './options.js';
import { StaticVaultToken, type VaultTokenProvider } from './token.js';

const TOKEN_PURPOSE = HashiCorpVaultSecretCache.TOKEN_PURPOSE;
const Limits = HashiCorpVaultSecretCacheOptions;

// --- A fake Vault ------------------------------------------------------------------------------

/** An answer given as it is: a status, a body ('' for none) and any extra headers. */
interface Answer {
  status: number;
  body: string;
  headers?: Record<string, string>;
}

/** Runs inside a read before it is answered; resolves to true if it has answered (or dropped) it itself. */
type OnRead = (request: IncomingMessage, response: ServerResponse) => boolean | void | Promise<boolean | void>;

/**
 * A KV secrets engine behind Vault's HTTP API, served over plain http on 127.0.0.1 (which the cache
 * allows on loopback): a GET of a secret's read path with the expected token is answered as Vault
 * answers it - the secret, or 404 with an empty error list - for KV version 2 (the default) or 1. A
 * request without that token is refused with 403, as Vault refuses it. Any other request - a LIST,
 * a query, another path - is recorded in unexpectedRequests and refused. Paths are matched exactly,
 * as Vault matches them.
 */
class FakeVault {
  static readonly TOKEN = 'hvs.CAESIFakeTokenForTests';

  readonly secrets = new Map<string, Record<string, unknown>>();
  readonly deleted = new Set<string>();
  readonly reads: string[] = [];
  readonly tokens: string[] = [];
  readonly namespaces: string[] = [];
  readonly vaultRequestHeaders: string[] = [];
  readonly unexpectedRequests: string[] = [];
  /** When set, a read with the right token is answered with this. */
  answer: Answer | undefined;
  /** When set, runs inside every read before it answers. */
  onRead: OnRead | undefined;
  /** Resolved on close, so hooks holding a read open let go. */
  readonly #stopping = Promise.withResolvers<void>();
  readonly #server: Server;

  private constructor(readonly mountPath: string, readonly kvVersion: VaultKvVersion, readonly pathPrefix: string) {
    this.#server = createServer((request, response) => {
      this.#handle(request, response).catch(() => response.socket?.destroy());
    });
  }

  static async start(mountPath = 'secret', kvVersion: VaultKvVersion = VaultKvVersion.v2, pathPrefix = ''): Promise<FakeVault> {
    const vault = new FakeVault(mountPath, kvVersion, pathPrefix);
    await new Promise<void>((resolve) => vault.#server.listen(0, '127.0.0.1', resolve));
    return vault;
  }

  get port(): number {
    return (this.#server.address() as { port: number }).port;
  }

  /** Vault's address, with the path prefix if any, as VAULT_ADDR would hold it. */
  get address(): string {
    return `http://127.0.0.1:${this.port}${this.pathPrefix}/`;
  }

  readUrl(path: string): string {
    return `http://127.0.0.1:${this.port}${this.#readPrefix()}${path}`;
  }

  /** Resolves on close, or after `ms`. */
  stopping(ms: number): Promise<void> {
    return Promise.race([this.#stopping.promise, sleep(ms)]);
  }

  setData(path: string, data: Record<string, unknown>): void {
    this.secrets.set(path, data);
  }

  set(path: string, value: string): void {
    this.setData(path, { value });
  }

  /** A KV version 2 secret whose latest version is deleted: Vault answers 404 with its metadata. */
  setDeleted(path: string): void {
    this.deleted.add(path);
  }

  async close(): Promise<void> {
    this.#stopping.resolve();
    this.#server.closeAllConnections();
    await new Promise<void>((resolve) => this.#server.close(() => resolve()));
  }

  #readPrefix(): string {
    return `${this.pathPrefix}/v1/${this.mountPath}/${this.kvVersion === VaultKvVersion.v2 ? 'data/' : ''}`;
  }

  async #handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const url = request.url ?? '';
    const prefix = this.#readPrefix();
    if (request.method !== 'GET' || url.includes('?') || !url.startsWith(prefix)) {
      this.unexpectedRequests.push(`${request.method} ${url}`);
      respond(response, { status: 405, body: '{"errors":["1 error occurred:\\n\\t* unsupported operation\\n\\n"]}' });
      return;
    }

    const token = header(request, 'x-vault-token');
    const path = url.slice(prefix.length);
    this.tokens.push(token ?? '');
    this.namespaces.push(header(request, 'x-vault-namespace') ?? '(none)');
    this.vaultRequestHeaders.push(header(request, 'x-vault-request') ?? '(none)');
    this.reads.push(path);

    if (this.onRead !== undefined && await this.onRead(request, response) === true) return;

    const secret = this.secrets.get(path);
    if (token !== FakeVault.TOKEN) respond(response, { status: 403, body: '{"errors":["permission denied"]}' });
    else if (this.answer !== undefined) respond(response, this.answer);
    else if (this.deleted.has(path)) respond(response, { status: 404, body: envelope({ data: null, metadata: metadata(true) }, 0) });
    else if (secret === undefined) respond(response, { status: 404, body: '{"errors":[]}' });
    else if (this.kvVersion === VaultKvVersion.v2) respond(response, { status: 200, body: envelope({ data: secret, metadata: metadata(false) }, 0) });
    else respond(response, { status: 200, body: envelope(secret, 2_764_800) });
  }
}

function header(request: IncomingMessage, name: string): string | undefined {
  const value = request.headers[name];
  return Array.isArray(value) ? value.join(',') : value;
}

function metadata(deleted: boolean): Record<string, unknown> {
  return {
    created_time: '2026-10-28T12:00:00.000000Z', custom_metadata: null,
    deletion_time: deleted ? '2026-10-28T13:00:00.000000Z' : '', destroyed: false, version: 3,
  };
}

function envelope(data: unknown, leaseDuration: number): string {
  return JSON.stringify({
    request_id: '0f3c2a8e-1b2d-4c5e-8f9a-0b1c2d3e4f5a', lease_id: '', renewable: false, lease_duration: leaseDuration,
    data, wrap_info: null, warnings: null, auth: null, mount_type: 'kv',
  });
}

function respond(response: ServerResponse, answer: Answer): void {
  if (response.destroyed) return;
  const body = Buffer.from(answer.body);
  response.writeHead(answer.status, { 'Content-Type': 'application/json', ...answer.headers, 'Content-Length': body.length });
  response.end(body);
}

/**
 * A token provider that counts its calls, and can hand out any token, fail or hang. Each token next
 * gives is protected by protector, as a real provider's is, unless the provider is unprotected.
 */
class FakeTokenProvider implements VaultTokenProvider {
  calls = 0;
  /** Gives the token for call number n (from 1); may throw. */
  next: (call: number) => unknown = () => FakeVault.TOKEN;
  /** Protects every token handed out; set to the cache's own token protector. */
  protector: DataProtector | undefined;
  /** 'honour': getToken waits until its signal is aborted; 'ignore': it never settles. */
  hang: 'honour' | 'ignore' | undefined;
  signalAborted = false;

  constructor(readonly unprotected = false) {}

  static giving(token: string): FakeTokenProvider {
    const provider = new FakeTokenProvider();
    provider.next = () => token;
    return provider;
  }

  async getToken(signal: AbortSignal): Promise<string> {
    if (this.hang === 'ignore') return new Promise<string>(() => undefined);
    if (this.hang === 'honour') {
      await new Promise<void>((_resolve, reject) => {
        signal.addEventListener('abort', () => {
          this.signalAborted = true;
          reject(signal.reason);
        }, { once: true });
      });
    }
    this.calls++;
    const token = this.next(this.calls);
    return (this.unprotected || this.protector === undefined || typeof token !== 'string' ? token : this.protector.encrypt(token)) as string;
  }
}

// --- Rings, caches and cleanup -----------------------------------------------------------------

const cleanups: (() => unknown)[] = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

function makeRing(version = 1): KeyRing {
  const ring = new KeyRing();
  ring.add(version, new RecordingKey());
  return ring;
}

async function startVault(mountPath?: string, kvVersion?: VaultKvVersion, pathPrefix?: string): Promise<FakeVault> {
  const vault = await FakeVault.start(mountPath, kvVersion, pathPrefix);
  cleanups.push(() => vault.close());
  return vault;
}

interface CreateOptions extends HashiCorpVaultSecretCacheOptions {
  address?: string;
  tokens?: VaultTokenProvider;
  ring?: KeyRing;
}

/**
 * A cache on a ring of its own, given the fake's token protected for it. No backoff, only each
 * retry's 0-100 ms of jitter, so a test that meets a 5xx stays quick.
 */
function create(vault: FakeVault | undefined, { address, tokens, ring, ...options }: CreateOptions = {}): HashiCorpVaultSecretCache {
  const keyRing = ring ?? makeRing();
  const protector = keyRing.createProtector(TOKEN_PURPOSE);
  if (tokens instanceof FakeTokenProvider && tokens.protector === undefined && !tokens.unprotected) tokens.protector = protector;
  const provider = tokens ?? StaticVaultToken.protect(protector, FakeVault.TOKEN);
  const cache = new HashiCorpVaultSecretCache(address ?? vault!.address, provider, protector, keyRing, { retryDelayMs: 0, ...options });
  cleanups.push(() => cache.close());
  return cache;
}

function newCache(address = 'https://vault.example.com:8200', options?: HashiCorpVaultSecretCacheOptions): HashiCorpVaultSecretCache {
  const ring = makeRing();
  const protector = ring.createProtector(TOKEN_PURPOSE);
  const cache = new HashiCorpVaultSecretCache(address, StaticVaultToken.protect(protector, FakeVault.TOKEN), protector, ring, options);
  cleanups.push(() => cache.close());
  return cache;
}

async function decryptString(cache: ProtectedReadOnlyCache, name: string, size = 64, signal?: AbortSignal): Promise<string> {
  const result = new Uint8Array(size);
  return new TextDecoder().decode(result.subarray(0, await cache.decrypt(name, result, signal)));
}

const decryptOf = (cache: ProtectedReadOnlyCache, name: string) => cache.decrypt(name, new Uint8Array(16));

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** A loopback port nothing listens on. */
async function freePort(): Promise<number> {
  const server = createNetServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as { port: number };
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

/** The error and every cause chained to it. */
function chain(error: unknown): unknown[] {
  const found: unknown[] = [];
  for (let current = error; current !== undefined && current !== null && !found.includes(current); current = (current as Error).cause) {
    found.push(current);
  }
  return found;
}

const isTimeout = (error: unknown) => error instanceof DOMException && error.name === 'TimeoutError';
const isStatus = (status: number) => (error: unknown) => error instanceof VaultRequestError && error.statusCode === status;

function withSensitiveLogging(): () => void {
  const original = HkdfGuardTelemetry.cache.enableSensitiveLogging;
  HkdfGuardTelemetry.cache.enableSensitiveLogging = true;
  return () => { HkdfGuardTelemetry.cache.enableSensitiveLogging = original; };
}

// --- Reading -----------------------------------------------------------------------------------

describe('HashiCorpVaultSecretCache: reading', () => {
  it('reads the one secret on a miss, then serves it from the cache', async () => {
    const vault = await startVault();
    const cache = create(vault);
    vault.set('myapp/Db', 's3cret');

    assert.equal(await decryptString(cache, 'myapp/Db'), 's3cret');
    assert.equal(await decryptString(cache, 'myapp/Db'), 's3cret');

    assert.deepEqual(vault.reads, ['myapp/Db']);
    assert.deepEqual(vault.vaultRequestHeaders, ['true']);
    assert.deepEqual(vault.unexpectedRequests, []);
  });

  it('caches every key the secret holds from one read', async () => {
    const vault = await startVault();
    const cache = create(vault);
    vault.setData('myapp/db', { username: 'app', password: 's3cret', value: 'default', 'Mixed-Case.key:1': 'mixed' });

    assert.equal(await decryptString(cache, 'myapp/db#password'), 's3cret');
    assert.equal(await decryptString(cache, 'myapp/db#username'), 'app');
    assert.equal(await decryptString(cache, 'myapp/db'), 'default');
    assert.equal(await decryptString(cache, 'myapp/db#value'), 'default');
    assert.equal(await decryptString(cache, 'myapp/db#Mixed-Case.key:1'), 'mixed');

    assert.deepEqual(vault.reads, ['myapp/db']);
  });

  it('shares one read between concurrent misses on different keys', async () => {
    const vault = await startVault();
    const cache = create(vault);
    vault.setData('shared', { a: '1', b: '2', value: '3' });
    const release = Promise.withResolvers<void>();
    vault.onRead = async () => { await release.promise; };

    const results = Promise.all(['shared#a', 'shared#b', 'shared'].map((name) => decryptString(cache, name)));
    await sleep(100);
    release.resolve();

    assert.deepEqual(await results, ['1', '2', '3']);
    assert.equal(vault.reads.length, 1);
  });

  it('shares one fetch between concurrent misses on one name', async () => {
    const vault = await startVault();
    const cache = create(vault);
    vault.set('shared', 'value');
    const release = Promise.withResolvers<void>();
    vault.onRead = async () => { await release.promise; };

    const results = Promise.all(Array.from({ length: 8 }, () => decryptString(cache, 'shared')));
    await sleep(100);
    release.resolve();

    assert.ok((await results).every((value) => value === 'value'));
    assert.equal(vault.reads.length, 1);
  });

  it('reports a missing secret through decrypt and maxDecryptedLength', async () => {
    const vault = await startVault();
    const cache = create(vault);
    vault.setData('myapp/db', { password: 's3cret', value: 'default' });

    assert.equal(await decryptString(cache, 'myapp/db#password'), 's3cret');
    assert.equal(await decryptString(cache, 'myapp/db'), 'default');
    assert.equal(await decryptOf(cache, 'missing'), 0);
    assert.equal(await cache.maxDecryptedLength('missing'), undefined);
    assert.deepEqual(vault.reads, ['myapp/db', 'missing', 'missing']);
  });

  it('aborts the provider\'s signal when the lookup waiting for the token is aborted', async () => {
    const vault = await startVault();
    const tokens = new FakeTokenProvider(true);
    tokens.hang = 'honour';
    const cache = create(vault, { tokens });
    const controller = new AbortController();
    const reason = new Error('the caller gave up');

    const lookup = cache.decrypt('item', new Uint8Array(16), controller.signal);
    await sleep(50);
    controller.abort(reason);

    await assert.rejects(lookup, (e: unknown) => e === reason);
    assert.ok(tokens.signalAborted);
    assert.deepEqual(vault.reads, []);
  });

  it('abandons the request, and doesn\'t retry it, when the lookup is aborted while Vault is answering', async () => {
    const vault = await startVault();
    const cache = create(vault);
    // Transient, so a read that wasn't abandoned would be retried once Vault answers.
    vault.answer = { status: 503, body: '{"errors":["Vault is sealed"]}' };
    const arrived = Promise.withResolvers<void>();
    vault.onRead = async () => {
      arrived.resolve();
      await vault.stopping(1000);
    };
    const controller = new AbortController();
    const reason = new Error('the caller gave up');

    const lookup = cache.decrypt('item', new Uint8Array(16), controller.signal);
    await arrived.promise;
    controller.abort(reason);

    await assert.rejects(lookup, (e: unknown) => e === reason);
    await sleep(300);
    assert.equal(vault.reads.length, 1);
  });

  it('reads a configurable default key', async () => {
    const vault = await startVault();
    const cache = create(vault, { defaultKey: 'secret_value' });
    vault.setData('item', { value: 'wrong', secret_value: 'right' });

    assert.equal(await decryptString(cache, 'item'), 'right');
  });

  it('reads KV version 1 at the mount\'s own path', async () => {
    const v1 = await startVault('kv', VaultKvVersion.v1);
    const cache = create(v1, { kvVersion: VaultKvVersion.v1, mountPath: 'kv' });
    v1.setData('myapp/db', { password: 'v1 value' });

    assert.equal(await decryptString(cache, 'myapp/db#password'), 'v1 value');
    assert.equal(await decryptOf(cache, 'missing'), 0);
    assert.deepEqual(v1.unexpectedRequests, []);
  });

  it('keeps a nested mount path and an address prefix', async () => {
    const prefixed = await startVault('kv/team-a', VaultKvVersion.v2, '/vault');
    const cache = create(prefixed, { mountPath: 'kv/team-a' });
    prefixed.set('item', 'prefixed');

    assert.equal(await decryptString(cache, 'item'), 'prefixed');
    assert.deepEqual(prefixed.unexpectedRequests, []);
  });

  it('reads the same at an address without a trailing slash, or given as a URL', async () => {
    const prefixed = await startVault('secret', VaultKvVersion.v2, '/vault');
    prefixed.set('item', 'prefixed');

    assert.equal(await decryptString(create(prefixed, { address: prefixed.address.slice(0, -1) }), 'item'), 'prefixed');
    const ring = makeRing();
    const protector = ring.createProtector(TOKEN_PURPOSE);
    const fromUrl = new HashiCorpVaultSecretCache(new URL(prefixed.address), StaticVaultToken.protect(protector, FakeVault.TOKEN), protector, ring);
    cleanups.push(() => fromUrl.close());
    assert.equal(await decryptString(fromUrl, 'item'), 'prefixed');
    assert.deepEqual(prefixed.unexpectedRequests, []);
  });

  it('sends the namespace only when one is set', async () => {
    const vault = await startVault();
    const withNamespace = create(vault, { namespace: 'team-a/prod' });
    const without = create(vault);
    vault.set('item', 'value');

    await decryptString(withNamespace, 'item');
    await decryptString(without, 'item');

    assert.deepEqual(vault.namespaces, ['team-a/prod', '(none)']);
  });

  it('reads over localhost too', async () => {
    const vault = await startVault();
    const cache = create(vault, { address: `http://localhost:${vault.port}` });
    vault.set('item', 'value');

    assert.equal(await decryptString(cache, 'item'), 'value');
  });
});

// --- The token ---------------------------------------------------------------------------------

describe('HashiCorpVaultSecretCache: the token', () => {
  it('asks the provider for the token on every fetch', async () => {
    const vault = await startVault();
    const tokens = new FakeTokenProvider();
    const cache = create(vault, { tokens });
    vault.set('a', '1');
    vault.set('b', '2');

    await decryptString(cache, 'a');
    await decryptString(cache, 'a');
    await decryptString(cache, 'b');

    assert.equal(tokens.calls, 2);
    assert.deepEqual(vault.tokens, [FakeVault.TOKEN, FakeVault.TOKEN]);
  });

  it('rejects a refused token with 403, and uses a new token next time', async () => {
    const vault = await startVault();
    const tokens = new FakeTokenProvider();
    tokens.next = (call) => (call === 1 ? 'hvs.expired' : FakeVault.TOKEN);
    const cache = create(vault, { tokens });
    vault.set('item', 'value');

    await assert.rejects(decryptOf(cache, 'item'), (e: unknown) => {
      assert.ok(isStatus(403)(e));
      assert.ok((e as Error).message.includes('permission denied'));
      assert.ok(!(e as Error).message.includes('hvs.'));
      assert.equal((e as VaultRequestError).code, 'ERR_HKDFGUARD_VAULT_REQUEST');
      return true;
    });

    assert.equal(await decryptString(cache, 'item'), 'value');
    assert.equal(vault.reads.length, 2);
  });

  for (const token of ['has space', 'tab\tinside', 'café', 'line\nbreak']) {
    it(`refuses a token that can't be sent (${JSON.stringify(token)}) without calling Vault`, async () => {
      const vault = await startVault();
      const cache = create(vault, { tokens: FakeTokenProvider.giving(token) });

      await assert.rejects(decryptOf(cache, 'item'), (e: unknown) => e instanceof HkdfGuardError && e.code === 'ERR_HKDFGUARD_INVALID_VAULT_TOKEN'
        && !e.message.includes(token));
      assert.deepEqual(vault.reads, []);
    });
  }

  for (const handedOver of [FakeVault.TOKEN, 'enc::v1::not base64!', 'enc::v1', 'enc::v1::AAAA', 'garbage']) {
    it(`refuses an unprotected token (${JSON.stringify(handedOver)}) without calling Vault, quoting or chaining nothing`, async () => {
      const vault = await startVault();
      const tokens = new FakeTokenProvider(true);
      tokens.next = () => handedOver;
      const cache = create(vault, { tokens });

      await assert.rejects(decryptOf(cache, 'item'), (e: unknown) => {
        assert.ok(e instanceof HkdfGuardError);
        assert.equal(e.code, 'ERR_HKDFGUARD_INVALID_VAULT_TOKEN');
        assert.equal(e.cause, undefined);
        assert.ok(!e.message.includes(handedOver));
        return true;
      });
      assert.deepEqual(vault.reads, []);
    });
  }

  for (const handedOver of [undefined, null, 42, '']) {
    it(`refuses a provider returning no token (${String(handedOver)}) without calling Vault`, async () => {
      const vault = await startVault();
      const tokens = new FakeTokenProvider(true);
      tokens.next = () => handedOver;
      const cache = create(vault, { tokens });

      await assert.rejects(decryptOf(cache, 'item'), (e: unknown) => e instanceof HkdfGuardError && /no token/.test(e.message));
      await assert.rejects(cache.maxDecryptedLength('item'), (e: unknown) => e instanceof HkdfGuardError && /no token/.test(e.message));
      assert.deepEqual(vault.reads, []);
    });
  }

  const foreignProtectors: [string, (ring: KeyRing) => DataProtector][] = [
    ['another purpose', (ring) => ring.createProtector('Some.Other.Purpose')],
    ['another ring', () => makeRing().createProtector(TOKEN_PURPOSE)],
    ['a version not on the ring', () => makeRing(7).createProtector(TOKEN_PURPOSE)],
  ];
  for (const [how, foreign] of foreignProtectors) {
    it(`refuses a token protected with ${how} without calling Vault`, async () => {
      const vault = await startVault();
      const ring = makeRing();
      const protector = ring.createProtector(TOKEN_PURPOSE);
      const cache = new HashiCorpVaultSecretCache(vault.address, new StaticVaultToken(foreign(ring).encrypt(FakeVault.TOKEN)), protector, ring);
      cleanups.push(() => cache.close());

      await assert.rejects(decryptOf(cache, 'item'), (e: unknown) => e instanceof HkdfGuardError
        && e.code === 'ERR_HKDFGUARD_INVALID_VAULT_TOKEN' && e.cause === undefined);
      assert.deepEqual(vault.reads, []);
    });
  }

  it('decrypts the token for each request, and it reaches Vault intact', async () => {
    const vault = await startVault();
    const cache = create(vault);
    vault.set('a', '1');
    vault.set('b', '2');

    assert.equal(await decryptString(cache, 'a'), '1');
    assert.equal(await decryptString(cache, 'b'), '2');

    assert.deepEqual(vault.tokens, [FakeVault.TOKEN, FakeVault.TOKEN]);
  });

  it('sends a long token whole', async () => {
    const vault = await startVault();
    const longToken = `hvs.${'x'.repeat(2000)}`;
    const cache = create(vault, { tokens: FakeTokenProvider.giving(longToken) });

    // Not the fake's token, so Vault refuses it - after receiving it intact.
    await assert.rejects(decryptOf(cache, 'item'), VaultRequestError);

    assert.deepEqual(vault.tokens, [longToken]);
  });

  it('propagates a token provider\'s failure as it is, and doesn\'t retry it', async () => {
    const vault = await startVault();
    const tokens = new FakeTokenProvider();
    const failure = new Error('The login endpoint is unreachable.');
    tokens.next = () => { throw failure; };
    const cache = create(vault, { tokens });

    await assert.rejects(decryptOf(cache, 'item'), (e: unknown) => e === failure);
    assert.equal(tokens.calls, 1);
    await assert.rejects(cache.maxDecryptedLength('item'), (e: unknown) => e === failure);
    assert.equal(tokens.calls, 2);
    assert.deepEqual(vault.reads, []);
  });

  it('propagates a synchronous provider\'s throw, and accepts its synchronous token', async () => {
    const vault = await startVault();
    vault.set('item', 'value');
    const ring = makeRing();
    const protector = ring.createProtector(TOKEN_PURPOSE);
    const failure = Object.assign(new Error("The token file can't be read."), { code: 'ENOENT' });
    let fail = true;
    const tokens: VaultTokenProvider = {
      getToken: () => {
        if (fail) throw failure;
        return protector.encrypt(FakeVault.TOKEN);
      },
    };
    const cache = new HashiCorpVaultSecretCache(vault.address, tokens, protector, ring, { retryDelayMs: 0 });
    cleanups.push(() => cache.close());

    await assert.rejects(decryptOf(cache, 'item'), (e: unknown) => e === failure);
    assert.deepEqual(vault.reads, []);
    fail = false;
    assert.equal(await decryptString(cache, 'item'), 'value');
  });

  for (const hang of ['honour', 'ignore'] as const) {
    it(`times out a provider slower than the timeout (one that ${hang}s its signal)`, async () => {
      const vault = await startVault();
      const tokens = new FakeTokenProvider(true);
      tokens.hang = hang;
      const cache = create(vault, { tokens, timeoutMs: 100 });

      await assert.rejects(decryptOf(cache, 'item'), (e: unknown) => isTimeout(e) && /no token within 100 ms/.test((e as Error).message));
      assert.equal(tokens.signalAborted, hang === 'honour');
      assert.deepEqual(vault.reads, []);
    });
  }
});

// --- Retries -----------------------------------------------------------------------------------

describe('HashiCorpVaultSecretCache: retries', () => {
  const transientAnswers: Answer[] = [
    { status: 503, body: '{"errors":["Vault is sealed"]}' },
    { status: 429, body: '{"errors":["request path \\"secret/data/item\\": rate limit quota exceeded"]}' },
    { status: 500, body: '{"errors":["internal error"]}' },
    { status: 502, body: '<html>Bad Gateway</html>' },
    { status: 504, body: '' },
  ];
  for (const answer of transientAnswers) {
    it(`retries ${answer.status} until Vault answers`, async () => {
      const vault = await startVault();
      const tokens = new FakeTokenProvider();
      const cache = create(vault, { tokens });
      vault.set('item', 'value');
      vault.answer = answer;
      vault.onRead = () => {
        if (vault.reads.length === 3) vault.answer = undefined;
      };

      assert.equal(await decryptString(cache, 'item'), 'value');

      assert.equal(vault.reads.length, 3);
      assert.equal(tokens.calls, 1);
    });
  }

  for (const retryCount of [Limits.MIN_RETRY_COUNT, Limits.MAX_RETRY_COUNT]) {
    it(`retries a transient answer ${retryCount} times, then rejects with it`, async () => {
      const vault = await startVault();
      const cache = create(vault, { retryCount });
      vault.answer = { status: 503, body: '{"errors":["Vault is sealed"]}' };

      await assert.rejects(decryptOf(cache, 'item'), (e: unknown) => isStatus(503)(e) && (e as VaultRequestError).isTransient);
      assert.equal(vault.reads.length, 1 + retryCount);
    });
  }

  const finalAnswers: Answer[] = [
    { status: 403, body: '{"errors":["permission denied"]}' },
    { status: 404, body: '{"errors":["no handler for route"]}' },
    { status: 400, body: '{"errors":["bad request"]}' },
    { status: 501, body: '{"errors":["unsupported operation"]}' },
    { status: 307, body: '' },
  ];
  for (const answer of finalAnswers) {
    it(`doesn't retry ${answer.status}, which would be answered the same`, async () => {
      const vault = await startVault();
      const cache = create(vault);
      vault.answer = answer;

      await assert.rejects(decryptOf(cache, 'item'), (e: unknown) => isStatus(answer.status)(e) && !(e as VaultRequestError).isTransient);
      assert.equal(vault.reads.length, 1);
    });
  }

  const losses: [string, OnRead][] = [
    ['no answer', (request) => { request.socket.destroy(); return true; }],
    ['dropped mid-response', (_request, response) => {
      response.writeHead(200, { 'Content-Length': 200 });
      response.write('{"data":{"data":{"value":"val', () => response.socket?.destroy());
      return true;
    }],
  ];
  for (const [how, lose] of losses) {
    it(`retries a lost connection (${how})`, async () => {
      const vault = await startVault();
      const cache = create(vault, { timeoutMs: 1000 });
      vault.set('item', 'value');
      vault.onRead = (request, response) => (vault.reads.length > 2 ? false : lose(request, response));

      assert.equal(await decryptString(cache, 'item'), 'value');
      assert.equal(vault.reads.length, 3);
    });
  }

  it('retries an attempt that timed out', async () => {
    const vault = await startVault();
    const cache = create(vault, { timeoutMs: 300 });
    vault.set('item', 'value');
    vault.onRead = async () => {
      if (vault.reads.length <= 2) await vault.stopping(1000);
    };

    assert.equal(await decryptString(cache, 'item'), 'value');
    assert.equal(vault.reads.length, 3);
  });

  it('times out a body that stalls within the attempt\'s timeout, and retries it', async () => {
    const vault = await startVault();
    const cache = create(vault, { timeoutMs: 300 });
    vault.onRead = async (_request, response) => {
      response.writeHead(200);
      response.write('{"data":{"data":{"value":"val');
      await vault.stopping(5000);
      response.socket?.destroy();
      return true;
    };

    const started = performance.now();
    await assert.rejects(decryptOf(cache, 'item'), (e: unknown) => isTimeout(e) && /took longer than 300 ms/.test((e as Error).message)
      && (e as Error).message.includes("'item'"));
    const elapsed = performance.now() - started;

    assert.equal(vault.reads.length, 1 + Limits.MIN_RETRY_COUNT);
    // Four attempts of 300 ms and three waits of at most 100 ms, far short of one stalled body.
    assert.ok(elapsed < 4000, `${elapsed} ms`);
  });

  it('retries an unreachable Vault, then rejects with Node\'s network error', async () => {
    const cache = create(undefined, { address: `http://127.0.0.1:${await freePort()}/` });

    await assert.rejects(decryptOf(cache, 'item'), (e: unknown) => (e as { code?: string }).code === 'ECONNREFUSED');
  });

  it('stops waiting to retry when the lookup is aborted', async () => {
    const vault = await startVault();
    const cache = create(vault, { retryDelayMs: Limits.MAX_RETRY_DELAY_MS });
    vault.answer = { status: 503, body: '{"errors":["Vault is sealed"]}' };
    const controller = new AbortController();
    const reason = new Error('the caller gave up');

    const lookup = cache.decrypt('item', new Uint8Array(16), controller.signal);
    await sleep(200);
    controller.abort(reason);

    await assert.rejects(lookup, (e: unknown) => e === reason);
    assert.equal(vault.reads.length, 1);
  });

  const delays: [number, number, number, number][] = [
    [200, 0, 0, 200], [200, 1, 0, 400], [200, 2, 0, 800], [200, 5, 0, 6400], [200, 6, 0, 10_000], [200, 9, 0, 10_000],
    [200, 0, 100, 300], [200, 9, 100, 10_100], [0, 3, 37, 37], [10_000, 0, 0, 10_000], [10_000, 40, 0, 10_000],
  ];
  it('doubles the retry delay up to the maximum, plus the jitter', () => {
    for (const [base, retry, jitter, expected] of delays) {
      assert.equal(retryDelay(base, retry, jitter), expected, `${base} ms, retry ${retry}, jitter ${jitter}`);
    }
  });

  it('checks the retry options', () => {
    for (const invalid of [{ retryCount: Limits.MIN_RETRY_COUNT - 1 }, { retryCount: Limits.MAX_RETRY_COUNT + 1 }, { retryCount: 3.5 },
      { retryDelayMs: -1 }, { retryDelayMs: Limits.MAX_RETRY_DELAY_MS + 1 }, { retryDelayMs: Number.NaN }]) {
      assert.throws(() => newCache(undefined, invalid), (e: unknown) => e instanceof InvalidArgumentError && /retry/.test(e.message), JSON.stringify(invalid));
    }

    newCache(undefined, { retryCount: Limits.MIN_RETRY_COUNT, retryDelayMs: 0 });
    newCache(undefined, { retryCount: Limits.MAX_RETRY_COUNT, retryDelayMs: Limits.MAX_RETRY_DELAY_MS });
  });
});

// --- What Vault answers ------------------------------------------------------------------------

describe('HashiCorpVaultSecretCache: what Vault answers', () => {
  it('unescapes a value with JSON escapes exactly', async () => {
    const vault = await startVault();
    const cache = create(vault);
    const secret = 'p"a\\ss/wörd\n\u0001秘密';
    vault.set('escaped', secret);

    assert.equal(await decryptString(cache, 'escaped'), secret);
  });

  it('round-trips a large secret', async () => {
    const vault = await startVault();
    const cache = create(vault);
    const large = 'é-秘密-'.repeat(1500);
    vault.set('large', large);

    const maximum = await cache.maxDecryptedLength('large');
    assert.ok(maximum !== undefined);
    assert.equal(await decryptString(cache, 'large', maximum), large);
  });

  it('treats paths differing only in case as different secrets and different entries', async () => {
    const vault = await startVault();
    const cache = create(vault);
    vault.set('myapp/Db', 'upper');
    vault.set('myapp/db', 'lower');

    assert.equal(await decryptString(cache, 'myapp/Db'), 'upper');
    assert.equal(await decryptString(cache, 'myapp/db'), 'lower');
    assert.equal(await decryptOf(cache, 'MYAPP/DB'), 0);
    assert.equal(await decryptString(cache, 'myapp/Db'), 'upper');

    assert.deepEqual(vault.reads, ['myapp/Db', 'myapp/db', 'MYAPP/DB']);
  });

  it('reports a missing secret as 0, and looks it up again until it exists', async () => {
    const vault = await startVault();
    const cache = create(vault);

    assert.equal(await decryptOf(cache, 'later'), 0);
    assert.equal(await cache.maxDecryptedLength('later'), undefined);

    vault.set('later', 'now here');
    assert.equal(await decryptString(cache, 'later'), 'now here');
    assert.equal(vault.reads.length, 3);
  });

  it('reports a deleted latest version as missing', async () => {
    const vault = await startVault();
    const cache = create(vault);
    vault.setDeleted('gone');

    assert.equal(await decryptOf(cache, 'gone'), 0);
  });

  it('caches numbers and booleans as their text, and reports other values missing', async () => {
    const vault = await startVault();
    const cache = create(vault);
    vault.setData('item', { number: 5432, flag: true, empty: '', object: { value: 'nested' }, array: ['x'], null: null });

    assert.equal(await decryptString(cache, 'item#number'), '5432');
    assert.equal(await decryptString(cache, 'item#flag'), 'true');
    for (const key of ['absent', 'empty', 'object', 'array', 'null', 'value']) {
      assert.equal(await decryptOf(cache, `item#${key}`), 0, key);
    }
  });

  for (const body of ['not json', '["value"]', '{"data":{"data":{"value":"a","value":"b"}}}', '{"data":{"data":{"k":"a","k":"b"}}}', '']) {
    it(`refuses a response that can't be trusted (${JSON.stringify(body)}), and doesn't retry it`, async () => {
      const vault = await startVault();
      const cache = create(vault);
      vault.answer = { status: 200, body };

      await assert.rejects(decryptOf(cache, 'item#k'), InvalidSecretDataError);
      assert.equal(vault.reads.length, 1);
    });
  }

  const otherAnswers: [Answer, string][] = [
    [{ status: 404, body: '{"errors":["no handler for route \\"nope/data/item\\". route entry not found."]}' }, 'no handler for route'],
    [{ status: 404, body: '<html>Not Found</html>' }, 'HTTP 404'],
    [{ status: 503, body: '{"errors":["Vault is sealed"]}' }, 'Vault is sealed'],
    [{ status: 500, body: '["internal"]' }, 'HTTP 500'],
    [{ status: 500, body: '{"errors":"internal"}' }, 'HTTP 500'],
    [{ status: 307, body: '' }, 'HTTP 307'],
    [{ status: 502, body: '{"request_id":"x"}' }, 'HTTP 502'],
    [{ status: 403, body: '{"errors":["permission denied","2 errors occurred"]}' }, 'permission denied; 2 errors occurred'],
  ];
  for (const [answer, expected] of otherAnswers) {
    it(`rejects ${answer.status} ${JSON.stringify(answer.body)} with Vault's status and errors`, async () => {
      const vault = await startVault();
      const cache = create(vault);
      vault.answer = answer;

      await assert.rejects(decryptOf(cache, 'item'), (e: unknown) => {
        assert.ok(isStatus(answer.status)(e));
        const message = (e as Error).message;
        assert.ok(message.includes(expected), message);
        assert.ok(message.includes("'item'"), message);
        assert.ok(!message.includes(FakeVault.TOKEN));
        return true;
      });

      vault.answer = undefined;
      vault.set('item', 'value');
      assert.equal(await decryptString(cache, 'item'), 'value');
    });
  }

  it('doesn\'t follow a redirect', async () => {
    const vault = await startVault();
    const cache = create(vault);
    vault.set('elsewhere', 'value');
    vault.answer = { status: 307, body: '', headers: { Location: vault.readUrl('elsewhere') } };

    await assert.rejects(decryptOf(cache, 'item'), isStatus(307));
    assert.deepEqual(vault.reads, ['item']);
  });

  it('refuses a body of a megabyte or more, and doesn\'t retry it', async () => {
    const vault = await startVault();
    const cache = create(vault);
    vault.set('huge', 'x'.repeat(1024 * 1024));

    await assert.rejects(decryptOf(cache, 'huge'), InvalidSecretDataError);
    assert.equal(vault.reads.length, 1);
  });

  it('reads a body served in many chunks', async () => {
    const vault = await startVault();
    const cache = create(vault);
    const value = 'chunked-秘密-'.repeat(200);
    vault.onRead = async (_request, response) => {
      const body = Buffer.from(envelope({ data: { value }, metadata: metadata(false) }, 0));
      response.writeHead(200, { 'Content-Type': 'application/json' });
      for (let offset = 0; offset < body.length; offset += 97) {
        response.write(body.subarray(offset, offset + 97));
        await sleep(0);
      }
      response.end();
      return true;
    };

    assert.equal(await decryptString(cache, 'item', 8192), value);
  });
});

// --- Names -------------------------------------------------------------------------------------

describe('HashiCorpVaultSecretCache: names', () => {
  const invalidNames = [
    '', 'ConnectionStrings:Admin', '../sys/seal-status', 'myapp/../other', 'myapp/./db', '..', '/leading', 'trailing/',
    'double//slash', 'has space', 'café', 'bang!', 'query?list=true', 'percent%2F', 'item#', '#key', 'item#a#b', 'item#a b',
    'item#bang!', '\ud800', 'x'.repeat(HashiCorpVaultSecretCache.MAX_SECRET_NAME_LENGTH + 1),
  ];
  for (const name of invalidNames) {
    it(`reports a name that isn't a path and key (${JSON.stringify(name.length > 40 ? `${name.slice(0, 20)}...` : name)}) missing without calling Vault`,
      async () => {
        const vault = await startVault();
        const cache = create(vault);

        assert.equal(await decryptOf(cache, name), 0);
        assert.equal(await cache.maxDecryptedLength(name), undefined);
        assert.deepEqual(vault.reads, []);
        assert.deepEqual(vault.unexpectedRequests, []);
      });
  }

  it('isValidSecretName accepts paths up to the limit', () => {
    const limit = HashiCorpVaultSecretCache.MAX_SECRET_NAME_LENGTH;
    assert.ok(HashiCorpVaultSecretCache.isValidSecretName('a'));
    assert.ok(HashiCorpVaultSecretCache.isValidSecretName('team-a/my_app/db.v2'));
    assert.ok(HashiCorpVaultSecretCache.isValidSecretName('...x/x..'));
    assert.ok(!HashiCorpVaultSecretCache.isValidSecretName('myapp/db#password'));
    assert.ok(HashiCorpVaultSecretCache.isValidSecretName('x'.repeat(limit)));
    assert.ok(!HashiCorpVaultSecretCache.isValidSecretName('x'.repeat(limit + 1)));
    assert.ok(!HashiCorpVaultSecretCache.isValidSecretName('ünïcode'));
    assert.ok(!HashiCorpVaultSecretCache.isValidSecretName(undefined));
    assert.ok(!HashiCorpVaultSecretCache.isValidSecretName(null));
  });

  it('rejects a name that isn\'t a string', async () => {
    const cache = newCache();
    await assert.rejects(cache.decrypt(42 as unknown as string, new Uint8Array(16)), TypeError);
  });
});

// --- The cache ---------------------------------------------------------------------------------

describe('HashiCorpVaultSecretCache: the cache', () => {
  it('still decrypts a cached secret after the ring rotates', async () => {
    const vault = await startVault();
    const ring = makeRing();
    const cache = create(vault, { ring });
    vault.set('before', 'v1 value');
    vault.set('after', 'v2 value');

    assert.equal(await decryptString(cache, 'before'), 'v1 value');
    ring.add(2, new RecordingKey());

    assert.equal(await decryptString(cache, 'after'), 'v2 value');
    assert.equal(await decryptString(cache, 'before'), 'v1 value');
    // The token, protected under version 1 and decrypted per request, still reads.
    vault.set('later', 'still read');
    assert.equal(await decryptString(cache, 'later'), 'still read');
  });

  it('in a collection, reads only the names the earlier sources miss', async () => {
    const vault = await startVault();
    const vaultCache = create(vault);
    vault.set('from-vault', 'vault value');
    const local = new ProtectedCache(makeRing());
    local.add('ConnectionStrings:Admin', new TextEncoder().encode('local value'));
    const collection = new ProtectedCacheCollection().add(local).add(vaultCache);

    assert.equal(await decryptString(collection, 'ConnectionStrings:Admin'), 'local value');
    assert.equal(await decryptString(collection, 'from-vault'), 'vault value');
    assert.deepEqual(vault.reads, ['from-vault']);
  });

  it('logs, with sensitive logging, the name of each fetch only, and every failure as an error', async () => {
    const restore = withSensitiveLogging();
    try {
      const vault = await startVault();
      const { logger, entries, withEventId } = capturingLogger();
      const cache = create(vault, { logger: logger as Logger });
      vault.set('myapp/Item', 'never-logged');

      assert.equal(await decryptString(cache, 'myapp/Item'), 'never-logged');
      vault.answer = { status: 503, body: '{"errors":["Vault is sealed"]}' };
      await assert.rejects(decryptOf(cache, 'other'), VaultRequestError);

      // The secret's own name, not its escaped entry name.
      assert.ok(withEventId(1).some((e) => e.level === 'debug' && e.message.includes('myapp/Item')));
      const failures = withEventId(2);
      assert.equal(failures.length, 1);
      assert.equal(failures[0]!.level, 'error');
      assert.ok(failures[0]!.attributes.error instanceof VaultRequestError);
      const logged = JSON.stringify(entries.map((e) => [e.message, String(e.attributes.error)]));
      assert.ok(!logged.includes('never-logged') && !logged.includes(FakeVault.TOKEN));
    } finally {
      restore();
    }
  });

  it('makes each fetch a populate span, counted, with the token and the secret nowhere in it', async () => {
    const restore = withSensitiveLogging();
    const spans = useSpanRecorder();
    const metrics = useMetricRecorder();
    try {
      const vault = await startVault();
      const cache = create(vault);
      vault.set('found', 'never-traced');
      assert.equal(await decryptString(cache, 'found'), 'never-traced');
      assert.equal(await decryptOf(cache, 'missing'), 0);
      vault.answer = { status: 403, body: '{"errors":["permission denied"]}' };
      await assert.rejects(decryptOf(cache, 'refused'), VaultRequestError);

      const [found, notFound, failed, ...rest] = spans.spans().filter((s) => s.name === SpanNames.cache.populate);
      assert.equal(rest.length, 0);
      assert.ok(found?.events.some((e) => e.attributes?.[AttributeNames.name] === 'found'));
      assert.notEqual(found?.status.code, SpanStatusCode.ERROR);
      assert.notEqual(notFound?.status.code, SpanStatusCode.ERROR);
      assert.equal(failed?.status.code, SpanStatusCode.ERROR);
      const everything = JSON.stringify(spans.spans().map((s) => [s.attributes, s.events.map((e) => [e.name, e.attributes]), s.status]));
      assert.ok(!everything.includes(FakeVault.TOKEN) && !everything.includes('never-traced'));

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

  it('quotes the token in no failure', async () => {
    const vault = await startVault();
    const failures: unknown[] = [];
    for (const status of [403, 404, 503]) {
      vault.answer = { status, body: JSON.stringify({ errors: ['denied'] }) };
      await decryptOf(create(vault), 'item').catch((e: unknown) => failures.push(e));
    }
    await decryptOf(create(undefined, { address: `http://127.0.0.1:${await freePort()}/` }), 'item').catch((e: unknown) => failures.push(e));
    await decryptOf(create(vault, { tokens: FakeTokenProvider.giving('hvs.bad token') }), 'item').catch((e: unknown) => failures.push(e));

    assert.equal(failures.length, 5);
    for (const failure of failures) {
      for (const linked of chain(failure)) {
        const error = linked as Error;
        assert.ok(!`${error.message} ${error.stack} ${JSON.stringify(error)}`.includes(FakeVault.TOKEN));
      }
    }
  });

  it('after close, serves cached secrets but reads nothing', async () => {
    const vault = await startVault();
    const cache = create(vault);
    vault.set('item', 'value');
    vault.set('other', 'value');
    assert.equal(await decryptString(cache, 'item'), 'value');

    cache.close();
    cache.close();

    assert.equal(await decryptString(cache, 'item'), 'value');
    await assert.rejects(decryptOf(cache, 'other'), ClosedError);
    await assert.rejects(cache.maxDecryptedLength('other'), ClosedError);
    assert.deepEqual(vault.reads, ['item']);
  });

  it('closing stops a fetch that is waiting to retry from retrying', async () => {
    const vault = await startVault();
    const cache = create(vault, { retryDelayMs: 300 });
    vault.answer = { status: 503, body: '{"errors":["Vault is sealed"]}' };

    const lookup = decryptOf(cache, 'item');
    await sleep(100);
    cache.close();

    await assert.rejects(lookup, (e: unknown) => e instanceof ClosedError || isStatus(503)(e));
    assert.equal(vault.reads.length, 1);
  });
});

// --- Construction ------------------------------------------------------------------------------

describe('HashiCorpVaultSecretCache: construction', () => {
  it('makes no call until a secret is requested', async () => {
    const cache = newCache();

    assert.equal(await decryptOf(cache, 'not:a:path'), 0);
  });

  it('reads Vault\'s own defaults: KV version 2 at secret, the key value', async () => {
    const vault = await startVault();
    vault.setData('item', { value: 'the value', other: 'other' });
    const ring = makeRing();
    const protector = ring.createProtector(TOKEN_PURPOSE);
    const cache = new HashiCorpVaultSecretCache(vault.address, StaticVaultToken.protect(protector, FakeVault.TOKEN), protector, ring);
    cleanups.push(() => cache.close());

    assert.equal(await decryptString(cache, 'item'), 'the value');
    assert.deepEqual(vault.namespaces, ['(none)']);
    assert.deepEqual(vault.unexpectedRequests, []);
  });

  it('has the limits of .NET\'s and Python\'s options', () => {
    assert.equal(Limits.MIN_RETRY_COUNT, 3);
    assert.equal(Limits.MAX_RETRY_COUNT, 10);
    assert.equal(Limits.MAX_RETRY_DELAY_MS, 10_000);
    assert.equal(VaultKvVersion.v1, 1);
    assert.equal(VaultKvVersion.v2, 2);
  });

  for (const address of ['http://localhost:8200', 'http://LOCALHOST', 'http://127.0.0.1:8200', 'http://127.1.2.3', 'http://[::1]:8200',
    'https://vault.example.com:8200', 'HTTPS://vault.example.com/prefix/', 'https://[2001:db8::1]:8200']) {
    it(`accepts ${address}: https, or http only on loopback`, () => {
      newCache(address);
    });
  }

  for (const address of ['relative/path', 'vault.test:8200', 'http://vault.example.com:8200', 'http://10.0.0.1:8200', 'http://[::2]',
    'http://127.0.0.1.example.com', 'http://localhost.example.com', 'ftp://127.0.0.1', 'https://user:pass@vault.example.com',
    'https://user@vault.example.com', 'https://vault.example.com/?x=1', 'https://vault.example.com/?', 'https://vault.example.com/#frag',
    'https:///no-host', 'https:\\\\vault.example.com', '']) {
    it(`rejects ${JSON.stringify(address)}, which would expose the token`, () => {
      assert.throws(() => newCache(address), (e: unknown) => e instanceof InvalidArgumentError
        && e.code === 'ERR_HKDFGUARD_INVALID_VAULT_ADDRESS' && /address/.test(e.message));
    });
  }

  it('rejects a missing argument', async () => {
    const vault = await startVault();
    const ring = makeRing();
    const protector = ring.createProtector(TOKEN_PURPOSE);
    const token = StaticVaultToken.protect(protector, FakeVault.TOKEN);
    const none = undefined as never;

    assert.throws(() => new HashiCorpVaultSecretCache(none, token, protector, ring), TypeError);
    assert.throws(() => new HashiCorpVaultSecretCache(42 as never, token, protector, ring), TypeError);
    assert.throws(() => new HashiCorpVaultSecretCache(vault.address, none, protector, ring), TypeError);
    assert.throws(() => new HashiCorpVaultSecretCache(vault.address, {} as never, protector, ring), TypeError);
    assert.throws(() => new HashiCorpVaultSecretCache(vault.address, token, none, ring), TypeError);
    assert.throws(() => new HashiCorpVaultSecretCache(vault.address, token, protector, none), TypeError);
    assert.throws(() => new HashiCorpVaultSecretCache(vault.address, token, protector, ring, null as never), TypeError);
    assert.throws(() => new HashiCorpVaultSecretCache(vault.address, token, protector, ring, 'options' as never), TypeError);
  });

  const invalidValues: HashiCorpVaultSecretCacheOptions[] = [
    { mountPath: '' }, { mountPath: '../sys' }, { mountPath: 'kv/' }, { defaultKey: '' }, { defaultKey: 'a b' }, { defaultKey: 'a#b' },
    { defaultKey: 'bang!' }, { namespace: 'team a' }, { namespace: '' }, { kvVersion: 3 as VaultKvVersion }, { timeoutMs: 0 },
    { timeoutMs: -1 }, { timeoutMs: Number.NaN }, { timeoutMs: Limits.MAX_TIMEOUT_MS + 1 },
  ];
  for (const invalid of invalidValues) {
    it(`rejects the option ${JSON.stringify(invalid)}`, () => {
      assert.throws(() => newCache(undefined, invalid), InvalidArgumentError);
    });
  }

  const wrongTypes = [
    { mountPath: 42 }, { defaultKey: null }, { namespace: 7 }, { kvVersion: 'v2' }, { timeoutMs: '30' }, { retryCount: '3' },
    { retryDelayMs: null }, { namespace: null }, { mountPath: null }, { agent: 'tls' },
  ] as unknown as HashiCorpVaultSecretCacheOptions[];
  for (const wrong of wrongTypes) {
    it(`rejects the option ${JSON.stringify(wrong)} of the wrong type`, () => {
      assert.throws(() => newCache(undefined, wrong), TypeError);
    });
  }

  it('sends every https request through the agent given', async () => {
    const vault = await startVault();
    const connections: string[] = [];
    class RecordingAgent extends HttpsAgent {
      override createConnection(options: { host?: string; servername?: string }, callback?: unknown): Socket {
        connections.push(options.host ?? '');
        return (HttpsAgent.prototype as unknown as { createConnection: (o: unknown, c: unknown) => Socket }).createConnection.call(this, options, callback);
      }
    }
    const agent = new RecordingAgent();
    cleanups.push(() => agent.destroy());
    // The fake speaks plain http, so the handshake fails - after the agent was asked to make it.
    const cache = create(vault, { address: `https://127.0.0.1:${vault.port}/`, agent });

    await assert.rejects(decryptOf(cache, 'item'));

    assert.deepEqual(connections, Array(1 + Limits.MIN_RETRY_COUNT).fill('127.0.0.1'));
  });
});

// --- StaticVaultToken --------------------------------------------------------------------------

describe('StaticVaultToken', () => {
  for (const token of ['', 'hvs.with space', 'hvs.line\nbreak', 'café', new Uint8Array(0), new Uint8Array([0x68, 0x20, 0x76])]) {
    it(`protect rejects a token that can't be sent (${JSON.stringify(typeof token === 'string' ? token : [...token])})`, () => {
      const protector = makeRing().createProtector(TOKEN_PURPOSE);

      assert.throws(() => StaticVaultToken.protect(protector, token), (e: unknown) => e instanceof InvalidArgumentError && /printable ASCII/.test(e.message));
    });
  }

  it('protect rejects a missing protector or token', () => {
    const protector = makeRing().createProtector(TOKEN_PURPOSE);
    const none = undefined as never;

    assert.throws(() => StaticVaultToken.protect(none, FakeVault.TOKEN), TypeError);
    assert.throws(() => StaticVaultToken.protect(protector, none), TypeError);
    assert.throws(() => StaticVaultToken.protect(protector, 42 as never), TypeError);
  });

  for (const protectedToken of ['', ' ', '\t\n']) {
    it(`rejects an empty protected token (${JSON.stringify(protectedToken)})`, () => {
      assert.throws(() => new StaticVaultToken(protectedToken), (e: unknown) => e instanceof InvalidArgumentError && /empty/.test(e.message));
    });
  }

  it('rejects a protected token that isn\'t a string', () => {
    assert.throws(() => new StaticVaultToken(undefined as never), TypeError);
    assert.throws(() => new StaticVaultToken(42 as never), TypeError);
  });

  it('protect holds only the protected token', async () => {
    const protector = makeRing().createProtector(TOKEN_PURPOSE);
    const held = await StaticVaultToken.protect(protector, FakeVault.TOKEN).getToken();

    assert.ok(!held.includes(FakeVault.TOKEN));
    const revealed = new Uint8Array(protector.maxDecryptedLength(held));
    assert.equal(new TextDecoder().decode(revealed.subarray(0, protector.decrypt(held, revealed))), FakeVault.TOKEN);
  });

  it('protect takes the token\'s bytes, and leaves them to their owner', async () => {
    const vault = await startVault();
    vault.set('item', 'value');
    const ring = makeRing();
    const protector = ring.createProtector(TOKEN_PURPOSE);
    const bytes = new TextEncoder().encode(FakeVault.TOKEN);

    const token = StaticVaultToken.protect(protector, bytes);
    assert.equal(new TextDecoder().decode(bytes), FakeVault.TOKEN);
    const cache = new HashiCorpVaultSecretCache(vault.address, token, protector, ring);
    cleanups.push(() => cache.close());

    assert.equal(await decryptString(cache, 'item'), 'value');
    assert.deepEqual(vault.tokens, [FakeVault.TOKEN]);
  });
});

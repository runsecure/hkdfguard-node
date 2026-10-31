import { strict as assert } from 'node:assert';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { ClientRequest, createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { Agent as HttpsAgent } from 'node:https';
import { createServer as createNetServer, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, it, type TestContext } from 'node:test';
import { ClosedError, HkdfGuardError, InvalidArgumentError, isZero, MAX_WRAPPED_KEY_BYTES, type KeyWrapper } from '@runsecure/hkdfguard-abstractions';
import { AesGcmCryptoProviderFactory } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { keyFileDirectory, windowsCurrentUserSid } from '@runsecure/hkdfguard-test-support';
import { decodeInto, encodedLength, encodeInto } from './base64.js';
import { HashiCorpVaultTransitError } from './errors.js';
import { KeyFileError, KeyFileTrust } from './index.js';
import { HashiCorpVaultTransitKeyWrapperOptions } from './options.js';
import { StaticVaultTokenSource, type VaultTokenSource } from './token.js';
import {
  GENERATED_KEY_LENGTH, HashiCorpVaultTransitKeyWrapper, isVaultCiphertext, MAX_CONTEXT_LENGTH, MAX_KEY_NAME_LENGTH, MAX_PLAINTEXT_LENGTH,
  MAX_RESPONSE_LENGTH, MAX_TOKEN_LENGTH, retryDelay,
} from './wrapper.js';

const CONTEXT = 'hkdfguard.test';
const CONTEXT_BASE64 = Buffer.from(CONTEXT).toString('base64');
const Limits = HashiCorpVaultTransitKeyWrapperOptions;
const isWindows = process.platform === 'win32';
const isUnix = process.platform === 'linux' || (process.platform === 'darwin' && process.arch === 'arm64');

// --- A fake transit engine ---------------------------------------------------------------------

/** An answer given as it is: a status, a body ('' for none) and any extra headers. */
interface Answer {
  status: number;
  body: string;
  headers?: Record<string, string>;
}

/** One transit request as it arrived: its operation, key, body bytes and headers. */
class TransitRequest {
  constructor(
    readonly operation: string,
    readonly key: string,
    readonly body: Buffer,
    readonly token: string,
    readonly namespace: string | undefined,
    readonly vaultRequest: string | undefined,
    readonly contentType: string | undefined,
  ) {}

  get json(): Record<string, unknown> {
    return JSON.parse(this.body.toString('utf8')) as Record<string, unknown>;
  }

  field(name: string): unknown {
    return this.json[name];
  }
}

/** Runs inside a request before it is answered; resolves to true if it has answered (or dropped) it itself. */
type OnRequest = (request: IncomingMessage, response: ServerResponse) => boolean | void | Promise<boolean | void>;

interface TransitKey {
  versions: Buffer[];
  minDecryptionVersion: number;
}

/**
 * A transit secrets engine behind Vault's HTTP API, served over plain http on 127.0.0.1 (which the
 * wrapper allows on loopback) and reached through the wrapper's real http client. A POST to
 * encrypt, decrypt or datakey/wrapped for a key it holds, with the expected token, is answered as
 * Vault 1.19 answers it: a ciphertext is "vault:v{n}:" and base64 of AES-GCM under that version of
 * the key, with associated_data as the AAD, so decrypt fails unless the key and the context both
 * match. Keys rotate (new versions encrypt; older ones decrypt while at or above
 * min_decryption_version). datakey/wrapped ignores associated_data and says so in its warnings, as
 * Vault does. A request without the token is refused with 403. Any other request is recorded in
 * unexpectedRequests and refused.
 */
class FakeTransit {
  static readonly TOKEN = 'hvs.CAESIFakeTokenForTests';
  static readonly KEY_NAME = 'myapp-kek';

  readonly keys = new Map<string, TransitKey>();
  readonly requests: TransitRequest[] = [];
  readonly unexpectedRequests: string[] = [];
  /** When set, answers a request with the right token in place of the engine, unless it returns undefined. */
  answer: ((request: TransitRequest, count: number) => Answer | undefined) | undefined;
  /** When set, runs inside every transit request before it answers. */
  onRequest: OnRequest | undefined;
  /** Answers as a Vault too old for associated_data would: ignoring it, with a warning. */
  ignoresAssociatedData = false;
  readonly #stopping = Promise.withResolvers<void>();
  readonly #server: Server;

  private constructor(readonly mountPath: string, readonly pathPrefix: string) {
    this.addKey(FakeTransit.KEY_NAME);
    this.#server = createServer((request, response) => {
      this.#handle(request, response).catch(() => response.socket?.destroy());
    });
  }

  static async start(mountPath = 'transit', pathPrefix = ''): Promise<FakeTransit> {
    const vault = new FakeTransit(mountPath, pathPrefix);
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

  url(path: string): string {
    return `http://127.0.0.1:${this.port}${this.pathPrefix}/v1/${this.mountPath}/${path}`;
  }

  addKey(name: string): void {
    this.keys.set(name, { versions: [randomBytes(32)], minDecryptionVersion: 1 });
  }

  /** transit/keys/{name}/rotate: a new latest version, which every encrypt uses from now on. */
  rotate(name: string): void {
    this.keys.get(name)!.versions.push(randomBytes(32));
  }

  /** transit/keys/{name}/config min_decryption_version. */
  setMinDecryptionVersion(name: string, version: number): void {
    this.keys.get(name)!.minDecryptionVersion = version;
  }

  /** Resolves on close, or after `ms`. */
  stopping(ms: number): Promise<void> {
    return Promise.race([this.#stopping.promise, sleep(ms)]);
  }

  async close(): Promise<void> {
    this.#stopping.resolve();
    this.#server.closeAllConnections();
    await new Promise<void>((resolve) => this.#server.close(() => resolve()));
  }

  async #handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const url = request.url ?? '';
    const prefix = `${this.pathPrefix}/v1/${this.mountPath}/`;
    const route = url.startsWith(prefix) ? url.slice(prefix.length) : '';
    const [operation, key] = route.startsWith('encrypt/') ? ['encrypt', route.slice(8)]
      : route.startsWith('decrypt/') ? ['decrypt', route.slice(8)]
        : route.startsWith('datakey/wrapped/') ? ['datakey', route.slice(16)] : ['', ''];
    if (request.method !== 'POST' || operation === '' || key.includes('/') || url.includes('?')) {
      this.unexpectedRequests.push(`${request.method} ${url}`);
      respond(response, { status: 405, body: '{"errors":["1 error occurred:\\n\\t* unsupported operation\\n\\n"]}' });
      return;
    }

    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk as Buffer);
    const recorded = new TransitRequest(operation, key, Buffer.concat(chunks), header(request, 'x-vault-token') ?? '',
      header(request, 'x-vault-namespace'), header(request, 'x-vault-request'), header(request, 'content-type'));
    this.requests.push(recorded);

    if (this.onRequest !== undefined && await this.onRequest(request, response) === true) return;

    if (recorded.token !== FakeTransit.TOKEN) {
      respond(response, { status: 403, body: '{"errors":["1 error occurred:\\n\\t* permission denied\\n\\n"]}' });
      return;
    }
    const answer = this.answer?.(recorded, this.requests.length);
    if (answer !== undefined) {
      respond(response, answer);
      return;
    }
    const transitKey = this.keys.get(key);
    if (transitKey === undefined) {
      respond(response, { status: 400, body: '{"errors":["encryption key not found"]}' });
      return;
    }

    const json = recorded.json;
    const ignored = Object.keys(json).filter((name) => !(operation === 'encrypt' ? name === 'plaintext' || (name === 'associated_data' && !this.ignoresAssociatedData)
      : operation === 'decrypt' ? name === 'ciphertext' || (name === 'associated_data' && !this.ignoresAssociatedData)
        : name === 'bits'));
    const aad = ignored.includes('associated_data') || json['associated_data'] === undefined
      ? Buffer.alloc(0) : Buffer.from(json['associated_data'] as string, 'base64');
    const warnings = ignored.length > 0 ? [`Endpoint ignored these unrecognized parameters: [${ignored.join(' ')}]`] : null;
    const latest = transitKey.versions.length;

    switch (operation) {
      case 'encrypt':
        respond(response, ok(envelope({ ciphertext: seal(transitKey, latest, Buffer.from(json['plaintext'] as string, 'base64'), aad), key_version: latest }, warnings)));
        return;
      case 'datakey':
        respond(response, ok(envelope({ ciphertext: seal(transitKey, latest, randomBytes((json['bits'] as number) / 8), aad), key_version: latest }, warnings)));
        return;
      default: {
        const match = /^vault:v(\d+):(.*)$/s.exec(json['ciphertext'] as string);
        if (match === null) {
          respond(response, { status: 400, body: '{"errors":["invalid ciphertext: no prefix"]}' });
          return;
        }
        const version = Number(match[1]);
        if (version < transitKey.minDecryptionVersion) {
          respond(response, { status: 400, body: '{"errors":["ciphertext or signature version is disallowed by policy (too old)"]}' });
          return;
        }
        if (version < 1 || version > latest) {
          respond(response, { status: 400, body: '{"errors":["invalid key version"]}' });
          return;
        }
        const plaintext = open(transitKey.versions[version - 1]!, Buffer.from(match[2]!, 'base64'), aad);
        respond(response, plaintext === undefined
          ? { status: 400, body: '{"errors":["cipher: message authentication failed"]}' }
          : ok(envelope({ plaintext: plaintext.toString('base64') }, warnings)));
      }
    }
  }
}

function seal(key: TransitKey, version: number, plaintext: Buffer, aad: Buffer): string {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key.versions[version - 1]!, nonce).setAAD(aad);
  return `vault:v${version}:${Buffer.concat([nonce, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]).toString('base64')}`;
}

function open(key: Buffer, sealed: Buffer, aad: Buffer): Buffer | undefined {
  if (sealed.length < 28) return undefined;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, sealed.subarray(0, 12)).setAAD(aad);
    decipher.setAuthTag(sealed.subarray(sealed.length - 16));
    return Buffer.concat([decipher.update(sealed.subarray(12, sealed.length - 16)), decipher.final()]);
  } catch {
    return undefined;
  }
}

function header(request: IncomingMessage, name: string): string | undefined {
  const value = request.headers[name];
  return Array.isArray(value) ? value.join(',') : value;
}

/** A body shaped as Vault shapes a successful answer. */
function envelope(data: unknown, warnings: string[] | null = null): string {
  return JSON.stringify({
    request_id: '0f3c2a8e-1b2d-4c5e-8f9a-0b1c2d3e4f5a', lease_id: '', renewable: false, lease_duration: 0,
    data, wrap_info: null, warnings, auth: null, mount_type: 'transit',
  });
}

const ok = (body: string): Answer => ({ status: 200, body });

function respond(response: ServerResponse, answer: Answer): void {
  if (response.destroyed) return;
  const body = Buffer.from(answer.body);
  response.writeHead(answer.status, { 'Content-Type': 'application/json', ...answer.headers, 'Content-Length': body.length });
  response.end(body);
}

/** A token source that counts its calls, records every destination it was given, and can hand out any token, fail or hang. */
class FakeTokenSource implements VaultTokenSource {
  calls = 0;
  readonly destinations: Uint8Array[] = [];
  signalAborted = false;
  /** Gives the token for call number n (from 1); may throw, or return what isn't a token. */
  next: (call: number, signal: AbortSignal) => unknown = () => FakeTransit.TOKEN;

  static giving(token: string): FakeTokenSource {
    const source = new FakeTokenSource();
    source.next = () => token;
    return source;
  }

  async copyToken(destination: Uint8Array, signal: AbortSignal): Promise<number> {
    this.calls++;
    this.destinations.push(destination);
    signal.addEventListener('abort', () => { this.signalAborted = true; }, { once: true });
    const token = await this.next(this.calls, signal);
    if (typeof token !== 'string') return token as number;
    const bytes = Buffer.from(token, 'utf8');
    destination.set(bytes.subarray(0, Math.min(bytes.length, destination.length)));
    return bytes.length;
  }
}

// --- Wrappers and cleanup ----------------------------------------------------------------------

const cleanups: (() => unknown)[] = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

async function startVault(mountPath?: string, pathPrefix?: string): Promise<FakeTransit> {
  const vault = await FakeTransit.start(mountPath, pathPrefix);
  cleanups.push(() => vault.close());
  return vault;
}

interface CreateOptions extends Omit<HashiCorpVaultTransitKeyWrapperOptions, 'context'> {
  address?: string | URL;
  tokens?: VaultTokenSource;
  keyName?: string;
  /** Default CONTEXT; given as undefined, none. */
  context?: string | undefined;
}

/** A wrapper over the fake's key. No backoff, only each retry's 0-100 ms of jitter, so a test that meets a 5xx stays quick. */
function create(vault: FakeTransit | undefined, options: CreateOptions = {}): HashiCorpVaultTransitKeyWrapper {
  const { address, tokens, keyName, ...rest } = options;
  const context = 'context' in options ? options.context : CONTEXT;
  const wrapper = new HashiCorpVaultTransitKeyWrapper(address ?? vault!.address, keyName ?? FakeTransit.KEY_NAME, tokens ?? new FakeTokenSource(),
    { retryDelayMs: 0, ...rest, context });
  cleanups.push(() => wrapper.close());
  return wrapper;
}

function newWrapper(address: string | URL = 'https://vault.example.com:8200', options?: HashiCorpVaultTransitKeyWrapperOptions,
  keyName = FakeTransit.KEY_NAME): HashiCorpVaultTransitKeyWrapper {
  const wrapper = new HashiCorpVaultTransitKeyWrapper(address, keyName, new FakeTokenSource(), options);
  cleanups.push(() => wrapper.close());
  return wrapper;
}

async function wrap(wrapper: KeyWrapper, dek: Uint8Array, signal?: AbortSignal): Promise<Uint8Array> {
  const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
  return wrapped.subarray(0, await wrapper.wrap(dek, wrapped, signal));
}

async function generate(wrapper: KeyWrapper, signal?: AbortSignal): Promise<Uint8Array> {
  const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
  return wrapped.subarray(0, await wrapper.generateAndWrap(wrapped, signal));
}

const ascii = (text: string) => new Uint8Array(Buffer.from(text, 'latin1'));
const text = (bytes: Uint8Array) => Buffer.from(bytes).toString('latin1');
const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** A loopback port nothing listens on. */
async function freePort(): Promise<number> {
  const server = createNetServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as { port: number };
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

const isTransitError = (status?: number) => (e: unknown) => e instanceof HashiCorpVaultTransitError && e.code === 'ERR_HKDFGUARD_VAULT_TRANSIT'
  && (status === undefined || e.statusCode === status);
const isInvalidToken = (e: unknown) => e instanceof HkdfGuardError && e.code === 'ERR_HKDFGUARD_INVALID_VAULT_TOKEN';
const isTimeout = (e: unknown) => e instanceof DOMException && e.name === 'TimeoutError';

/** Every Buffer handed to ClientRequest.end until the test ends: the request bodies, as the wrapper wrote them. */
function recordRequestBodies(t: TestContext): Uint8Array[] {
  const bodies: Uint8Array[] = [];
  const prototype = ClientRequest.prototype;
  const own = Object.hasOwn(prototype, 'end');
  const original = prototype.end;
  prototype.end = function end(this: ClientRequest, ...args: unknown[]) {
    if (args[0] instanceof Uint8Array) bodies.push(args[0]);
    return (original as (...a: unknown[]) => ClientRequest).apply(this, args);
  } as typeof original;
  t.after(() => {
    if (own) prototype.end = original;
    else delete (prototype as { end?: unknown }).end;
  });
  return bodies;
}

// --- Construction ------------------------------------------------------------------------------

describe('constructing a HashiCorpVaultTransitKeyWrapper', () => {
  it('has the limits of .NET\'s wrapper and options', () => {
    assert.equal(GENERATED_KEY_LENGTH, 32);
    assert.equal(MAX_PLAINTEXT_LENGTH, 256);
    assert.equal(MAX_CONTEXT_LENGTH, 1024);
    assert.equal(MAX_KEY_NAME_LENGTH, 128);
    assert.equal(MAX_TOKEN_LENGTH, 2048);
    assert.equal(MAX_RESPONSE_LENGTH, 16 * 1024);
    assert.equal(Limits.MIN_RETRY_COUNT, 3);
    assert.equal(Limits.MAX_RETRY_COUNT, 10);
    assert.equal(Limits.MAX_RETRY_DELAY_MS, 10_000);
  });

  it('refuses a missing token source, options or address', () => {
    const tokens = new FakeTokenSource();
    const none = undefined as never;
    for (const make of [
      () => new HashiCorpVaultTransitKeyWrapper(none, FakeTransit.KEY_NAME, tokens),
      () => new HashiCorpVaultTransitKeyWrapper(42 as never, FakeTransit.KEY_NAME, tokens),
      () => new HashiCorpVaultTransitKeyWrapper('https://vault.example.com', none, tokens),
      () => new HashiCorpVaultTransitKeyWrapper('https://vault.example.com', FakeTransit.KEY_NAME, none),
      () => new HashiCorpVaultTransitKeyWrapper('https://vault.example.com', FakeTransit.KEY_NAME, {} as never),
      () => new HashiCorpVaultTransitKeyWrapper('https://vault.example.com', FakeTransit.KEY_NAME, tokens, null as never),
      () => new HashiCorpVaultTransitKeyWrapper('https://vault.example.com', FakeTransit.KEY_NAME, tokens, 'options' as never),
    ]) {
      assert.throws(make, InvalidArgumentError);
    }
  });

  for (const keyName of ['', '.', '..', 'team/kek', 'my kek', 'kek?x=1', 'kék', 'k'.repeat(MAX_KEY_NAME_LENGTH + 1)]) {
    it(`refuses a key name that isn't one (${JSON.stringify(keyName.length > 20 ? `${keyName.slice(0, 10)}...` : keyName)})`, () => {
      assert.throws(() => newWrapper(undefined, undefined, keyName), (e: unknown) => e instanceof InvalidArgumentError && /key name/.test(e.message));
    });
  }

  it('accepts a key name of every allowed character, up to the limit', () => {
    assert.doesNotThrow(() => newWrapper(undefined, undefined, 'My_Kek-1.2'));
    assert.doesNotThrow(() => newWrapper(undefined, undefined, 'k'.repeat(MAX_KEY_NAME_LENGTH)));
  });

  for (const address of ['http://localhost:8200', 'http://LOCALHOST', 'http://127.0.0.1:8200', 'http://127.1.2.3', 'http://[::1]:8200',
    'https://vault.example.com:8200', 'HTTPS://vault.example.com/prefix/', 'https://[2001:db8::1]:8200', new URL('https://vault.example.com')]) {
    it(`accepts ${String(address)}: https, or http only on loopback`, () => {
      assert.doesNotThrow(() => newWrapper(address));
    });
  }

  for (const address of ['relative/path', 'vault.test:8200', 'http://vault.example.com:8200', 'http://10.0.0.1:8200', 'http://[::2]',
    'http://127.0.0.1.example.com', 'http://localhost.example.com', 'ftp://vault.example.com', 'https://user:pass@vault.example.com:8200',
    'https://user@vault.example.com', 'https://vault.example.com:8200/?x=1', 'https://vault.example.com/?', 'https://vault.example.com:8200/#f',
    'https:///no-host', 'https:\\\\vault.example.com', '']) {
    it(`refuses ${JSON.stringify(address)}, which would expose the token or DEKs`, () => {
      assert.throws(() => newWrapper(address), (e: unknown) => e instanceof InvalidArgumentError
        && e.code === 'ERR_HKDFGUARD_INVALID_VAULT_ADDRESS' && /address/.test(e.message));
    });
  }

  it('refuses a context that isn\'t a string, isn\'t well-formed text, or is over the limit', () => {
    for (const context of [42, '\ud800', 'c'.repeat(MAX_CONTEXT_LENGTH + 1), 'é'.repeat(MAX_CONTEXT_LENGTH / 2 + 1)]) {
      assert.throws(() => newWrapper(undefined, { context: context as string }), InvalidArgumentError);
    }
    newWrapper(undefined, { context: 'c'.repeat(MAX_CONTEXT_LENGTH) });
    newWrapper(undefined, { context: 'é'.repeat(MAX_CONTEXT_LENGTH / 2) });
  });

  const invalidValues: HashiCorpVaultTransitKeyWrapperOptions[] = [
    { mountPath: '' }, { mountPath: 'transit/../sys' }, { mountPath: '/transit' }, { mountPath: 'transit/' }, { mountPath: 'transit?x' },
    { namespace: 'team a' }, { namespace: '' }, { timeoutMs: 0 }, { timeoutMs: -1 }, { timeoutMs: Number.NaN }, { timeoutMs: Limits.MAX_TIMEOUT_MS + 1 },
    { retryCount: Limits.MIN_RETRY_COUNT - 1 }, { retryCount: Limits.MAX_RETRY_COUNT + 1 }, { retryCount: 3.5 }, { retryDelayMs: -1 },
    { retryDelayMs: Limits.MAX_RETRY_DELAY_MS + 1 },
  ];
  const wrongTypes = [
    { mountPath: 42 }, { mountPath: null }, { namespace: 7 }, { namespace: null }, { timeoutMs: '30' }, { retryCount: '3' }, { retryDelayMs: null },
    { agent: 'tls' }, { keyFileTrust: 'administrators' }, { keyFileTrust: null },
  ] as unknown as HashiCorpVaultTransitKeyWrapperOptions[];
  for (const invalid of [...invalidValues, ...wrongTypes]) {
    it(`refuses the option ${JSON.stringify(invalid)}`, () => {
      assert.throws(() => newWrapper(undefined, invalid), InvalidArgumentError);
    });
  }

  it('makes no call until it is used', async () => {
    const vault = await startVault();
    const tokens = new FakeTokenSource();
    create(vault, { tokens });
    await sleep(20);
    assert.equal(vault.requests.length, 0);
    assert.equal(tokens.calls, 0);
  });

  it('is a KeyWrapper', async () => {
    const vault = await startVault();
    const wrapper: KeyWrapper = create(vault);
    const dek = randomBytes(32);
    const revealed = new Uint8Array(32);
    assert.equal(await wrapper.unwrap(await wrap(wrapper, dek), revealed), 32);
    assert.deepEqual(Buffer.from(revealed), dek);
  });
});

// --- Wrap, unwrap and generate-and-wrap ---------------------------------------------------------

describe('wrap, unwrap and generate-and-wrap', () => {
  it('round-trip a DEK through Vault, as an ASCII Vault ciphertext', async () => {
    const vault = await startVault();
    const wrapper = create(vault);
    const dek = randomBytes(32);

    const wrapped = await wrap(wrapper, dek);
    const revealed = new Uint8Array(32);

    assert.match(text(wrapped), /^vault:v1:[A-Za-z0-9+/]+=*$/);
    assert.equal(await wrapper.unwrap(wrapped, revealed), 32);
    assert.deepEqual(Buffer.from(revealed), dek);
  });

  it('encrypt under the key with the context, sending exactly .NET\'s body, and zero what was sent', async (t) => {
    const vault = await startVault();
    const tokens = new FakeTokenSource();
    const wrapper = create(vault, { tokens });
    const bodies = recordRequestBodies(t);
    const dek = randomBytes(32);

    await wrap(wrapper, dek);

    assert.equal(vault.requests.length, 1);
    const request = vault.requests[0]!;
    assert.deepEqual([request.operation, request.key], ['encrypt', FakeTransit.KEY_NAME]);
    assert.equal(request.body.toString('latin1'), `{"plaintext":"${dek.toString('base64')}","associated_data":"${CONTEXT_BASE64}"}`);
    assert.equal(request.token, FakeTransit.TOKEN);
    assert.equal(request.namespace, undefined);
    assert.equal(request.vaultRequest, 'true');
    assert.equal(request.contentType, 'application/json');
    assert.deepEqual(vault.unexpectedRequests, []);

    // The body was sent from one buffer of the wrapper's own - its whole backing store, not a slice
    // of Node's shared pool - and nothing of it is left; nor of the token's buffer.
    assert.equal(bodies.length, 1);
    assert.equal(bodies[0]!.length, request.body.length);
    assert.ok(isZero(new Uint8Array(bodies[0]!.buffer)), 'the request body is zeroed');
    assert.equal(tokens.destinations.length, 1);
    assert.equal(tokens.destinations[0]!.length, MAX_TOKEN_LENGTH);
    assert.ok(isZero(tokens.destinations[0]!), 'the token buffer is zeroed');
  });

  it('decrypt under the key with the context, sending exactly .NET\'s body', async () => {
    const vault = await startVault();
    const wrapper = create(vault);
    const wrapped = await wrap(wrapper, randomBytes(32));

    await wrapper.unwrap(wrapped, new Uint8Array(32));

    const request = vault.requests.at(-1)!;
    assert.deepEqual([request.operation, request.key], ['decrypt', FakeTransit.KEY_NAME]);
    assert.equal(request.body.toString('latin1'), `{"ciphertext":"${text(wrapped)}","associated_data":"${CONTEXT_BASE64}"}`);
  });

  it('generate with no context in Vault, with datakey/wrapped asking for 256 bits, and bind none', async () => {
    const vault = await startVault();
    const wrapper = create(vault, { context: undefined });

    const wrapped = await generate(wrapper);
    const revealed = new Uint8Array(32);
    const revealedLength = await wrapper.unwrap(wrapped, revealed);

    assert.deepEqual([vault.requests[0]!.operation, vault.requests[0]!.key], ['datakey', FakeTransit.KEY_NAME]);
    assert.equal(vault.requests[0]!.body.toString('latin1'), '{"bits":256}');
    assert.equal(vault.requests[1]!.body.toString('latin1'), `{"ciphertext":"${text(wrapped)}"}`);
    assert.equal(revealedLength, GENERATED_KEY_LENGTH);
    assert.ok(!isZero(revealed));
  });

  it('treat an empty context as none', async () => {
    const vault = await startVault();
    const wrapper = create(vault, { context: '' });
    const dek = randomBytes(32);

    const wrapped = await wrap(wrapper, dek);
    await wrapper.unwrap(wrapped, new Uint8Array(32));
    await generate(wrapper);

    assert.equal(vault.requests[0]!.body.toString('latin1'), `{"plaintext":"${dek.toString('base64')}"}`);
    for (const request of vault.requests) assert.equal(request.field('associated_data'), undefined);
    assert.equal(vault.requests.at(-1)!.operation, 'datakey');
  });

  it('encode the context as UTF-8, then base64', async () => {
    const vault = await startVault();
    const wrapper = create(vault, { context: 'contexte été 😀' });
    await wrap(wrapper, randomBytes(32));
    assert.equal(vault.requests[0]!.field('associated_data'), Buffer.from('contexte été 😀', 'utf8').toString('base64'));
  });

  it('generate here with a context, which datakey/wrapped would ignore, and encrypt with it', async (t) => {
    const vault = await startVault();
    const wrapper = create(vault);
    const bodies = recordRequestBodies(t);

    const wrapped = await generate(wrapper);
    const revealed = new Uint8Array(32);
    await wrapper.unwrap(wrapped, revealed);

    const request = vault.requests[0]!;
    assert.equal(request.operation, 'encrypt');
    assert.equal(request.field('associated_data'), CONTEXT_BASE64);
    assert.deepEqual(Buffer.from(request.field('plaintext') as string, 'base64'), Buffer.from(revealed));
    assert.ok(!isZero(revealed));
    assert.ok(isZero(new Uint8Array(bodies[0]!.buffer)), 'the request body holding the generated DEK is zeroed');
  });

  it('wrap a view into a larger buffer, and write into one', async () => {
    const vault = await startVault();
    const wrapper = create(vault);
    const backing = randomBytes(64);
    const dek = backing.subarray(16, 48);

    const out = new Uint8Array(MAX_WRAPPED_KEY_BYTES + 20);
    const length = await wrapper.wrap(dek, out.subarray(10));
    const revealed = new Uint8Array(48);
    assert.equal(await wrapper.unwrap(out.subarray(10, 10 + length), revealed.subarray(8)), 32);

    assert.deepEqual(Buffer.from(revealed.subarray(8, 40)), Buffer.from(dek));
    assert.ok(isZero(out.subarray(0, 10)));
    assert.ok(isZero(revealed.subarray(0, 8)));
    assert.equal(vault.requests[0]!.field('plaintext'), Buffer.from(dek).toString('base64'));
  });

  it('leave the caller\'s plaintext alone', async () => {
    const vault = await startVault();
    const wrapper = create(vault);
    const dek = randomBytes(32);
    const copy = Buffer.from(dek);
    await wrap(wrapper, dek);
    assert.deepEqual(dek, copy);
  });

  it('accept the largest plaintext, and it fits a key file', async () => {
    const vault = await startVault();
    const wrapper = create(vault);
    const dek = randomBytes(MAX_PLAINTEXT_LENGTH);

    const wrapped = await wrap(wrapper, dek);
    const revealed = new Uint8Array(dek.length);

    assert.ok(wrapped.length <= MAX_WRAPPED_KEY_BYTES);
    assert.equal(await wrapper.unwrap(wrapped, revealed), dek.length);
    assert.deepEqual(Buffer.from(revealed), dek);
  });

  it('encode every plaintext length as Buffer\'s base64 does', async () => {
    const vault = await startVault();
    const wrapper = create(vault, { context: undefined });
    for (const length of [1, 2, 3, 4, 5, 31, 32, 33, 255, 256]) {
      const dek = randomBytes(length);
      const wrapped = await wrap(wrapper, dek);
      assert.equal(vault.requests.at(-1)!.field('plaintext'), dek.toString('base64'), `${length} bytes`);
      const revealed = new Uint8Array(length);
      assert.equal(await wrapper.unwrap(wrapped, revealed), length);
      assert.deepEqual(Buffer.from(revealed), dek);
    }
  });
});

// --- Key versions --------------------------------------------------------------------------------

describe('key versions', () => {
  it('wrap under the latest version once the key rotates, and keep revealing older ones', async () => {
    const vault = await startVault();
    const wrapper = create(vault);
    const first = randomBytes(32);
    const v1 = await wrap(wrapper, first);

    vault.rotate(FakeTransit.KEY_NAME);
    const second = randomBytes(32);
    const v2 = await wrap(wrapper, second);

    assert.match(text(v1), /^vault:v1:/);
    assert.match(text(v2), /^vault:v2:/);
    const revealed = new Uint8Array(32);
    await wrapper.unwrap(v1, revealed);
    assert.deepEqual(Buffer.from(revealed), first);
    await wrapper.unwrap(v2, revealed);
    assert.deepEqual(Buffer.from(revealed), second);
  });

  it('refuse a version below min_decryption_version, naming Vault\'s error, and zero the result', async () => {
    const vault = await startVault();
    const wrapper = create(vault);
    const v1 = await wrap(wrapper, randomBytes(32));
    vault.rotate(FakeTransit.KEY_NAME);
    const v2 = await generate(wrapper);
    vault.setMinDecryptionVersion(FakeTransit.KEY_NAME, 2);

    const result = new Uint8Array(32).fill(0xaa);
    await assert.rejects(wrapper.unwrap(v1, result), (e: unknown) => isTransitError(400)(e)
      && (e as Error).message.endsWith('Vault answered 400 BadRequest: ciphertext or signature version is disallowed by policy (too old)'));
    assert.ok(isZero(result));
    assert.equal(await wrapper.unwrap(v2, new Uint8Array(32)), 32);
  });

  it('accept any version Vault writes, up to ten digits', () => {
    assert.ok(isVaultCiphertext(ascii('vault:v1234567890:AB+/=')));
  });
});

// --- Refusals ------------------------------------------------------------------------------------

describe('refusals', () => {
  it('refuse a DEK wrapped under another key, naming Vault\'s answer, and zero the result', async () => {
    const vault = await startVault();
    vault.addKey('other-kek');
    const other = create(vault, { keyName: 'other-kek' });
    const wrapped = await wrap(other, randomBytes(32));

    const wrapper = create(vault);
    const result = new Uint8Array(32).fill(0xaa);
    await assert.rejects(wrapper.unwrap(wrapped, result), (e: unknown) => {
      assert.ok(e instanceof HashiCorpVaultTransitError);
      assert.equal(e.message, `Vault transit unwrap failed for key '${FakeTransit.KEY_NAME}': Vault answered 400 BadRequest: cipher: message authentication failed`);
      assert.equal(e.statusCode, 400);
      assert.equal(e.operation, 'unwrap');
      assert.equal(e.keyName, FakeTransit.KEY_NAME);
      return true;
    });
    assert.ok(isZero(result));
    assert.equal(vault.requests.length, 2);
  });

  it('refuse a DEK wrapped under another context, or none', async () => {
    const vault = await startVault();
    const wrapper = create(vault);
    const other = create(vault, { context: 'other' });
    const none = create(vault, { context: undefined });
    const wrapped = await wrap(wrapper, randomBytes(32));

    await assert.rejects(other.unwrap(wrapped, new Uint8Array(32)), isTransitError(400));
    await assert.rejects(none.unwrap(wrapped, new Uint8Array(32)), isTransitError(400));
  });

  it('refuse a tampered DEK', async () => {
    const vault = await startVault();
    const wrapper = create(vault);
    const wrapped = Uint8Array.from(await wrap(wrapper, randomBytes(32)));
    // Another base64 character, so it still reaches Vault and fails there.
    wrapped[12] = wrapped[12] === 0x41 ? 0x42 : 0x41;

    await assert.rejects(wrapper.unwrap(wrapped, new Uint8Array(32)), isTransitError(400));
  });

  for (const wrapped of ['', 'vault:v1:', 'vault:v:AAAA', 'vault:x1:AAAA', 'vault:v12345678901:AAAA', 'vault:v1:AA"},"x":"AA', 'vault:v1:AA AA',
    'VAULT:v1:AAAA', 'vault:v1:AA\\u0041']) {
    it(`refuse ${JSON.stringify(wrapped)}, which isn't a ciphertext, without calling Vault, zeroing the result`, async () => {
      const vault = await startVault();
      const wrapper = create(vault);
      const result = new Uint8Array(32).fill(0xaa);

      await assert.rejects(wrapper.unwrap(ascii(wrapped), result), isTransitError());
      assert.equal(vault.requests.length, 0);
      assert.ok(isZero(result));
    });
  }

  it('refuse a wrapped DEK over the key-file limit without calling Vault', async () => {
    const vault = await startVault();
    const wrapper = create(vault);

    await assert.rejects(wrapper.unwrap(ascii(`vault:v1:${'A'.repeat(MAX_WRAPPED_KEY_BYTES)}`), new Uint8Array(32)),
      (e: unknown) => isTransitError()(e) && (e as Error).message.includes(`1-${MAX_WRAPPED_KEY_BYTES} bytes`));
    assert.equal(vault.requests.length, 0);
  });

  it('refuse a result too small for the revealed key, zeroing it', async () => {
    const vault = await startVault();
    const wrapper = create(vault);
    const wrapped = await wrap(wrapper, randomBytes(32));

    const result = new Uint8Array(16).fill(0xaa);
    await assert.rejects(wrapper.unwrap(wrapped, result), (e: unknown) => e instanceof InvalidArgumentError && /result holds 16/.test(e.message));
    assert.ok(isZero(result));
  });

  for (const size of [0, MAX_PLAINTEXT_LENGTH + 1]) {
    it(`refuse a plaintext of ${size} bytes without calling Vault`, async () => {
      const vault = await startVault();
      const wrapper = create(vault);

      await assert.rejects(wrapper.wrap(new Uint8Array(size), new Uint8Array(MAX_WRAPPED_KEY_BYTES)), InvalidArgumentError);
      assert.equal(vault.requests.length, 0);
    });
  }

  it('refuse a result too small for the wrapped DEK', async () => {
    const vault = await startVault();
    const wrapper = create(vault);
    await assert.rejects(wrapper.wrap(new Uint8Array(32), new Uint8Array(8)), (e: unknown) => e instanceof InvalidArgumentError && /result holds 8/.test(e.message));
    await assert.rejects(wrapper.generateAndWrap(new Uint8Array(8)), InvalidArgumentError);
  });

  it('refuse buffers that are not Uint8Arrays', async () => {
    const vault = await startVault();
    const wrapper = create(vault);
    const bytes = new Uint8Array(32);
    await assert.rejects(wrapper.wrap('dek' as never, bytes), InvalidArgumentError);
    await assert.rejects(wrapper.wrap(bytes, [] as never), InvalidArgumentError);
    await assert.rejects(wrapper.unwrap('vault:v1:AAAA' as never, bytes), InvalidArgumentError);
    await assert.rejects(wrapper.unwrap(bytes, undefined as never), InvalidArgumentError);
    await assert.rejects(wrapper.generateAndWrap(null as never), InvalidArgumentError);
    assert.equal(vault.requests.length, 0);
  });
});

// --- What Vault answers ----------------------------------------------------------------------------

describe('what Vault answers', () => {
  const badAnswers: [string, string][] = [
    ['not JSON', '<html>proxy</html>'],
    ['empty', ''],
    ['not an object', '[]'],
    ['truncated', '{"data":{"ciphertext":"vault:v1:AAAA"'],
    ['no data', envelope(null)],
    ['data not an object', '{"data":"x"}'],
    ['no ciphertext', envelope({ key_version: 1 })],
    ['ciphertext not a string', envelope({ ciphertext: 7 })],
    ['ciphertext empty', envelope({ ciphertext: '' })],
    ['ciphertext twice', '{"data":{"ciphertext":"vault:v1:AAAA","ciphertext":"vault:v1:BBBB"}}'],
    ['data twice', '{"data":{"ciphertext":"vault:v1:AAAA"},"data":{"ciphertext":"vault:v1:BBBB"}}'],
    ['not a ciphertext', envelope({ ciphertext: 'AAAA' })],
    ['over the key file limit', envelope({ ciphertext: `vault:v1:${'A'.repeat(MAX_WRAPPED_KEY_BYTES)}` })],
    ['a parameter ignored', envelope({ ciphertext: 'vault:v1:AAAA' }, ['Endpoint ignored these unrecognized parameters: [associated_data]'])],
    ['nested too deep', `{"data":{"ciphertext":"vault:v1:AAAA"},"x":${'['.repeat(20)}${']'.repeat(20)}}`],
  ];
  for (const [because, body] of badAnswers) {
    it(`refuse an answer that isn't a ciphertext (${because}), and don't retry it`, async () => {
      const vault = await startVault();
      vault.answer = () => ok(body);
      const wrapper = create(vault);

      await assert.rejects(wrapper.wrap(new Uint8Array(32), new Uint8Array(2 * MAX_WRAPPED_KEY_BYTES)),
        (e: unknown) => isTransitError()(e) && (e as HashiCorpVaultTransitError).statusCode === undefined);
      assert.equal(vault.requests.length, 1);
    });
  }

  it('unescape an escaped answer', async () => {
    // vault:v1:AB+/ with '+' as a \u escape and '/' as \/, as a proxy re-encoding the answer might write it.
    const vault = await startVault();
    vault.answer = () => ok('{"data":{"ciphertext":"vault:v1:AB\\u002B\\/"}}');
    const wrapper = create(vault);

    assert.equal(text(await wrap(wrapper, new Uint8Array(32))), 'vault:v1:AB+/');
  });

  it('accept an answer with other warnings', async () => {
    const vault = await startVault();
    vault.answer = () => ok('{"data":{"ciphertext":"vault:v1:AAAA"},"warnings":[7,{"unrecognized parameters":1},"some other warning"]}');
    const wrapper = create(vault);

    assert.equal(text(await wrap(wrapper, new Uint8Array(32))), 'vault:v1:AAAA');
  });

  it('refuse a Vault that ignores the context, rather than wrapping unbound', async () => {
    const vault = await startVault();
    vault.ignoresAssociatedData = true;
    const wrapper = create(vault);

    await assert.rejects(generate(wrapper), (e: unknown) => isTransitError()(e) && (e as Error).message.includes('ignored a parameter'));
    await assert.rejects(wrap(wrapper, randomBytes(32)), (e: unknown) => isTransitError()(e) && (e as Error).message.includes('ignored a parameter'));
  });

  for (const body of ['{"data":{"plaintext":"not base64!"}}', '{"data":{"plaintext":"AAA"}}', '{"data":{"plaintext":"A==="}}', '{"data":{}}',
    '{"data":{"plaintext":""}}', '{"data":{"plaintext":"===="}}']) {
    it(`refuse an unwrap answer that isn't a plaintext (${body}), zeroing the result`, async () => {
      const vault = await startVault();
      vault.answer = () => ok(body);
      const wrapper = create(vault);

      const result = new Uint8Array(32).fill(0xaa);
      await assert.rejects(wrapper.unwrap(ascii('vault:v1:AAAA'), result), isTransitError());
      assert.ok(isZero(result));
    });
  }

  it('refuse an answer over the response limit, and don\'t retry it', async () => {
    const vault = await startVault();
    vault.answer = () => ok(envelope({ ciphertext: 'vault:v1:AAAA', padding: 'x'.repeat(MAX_RESPONSE_LENGTH) }));
    const wrapper = create(vault);

    await assert.rejects(wrap(wrapper, new Uint8Array(32)), (e: unknown) => isTransitError()(e) && (e as Error).message.includes('over'));
    assert.equal(vault.requests.length, 1);
  });

  it('read an answer of exactly the response limit', async () => {
    const vault = await startVault();
    const shell = envelope({ ciphertext: 'vault:v1:AAAA', padding: '' });
    const body = shell.replace('"padding":""', `"padding":"${'x'.repeat(MAX_RESPONSE_LENGTH - shell.length)}"`);
    assert.equal(body.length, MAX_RESPONSE_LENGTH);
    vault.answer = () => ok(body);
    const wrapper = create(vault);

    assert.equal(text(await wrap(wrapper, new Uint8Array(32))), 'vault:v1:AAAA');
  });

  it('read an answer served in many chunks', async () => {
    const vault = await startVault();
    const wrapper = create(vault);
    const dek = randomBytes(32);
    const wrapped = await wrap(wrapper, dek);
    vault.onRequest = async (_request, response) => {
      const body = Buffer.from(envelope({ plaintext: dek.toString('base64') }));
      response.writeHead(200, { 'Content-Type': 'application/json' });
      for (let offset = 0; offset < body.length; offset += 7) {
        response.write(body.subarray(offset, offset + 7));
        await sleep(0);
      }
      response.end();
      return true;
    };

    const revealed = new Uint8Array(32);
    assert.equal(await wrapper.unwrap(wrapped, revealed), 32);
    assert.deepEqual(Buffer.from(revealed), dek);
  });
});

// --- Failures and retries -------------------------------------------------------------------------

describe('failures and retries', () => {
  it('make a Vault refusal a HashiCorpVaultTransitError naming Vault\'s status and errors, and don\'t retry it', async () => {
    const vault = await startVault();
    const wrapper = create(vault, { tokens: FakeTokenSource.giving('hvs.revoked') });

    await assert.rejects(wrap(wrapper, new Uint8Array(32)), (e: unknown) => {
      assert.ok(e instanceof HashiCorpVaultTransitError);
      assert.equal(e.message, `Vault transit wrap failed for key '${FakeTransit.KEY_NAME}': Vault answered 403 Forbidden: 1 error occurred:\n\t* permission denied\n\n`);
      assert.equal(e.statusCode, 403);
      assert.equal(e.operation, 'wrap');
      assert.ok(!e.message.includes('hvs.revoked'));
      return true;
    });
    assert.equal(vault.requests.length, 1);
  });

  for (const body of ['<html>bad gateway</html>', '{"errors":"x"}', '[]', '{}', '']) {
    it(`report a refusal that isn't Vault's JSON (${JSON.stringify(body)}) by its status`, async () => {
      const vault = await startVault();
      vault.answer = () => ({ status: 404, body });
      const wrapper = create(vault);

      await assert.rejects(generate(wrapper), (e: unknown) => isTransitError(404)(e)
        && (e as Error).message === `Vault transit wrap failed for key '${FakeTransit.KEY_NAME}': Vault answered 404 NotFound`);
    });
  }

  it('name the operation generate-and-wrap without a context', async () => {
    const vault = await startVault();
    vault.answer = () => ({ status: 400, body: '{"errors":["bad"]}' });
    const wrapper = create(vault, { context: undefined });

    await assert.rejects(generate(wrapper), (e: unknown) => isTransitError(400)(e) && (e as HashiCorpVaultTransitError).operation === 'generate-and-wrap'
      && (e as Error).message === `Vault transit generate-and-wrap failed for key '${FakeTransit.KEY_NAME}': Vault answered 400 BadRequest: bad`);
  });

  const transientAnswers: Answer[] = [
    { status: 503, body: '{"errors":["Vault is sealed"]}' },
    { status: 500, body: '{"errors":["internal error"]}' },
    { status: 429, body: '{"errors":["rate limit quota exceeded"]}' },
    { status: 502, body: '<html>Bad Gateway</html>' },
    { status: 504, body: '' },
  ];
  for (const answer of transientAnswers) {
    it(`retry ${answer.status}, asking for the token once`, async () => {
      const vault = await startVault();
      vault.answer = (_request, count) => (count <= 2 ? answer : undefined);
      const tokens = new FakeTokenSource();
      const wrapper = create(vault, { tokens });
      const dek = randomBytes(32);

      const wrapped = await wrap(wrapper, dek);

      assert.equal(vault.requests.length, 3);
      assert.equal(tokens.calls, 1);
      assert.ok(isZero(tokens.destinations[0]!));
      const revealed = new Uint8Array(32);
      await wrapper.unwrap(wrapped, revealed);
      assert.deepEqual(Buffer.from(revealed), dek);
    });
  }

  for (const retryCount of [4, Limits.MAX_RETRY_COUNT]) {
    it(`retry a transient answer ${retryCount} times, then reject with it`, async () => {
      const vault = await startVault();
      vault.answer = () => ({ status: 503, body: '{"errors":["Vault is sealed"]}' });
      const wrapper = create(vault, { retryCount });

      await assert.rejects(generate(wrapper), (e: unknown) => isTransitError(503)(e)
        && (e as Error).message.endsWith('Vault answered 503 ServiceUnavailable: Vault is sealed'));
      assert.equal(vault.requests.length, 1 + retryCount);
    });
  }

  const finalAnswers: Answer[] = [
    { status: 501, body: '{"errors":[]}' },
    { status: 400, body: '{"errors":["bad request"]}' },
    { status: 403, body: '{"errors":["permission denied"]}' },
    { status: 404, body: '{"errors":["no handler for route"]}' },
    { status: 307, body: '' },
  ];
  for (const answer of finalAnswers) {
    it(`don't retry ${answer.status}, which would be answered the same`, async () => {
      const vault = await startVault();
      vault.answer = () => answer;
      const wrapper = create(vault);

      await assert.rejects(generate(wrapper), isTransitError(answer.status));
      assert.equal(vault.requests.length, 1);
    });
  }

  it('don\'t follow a redirect, which would carry the token elsewhere', async () => {
    const vault = await startVault();
    vault.answer = (request) => (request.operation === 'encrypt' ? { status: 307, body: '', headers: { Location: vault.url('decrypt/elsewhere') } } : undefined);
    const wrapper = create(vault);

    await assert.rejects(generate(wrapper), (e: unknown) => isTransitError(307)(e) && (e as Error).message.endsWith('Vault answered 307 TemporaryRedirect'));
    assert.deepEqual(vault.requests.map((r) => r.operation), ['encrypt']);
    assert.deepEqual(vault.unexpectedRequests, []);
  });

  const losses: [string, OnRequest][] = [
    ['no answer', (request) => { request.socket.destroy(); return true; }],
    ['dropped mid-response', (_request, response) => {
      response.writeHead(200, { 'Content-Length': 200 });
      response.write('{"data":{"ciphertext":"vault:v1:AA', () => response.socket?.destroy());
      return true;
    }],
  ];
  for (const [how, lose] of losses) {
    it(`retry a lost connection (${how})`, async () => {
      const vault = await startVault();
      vault.onRequest = (request, response) => (vault.requests.length > 1 ? false : lose(request, response));
      const wrapper = create(vault, { timeoutMs: 1000 });

      await generate(wrapper);
      assert.equal(vault.requests.length, 2);
    });
  }

  it('retry an attempt that times out, then report no answer, with the timeout as the cause', async () => {
    const vault = await startVault();
    vault.onRequest = async () => {
      await vault.stopping(5000);
    };
    const wrapper = create(vault, { timeoutMs: 50 });

    await assert.rejects(generate(wrapper), (e: unknown) => isTransitError()(e) && (e as Error).message.includes('no answer within 50 ms')
      && isTimeout((e as Error).cause));
    assert.equal(vault.requests.length, 1 + Limits.MIN_RETRY_COUNT);
  });

  it('time out a body that stalls within the attempt\'s timeout, and retry it', async () => {
    const vault = await startVault();
    vault.onRequest = async (_request, response) => {
      response.writeHead(200);
      response.write('{"data":{"ciphertext":"vault:v1:AA');
      await vault.stopping(5000);
      response.socket?.destroy();
      return true;
    };
    const wrapper = create(vault, { timeoutMs: 300 });

    const started = performance.now();
    await assert.rejects(generate(wrapper), (e: unknown) => isTransitError()(e) && (e as Error).message.includes('no answer within 300 ms'));
    const elapsed = performance.now() - started;

    assert.equal(vault.requests.length, 1 + Limits.MIN_RETRY_COUNT);
    // Four attempts of 300 ms and three waits of at most 100 ms, far short of one stalled body.
    assert.ok(elapsed < 4000, `${elapsed} ms`);
  });

  it('retry an unreachable Vault, then reject with Node\'s network error as the cause', async () => {
    const wrapper = create(undefined, { address: `http://127.0.0.1:${await freePort()}/` });

    await assert.rejects(generate(wrapper), (e: unknown) => isTransitError()(e) && (e as HashiCorpVaultTransitError).statusCode === undefined
      && ((e as Error).cause as { code?: string }).code === 'ECONNREFUSED' && (e as Error).message.includes('ECONNREFUSED'));
  });

  it('wait longer before each retry', async () => {
    const vault = await startVault();
    const times: number[] = [];
    vault.answer = () => {
      times.push(performance.now());
      return { status: 503, body: '{"errors":["sealed"]}' };
    };
    const wrapper = create(vault, { retryDelayMs: 100 });

    await assert.rejects(generate(wrapper), isTransitError(503));
    const waits = times.slice(1).map((time, i) => time - times[i]!);
    // 100, 200 and 400 ms, plus 0-100 ms of jitter each (and a little for the request).
    assert.ok(waits[0]! >= 95 && waits[1]! >= 195 && waits[2]! >= 395, waits.join(', '));
  });
});

// --- Cancellation -------------------------------------------------------------------------------

describe('cancellation', () => {
  it('rejects an aborted signal without calling Vault or the token source', async () => {
    const vault = await startVault();
    const tokens = new FakeTokenSource();
    const wrapper = create(vault, { tokens });
    const signal = AbortSignal.abort();

    await assert.rejects(generate(wrapper, signal), { name: 'AbortError' });
    await assert.rejects(wrap(wrapper, new Uint8Array(32), signal), { name: 'AbortError' });
    const result = new Uint8Array(32).fill(0xaa);
    await assert.rejects(wrapper.unwrap(ascii('vault:v1:AAAA'), result, signal), { name: 'AbortError' });
    assert.ok(isZero(result));
    assert.equal(vault.requests.length, 0);
    assert.equal(tokens.calls, 0);
  });

  it('abandons the request, and doesn\'t wrap or retry it, when aborted while Vault is answering', async () => {
    const vault = await startVault();
    // Transient, so a request that wasn't abandoned would be retried once Vault answers.
    vault.answer = () => ({ status: 503, body: '{"errors":["Vault is sealed"]}' });
    const arrived = Promise.withResolvers<void>();
    vault.onRequest = async () => {
      arrived.resolve();
      await vault.stopping(1000);
    };
    const wrapper = create(vault);
    const controller = new AbortController();
    const reason = new Error('the caller gave up');

    const call = generate(wrapper, controller.signal);
    await arrived.promise;
    controller.abort(reason);

    await assert.rejects(call, (e: unknown) => e === reason);
    await sleep(300);
    assert.equal(vault.requests.length, 1);
  });

  it('aborts the token source\'s signal when the call waiting for the token is aborted', async () => {
    const vault = await startVault();
    const tokens = new FakeTokenSource();
    tokens.next = (_call, signal) => new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(signal.reason)));
    const wrapper = create(vault, { tokens });
    const controller = new AbortController();
    const reason = new Error('the caller gave up');

    const call = generate(wrapper, controller.signal);
    await sleep(50);
    controller.abort(reason);

    await assert.rejects(call, (e: unknown) => e === reason);
    assert.ok(tokens.signalAborted);
    assert.equal(vault.requests.length, 0);
  });

  it('stops waiting to retry when aborted', async () => {
    const vault = await startVault();
    vault.answer = () => ({ status: 503, body: '{"errors":["Vault is sealed"]}' });
    const wrapper = create(vault, { retryDelayMs: Limits.MAX_RETRY_DELAY_MS });
    const controller = new AbortController();
    const reason = new Error('the caller gave up');

    const call = generate(wrapper, controller.signal);
    await sleep(200);
    controller.abort(reason);

    await assert.rejects(call, (e: unknown) => e === reason);
    assert.equal(vault.requests.length, 1);
  });
});

// --- The token ------------------------------------------------------------------------------------

describe('the token', () => {
  for (const token of ['', 'hvs.with space', 'hvs.é', 'hvs.\n', 't'.repeat(MAX_TOKEN_LENGTH + 1)]) {
    it(`refuses a token that isn't one (${JSON.stringify(token.length > 20 ? `${token.slice(0, 10)}...` : token)}) without calling Vault, quoting nothing`, async () => {
      const vault = await startVault();
      const wrapper = create(vault, { tokens: FakeTokenSource.giving(token) });

      await assert.rejects(generate(wrapper), (e: unknown) => isInvalidToken(e) && (token.length < 5 || !(e as Error).message.includes(token)));
      assert.equal(vault.requests.length, 0);
    });
  }

  for (const length of [undefined, null, 0, -1, 1.5, [20], { length: 20 }, MAX_TOKEN_LENGTH + 1]) {
    it(`refuses a source that returns ${JSON.stringify(length)} as the length without calling Vault`, async () => {
      const vault = await startVault();
      const tokens = new FakeTokenSource();
      tokens.next = () => length;
      const wrapper = create(vault, { tokens });

      await assert.rejects(generate(wrapper), isInvalidToken);
      assert.equal(vault.requests.length, 0);
    });
  }

  it('sends the longest token whole', async () => {
    const vault = await startVault();
    const token = `hvs.${'t'.repeat(MAX_TOKEN_LENGTH - 4)}`;
    const wrapper = create(vault, { tokens: FakeTokenSource.giving(token) });

    await assert.rejects(generate(wrapper), isTransitError(403));
    assert.equal(vault.requests[0]!.token, token);
  });

  it('propagates a token source\'s failure as it is, and doesn\'t retry it', async () => {
    const vault = await startVault();
    const failure = new Error('login failed');
    const tokens = new FakeTokenSource();
    tokens.next = () => { throw failure; };
    const wrapper = create(vault, { tokens });

    await assert.rejects(generate(wrapper), (e: unknown) => e === failure);
    assert.equal(tokens.calls, 1);
    assert.equal(vault.requests.length, 0);
  });

  it('propagates a synchronous source\'s throw, and accepts its synchronous length', async () => {
    const vault = await startVault();
    const failure = new Error('no token');
    const wrapper = create(vault, { tokens: { copyToken: () => { throw failure; } } });
    await assert.rejects(generate(wrapper), (e: unknown) => e === failure);

    const synchronous = create(vault, {
      tokens: {
        copyToken: (destination: Uint8Array) => {
          destination.set(Buffer.from(FakeTransit.TOKEN));
          return FakeTransit.TOKEN.length;
        },
      },
    });
    assert.ok((await generate(synchronous)).length > 0);
  });

  for (const hang of ['honour', 'ignore'] as const) {
    it(`times out a source slower than the timeout (one that ${hang}s its signal)`, async () => {
      const vault = await startVault();
      const tokens = new FakeTokenSource();
      tokens.next = (_call, signal) => new Promise((_resolve, reject) => {
        if (hang === 'honour') signal.addEventListener('abort', () => reject(signal.reason));
      });
      const wrapper = create(vault, { tokens, timeoutMs: 50 });

      await assert.rejects(generate(wrapper), (e: unknown) => isTimeout(e) && /token source supplied no token within 50 ms/.test((e as Error).message));
      assert.ok(tokens.signalAborted);
      assert.equal(vault.requests.length, 0);
    });
  }

  it('zeroes the token buffer when Vault refuses the call, too', async () => {
    const vault = await startVault();
    vault.answer = () => ({ status: 400, body: '{"errors":["bad"]}' });
    const tokens = new FakeTokenSource();
    const wrapper = create(vault, { tokens });

    await assert.rejects(generate(wrapper), isTransitError(400));
    assert.ok(isZero(tokens.destinations[0]!));
  });
});

describe('StaticVaultTokenSource', () => {
  it('supplies its token until closed, then fails every call without calling Vault', async () => {
    const vault = await startVault();
    const tokens = new StaticVaultTokenSource(FakeTransit.TOKEN);
    const wrapper = create(vault, { tokens });

    await generate(wrapper);
    tokens.close();
    tokens.close();

    await assert.rejects(generate(wrapper), isInvalidToken);
    assert.equal(vault.requests.length, 1);
  });

  it('takes the token\'s bytes, and leaves them to their owner', async () => {
    const vault = await startVault();
    const bytes = Buffer.from(FakeTransit.TOKEN);
    const tokens = new StaticVaultTokenSource(bytes);
    bytes.fill(0);
    const wrapper = create(vault, { tokens });

    await generate(wrapper);
    assert.equal(vault.requests[0]!.token, FakeTransit.TOKEN);
  });

  for (const token of ['', 'hvs.with space', 'hvs.é', 'hvs.\n', 't'.repeat(MAX_TOKEN_LENGTH + 1), new Uint8Array(0), new Uint8Array([0x68, 0x20, 0x76]), 42, undefined]) {
    it(`refuses a token that isn't one (${JSON.stringify(typeof token === 'string' && token.length > 20 ? `${token.slice(0, 10)}...` : token)})`, () => {
      assert.throws(() => new StaticVaultTokenSource(token as string), InvalidArgumentError);
    });
  }

  it('accepts the longest token, and refuses a destination too small for it', () => {
    new StaticVaultTokenSource('t'.repeat(MAX_TOKEN_LENGTH));
    const tokens = new StaticVaultTokenSource(FakeTransit.TOKEN);
    assert.throws(() => tokens.copyToken(new Uint8Array(4)), InvalidArgumentError);
    const destination = new Uint8Array(MAX_TOKEN_LENGTH);
    assert.equal(tokens.copyToken(destination), FakeTransit.TOKEN.length);
    assert.equal(text(destination.subarray(0, FakeTransit.TOKEN.length)), FakeTransit.TOKEN);
  });
});

// --- Where requests go -----------------------------------------------------------------------------

describe('where requests go', () => {
  it('uses the namespace, the mount and the address\'s path prefix', async () => {
    const vault = await startVault('transit/team-a', '/vault');
    const wrapper = create(vault, { address: `http://127.0.0.1:${vault.port}/vault/`, mountPath: 'transit/team-a', namespace: 'team-a/prod' });

    await generate(wrapper);

    assert.equal(vault.requests[0]!.namespace, 'team-a/prod');
    assert.deepEqual(vault.unexpectedRequests, []);
  });

  for (const form of ['without a trailing slash', 'as a URL', 'as localhost'] as const) {
    it(`reaches the same Vault given its address ${form}`, async () => {
      const vault = await startVault();
      const address = form === 'as a URL' ? new URL(vault.address) : form === 'as localhost' ? `http://localhost:${vault.port}`
        : `http://127.0.0.1:${vault.port}`;
      const wrapper = create(vault, { address });

      await generate(wrapper);
      assert.equal(vault.requests.length, 1);
      assert.deepEqual(vault.unexpectedRequests, []);
    });
  }

  it('sends every https request through the agent given', async () => {
    const vault = await startVault();
    const connections: string[] = [];
    class RecordingAgent extends HttpsAgent {
      override createConnection(options: { host?: string }, callback?: unknown): Socket {
        connections.push(options.host ?? '');
        return (HttpsAgent.prototype as unknown as { createConnection: (o: unknown, c: unknown) => Socket }).createConnection.call(this, options, callback);
      }
    }
    const agent = new RecordingAgent();
    cleanups.push(() => agent.destroy());
    // The fake speaks plain http, so the handshake fails - after the agent was asked to make it.
    const wrapper = create(vault, { address: `https://127.0.0.1:${vault.port}/`, agent });

    await assert.rejects(generate(wrapper), isTransitError());

    assert.deepEqual(connections, Array(1 + Limits.MIN_RETRY_COUNT).fill('127.0.0.1'));
  });

  it('after close, rejects every call with ClosedError, leaving an agent given usable', async () => {
    const vault = await startVault();
    const wrapper = create(vault);
    await generate(wrapper);
    wrapper.close();
    wrapper.close();

    await assert.rejects(generate(wrapper), ClosedError);
    await assert.rejects(wrap(wrapper, new Uint8Array(32)), ClosedError);
    await assert.rejects(wrapper.unwrap(ascii('vault:v1:AAAA'), new Uint8Array(32)), ClosedError);
    assert.equal(vault.requests.length, 1);

    let destroyed = false;
    class WatchedAgent extends HttpsAgent {
      override destroy(): void {
        destroyed = true;
        super.destroy();
      }
    }
    const agent = new WatchedAgent();
    newWrapper('https://vault.example.com', { agent }).close();
    assert.ok(!destroyed);
    agent.destroy();
  });

  it('closing stops a call waiting to retry from retrying', async () => {
    const vault = await startVault();
    vault.answer = () => ({ status: 503, body: '{"errors":["Vault is sealed"]}' });
    const wrapper = create(vault, { retryDelayMs: 300 });

    const call = generate(wrapper);
    await sleep(100);
    wrapper.close();

    await assert.rejects(call, ClosedError);
    assert.equal(vault.requests.length, 1);
  });
});

// --- Helpers ----------------------------------------------------------------------------------------

describe('helpers', () => {
  const ciphertexts: [string, boolean][] = [
    ['vault:v1:AAAA', true], ['vault:v1234567890:AB+/=', true], ['vault:v1:', false], ['vault:v:AAAA', false], ['vault:v1AAAA', false],
    ['vault:v12345678901:AAAA', false], ['vault:v1:AA-A', false], ['vault:', false], ['', false],
  ];
  it('isVaultCiphertext accepts only Vault\'s format', () => {
    for (const [value, expected] of ciphertexts) assert.equal(isVaultCiphertext(ascii(value)), expected, value);
  });

  const delays: [number, number, number, number][] = [
    [200, 0, 0, 200], [200, 1, 0, 400], [200, 2, 50, 850], [200, 20, 0, 10_000], [200, 20, 100, 10_100], [0, 3, 37, 37], [10_000, 40, 0, 10_000],
  ];
  it('retryDelay doubles up to the limit, plus the jitter', () => {
    for (const [base, retry, jitter, expected] of delays) assert.equal(retryDelay(base, retry, jitter), expected, `${base} ms, retry ${retry}, jitter ${jitter}`);
  });

  it('base64 encodes and decodes as Buffer does, without a string', () => {
    for (let length = 0; length <= 40; length++) {
      const bytes = randomBytes(length);
      const encoded = new Uint8Array(encodedLength(length) + 2);
      const end = encodeInto(bytes, encoded, 1);
      assert.equal(end, 1 + encodedLength(length));
      assert.equal(text(encoded.subarray(1, end)), bytes.toString('base64'));

      const decoded = new Uint8Array(encodedLength(length));
      const decodedLength = decodeInto(encoded.subarray(1, end), decoded);
      assert.equal(decodedLength, length);
      assert.deepEqual(Buffer.from(decoded.subarray(0, decodedLength)), bytes);
    }
    for (const bad of ['A', 'AA', 'AAA', 'AA=A', 'A===', '====', '=AAA', 'AA-A', 'AA_A', 'AA A', 'AAAA====', 'AA==AAAA']) {
      assert.equal(decodeInto(ascii(bad), new Uint8Array(12)), -1, bad);
    }
  });
});

// --- With the rest of HkdfGuard -------------------------------------------------------------------------

describe('with the rest of HkdfGuard', () => {
  for (const context of [undefined, CONTEXT]) {
    it(`lets a crypto provider generate and reveal its DEK through Vault (${context === undefined ? 'no context' : 'a context'})`, async () => {
      const vault = await startVault();
      const provider = await new AesGcmCryptoProviderFactory().createEphemeral(create(vault, { context }), { expirySeconds: 60 });
      try {
        const expected = new TextEncoder().encode('hello, vault');
        // encrypt zeroes the plaintext it is given, so it gets a copy.
        const encrypted = new Uint8Array(provider.encryptedAllocationLength(expected.length));
        const encryptedLength = provider.encrypt(Uint8Array.from(expected), encrypted);
        const decrypted = new Uint8Array(provider.decryptedAllocationLength(encryptedLength));
        const decryptedLength = provider.decrypt(encrypted.subarray(0, encryptedLength), decrypted);
        assert.deepEqual(decrypted.subarray(0, decryptedLength), expected);
        assert.equal(vault.requests[0]!.operation, context === undefined ? 'datakey' : 'encrypt');
        assert.ok(vault.requests.some((r) => r.operation === 'decrypt'));
      } finally {
        await provider.close();
      }
    });
  }
});

// --- Reading key files -----------------------------------------------------------------------------------

/**
 * A key file in a folder the user running the tests could replace: under the user's temp folder
 * (Windows) or the shared /tmp (Linux and macOS) - neither somewhere only administrators can write.
 */
function userWritableKeyFile(t: TestContext): string {
  const directory = mkdtempSync(join(isWindows ? tmpdir() : '/tmp', 'hkdfguard-keys-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, 'v1.key');
  writeFileSync(path, 'vault:v1:AAAA');
  return path;
}

const notTrusted = (e: unknown) => e instanceof KeyFileError && e.code === 'EACCES' && e.message.includes('not trusted');

describe('reading key files', () => {
  it('refuses by default a file the current user could have replaced', { skip: !isWindows && !isUnix && 'Windows, Linux and Apple silicon macOS only.' }, async (t) => {
    await assert.rejects(newWrapper().readKeyFile(userWritableKeyFile(t)), notTrusted);
  });

  it('trusts administrators only when given no trust', { skip: !isWindows && !isUnix && 'Windows, Linux and Apple silicon macOS only.' }, async (t) => {
    // The same refusal as the default: an omitted trust is administratorsOnly, never "anyone".
    await assert.rejects(newWrapper(undefined, { keyFileTrust: undefined }).readKeyFile(userWritableKeyFile(t)), notTrusted);
  });

  it('refuses a missing path', async () => {
    for (const path of ['', undefined]) {
      await assert.rejects(newWrapper().readKeyFile(path as string), InvalidArgumentError);
    }
  });

  it('reads a file the writer\'s account is trusted for, and it reveals (Windows)', { skip: !isWindows && 'Windows only.' }, async (t) => {
    const vault = await startVault();
    const wrapper = create(vault, { keyFileTrust: new KeyFileTrust({ windowsPrincipals: [windowsCurrentUserSid()] }) });
    const wrapped = await generate(wrapper);
    const path = userWritableKeyFile(t);
    writeFileSync(path, wrapped);

    const read = await wrapper.readKeyFile(path);
    assert.deepEqual(read, wrapped);
    assert.equal(await wrapper.unwrap(read, new Uint8Array(32)), 32);
  });

  it('refuses to trust everyone (Windows)', { skip: !isWindows && 'Windows only.' }, async (t) => {
    const wrapper = newWrapper(undefined, { keyFileTrust: new KeyFileTrust({ windowsPrincipals: ['S-1-1-0'] }) });
    await assert.rejects(wrapper.readKeyFile(userWritableKeyFile(t)), (e: unknown) => e instanceof InvalidArgumentError && e.message.includes('every account'));
  });

  it('reads a file in a directory only its trusted owner can write, and it reveals (Linux and macOS)', { skip: !isUnix && 'Linux and Apple silicon macOS only.' }, async (t) => {
    const directory = keyFileDirectory(t, 'hkdfguard-vaulttransit-');
    if (directory === undefined) return;
    const vault = await startVault();
    const wrapper = create(vault, { keyFileTrust: new KeyFileTrust({ unixUserIds: [process.geteuid!()] }) });
    const wrapped = await generate(wrapper);
    const path = join(directory, 'v1.key');
    writeFileSync(path, wrapped, { mode: 0o600 });

    const read = await wrapper.readKeyFile(path);
    assert.deepEqual(read, wrapped);
    assert.equal(await wrapper.unwrap(read, new Uint8Array(32)), 32);
  });
});

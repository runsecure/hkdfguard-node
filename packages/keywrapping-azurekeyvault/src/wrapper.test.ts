import { strict as assert } from 'node:assert';
import {
  constants, createHash, createPublicKey, generateKeyPairSync, privateDecrypt, publicEncrypt, randomBytes, verify as verifySignature, type KeyObject,
} from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, type TestContext } from 'node:test';
import { createHttpHeaders, type HttpClient, type PipelineRequest, type PipelineResponse } from '@azure/core-rest-pipeline';
import { HkdfGuardError, InvalidArgumentError, isZero, MAX_WRAPPED_KEY_BYTES, type KeyWrapper } from '@runsecure/hkdfguard-abstractions';
import { AesGcmCryptoProviderFactory } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { keyFileDirectory, windowsCurrentUserSid } from '@runsecure/hkdfguard-test-support';
import * as envelope from './envelope.js';
import { AzureKeyVaultError } from './errors.js';
import { KeyFileError, KeyFileTrust } from './index.js';
import { AzureKeyVaultKeyWrapper, GENERATED_KEY_LENGTH, MAX_PLAINTEXT_LENGTH, type AzureKeyVaultKeyWrapperOptions, type KeyVaultCredential } from './wrapper.js';

const HOST = 'myvault.vault.azure.net';
const CONTEXT = 'hkdfguard.test';
const isWindows = process.platform === 'win32';
const isUnix = process.platform === 'linux' || (process.platform === 'darwin' && process.arch === 'arm64');

// ECDSA over P-256 on a digest the caller computed, as Key Vault's ES256 sign and verify take it:
// node:crypto always hashes what it signs, so the fake vault does the curve arithmetic itself.
// Test-only and not constant-time.
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const G: Point = [0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n];
type Point = readonly [bigint, bigint] | undefined;

const mod = (a: bigint, m: bigint) => ((a % m) + m) % m;
function inverse(a: bigint, m: bigint): bigint {
  let [result, base, exponent] = [1n, mod(a, m), m - 2n];
  for (; exponent > 0n; exponent >>= 1n, base = (base * base) % m) if (exponent & 1n) result = (result * base) % m;
  return result;
}
function add(a: Point, b: Point): Point {
  if (a === undefined) return b;
  if (b === undefined) return a;
  if (a[0] === b[0] && mod(a[1] + b[1], P) === 0n) return undefined;
  const slope = a[0] === b[0] ? mod(3n * a[0] * a[0] - 3n, P) * inverse(2n * a[1], P) : mod(b[1] - a[1], P) * inverse(b[0] - a[0], P);
  const x = mod(slope * slope - a[0] - b[0], P);
  return [x, mod(slope * (a[0] - x) - a[1], P)];
}
function multiply(k: bigint, point: Point): Point {
  let result: Point;
  for (let addend = point; k > 0n; k >>= 1n, addend = add(addend, addend)) if (k & 1n) result = add(result, addend);
  return result;
}
const toBigInt = (bytes: Uint8Array) => BigInt(`0x${Buffer.from(bytes).toString('hex') || '0'}`);
const toBytes = (value: bigint) => Buffer.from(value.toString(16).padStart(64, '0'), 'hex');

function ecdsaSign(d: bigint, digest: Uint8Array): Uint8Array {
  for (;;) {
    const k = mod(toBigInt(randomBytes(32)), N);
    const r = k === 0n ? 0n : mod(multiply(k, G)![0], N);
    const s = mod(inverse(k, N) * (toBigInt(digest) + r * d), N);
    if (r !== 0n && s !== 0n) return new Uint8Array(Buffer.concat([toBytes(r), toBytes(s)]));
  }
}
function ecdsaVerify(q: Point, digest: Uint8Array, signature: Uint8Array): boolean {
  if (signature.length !== 64) return false;
  const [r, s] = [toBigInt(signature.subarray(0, 32)), toBigInt(signature.subarray(32))];
  if (r <= 0n || r >= N || s <= 0n || s >= N) return false;
  const w = inverse(s, N);
  const point = add(multiply(mod(toBigInt(digest) * w, N), G), multiply(mod(r * w, N), q));
  return point !== undefined && mod(point[0], N) === r;
}

// Key generation is slow (RSA most of all), so each test takes keys from pools made once, as needed.
const pools = new Map<string, KeyObject[]>();
function pooledKey(type: string, index: number): KeyObject {
  const pool = pools.get(type) ?? [];
  pools.set(type, pool);
  while (pool.length <= index) {
    pool.push(type === 'EC' ? generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey
      : generateKeyPairSync('rsa', { modulusLength: Number(type.slice(4)) }).privateKey);
  }
  return pool[index]!;
}

interface KeyVersion {
  readonly version: string;
  readonly kty: 'RSA' | 'EC';
  readonly privateKey: KeyObject;
  keyOps: string[];
}

interface KeyEntry {
  readonly name: string;
  readonly versions: Map<string, KeyVersion>;
  current: string;
}

type VaultOperation = 'get' | 'wrapkey' | 'unwrapkey' | 'sign' | 'verify';
type Body = Record<string, unknown>;

interface Recorded {
  readonly method: string;
  readonly path: string;
  readonly operation: VaultOperation;
  readonly body: Body;
}

/**
 * An in-process stand-in for Key Vault, answering the Azure SDK's own HTTP requests (the
 * `httpClient` client option) for the five operations the wrapper's clients make: get a key, wrapkey,
 * unwrapkey, sign and verify. It behaves like a vault: the first request on each client is answered
 * with the bearer challenge, RSA keys really wrap and unwrap with RSA-OAEP-256 and EC keys really sign
 * and verify ES256 digests, every key has versions, and an unknown key or version is KeyNotFound. Any
 * operation can be refused with a status and error code, or answered by a handler instead. Every
 * authorized request is recorded with its decoded body.
 */
class FakeKeyVault {
  private readonly keys = new Map<string, KeyEntry>();
  private readonly used = new Map<string, number>();
  readonly requests: Recorded[] = [];
  readonly refusals = new Map<VaultOperation, { status: number; code?: string }>();
  readonly answers = new Map<VaultOperation, (body: Body, key: KeyVersion) => unknown>();
  /** Whether the caller may read keys (get): without it, the SDK does everything in the vault. */
  canGet = true;
  /** Never answer, until the request is aborted. */
  hang = false;
  readonly httpClient: HttpClient = { sendRequest: (request) => this.handle(request) };

  constructor(readonly host = HOST) {}

  /** A key's identifier, at a version if one is given. */
  url(name: string, version?: string): string {
    return `https://${this.host}/keys/${name}${version === undefined ? '' : `/${version}`}`;
  }

  /** Creates a key - "RSA-2048", "RSA-3072", "RSA-4096" or "EC" (P-256) - or a new version of it; returns the version. */
  create(name: string, type: string): string {
    const index = this.used.get(type) ?? 0;
    this.used.set(type, index + 1);
    const version = randomBytes(16).toString('hex');
    const kty = type === 'EC' ? 'EC' : 'RSA';
    const entry = this.keys.get(name.toLowerCase()) ?? { name, versions: new Map<string, KeyVersion>(), current: version };
    entry.versions.set(version, { version, kty, privateKey: pooledKey(type, index), keyOps: kty === 'EC' ? ['sign', 'verify'] : ['wrapKey', 'unwrapKey'] });
    entry.current = version;
    this.keys.set(name.toLowerCase(), entry);
    return version;
  }

  /** A new version of the key, of the same type, which becomes current. */
  rotate(name: string): string {
    const entry = this.keys.get(name.toLowerCase())!;
    const current = entry.versions.get(entry.current)!;
    return this.create(name, current.kty === 'EC' ? 'EC' : `RSA-${current.privateKey.asymmetricKeyDetails!.modulusLength!}`);
  }

  current(name: string): string {
    return this.keys.get(name.toLowerCase())!.current;
  }

  key(name: string, version = this.current(name)): KeyVersion {
    return this.keys.get(name.toLowerCase())!.versions.get(version)!;
  }

  purge(name: string, version: string): void {
    this.keys.get(name.toLowerCase())!.versions.delete(version);
  }

  /** The authorized requests for one operation, as [path, body]. */
  calls(operation: VaultOperation): Recorded[] {
    return this.requests.filter((r) => r.operation === operation);
  }

  private async handle(request: PipelineRequest): Promise<PipelineResponse> {
    const url = new URL(request.url);
    if (this.hang) {
      return new Promise((_, reject) => request.abortSignal?.addEventListener('abort',
        () => reject(Object.assign(new Error('The operation was aborted.'), { name: 'AbortError' })), { once: true }));
    }
    // The SDK's first request on a client carries no token and no body; the challenge names the
    // resource to get a token for, and it sends the request again with both.
    if (request.headers.get('authorization') !== 'Bearer fake-token') {
      return respond(request, 401, '', { 'WWW-Authenticate': 'Bearer authorization="https://login.microsoftonline.com/tenant", resource="https://vault.azure.net"' });
    }
    assert.equal(url.host, this.host);

    const [, collection, name, version, action] = url.pathname.split('/');
    assert.equal(collection, 'keys');
    const operation = (request.method === 'GET' ? 'get' : action) as VaultOperation;
    const body = typeof request.body === 'string' && request.body !== '' ? JSON.parse(request.body) as Body : {};
    this.requests.push({ method: request.method, path: url.pathname, operation, body });

    const refusal = this.refusals.get(operation) ?? (operation === 'get' && !this.canGet ? { status: 403, code: 'Forbidden' } : undefined);
    if (refusal !== undefined) return refuse(request, refusal.status, refusal.code);
    const entry = this.keys.get(name!.toLowerCase());
    const key = entry?.versions.get(version || entry.current);
    if (entry === undefined || key === undefined) return refuse(request, 404, 'KeyNotFound');

    const answer = this.answers.get(operation);
    if (answer !== undefined) return respond(request, 200, answer(body, key));
    const kid = this.url(entry.name, key.version);
    const value = (field: string) => Buffer.from(body[field] as string, 'base64url');
    switch (operation) {
      case 'get':
        return respond(request, 200, { key: { kid, kty: key.kty, key_ops: key.keyOps, ...publicJwk(key) }, attributes: { enabled: true, recoveryLevel: 'Recoverable' } });
      case 'wrapkey':
        if (key.kty !== 'RSA' || body['alg'] !== 'RSA-OAEP-256') return refuse(request, 400, 'BadParameter');
        return respond(request, 200, { kid, value: encode(publicEncrypt({ key: key.privateKey, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING }, value('value'))) });
      case 'unwrapkey':
        if (key.kty !== 'RSA' || body['alg'] !== 'RSA-OAEP-256') return refuse(request, 400, 'BadParameter');
        try {
          return respond(request, 200, { kid, value: encode(privateDecrypt({ key: key.privateKey, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING }, value('value'))) });
        } catch {
          return refuse(request, 400, 'BadParameter');
        }
      case 'sign':
        if (key.kty !== 'EC' || body['alg'] !== 'ES256') return refuse(request, 400, 'BadParameter');
        return respond(request, 200, { kid, value: encode(ecdsaSign(toBigInt(Buffer.from(key.privateKey.export({ format: 'jwk' }).d!, 'base64url')), value('value'))) });
      case 'verify':
        if (key.kty !== 'EC' || body['alg'] !== 'ES256') return refuse(request, 400, 'BadParameter');
        return respond(request, 200, { value: ecdsaVerify(ecPoint(key), value('digest'), value('value')) });
      default:
        throw new Error(`FakeKeyVault does not implement ${request.method} ${url.pathname}`);
    }
  }
}

function publicJwk(key: KeyVersion): Body {
  const { kty: _, ...fields } = createPublicKey(key.privateKey).export({ format: 'jwk' });
  return fields;
}

function ecPoint(key: KeyVersion): Point {
  const { x, y } = key.privateKey.export({ format: 'jwk' });
  return [toBigInt(Buffer.from(x!, 'base64url')), toBigInt(Buffer.from(y!, 'base64url'))];
}

const encode = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');

function respond(request: PipelineRequest, status: number, body: unknown, headers: Record<string, string> = {}): PipelineResponse {
  return {
    request, status, headers: createHttpHeaders({ 'content-type': 'application/json; charset=utf-8', ...headers }),
    bodyAsText: typeof body === 'string' ? body : JSON.stringify(body),
  };
}

function refuse(request: PipelineRequest, status: number, code: string | undefined): PipelineResponse {
  return respond(request, status, { error: { ...(code === undefined ? {} : { code }), message: `${code ?? 'An error'} from FakeKeyVault.` } });
}

/** A credential that hands out a fixed token, or fails as a credential with no sign-in does. */
function credential(failure?: Error): KeyVaultCredential & { readonly scopes: string[] } {
  const scopes: string[] = [];
  return {
    scopes,
    async getToken(scope: string | string[]) {
      scopes.push(...[scope].flat());
      if (failure !== undefined) throw failure;
      return { token: 'fake-token', expiresOnTimestamp: Date.now() + 3_600_000 };
    },
  };
}

/** A vault with an RSA-2048 wrapping key "wrap" and a P-256 signing key "sign". */
function vault(): FakeKeyVault {
  const v = new FakeKeyVault();
  v.create('wrap', 'RSA-2048');
  v.create('sign', 'EC');
  return v;
}

function wrapperFor(v: FakeKeyVault, options: AzureKeyVaultKeyWrapperOptions & { wrap?: string; sign?: string; credential?: KeyVaultCredential } = {}):
  AzureKeyVaultKeyWrapper {
  return new AzureKeyVaultKeyWrapper(options.wrap ?? v.url('wrap'), options.sign ?? v.url('sign'), options.credential ?? credential(), {
    context: CONTEXT,
    clientOptions: { httpClient: v.httpClient, retryOptions: { maxRetries: 0 } },
    ...options,
  });
}

async function wrapWith(wrapper: KeyWrapper, dek: Uint8Array): Promise<Uint8Array> {
  const result = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
  const length = await wrapper.wrap(dek, result);
  return result.slice(0, length);
}

async function generate(wrapper: KeyWrapper): Promise<Uint8Array> {
  const result = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
  const length = await wrapper.generateAndWrap(result);
  return result.slice(0, length);
}

const dek = () => new Uint8Array(randomBytes(32));
const filled = (length: number) => new Uint8Array(length).fill(0xaa);
const parse = (wrapped: Uint8Array) => envelope.parse(wrapped, (message) => new Error(message));
const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

/** A predicate for assert.rejects: an AzureKeyVaultError whose message is `message` exactly, or matches it. */
function vaultError(message: string | RegExp, operation?: string): (e: unknown) => boolean {
  return (e: unknown) => {
    assert.ok(e instanceof AzureKeyVaultError, String(e));
    assert.equal(e.code, 'ERR_HKDFGUARD_AZURE_KEY_VAULT');
    if (typeof message === 'string') assert.equal(e.message, message);
    else assert.match(e.message, message);
    if (operation !== undefined) assert.equal(e.operation, operation);
    return true;
  };
}

describe('constructing an AzureKeyVaultKeyWrapper', () => {
  it('refuses missing or invalid arguments', () => {
    const v = vault();
    const [wrap, sign, ok] = [v.url('wrap'), v.url('sign'), credential()];
    for (const [w, s, c, options] of [
      [undefined, sign, ok, {}], [wrap, undefined, ok, {}], [42, sign, ok, {}], ['', sign, ok, {}], [wrap, 'not a key', ok, {}],
      [wrap, sign, undefined, {}], [wrap, sign, null, {}], [wrap, sign, {}, {}], [wrap, sign, { getToken: 'token' }, {}],
      [wrap, sign, ok, null], [wrap, sign, ok, 'context'], [wrap, sign, ok, { context: 42 }], [wrap, sign, ok, { context: '\ud800' }],
      [wrap, sign, ok, { context: 'x'.repeat(65_536) }], [wrap, sign, ok, { keyFileTrust: 'S-1-5-18' }],
      [wrap, sign, ok, { keyFileTrust: { windowsPrincipals: [] } }], [wrap, sign, ok, { clientOptions: 'retry' }],
    ] as const) {
      assert.throws(() => new AzureKeyVaultKeyWrapper(w as string, s as string, c as KeyVaultCredential, options as AzureKeyVaultKeyWrapperOptions),
        InvalidArgumentError, JSON.stringify([w, s, options]));
    }
  });

  it('refuses the same key for wrapping and signing, in any version or case', () => {
    const v = vault();
    for (const signing of [v.url('wrap'), v.url('WRAP'), v.url('wrap', v.current('wrap')), `https://MYVAULT.vault.azure.net/keys/wrap/`]) {
      assert.throws(() => new AzureKeyVaultKeyWrapper(v.url('wrap'), signing, credential()),
        (e: unknown) => e instanceof InvalidArgumentError && e.message.includes('use an RSA key to wrap and a separate EC P-256 key to sign'));
    }
  });

  it('allows keys with the same name in different vaults', () => {
    const wrapper = new AzureKeyVaultKeyWrapper('https://one.vault.azure.net/keys/k', 'https://two.vault.azure.net/keys/k', credential());
    assert.equal(wrapper.wrappingKeyId, 'https://one.vault.azure.net/keys/k');
    assert.equal(wrapper.signingKeyId, 'https://two.vault.azure.net/keys/k');
  });

  it('makes no call until the wrapper is used', () => {
    const v = vault();
    const c = credential();
    wrapperFor(v, { credential: c });
    assert.equal(v.requests.length, 0);
    assert.equal(c.scopes.length, 0);
  });

  it('is a KeyWrapper', () => {
    const wrapper: KeyWrapper = wrapperFor(vault());
    assert.equal(typeof wrapper.readKeyFile, 'function');
    assert.equal(GENERATED_KEY_LENGTH, 32);
    assert.equal(MAX_PLAINTEXT_LENGTH, 190);
  });
});

describe('the fake vault', () => {
  it('signs ES256 digests that node:crypto verifies over the data, as Key Vault\'s do', async () => {
    // So a wrapped DEK's signature is a standard ES256 signature over envelope.signedData: what the
    // other ports, and Key Vault itself, verify.
    const v = vault();
    const wrapped = await generate(wrapperFor(v));
    const parts = parse(wrapped);
    const data = envelope.signedData(wrapped.subarray(0, parts.unsignedLength), envelope.encodeContext(CONTEXT));

    assert.ok(verifySignature('sha256', data, { key: v.key('sign').privateKey, dsaEncoding: 'ieee-p1363' }, parts.signature));
    assert.ok(!verifySignature('sha256', data.subarray(1), { key: v.key('sign').privateKey, dsaEncoding: 'ieee-p1363' }, parts.signature));
  });
});

describe('wrap and unwrap', () => {
  it('round-trip a DEK', async () => {
    const wrapper = wrapperFor(vault());
    const key = dek();
    const wrapped = await wrapWith(wrapper, key);
    const revealed = new Uint8Array(32);

    assert.equal(wrapped.length, 256 + envelope.OVERHEAD);
    assert.equal(await wrapper.unwrap(wrapped, revealed), 32);
    assert.deepEqual(revealed, key);
  });

  it('wrap sends Key Vault the DEK and leaves the caller\'s plaintext alone', async () => {
    const v = vault();
    const key = dek();
    const copy = Uint8Array.from(key);
    await wrapWith(wrapperFor(v), key);

    assert.deepEqual(key, copy);
    const [request] = v.calls('wrapkey');
    assert.equal(request!.body['alg'], 'RSA-OAEP-256');
    assert.deepEqual(new Uint8Array(Buffer.from(request!.body['value'] as string, 'base64url')), copy);
  });

  it('wrap reads each key\'s current version, wraps and signs under it, and records it', async () => {
    const v = vault();
    const wrapped = await wrapWith(wrapperFor(v), dek());
    const parts = parse(wrapped);

    assert.equal(parts.wrappingKeyVersion, v.current('wrap'));
    assert.equal(parts.signingKeyVersion, v.current('sign'));
    assert.deepEqual(v.calls('get').map((r) => r.path), ['/keys/wrap/', '/keys/sign/']);
    assert.deepEqual(v.calls('wrapkey').map((r) => r.path), [`/keys/wrap/${v.current('wrap')}/wrapkey`]);
    assert.deepEqual(v.calls('sign').map((r) => r.path), [`/keys/sign/${v.current('sign')}/sign`]);
    // ES256 over the SHA-256 digest of the signed data, computed here.
    const data = envelope.signedData(wrapped.subarray(0, parts.unsignedLength), envelope.encodeContext(CONTEXT));
    assert.equal(v.calls('sign')[0]!.body['value'], encode(createHash('sha256').update(data).digest()));
  });

  it('wrap under versions named at construction uses those versions, whatever is current', async () => {
    const v = vault();
    const [wrapVersion, signVersion] = [v.current('wrap'), v.current('sign')];
    v.rotate('wrap');
    v.rotate('sign');
    const wrapper = wrapperFor(v, { wrap: v.url('wrap', wrapVersion), sign: v.url('sign', signVersion) });
    const parts = parse(await wrapWith(wrapper, dek()));

    assert.equal(parts.wrappingKeyVersion, wrapVersion);
    assert.equal(parts.signingKeyVersion, signVersion);
    assert.deepEqual(v.calls('wrapkey').map((r) => r.path), [`/keys/wrap/${wrapVersion}/wrapkey`]);
  });

  it('keeps the version it resolved for as long as the wrapper lives; a new wrapper picks up a rotation', async () => {
    const v = vault();
    const wrapper = wrapperFor(v);
    const first = parse(await wrapWith(wrapper, dek()));
    v.rotate('wrap');
    v.rotate('sign');
    const second = parse(await wrapWith(wrapper, dek()));
    const fresh = parse(await wrapWith(wrapperFor(v), dek()));

    assert.deepEqual([second.wrappingKeyVersion, second.signingKeyVersion], [first.wrappingKeyVersion, first.signingKeyVersion]);
    assert.deepEqual([fresh.wrappingKeyVersion, fresh.signingKeyVersion], [v.current('wrap'), v.current('sign')]);
  });

  it('unwrap verifies the signature first, then unwraps, both under the recorded versions', async () => {
    const v = vault();
    const wrapper = wrapperFor(v);
    const wrapped = await wrapWith(wrapper, dek());
    const parts = parse(wrapped);
    v.requests.length = 0;

    await wrapper.unwrap(wrapped, new Uint8Array(32));

    const posts = v.requests.filter((r) => r.method === 'POST').map((r) => r.path);
    assert.deepEqual(posts, [`/keys/sign/${parts.signingKeyVersion}/verify`, `/keys/wrap/${parts.wrappingKeyVersion}/unwrapkey`]);
  });

  it('unwrap still reveals older key files after both keys rotate', async () => {
    const v = vault();
    const key = dek();
    const wrapped = await wrapWith(wrapperFor(v), key);
    v.rotate('wrap');
    v.rotate('sign');
    const wrapper = wrapperFor(v);
    const newer = parse(await wrapWith(wrapper, dek()));
    const revealed = new Uint8Array(32);

    assert.notEqual(newer.wrappingKeyVersion, parse(wrapped).wrappingKeyVersion);
    assert.equal(await wrapper.unwrap(wrapped, revealed), 32);
    assert.deepEqual(revealed, key);
  });

  it('generateAndWrap produces a 32-byte DEK that reveals', async () => {
    const v = vault();
    const wrapper = wrapperFor(v);
    const wrapped = await generate(wrapper);
    const revealed = new Uint8Array(32);

    assert.equal(wrapped.length, 359);
    assert.equal(Buffer.from(v.calls('wrapkey')[0]!.body['value'] as string, 'base64url').length, GENERATED_KEY_LENGTH);
    assert.equal(await wrapper.unwrap(wrapped, revealed), 32);
    assert.ok(!isZero(revealed));
    assert.notDeepEqual(await generate(wrapper), wrapped);
  });

  it('unwrap writes into a view of a larger buffer', async () => {
    const wrapper = wrapperFor(vault());
    const key = dek();
    const buffer = filled(64);

    assert.equal(await wrapper.unwrap(await wrapWith(wrapper, key), buffer.subarray(16, 48)), 32);
    assert.deepEqual(buffer.subarray(16, 48), key);
    assert.deepEqual(buffer.subarray(0, 16), filled(16));
  });

  it('no context and an empty context are the same context', async () => {
    const v = vault();
    const wrapped = await wrapWith(wrapperFor(v, { context: undefined }), dek());
    assert.equal(await wrapperFor(v, { context: '' }).unwrap(wrapped, new Uint8Array(32)), 32);
  });

  it('wrap accepts the largest plaintext RSA-OAEP-256 wraps under a 2048-bit key', async () => {
    const wrapper = wrapperFor(vault());
    const key = new Uint8Array(randomBytes(MAX_PLAINTEXT_LENGTH));
    const revealed = new Uint8Array(MAX_PLAINTEXT_LENGTH);

    assert.equal(await wrapper.unwrap(await wrapWith(wrapper, key), revealed), MAX_PLAINTEXT_LENGTH);
    assert.deepEqual(revealed, key);
  });

  it('wraps under an RSA-3072 key into a key file', async () => {
    const v = new FakeKeyVault();
    v.create('wrap', 'RSA-3072');
    v.create('sign', 'EC');
    const wrapper = wrapperFor(v);
    const wrapped = await generate(wrapper);

    assert.equal(wrapped.length, 487);
    assert.equal(await wrapper.unwrap(wrapped, new Uint8Array(32)), 32);
  });
});

describe('unwrap refuses', () => {
  it('a wrapped DEK forged from the public key, without unwrapping it', async () => {
    // Anyone can RSA-OAEP-wrap a DEK of their choosing under the public key; without the signing
    // key's private half they can't sign it.
    const v = vault();
    const chosen = dek();
    const ciphertext = publicEncrypt({ key: v.key('wrap').privateKey, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING }, chosen);
    const unsigned = envelope.buildUnsigned(v.current('wrap'), new Uint8Array(ciphertext), (m) => new Error(m));
    const forged = new Uint8Array(unsigned.length + 80);
    envelope.write(unsigned, v.current('sign'), new Uint8Array(randomBytes(64)), forged, (m) => new Error(m));
    const result = filled(32);

    await assert.rejects(wrapperFor(v).unwrap(forged, result), vaultError(/signature doesn't verify under 'sign' version/, 'verify'));
    assert.ok(isZero(result));
    assert.equal(v.calls('unwrapkey').length, 0);
  });

  it('a wrapped DEK changed anywhere, without unwrapping it, and zeroes the result', async () => {
    const v = vault();
    const wrapper = wrapperFor(v);
    const wrapped = await wrapWith(wrapper, dek());
    for (const offset of [0, 4, 5, 20, 21, 23, 100, 278, 279, 295, wrapped.length - 1]) {
      const changed = Uint8Array.from(wrapped);
      changed[offset]! ^= 1;
      const result = filled(32);

      await assert.rejects(wrapper.unwrap(changed, result), AzureKeyVaultError, `offset ${offset}`);
      assert.ok(isZero(result), `offset ${offset}`);
    }
    assert.equal(v.calls('unwrapkey').length, 0);
  });

  it('a wrapped DEK made under another context', async () => {
    const v = vault();
    const wrapped = await wrapWith(wrapperFor(v), dek());
    for (const context of ['hkdfguard.test.other', 'HKDFGUARD.TEST', '', undefined]) {
      await assert.rejects(wrapperFor(v, { context }).unwrap(wrapped, new Uint8Array(32)), vaultError(/signature doesn't verify/));
    }
    assert.equal(v.calls('unwrapkey').length, 0);
  });

  it('a wrapped DEK made with other keys', async () => {
    const v = vault();
    v.create('wrap2', 'RSA-2048');
    v.create('sign2', 'EC');
    const wrapped = await wrapWith(wrapperFor(v), dek());

    // The versions it records aren't versions of this wrapper's keys.
    await assert.rejects(wrapperFor(v, { wrap: v.url('wrap2'), sign: v.url('sign2') }).unwrap(wrapped, new Uint8Array(32)),
      vaultError('Azure Key Vault verify failed for key \'sign2\': KeyNotFound (HTTP 404).', 'verify'));
  });

  it('a wrapped DEK whose recorded version has been purged', async () => {
    const v = vault();
    const wrapper = wrapperFor(v);
    const wrapped = await wrapWith(wrapper, dek());
    v.purge('wrap', parse(wrapped).wrappingKeyVersion);
    const result = filled(32);

    await assert.rejects(wrapperFor(v).unwrap(wrapped, result), vaultError('Azure Key Vault unwrap failed for key \'wrap\': KeyNotFound (HTTP 404).', 'unwrap'));
    assert.ok(isZero(result));
  });

  it('what isn\'t a wrapped DEK, without calling Key Vault, and zeroes the result', async () => {
    const v = vault();
    for (const wrapped of [new Uint8Array(0), new Uint8Array(randomBytes(359)), new TextEncoder().encode('HGKV'), new Uint8Array(envelope.OVERHEAD)]) {
      const result = filled(32);
      await assert.rejects(wrapperFor(v).unwrap(wrapped, result),
        vaultError('This is not a wrapped DEK written by AzureKeyVaultKeyWrapper.', 'unwrap'));
      assert.ok(isZero(result));
    }
    assert.equal(v.requests.length, 0);
  });

  it('a result too small, and zeroes it', async () => {
    const wrapper = wrapperFor(vault());
    const wrapped = await wrapWith(wrapper, dek());
    const result = filled(31);

    await assert.rejects(wrapper.unwrap(wrapped, result), (e: unknown) => e instanceof InvalidArgumentError && e.message.includes('32 bytes; result holds 31'));
    assert.ok(isZero(result));
  });

  it('an answer with no key', async () => {
    const v = vault();
    const wrapper = wrapperFor(v);
    const wrapped = await wrapWith(wrapper, dek());
    v.answers.set('unwrapkey', () => ({ kid: v.url('wrap', v.current('wrap')), value: '' }));
    const result = filled(32);

    await assert.rejects(wrapper.unwrap(wrapped, result), vaultError('Azure Key Vault unwrap for key \'wrap\' returned no key.', 'unwrap'));
    assert.ok(isZero(result));
  });

  it('a verify answer that isn\'t true', async () => {
    const v = vault();
    const wrapper = wrapperFor(v);
    const wrapped = await wrapWith(wrapper, dek());
    for (const answer of [{ value: false }, {}, { value: 'true' }]) {
      v.answers.set('verify', () => answer);
      await assert.rejects(wrapper.unwrap(wrapped, new Uint8Array(32)), vaultError(/signature doesn't verify/), JSON.stringify(answer));
    }
    assert.equal(v.calls('unwrapkey').length, 0);
  });

  it('arguments that aren\'t byte arrays, zeroing the result', async () => {
    const wrapper = wrapperFor(vault());
    const result = filled(32);
    await assert.rejects(wrapper.unwrap('HGKV' as unknown as Uint8Array, result), InvalidArgumentError);
    assert.ok(isZero(result));
    await assert.rejects(wrapper.unwrap(new Uint8Array(359), [] as unknown as Uint8Array), InvalidArgumentError);
  });
});

describe('wrap refuses', () => {
  it('a plaintext RSA-OAEP-256 can\'t wrap, or a result that isn\'t a byte array', async () => {
    const v = vault();
    for (const size of [0, MAX_PLAINTEXT_LENGTH + 1]) {
      await assert.rejects(wrapperFor(v).wrap(new Uint8Array(size), new Uint8Array(512)),
        (e: unknown) => e instanceof InvalidArgumentError && e.message === `Azure Key Vault wraps 1-190 bytes; got ${size}.`);
    }
    await assert.rejects(wrapperFor(v).wrap([1, 2] as unknown as Uint8Array, new Uint8Array(512)), InvalidArgumentError);
    await assert.rejects(wrapperFor(v).wrap(dek(), undefined as unknown as Uint8Array), InvalidArgumentError);
    await assert.rejects(wrapperFor(v).generateAndWrap(null as unknown as Uint8Array), InvalidArgumentError);
    assert.equal(v.requests.length, 0);
  });

  it('a result too small, leaving it as it was', async () => {
    const result = filled(358);
    await assert.rejects(wrapperFor(vault()).wrap(dek(), result),
      (e: unknown) => e instanceof InvalidArgumentError && e.message === 'The wrapped DEK is 359 bytes; result holds 358.');
    assert.deepEqual(result, filled(358));
  });

  it('an RSA key too large for a key file, before signing', async () => {
    const v = new FakeKeyVault();
    v.create('wrap', 'RSA-4096');
    v.create('sign', 'EC');

    await assert.rejects(generate(wrapperFor(v)), vaultError(
      'The wrapped DEK would be 615 bytes; a wrapped DEK is at most 512. Use a 2048- or 3072-bit RSA key for \'wrap\'.', 'wrap'));
    assert.equal(v.calls('sign').length, 0);
  });

  it('a signature that isn\'t ES256\'s', async () => {
    const v = vault();
    v.answers.set('sign', (_, key) => ({ kid: v.url('sign', key.version), value: encode(randomBytes(96)) }));

    await assert.rejects(generate(wrapperFor(v)), vaultError(
      'Azure Key Vault returned a 96-byte signature; an ES256 signature is 64. The signing key must be an EC P-256 key.', 'sign'));
  });

  it('a wrapping key Key Vault reports as another key', async () => {
    const v = vault();
    for (const kid of [`https://${HOST}/keys/other/${'a'.repeat(32)}`, `https://other.vault.azure.net/keys/wrap/${'a'.repeat(32)}`]) {
      v.answers.set('get', (_, key) => ({ key: { kid, kty: 'RSA', key_ops: key.keyOps, ...publicJwk(key) } }));
      await assert.rejects(generate(wrapperFor(v)), vaultError(`Azure Key Vault wrap for key 'wrap' reported key '${kid}' instead.`, 'wrap'));
    }
    assert.equal(v.calls('wrapkey').length, 0);
  });

  it('a key Key Vault reports with no version, or an identifier that isn\'t one', async () => {
    const v = vault();
    v.answers.set('get', (_, key) => ({ key: { kid: v.url('wrap'), kty: 'RSA', key_ops: key.keyOps, ...publicJwk(key) } }));
    await assert.rejects(generate(wrapperFor(v)), vaultError('Azure Key Vault wrap for key \'wrap\' didn\'t report which version is current.', 'wrap'));

    v.answers.set('get', (_, key) => ({ key: { kid: 'https://myvault.vault.azure.net/secrets/wrap', kty: 'RSA', ...publicJwk(key) } }));
    await assert.rejects(generate(wrapperFor(v)), vaultError(/^Azure Key Vault wrap for key 'wrap' reported key "https:\/\/myvault\.vault\.azure\.net\/secrets\/wrap", which isn't a key identifier\.$/));
  });

  it('a key version Key Vault reports that isn\'t one a wrapped DEK can record', async () => {
    const v = vault();
    const version = v.current('wrap');
    v.answers.set('get', (_, key) => ({ key: { kid: v.url('wrap', `${version}00`), kty: 'RSA', key_ops: key.keyOps, ...publicJwk(key) } }));

    await assert.rejects(generate(wrapperFor(v)), AzureKeyVaultError);
    assert.equal(v.calls('sign').length, 0);
  });

  it('a key Key Vault may not wrap with, as the SDK reports it', async () => {
    const v = vault();
    v.key('wrap').keyOps = ['unwrapKey'];

    await assert.rejects(generate(wrapperFor(v)), vaultError(/^Azure Key Vault wrap failed for key 'wrap': Operation wrapKey is not supported on key /, 'wrap'));
    assert.equal(v.calls('wrapkey').length, 0);
  });
});

describe('without permission to read the keys', () => {
  it('does everything in the vault when the identifiers name versions', async () => {
    const v = vault();
    v.canGet = false;
    const wrapper = wrapperFor(v, { wrap: v.url('wrap', v.current('wrap')), sign: v.url('sign', v.current('sign')) });
    const key = dek();
    const wrapped = await wrapWith(wrapper, key);
    const revealed = new Uint8Array(32);

    assert.equal(await wrapper.unwrap(wrapped, revealed), 32);
    assert.deepEqual(revealed, key);
    assert.deepEqual(new Set(v.requests.map((r) => r.operation)), new Set(['get', 'wrapkey', 'sign', 'verify', 'unwrapkey']));
  });

  it('refuses to wrap under a key named without a version, naming the permission it needs', async () => {
    const v = vault();
    v.canGet = false;

    await assert.rejects(generate(wrapperFor(v)), (e: unknown) => {
      vaultError('Azure Key Vault wrap for key \'wrap\' couldn\'t read its current version: Forbidden (HTTP 403). Give the identity get on the key, '
        + 'or name a version in its key identifier.', 'wrap')(e);
      assert.equal(((e as AzureKeyVaultError).cause as { statusCode?: number }).statusCode, 403);
      return true;
    });
    assert.equal(v.calls('wrapkey').length, 0);
  });

  it('still unwraps key files, which name their versions', async () => {
    const v = vault();
    const key = dek();
    const wrapped = await wrapWith(wrapperFor(v), key);
    v.canGet = false;
    const revealed = new Uint8Array(32);

    assert.equal(await wrapperFor(v).unwrap(wrapped, revealed), 32);
    assert.deepEqual(revealed, key);
  });
});

describe('failures', () => {
  it('a Key Vault refusal is an AzureKeyVaultError naming the operation, the key, the error code and the status', async () => {
    for (const [operation, refused, status, code] of [
      ['wrap', 'wrapkey', 403, 'Forbidden'], ['sign', 'sign', 403, 'ForbiddenByRbac'], ['verify', 'verify', 404, 'KeyNotFound'],
      ['unwrap', 'unwrapkey', 400, 'BadParameter'], ['wrap', 'get', 404, 'KeyNotFound'], ['sign', 'sign', 429, 'Throttled'],
    ] as const) {
      const v = vault();
      const wrapped = await wrapWith(wrapperFor(v), dek());
      v.refusals.set(refused, { status, code });
      const keyName = operation === 'wrap' || operation === 'unwrap' ? 'wrap' : 'sign';
      const result = filled(32);
      const call = operation === 'wrap' || operation === 'sign' ? wrapWith(wrapperFor(v), dek()) : wrapperFor(v).unwrap(wrapped, result);

      await assert.rejects(call, (e: unknown) => {
        vaultError(`Azure Key Vault ${operation} failed for key '${keyName}': ${code} (HTTP ${status}).`, operation)(e);
        const cause = (e as AzureKeyVaultError).cause as { name: string; statusCode: number; code: string };
        assert.deepEqual([cause.name, cause.statusCode, cause.code], ['RestError', status, code]);
        assert.match((e as AzureKeyVaultError).keyId, new RegExp(`^https://${escape(HOST)}/keys/${keyName}`));
        return true;
      }, `${refused} ${status}`);
      if (operation === 'verify' || operation === 'unwrap') assert.ok(isZero(result));
    }
  });

  it('a refusal without an error code is still named', async () => {
    const v = vault();
    v.refusals.set('wrapkey', { status: 400 });
    await assert.rejects(generate(wrapperFor(v)), vaultError('Azure Key Vault wrap failed for key \'wrap\': error (HTTP 400).'));
  });

  it('a credential that can\'t get a token is an AzureKeyVaultError with its message', async () => {
    const failure = Object.assign(new Error('DefaultAzureCredential failed to retrieve a token from the included credentials.'), { name: 'AggregateAuthenticationError' });
    const c = credential(failure);

    await assert.rejects(generate(wrapperFor(vault(), { credential: c })), (e: unknown) => {
      vaultError('Azure Key Vault wrap failed for key \'wrap\': DefaultAzureCredential failed to retrieve a token from the included credentials.', 'wrap')(e);
      assert.equal((e as AzureKeyVaultError).cause, failure);
      return true;
    });
    // The scope the challenge named: Key Vault's.
    assert.deepEqual(c.scopes, ['https://vault.azure.net/.default']);
  });

  it('a refused connection is an AzureKeyVaultError', async () => {
    // A client-side failure end to end, through the SDK's own HTTP client: a port this machine just
    // stopped listening on, so the connection is refused locally and no request leaves it.
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as { port: number };
    await new Promise<void>((resolve) => server.close(() => resolve()));
    const wrapper = new AzureKeyVaultKeyWrapper(`https://localhost:${port}/keys/wrap/${'a'.repeat(32)}`, `https://localhost:${port}/keys/sign/${'b'.repeat(32)}`,
      credential(), { clientOptions: { retryOptions: { maxRetries: 0 } } });

    await assert.rejects(generate(wrapper), (e: unknown) => {
      vaultError(/^Azure Key Vault wrap failed for key 'wrap': .*ECONNREFUSED/, 'wrap')(e);
      assert.equal(((e as AzureKeyVaultError).cause as { name?: string; code?: string }).code, 'ECONNREFUSED');
      return true;
    });
  });

  it('an abort is rethrown as the SDK reports it, and unwrap zeroes the result', async () => {
    const v = vault();
    const wrapped = await wrapWith(wrapperFor(v), dek());
    v.hang = true;
    const isAbort = (e: unknown) => e instanceof Error && e.name === 'AbortError' && !(e instanceof HkdfGuardError);
    // Not AbortSignal.timeout, whose timer doesn't keep the process alive while the vault hangs.
    const abortSoon = () => {
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 50);
      return controller.signal;
    };

    await assert.rejects(wrapperFor(v).wrap(dek(), new Uint8Array(512), abortSoon()), isAbort);
    const result = filled(32);
    await assert.rejects(wrapperFor(v).unwrap(wrapped, result, abortSoon()), isAbort);
    assert.ok(isZero(result));
  });

  it('an already-aborted signal makes no call', async () => {
    const v = vault();
    const signal = AbortSignal.abort();
    const result = filled(32);

    await assert.rejects(wrapperFor(v).wrap(dek(), new Uint8Array(512), signal), { name: 'AbortError' });
    await assert.rejects(wrapperFor(v).generateAndWrap(new Uint8Array(512), signal), { name: 'AbortError' });
    await assert.rejects(wrapperFor(v).unwrap(new Uint8Array(359), result, signal), { name: 'AbortError' });
    assert.ok(isZero(result));
    assert.equal(v.requests.length, 0);
  });
});

describe('Key Vault clients', () => {
  it('read each key version once, and keep it', async () => {
    const v = vault();
    const wrapper = wrapperFor(v);
    const wrapped = await wrapWith(wrapper, dek());
    for (let i = 0; i < 3; i++) {
      await wrapWith(wrapper, dek());
      await wrapper.unwrap(wrapped, new Uint8Array(32));
    }

    // The current versions read once each; the clients for them reuse the keys read, and never get them again.
    assert.deepEqual(v.calls('get').map((r) => r.path), ['/keys/wrap/', '/keys/sign/']);
    assert.equal(v.calls('wrapkey').length, 4);
    assert.equal(v.calls('unwrapkey').length, 3);
  });

  it('read a version a key file names once, and keep it', async () => {
    const v = vault();
    const wrapped = await wrapWith(wrapperFor(v), dek());
    const parts = parse(wrapped);
    const wrapper = wrapperFor(v);
    v.requests.length = 0;
    for (let i = 0; i < 3; i++) await wrapper.unwrap(wrapped, new Uint8Array(32));

    assert.deepEqual(v.calls('get').map((r) => r.path), [`/keys/sign/${parts.signingKeyVersion}`, `/keys/wrap/${parts.wrappingKeyVersion}`]);
  });

  it('are given the client options', async () => {
    const v = vault();
    const wrapper = wrapperFor(v, { clientOptions: { httpClient: v.httpClient, retryOptions: { maxRetries: 0 }, userAgentOptions: { userAgentPrefix: 'hkdfguard-test' } } });
    const seen: string[] = [];
    const send = v.httpClient.sendRequest;
    v.httpClient.sendRequest = (request) => {
      seen.push(request.headers.get('user-agent') ?? '');
      return send(request);
    };

    await generate(wrapper);
    assert.ok(seen.length > 0 && seen.every((agent) => agent.startsWith('hkdfguard-test ')), seen.join('\n'));
  });
});

describe('with the rest of HkdfGuard', () => {
  it('lets a crypto provider generate and reveal its DEK through Key Vault', async () => {
    const v = vault();
    const provider = await new AesGcmCryptoProviderFactory().createEphemeral(wrapperFor(v), { expirySeconds: 60 });
    try {
      const expected = new TextEncoder().encode('hello, key vault');
      // encrypt zeroes the plaintext it is given, so it gets a copy.
      const encrypted = new Uint8Array(provider.encryptedAllocationLength(expected.length));
      const encryptedLength = provider.encrypt(Uint8Array.from(expected), encrypted);
      const decrypted = new Uint8Array(provider.decryptedAllocationLength(encryptedLength));
      const decryptedLength = provider.decrypt(encrypted.subarray(0, encryptedLength), decrypted);
      assert.deepEqual(decrypted.subarray(0, decryptedLength), expected);
      assert.equal(v.calls('wrapkey').length, 1);
      assert.ok(v.calls('unwrapkey').length >= 1);
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
  writeFileSync(path, randomBytes(359));
  return path;
}

const notTrusted = (e: unknown) => e instanceof KeyFileError && e.code === 'EACCES' && e.message.includes('not trusted');

describe('reading key files', () => {
  it('refuses by default a file the current user could have replaced', { skip: !isWindows && !isUnix && 'Windows, Linux and Apple silicon macOS only.' }, async (t) => {
    await assert.rejects(wrapperFor(vault()).readKeyFile(userWritableKeyFile(t)), notTrusted);
  });

  it('trusts administrators only when given no trust', { skip: !isWindows && !isUnix && 'Windows, Linux and Apple silicon macOS only.' }, async (t) => {
    // The same refusal as the default: an omitted trust is administratorsOnly, never "anyone".
    await assert.rejects(wrapperFor(vault(), { keyFileTrust: undefined }).readKeyFile(userWritableKeyFile(t)), notTrusted);
  });

  it('refuses a missing path', async () => {
    for (const path of ['', undefined]) {
      await assert.rejects(wrapperFor(vault()).readKeyFile(path as string), InvalidArgumentError);
    }
  });

  it('reads a file the writer\'s account is trusted for, and it reveals (Windows)', { skip: !isWindows && 'Windows only.' }, async (t) => {
    const v = vault();
    const wrapper = wrapperFor(v, { keyFileTrust: new KeyFileTrust({ windowsPrincipals: [windowsCurrentUserSid()] }) });
    const wrapped = await generate(wrapper);
    const path = userWritableKeyFile(t);
    writeFileSync(path, wrapped);

    const read = await wrapper.readKeyFile(path);
    assert.deepEqual(read, wrapped);
    assert.equal(await wrapper.unwrap(read, new Uint8Array(32)), 32);
  });

  it('refuses to trust everyone (Windows)', { skip: !isWindows && 'Windows only.' }, async (t) => {
    const wrapper = wrapperFor(vault(), { keyFileTrust: new KeyFileTrust({ windowsPrincipals: ['S-1-1-0'] }) });
    await assert.rejects(wrapper.readKeyFile(userWritableKeyFile(t)), (e: unknown) => e instanceof InvalidArgumentError && e.message.includes('every account'));
  });

  it('reads a file in a directory only its trusted owner can write, and it reveals (Linux and macOS)', { skip: !isUnix && 'Linux and Apple silicon macOS only.' }, async (t) => {
    const directory = keyFileDirectory(t, 'hkdfguard-azurekeyvault-');
    if (directory === undefined) return;
    const v = vault();
    const wrapper = wrapperFor(v, { keyFileTrust: new KeyFileTrust({ unixUserIds: [process.geteuid!()] }) });
    const wrapped = await generate(wrapper);
    const path = join(directory, 'v1.key');
    writeFileSync(path, wrapped, { mode: 0o600 });

    const read = await wrapper.readKeyFile(path);
    assert.deepEqual(read, wrapped);
    assert.equal(await wrapper.unwrap(read, new Uint8Array(32)), 32);
  });
});

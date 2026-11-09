import { strict as assert } from 'node:assert';
import { Readable } from 'node:stream';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { ClosedError, HkdfGuardError } from '@runsecure/hkdfguard-abstractions';
import { readBody } from './body.js';
import { VaultJsonError, VaultRedirectError, VaultResponseError } from './client-errors.js';
import type { VaultRequest } from './client-options.js';
import { VaultClient } from './client.js';
import { VaultRequestError } from './errors.js';
import { decrypt, harness, makeProtector, makeRing, TOKEN, type Harness } from './fake-vault.test-support.js';
import { JsonValue } from './json.js';
import { ReplicationForwardingMode } from './replication.js';
import { StaticVaultToken, type VaultTokenProvider } from './token.js';

let h: Harness;
beforeEach(async () => {
  h = await harness();
});
afterEach(async () => {
  await h.closeAll();
});

describe('VaultClient requests', () => {
  it('reads the path with the token and the client headers', async () => {
    h.vault.answer(200, '{"request_id":"r1","lease_duration":7,"renewable":true,"data":{"a":"b"},"warnings":["w"]}');
    const response = await h.client().read('secret/data/app');
    const received = h.vault.single();
    assert.equal(received.method, 'GET');
    assert.equal(received.target, '/v1/secret/data/app');
    assert.equal(received.header('X-Vault-Token'), TOKEN);
    assert.equal(received.header('X-Vault-Request'), 'true');
    assert.match(received.header('User-Agent')!, /^hkdfguard-integration-hashicorpvault\//);
    assert.equal(response?.requestId, 'r1');
    assert.equal(response?.leaseDuration, 7);
    assert.equal(response?.renewable, true);
    assert.equal(response?.data?.a?.asString(), 'b');
    assert.deepEqual(response?.warnings, ['w']);
  });

  for (const path of ['secret/x', '/secret/x', 'v1/secret/x', '/v1/secret/x']) {
    it(`puts ${path} under /v1/ once`, async () => {
      await h.client().read(path);
      assert.equal(h.vault.single().target, '/v1/secret/x');
    });
  }

  it('never shows callbacks the token', async () => {
    const seen: string[] = [];
    const client = h.client();
    client.setRequestCallbacks((request) => seen.push(...request.headers.map(([n, v]) => `${n}: ${v}`)));
    client.setResponseCallbacks((request) => seen.push(...request.headers.map(([n, v]) => `${n}: ${v}`)));
    await client.read('a');
    assert.ok(seen.length > 0);
    assert.ok(seen.every((line) => !line.includes(TOKEN) && !line.toLowerCase().startsWith('x-vault-token')));
  });

  it('sends no token header without a token', async () => {
    const client = h.client();
    client.clearToken();
    await client.read('a');
    assert.equal(h.vault.single().header('X-Vault-Token'), undefined);
  });

  it("protects a token it's set, and a request's own token wins", async () => {
    const client = h.client();
    client.setToken('first-token');
    await client.read('a');
    await client.read('a', { token: client.protectToken('request-token') });
    assert.deepEqual(h.vault.requests.map((r) => r.header('X-Vault-Token')), ['first-token', 'request-token']);
  });

  it('fails a request whose token is unprotected, without quoting it', async () => {
    const client = h.client({ token: new StaticVaultToken('raw-token-not-protected') });
    await assert.rejects(client.read('a'), (error: HkdfGuardError) => {
      assert.equal(error.code, 'ERR_HKDFGUARD_INVALID_VAULT_TOKEN');
      assert.ok(!error.message.includes('raw-token-not-protected'));
      return true;
    });
    assert.equal(h.vault.requests.length, 0);
  });

  it('fails a request whose token is protected for something else', async () => {
    const foreign = makeRing().createProtector('Some.Other.Purpose');
    const client = h.client({ token: new StaticVaultToken(foreign.encrypt(TOKEN)) });
    await assert.rejects(client.read('a'), { code: 'ERR_HKDFGUARD_INVALID_VAULT_TOKEN' });
  });

  it("fails a request whose protected value isn't a token", async () => {
    const client = h.client({ token: new StaticVaultToken(h.protector.encrypt('has a space')) });
    await assert.rejects(client.read('a'), { code: 'ERR_HKDFGUARD_INVALID_VAULT_TOKEN' });
  });

  it('fails a request whose provider returns no token', async () => {
    const empty: VaultTokenProvider = { getToken: () => '' };
    await assert.rejects(h.client({ token: empty }).read('a'), { code: 'ERR_HKDFGUARD_INVALID_VAULT_TOKEN' });
  });

  it("keeps an address's path as a prefix", async () => {
    await h.client({ address: `${h.vault.address}/proxy/` }).read('a');
    assert.equal(h.vault.single().target, '/proxy/v1/a');
  });

  it("takes the namespace from the options, a request's over it, and clears it", async () => {
    const client = h.client({ namespace: 'team-a' });
    await client.read('a');
    await client.read('a', { namespace: 'team-b' });
    client.clearNamespace();
    await client.read('a');
    client.setNamespace('team-c');
    await client.read('a');
    assert.deepEqual(h.vault.requests.map((r) => r.header('X-Vault-Namespace')), ['team-a', 'team-b', undefined, 'team-c']);
  });

  it("appends MFA credentials, the client's first", async () => {
    const client = h.client();
    client.setMfaCredentials('m1:111');
    await client.read('a', { mfaCredentials: ['m2:222'] });
    assert.equal(h.vault.single().header('X-Vault-MFA'), 'm1:111, m2:222');
  });

  it("sends the wrapping TTL as a Go duration, a request's over the client's", async () => {
    const client = h.client();
    client.setResponseWrapping(90_000);
    await client.read('a');
    await client.read('a', { responseWrappingTtlMs: 1500 });
    client.clearResponseWrapping();
    await client.read('a');
    assert.deepEqual(h.vault.requests.map((r) => r.header('X-Vault-Wrap-TTL')), ['1m30s', '1.5s', undefined]);
    assert.throws(() => client.setResponseWrapping(-1), RangeError);
  });

  it('sends the replication forwarding header', async () => {
    const client = h.client();
    client.setReplicationForwardingMode(ReplicationForwardingMode.always);
    await client.read('a');
    await client.read('a', { replicationForwardingMode: ReplicationForwardingMode.inconsistent });
    client.clearReplicationForwardingMode();
    await client.read('a');
    const [first, second, third] = h.vault.requests;
    assert.equal(first!.header('X-Vault-Forward'), 'active-node');
    assert.equal(second!.header('X-Vault-Inconsistent'), 'forward-active-node');
    assert.equal(third!.header('X-Vault-Forward') ?? third!.header('X-Vault-Inconsistent'), undefined);
  });

  it("replaces custom headers a request names the same, and keeps the rest", async () => {
    const client = h.client();
    client.setCustomHeaders({ 'X-One': ['1'], 'X-Two': ['2a', '2b'] });
    await client.read('a', { customHeaders: { 'x-one': ['one'] } });
    const received = h.vault.single();
    assert.equal(received.header('X-One'), 'one');
    assert.equal(received.header('X-Two'), '2a, 2b');
    assert.throws(() => client.setCustomHeaders({ 'X-Vault-Token': ['x'] }), RangeError);
    assert.throws(() => client.setCustomHeaders({ Host: ['x'] }), RangeError);
    assert.throws(() => client.setCustomHeaders({ 'X-Bad': ['a\nb'] }), RangeError);
  });

  it("replaces the client's content type with a custom one", async () => {
    await h.client().write('a', { x: 1 }, { customHeaders: { 'Content-Type': ['application/merge-patch+json'] } });
    assert.equal(h.vault.single().header('Content-Type'), 'application/merge-patch+json');
  });

  it('sends a long token, and protects a long login token', async () => {
    const long = `hvs.${'A'.repeat(1500)}`;
    h.vault.answer(200, JSON.stringify({ auth: { client_token: long } }));
    const client = h.client();
    client.setToken(long);
    const response = await client.write('auth/x/login', {});
    assert.equal(h.vault.single().header('X-Vault-Token'), long);
    assert.equal(await decrypt(h.protector, response?.auth?.clientToken), long);
  });

  it('sorts query parameters by name, escapes them, and has list add list=true', async () => {
    const client = h.client();
    await client.read('a', { queryParameters: [['z', '1'], ['a b', 'x/y'], ['m', '2']] });
    await client.list('kv/metadata', { queryParameters: [['after', 'k']] });
    assert.equal(h.vault.requests[0]!.target, '/v1/a?a%20b=x%2Fy&m=2&z=1');
    assert.equal(h.vault.requests[1]!.target, '/v1/kv/metadata?after=k&list=true');
  });

  it('posts a body as JSON', async () => {
    await h.client().write('secret/data/app', { data: { password: Buffer.from('s3crét'), n: 3, ok: true, none: null } });
    const received = h.vault.single();
    assert.equal(received.method, 'POST');
    assert.equal(received.header('Content-Type'), 'application/json');
    assert.equal(received.bodyText, '{"data":{"password":"s3crét","n":3,"ok":true,"none":null}}');
  });

  it('posts bytes and a stream as they are', async () => {
    const client = h.client();
    await client.writeFromBytes('a', Buffer.from('{"raw":1}'));
    await client.writeFromStream('b', Readable.from([Buffer.from('{"str'), Buffer.from('eam":2}')]));
    assert.deepEqual(h.vault.requests.map((r) => r.bodyText), ['{"raw":1}', '{"stream":2}']);
  });

  it('rejects a body it can\'t write, sending nothing', async () => {
    const client = h.client();
    await assert.rejects(client.write('a', { x: Symbol('no') }), TypeError);
    await assert.rejects(client.write('a', { x: Number.NaN }), RangeError);
    await assert.rejects(client.write('a', [] as unknown as Record<string, unknown>), TypeError);
    assert.equal(h.vault.requests.length, 0);
  });

  it('deletes', async () => {
    h.vault.answer(204);
    assert.equal(await h.client().delete('secret/data/app'), undefined);
    assert.equal(h.vault.single().method, 'DELETE');
  });

  it('reads a body without an envelope whole as its data', async () => {
    h.vault.answer(200, '{"initialized":true,"sealed":false}');
    const response = await h.client().read('sys/seal-status');
    assert.equal(response?.data?.sealed?.asBoolean(), false);
  });

  it("returns sys/health's error statuses as its status", async () => {
    h.vault.answer(503, '{"initialized":true,"sealed":true}');
    const response = await h.client({ retry: { retryMax: 0 } }).read('sys/health');
    assert.equal(response?.data?.sealed?.asBoolean(), true);
  });

  it('protects a login token as it is read, and it can be set as the client\'s', async () => {
    h.vault.answer(200, JSON.stringify({ auth: { client_token: 'hvs.login', accessor: 'acc', policies: ['p'], token_policies: ['p'], metadata: { m: 'v' },
      lease_duration: 60, renewable: true, orphan: true, entity_id: 'e' } }));
    const client = h.client();
    client.clearToken();
    const login = await client.write('auth/approle/login', { role_id: 'r', secret_id: 's' });
    const auth = login!.auth!;
    assert.equal(await decrypt(h.protector, auth.clientToken), 'hvs.login');
    assert.equal(auth.accessor, 'acc');
    assert.deepEqual(auth.metadata, { m: 'v' });
    assert.equal(auth.leaseDuration, 60);
    assert.equal(auth.orphan, true);
    client.setToken(auth.clientToken!);
    await client.read('a');
    assert.equal(h.vault.requests[1]!.header('X-Vault-Token'), 'hvs.login');
  });

  it('unescapes a login token escaped in the JSON before protecting it', async () => {
    h.vault.answer(200, '{"auth":{"client_token":"hvs.\\u0041B\\/C"}}');
    const login = await h.client().write('auth/x/login', {});
    assert.equal(await decrypt(h.protector, login?.auth?.clientToken), 'hvs.AB/C');
  });

  it("fails a response whose login token isn't one", async () => {
    h.vault.answer(200, '{"auth":{"client_token":"has space"}}');
    await assert.rejects(h.client().write('auth/x/login', {}), VaultJsonError);
  });

  it('reads an MFA requirement', async () => {
    h.vault.answer(200, JSON.stringify({ auth: { mfa_requirement: { mfa_request_id: 'req', mfa_constraints: {
      c: { any: [{ type: 'totp', id: 'm1', uses_passcode: true }] } } } } }));
    const requirement = (await h.client().write('auth/userpass/login/u', { password: 'p' }))?.auth?.mfaRequirement;
    assert.equal(requirement?.mfaRequestId, 'req');
    assert.deepEqual(requirement?.mfaConstraints?.c?.any, [{ type: 'totp', id: 'm1', usesPasscode: true }]);
  });

  it('unwraps with the wrapping token, reading the wrapped response', async () => {
    h.vault.answer(200, JSON.stringify({ wrap_info: { token: 'hvs.wrap', accessor: 'wa', ttl: 300, creation_time: '2024-01-02T03:04:05.123456789Z',
      creation_path: 'secret/data/app' } }));
    h.vault.answer(200, '{"data":{"data":{"k":"v"}}}');
    const client = h.client();
    const wrapped = await client.read('secret/data/app', { responseWrappingTtlMs: 300_000 });
    const info = wrapped!.wrapInfo!;
    assert.equal(info.ttl, 300);
    assert.equal(info.creationTime?.toISOString(), '2024-01-02T03:04:05.123Z');
    const unwrapped = await client.unwrap(info.token!, (json) => json.readJsonRecord());
    const second = h.vault.requests[1]!;
    assert.equal(second.method, 'PUT');
    assert.equal(second.target, '/v1/sys/wrapping/unwrap');
    assert.equal(second.header('X-Vault-Token'), 'hvs.wrap');
    assert.equal(unwrapped?.data?.data?.member('k').asString(), 'v');
  });

  it("reports a refusal as a VaultResponseError listing Vault's errors", async () => {
    h.vault.answer(403, '{"errors":["permission denied"]}');
    h.vault.answer(400, '{"error":"bad thing"}');
    h.vault.answer(404, 'not json');
    const client = h.client();
    await assert.rejects(client.read('a?b'), (error: VaultResponseError) => {
      assert.ok(error instanceof VaultRequestError);
      assert.equal(error.statusCode, 403);
      assert.deepEqual(error.errors, ['permission denied']);
      assert.equal(error.message, '403 Forbidden: permission denied');
      assert.equal(error.requestMethod, 'GET');
      assert.equal(error.rawResponseBytes, undefined);
      return true;
    });
    await assert.rejects(client.read('a'), { message: '400 Bad Request: bad thing' });
    await assert.rejects(client.read('a'), (error: VaultResponseError) => {
      assert.equal(Buffer.from(error.rawResponseBytes!).toString(), 'not json');
      return true;
    });
  });

  it('finds an error status through causes, and none in other errors', () => {
    const refusal = new VaultResponseError('x', 404, [], undefined, 'GET', 'u');
    assert.equal(VaultClient.isErrorStatus(new Error('outer', { cause: refusal }), 404), true);
    assert.equal(VaultClient.isErrorStatus(refusal, 403), false);
    assert.equal(VaultClient.isErrorStatus(new Error('plain'), 404), false);
    assert.equal(VaultClient.isErrorStatus(undefined, 404), false);
  });

  it("doesn't treat a 304 as an error", async () => {
    h.vault.answer(304);
    assert.equal(await h.client().read('a'), undefined);
  });

  it('returns a raw response unchecked', async () => {
    h.vault.answer(418, 'teapot body', { 'X-Extra': 'e' });
    const raw = await h.client().readRaw('a');
    assert.equal(raw.statusCode, 418);
    assert.equal(raw.headers['x-extra'], 'e');
    const chunks: Buffer[] = [];
    for await (const chunk of raw) chunks.push(chunk);
    assert.equal(Buffer.concat(chunks).toString(), 'teapot body');
    raw.close();
  });

  it("gives a raw response's body as a stream of its own, with no way back to the request's token", async () => {
    h.vault.answer(200, 'raw body');
    const raw = await h.client().readRaw('a');
    const body = raw.body as Readable & { req?: unknown; socket?: unknown };
    assert.equal(body.req, undefined);
    assert.equal(body.socket, undefined);
    assert.equal(raw.body, body, 'the same stream each time');
    const chunks: Buffer[] = [];
    for await (const chunk of body) chunks.push(chunk as Buffer);
    assert.equal(Buffer.concat(chunks).toString(), 'raw body');
    raw.close();
  });

  it('refuses a response longer than maxResponseBytes', async () => {
    const big = 'x'.repeat(4096);
    h.vault.answer(200, `{"data":{"v":"${big}"}}`);
    h.vault.answer(200, '{"data":{}}');
    h.vault.answer(502, big);
    const client = h.client({ maxResponseBytes: 1024, retry: { retryMax: 0 } });
    await assert.rejects(client.read('a'), (error: VaultRequestError) =>
      error instanceof VaultRequestError && /longer than 1024 bytes/.test(error.message) && error.statusCode === 200 && !error.message.includes(big));
    // Under the limit, as before.
    assert.ok(await client.read('a'));
    // A refusal is held to the limit too.
    await assert.rejects(client.read('a'), /longer than 1024 bytes/);
  });

  it("sizes its first buffer by the limit, not by what Content-Length claims", async () => {
    // What a lying Content-Length of 2 GiB once allocated up front; now the limit bounds it.
    async function* chunks() { yield Buffer.from('{}'); }
    const body = await readBody(chunks(), 1024, 2 ** 31);
    assert.equal(Buffer.from(body!.view()).toString(), '{}');
    body!.close();
  });

  it('checks maxResponseBytes', () => {
    for (const bad of [0, -1, 1.5, Number.NaN, 2 ** 53, '1024']) {
      assert.throws(() => h.client({ maxResponseBytes: bad as number }), HkdfGuardError, String(bad));
    }
  });

  it("quotes no more than the start of a body that isn't Vault's, and none of a JSON one listing no errors", async () => {
    const page = `<html>${'proxy error '.repeat(200)}</html>`;
    h.vault.answer(502, page);
    // A KV v2 read of a deleted version: 404, the secret's metadata, no errors.
    h.vault.answer(404, '{"data":{"data":null,"metadata":{"custom_metadata":{"owner":"payroll"},"deletion_time":"2026-01-01T00:00:00Z"}}}');
    const client = h.client({ retry: { retryMax: 0 } });
    await assert.rejects(client.read('a'), (error: VaultResponseError) => {
      assert.ok(error.message.startsWith('502 Bad Gateway: <html>proxy error'));
      assert.ok(error.message.endsWith(`... (${Buffer.byteLength(page)} bytes)`), error.message);
      assert.ok(error.message.length < 600);
      assert.equal(Buffer.from(error.rawResponseBytes!).toString(), page);
      return true;
    });
    await assert.rejects(client.read('a'), (error: VaultResponseError) => {
      assert.equal(error.message, '404 Not Found');
      assert.ok(Buffer.from(error.rawResponseBytes!).toString().includes('payroll'));
      return true;
    });
  });

  it("runs the client's callbacks before the request's", async () => {
    const order: string[] = [];
    const client = h.client();
    client.setRequestCallbacks(() => order.push('client request'));
    client.setResponseCallbacks((_r, status) => order.push(`client response ${status}`));
    await client.read('a', { requestCallbacks: [() => order.push('request')], responseCallbacks: [() => order.push('response')] });
    assert.deepEqual(order, ['client request', 'request', 'client response 200', 'response']);
  });

  it('lets a request callback add headers, but not the token', async () => {
    const client = h.client();
    await client.read('a', { requestCallbacks: [(request: VaultRequest) => request.addHeader('X-Vault-Index', 'state')] });
    assert.equal(h.vault.single().header('X-Vault-Index'), 'state');
    await assert.rejects(client.read('a', { requestCallbacks: [(request) => request.addHeader('X-Vault-Token', 'x')] }), RangeError);
  });

  it('fails a request whose response callback throws', async () => {
    await assert.rejects(h.client().read('a', { responseCallbacks: [() => { throw new Error('callback failed'); }] }), { message: 'callback failed' });
  });

  it('copies settings, which then change independently, and a copy closes nothing', async () => {
    const client = h.client({ namespace: 'ns' });
    const copy = client.copy();
    copy.setNamespace('other');
    copy.setToken('copy-token');
    await client.read('a');
    await copy.read('a');
    assert.deepEqual(h.vault.requests.map((r) => [r.header('X-Vault-Namespace'), r.header('X-Vault-Token')]), [['ns', TOKEN], ['other', 'copy-token']]);
    copy.close();
    await client.read('a');
    client.close();
    await assert.rejects(copy.read('a'), ClosedError);
    await assert.rejects(client.read('a'), ClosedError);
  });

  it('abandons a request its signal aborts, rejecting with the reason', async () => {
    h.vault.delayMs = 5_000;
    const controller = new AbortController();
    const pending = h.client().read('a', { signal: controller.signal });
    setTimeout(() => controller.abort(new Error('stop')), 50);
    await assert.rejects(pending, { message: 'stop' });
  });

  it('names the library and platform in its User-Agent, in printable ASCII', () => {
    assert.match(VaultClient.USER_AGENT, /^hkdfguard-integration-hashicorpvault\/\d+\.\d+\.\d+ \(.+; .+; Node \d+\.\d+\.\d+\)$/);
    assert.match(VaultClient.USER_AGENT, /^[\x20-\x7e]+$/);
  });

  it('holds only the protected form of a token it protects', async () => {
    const protector = makeProtector();
    const client = new VaultClient(protector);
    const token = client.protectToken(TOKEN);
    const held = await token.getToken();
    assert.notEqual(held, TOKEN);
    assert.equal(await decrypt(protector, held), TOKEN);
    assert.throws(() => client.protectToken('has space'));
    client.close();
  });

  it('refuses a redirect by default', async () => {
    h.vault.answer(307, '', { Location: '/v1/elsewhere' });
    await assert.rejects(h.client().read('a'), (error: VaultRedirectError) => {
      assert.equal(error.statusCode, 307);
      assert.equal(error.reason, 'redirects are disabled');
      assert.equal(error.redirectLocation, `${h.vault.address}/v1/elsewhere`);
      return true;
    });
  });

  it('reads a value of JSON the generic methods return', async () => {
    h.vault.answer(200, '{"data":{"keys":["a","b"]}}');
    const listed = await h.client().list('secret/metadata');
    assert.deepEqual(listed?.data?.keys?.asArray().map((k: JsonValue) => k.asString()), ['a', 'b']);
  });
});

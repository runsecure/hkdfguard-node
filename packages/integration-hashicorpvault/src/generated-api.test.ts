import { strict as assert } from 'node:assert';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { decrypt, harness, type Harness } from './fake-vault.test-support.js';
import { AuthApi, SecretsApi, SystemApi } from './generated/index.js';
import { escapePathSegment, mountPathOr } from './sender.js';

let h: Harness;
beforeEach(async () => {
  h = await harness();
});
afterEach(async () => {
  await h.closeAll();
});

describe('the generated API', () => {
  it('escapes the path, using the default mount or the one given', async () => {
    h.vault.answer(200, '{"data":{"data":{"k":"v"},"metadata":{"version":2}}}');
    const client = h.client();
    const response = await client.secrets.kvV2Read('my app/db');
    await client.secrets.kvV2Read('x', { mountPath: '/team/kv/' });
    assert.deepEqual(h.vault.requests.map((r) => r.target), ['/v1/kv-v2/data/my%20app%2Fdb', '/v1/team%2Fkv/data/x']);
    assert.equal(response?.data?.data?.k?.asString(), 'v');
  });

  it('posts its model, leaving out what is not set', async () => {
    await h.client().secrets.kvV2Write('app', { data: { password: Buffer.from('p') }, options: { cas: 0 } });
    assert.equal(h.vault.single().bodyText, '{"data":{"password":"p"},"options":{"cas":0}}');
  });

  it('sends the required members, and rejects their absence from the call, sending nothing', async () => {
    const client = h.client();
    await assert.rejects(client.auth.aliCloudLogin({} as never), /AliCloudLoginRequest needs its role/);
    await assert.rejects(client.secrets.kvV2Write('app', undefined as never), TypeError);
    assert.equal(h.vault.requests.length, 0);
  });

  it('reads JSON values a transit encrypt returns', async () => {
    h.vault.answer(200, '{"data":{"ciphertext":"vault:v1:abc","key_version":1}}');
    const response = await h.client().secrets.transitEncrypt('my-key', { plaintext: 'cGxhaW4=', context: 'Y3R4' });
    const received = h.vault.single();
    assert.equal(received.target, '/v1/transit/encrypt/my-key');
    assert.deepEqual(JSON.parse(received.bodyText!), { context: 'Y3R4', plaintext: 'cGxhaW4=' });
    assert.equal(response?.data?.ciphertext?.asString(), 'vault:v1:abc');
  });

  it("adds list=true to the caller's query", async () => {
    await h.client().secrets.kvV2List('dir/', { queryParameters: [['a', '1']] });
    assert.equal(h.vault.single().target, '/v1/kv-v2/metadata/dir%2F/?a=1&list=true');
  });

  it('sends a query parameter only when given', async () => {
    const client = h.client();
    await client.auth.jwtOidcCallback({ state: 's1', code: 'c 1' });
    await client.auth.jwtOidcCallback();
    assert.deepEqual(h.vault.requests.map((r) => r.target), ['/v1/auth/jwt/oidc/callback?code=c%201&state=s1', '/v1/auth/jwt/oidc/callback']);
  });

  it('protects the token a token create issues', async () => {
    h.vault.answer(200, '{"auth":{"client_token":"hvs.child","policies":["default"]}}');
    const response = await h.client().auth.tokenCreate({ policies: ['default'] });
    assert.equal(h.vault.single().target, '/v1/auth/token/create');
    assert.equal(await decrypt(h.protector, response?.auth?.clientToken), 'hvs.child');
  });

  it('logs in at its mount', async () => {
    h.vault.answer(200, '{"auth":{"client_token":"hvs.app"}}');
    const client = h.client();
    client.clearToken();
    await client.auth.appRoleLogin({ roleId: 'r', secretId: 's' }, { mountPath: 'approle-2' });
    const received = h.vault.single();
    assert.equal(received.target, '/v1/auth/approle-2/login');
    assert.equal(received.header('X-Vault-Token'), undefined);
    assert.deepEqual(JSON.parse(received.bodyText!), { role_id: 'r', secret_id: 's' });
  });

  it('escapes all but unreserved characters in a segment', () => {
    assert.equal(escapePathSegment('a-_.~Z9 /?%é'), 'a-_.~Z9%20%2F%3F%25%C3%A9');
    assert.equal(escapePathSegment(5), '5');
  });

  it('trims slashes from a mount path, falling back to the default', () => {
    assert.equal(mountPathOr(undefined, 'kv'), 'kv');
    assert.equal(mountPathOr({ mountPath: '//a/b//' }, 'kv'), 'a/b');
    assert.equal(mountPathOr({ mountPath: '/' }, 'kv'), 'kv');
  });

  it('reaches its groups through the client', () => {
    const client = h.client();
    assert.ok(client.auth instanceof AuthApi);
    assert.ok(client.secrets instanceof SecretsApi);
    assert.ok(client.system instanceof SystemApi);
  });
});

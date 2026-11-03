import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { Agent as HttpsAgent, createServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { capturingLogger } from '@runsecure/hkdfguard-test-support';
import { VaultRedirectError, VaultResponseError } from './client-errors.js';
import { VaultClient } from './client.js';
import { DROP, harness, makeProtector, TOKEN, type Harness } from './fake-vault.test-support.js';
import { defaultRetryPolicy, linearJitterBackoff, VaultRateLimiter } from './retry.js';
import { StaticVaultToken, type VaultTokenProvider } from './token.js';

let h: Harness;
beforeEach(async () => {
  h = await harness();
});
afterEach(async () => {
  await h.closeAll();
});

describe('VaultClient retries', () => {
  it('rejects with the last response once the retries run out', async () => {
    h.vault.respond = () => ({ status: 503, body: '{"errors":["sealed"]}' });
    await assert.rejects(h.client().read('a'), (error: VaultResponseError) => error.statusCode === 503 && /sealed/.test(error.message));
    assert.equal(h.vault.requests.length, 3);
  });

  it("retries no answer, and once the retries run out rejects with Node's error", async () => {
    h.vault.respond = () => DROP;
    await assert.rejects(h.client().read('a'), (error: NodeJS.ErrnoException) => typeof error.code === 'string');
    assert.equal(h.vault.requests.length, 3);
  });

  it('succeeds when an answer follows no answer', async () => {
    h.vault.answer(() => DROP).answer(200, '{"data":{"ok":true}}');
    const response = await h.client().read('a');
    assert.equal(response?.data?.ok?.asBoolean(), true);
    assert.equal(h.vault.requests.length, 2);
  });

  it('asks the token provider once per request, not per retry', async () => {
    const token = await StaticVaultToken.protect(h.protector, TOKEN).getToken();
    let calls = 0;
    const provider: VaultTokenProvider = { getToken: () => { calls++; return token; } };
    h.vault.answer(500).answer(500);
    await h.client({ token: provider }).read('a');
    assert.equal(calls, 1);
    assert.equal(h.vault.requests.length, 3);
  });

  it('uses a retry policy and backoff of its own', async () => {
    const seen: [number, number][] = [];
    h.vault.respond = () => ({ status: 409 });
    const client = h.client({ retry: { retryMax: 2, checkRetry: (status) => status === 409, backoff: (_min, _max, attempt, status) => { seen.push([attempt, status]); return 1; } } });
    await assert.rejects(client.read('a'), { statusCode: 409 });
    assert.deepEqual(seen, [[0, 409], [1, 409]]);
  });

  it('logs retries without the query', async () => {
    const { logger, entries } = capturingLogger();
    h.vault.answer(503);
    const client = new VaultClient(h.protector, { address: h.vault.address, retry: { retryWaitMinMs: 1, retryWaitMaxMs: 1 } }, logger);
    await client.read('secret/a', { queryParameters: [['secret', 'value']] });
    client.close();
    const retry = entries.find((e) => e.attributes['event.id'] === 1);
    assert.ok(retry);
    assert.match(retry.message, /GET \/v1\/secret\/a failed \(503 Service Unavailable\); retry 1 of 2/);
    assert.ok(!retry.message.includes('value'));
  });

  it('waits between the minimum and maximum, times the attempts', () => {
    for (let attempt = 0; attempt < 3; attempt++) {
      const wait = linearJitterBackoff(100, 200, attempt, 0);
      assert.ok(wait >= 100 * (attempt + 1) && wait < 200 * (attempt + 1), `${wait}`);
    }
    assert.equal(linearJitterBackoff(300, 100, 1, 0), 600);
  });

  it('retries by default what another attempt may not meet', () => {
    for (const status of [0, 412, 429, 500, 502, 503]) assert.equal(defaultRetryPolicy(status, undefined), true, `${status}`);
    for (const status of [200, 400, 403, 404, 501]) assert.equal(defaultRetryPolicy(status, undefined), false, `${status}`);
    assert.equal(defaultRetryPolicy(0, Object.assign(new Error('reset'), { code: 'ECONNRESET' })), true);
    assert.equal(defaultRetryPolicy(0, Object.assign(new Error('bad cert'), { code: 'SELF_SIGNED_CERT_IN_CHAIN' })), false);
    assert.equal(defaultRetryPolicy(0, new Error('outer', { cause: Object.assign(new Error('x'), { code: 'CERT_HAS_EXPIRED' }) })), false);
  });
});

describe('VaultClient redirects', () => {
  it('follows a relative redirect, resolved against the request', async () => {
    h.vault.answer(307, '', { Location: '/v1/elsewhere?x=1' });
    await h.client({ followRedirects: true }).read('a');
    assert.deepEqual(h.vault.requests.map((r) => r.target), ['/v1/a', '/v1/elsewhere?x=1']);
    assert.equal(h.vault.requests[1]!.header('X-Vault-Token'), TOKEN);
  });

  it('refuses a second redirect', async () => {
    h.vault.respond = () => ({ status: 302, headers: { Location: '/v1/again' } });
    await assert.rejects(h.client({ followRedirects: true }).read('a'), { reason: 'at most one redirect is allowed' });
  });

  it('follows an http redirect on loopback', async () => {
    h.vault.answer(301, '', { Location: `http://localhost:${h.vault.port}/v1/b` });
    await h.client({ followRedirects: true }).read('a');
    assert.equal(h.vault.requests[1]!.target, '/v1/b');
  });

  it('refuses a redirect over http off loopback', async () => {
    h.vault.answer(307, '', { Location: 'http://vault.example.com/v1/b' });
    await assert.rejects(h.client({ followRedirects: true }).read('a'), { reason: 'the redirect would send the token over unencrypted http' });
  });

  it('refuses a redirect without a location', async () => {
    h.vault.answer(307);
    await assert.rejects(h.client({ followRedirects: true }).read('a'), (error: VaultRedirectError) => {
      assert.equal(error.reason, 'could not read the redirect location');
      assert.equal(error.redirectLocation, undefined);
      return true;
    });
  });
});

describe('VaultClient timeouts and rate limits', () => {
  it('rejects a request that outlives the timeout with a TimeoutError', async () => {
    h.vault.delayMs = 2_000;
    await assert.rejects(h.client({ requestTimeoutMs: 100 }).read('a?q'), (error: DOMException) => {
      assert.equal(error.name, 'TimeoutError');
      assert.match(error.message, /GET \/v1\/a within 100 ms/);
      return true;
    });
  });

  it('counts a slow token provider against the timeout', async () => {
    const slow: VaultTokenProvider = { getToken: () => new Promise((resolve) => setTimeout(() => resolve('x'), 2_000)) };
    await assert.rejects(h.client({ requestTimeoutMs: 100, token: slow }).read('a'), { name: 'TimeoutError' });
    assert.equal(h.vault.requests.length, 0);
  });

  it('has no timeout for zero', async () => {
    h.vault.delayMs = 50;
    await h.client({ requestTimeoutMs: 0 }).read('a');
    assert.equal(h.vault.requests.length, 1);
  });

  it('spaces requests out once the burst is spent', async () => {
    const client = h.client({ rateLimiter: new VaultRateLimiter(20, 1) });
    const start = performance.now();
    await client.read('a');
    await client.read('a');
    await client.read('a');
    assert.ok(performance.now() - start >= 80, `${performance.now() - start}`);
  });

  it('fails a rate-limited request that would outlive the timeout at once', async () => {
    const limiter = new VaultRateLimiter(0.1, 1);
    const client = h.client({ rateLimiter: limiter, requestTimeoutMs: 200 });
    await client.read('a');
    const start = performance.now();
    await assert.rejects(client.read('a'), { name: 'TimeoutError' });
    assert.ok(performance.now() - start < 150);
  });

  it('gives back the turn of a rate-limited wait that is aborted', async () => {
    const limiter = new VaultRateLimiter(10, 1);
    assert.equal(await limiter.acquire(1000), true);
    const controller = new AbortController();
    const waiting = limiter.acquire(1000, controller.signal);
    controller.abort(new Error('gone'));
    await assert.rejects(waiting, { message: 'gone' });
    const start = performance.now();
    assert.equal(await limiter.acquire(1000), true);
    assert.ok(performance.now() - start < 150);
  });

  it("refuses a rate that isn't one", () => {
    for (const [rate, burst] of [[0, 1], [-1, 1], [Number.NaN, 1], [Infinity, 1], [1, 0], [1, 1.5]] as const) {
      assert.throws(() => new VaultRateLimiter(rate, burst), RangeError);
    }
  });
});

describe('VaultClient read-your-writes', () => {
  const state = (local: number) => Buffer.from(`v1:cluster:${local}:${local}:`).toString('base64');

  it("sends the states seen, and a copy's change independently", async () => {
    h.vault.answer(200, '{"data":{}}', { 'X-Vault-Index': state(1) });
    const client = h.client({ enforceReadYourWritesConsistency: true });
    await client.write('a', {});
    const copy = client.copy();
    h.vault.answer(200, '{"data":{}}', { 'X-Vault-Index': state(2) });
    await copy.read('a');
    await client.read('a');
    assert.deepEqual(h.vault.requests.map((r) => r.header('X-Vault-Index')), [undefined, state(1), state(1)]);
    await copy.read('a');
    assert.equal(h.vault.requests[3]!.header('X-Vault-Index'), state(2));
  });

  it('sends no states without read-your-writes', async () => {
    h.vault.answer(200, '{"data":{}}', { 'X-Vault-Index': state(1) });
    const client = h.client();
    await client.read('a');
    await client.read('a');
    assert.equal(h.vault.requests[1]!.header('X-Vault-Index'), undefined);
  });
});

describe('VaultClient TLS', () => {
  const fixture = (name: string) => join(__dirname, '..', 'test-fixtures', name);

  async function tlsServer(): Promise<{ port: number; close(): void }> {
    const server = createServer({ key: readFileSync(fixture('server.key')), cert: readFileSync(fixture('server.pem')) }, (_request, response) => {
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end('{"data":{"tls":true}}');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    return { port: (server.address() as AddressInfo).port, close: () => { server.closeAllConnections(); server.close(); } };
  }

  it("trusts Vault's CA given in the TLS options", async () => {
    const server = await tlsServer();
    const client = new VaultClient(makeProtector(), {
      address: `https://127.0.0.1:${server.port}`, tls: { serverCertificateFile: fixture('ca.pem'), serverName: 'vault.test' },
    });
    try {
      assert.equal((await client.read('a'))?.data?.tls?.asBoolean(), true);
    } finally {
      client.close();
      server.close();
    }
  });

  it('refuses an untrusted certificate without retrying', async () => {
    const server = await tlsServer();
    let attempts = 0;
    const client = new VaultClient(makeProtector(), {
      address: `https://127.0.0.1:${server.port}`, requestTimeoutMs: 10_000,
      retry: { retryWaitMinMs: 1, retryWaitMaxMs: 1, checkRetry: (status, failure) => { attempts++; return defaultRetryPolicy(status, failure); } },
    });
    try {
      await assert.rejects(client.read('a'), (error: NodeJS.ErrnoException) => typeof error.code === 'string');
      assert.equal(attempts, 1);
    } finally {
      client.close();
      server.close();
    }
  });

  it('refuses TLS options and an agent together', () => {
    assert.throws(() => new VaultClient(makeProtector(), { agent: new HttpsAgent(), tls: {} }), /not both/);
  });
});

describe('VaultClient concurrency', () => {
  it('sends many requests at once through one client', async () => {
    const client = h.client();
    await Promise.all(Array.from({ length: 20 }, (_, i) => client.read(`a/${i}`)));
    assert.equal(h.vault.requests.length, 20);
  });
});

import { strict as assert } from 'node:assert';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { Agent as HttpsAgent } from 'node:https';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, it } from 'node:test';
import { HkdfGuardError, InvalidArgumentError, type DataProtector } from '@runsecure/hkdfguard-abstractions';
import { KeyRing } from '@runsecure/hkdfguard-dek';
import { RecordingKey } from '@runsecure/hkdfguard-test-support';
import { describeAnswer, readBody, readVaultErrors, vaultRefusal } from './body.js';
import {
  apiBase, checkConnectionOptions, checkConnectionSettings, DEFAULT_RETRY_DELAY_MS, DEFAULT_TIMEOUT_MS, isLoopback, isValidPath, isValidSegment,
  MAX_RETRY_COUNT, MAX_RETRY_DELAY_MS, MAX_TIMEOUT_MS, MIN_RETRY_COUNT, NAMESPACE_HEADER, REQUEST_HEADER, retryDelay, TOKEN_HEADER,
  type VaultConnectionOptions,
} from './connection.js';
import { VaultRequestError } from './errors.js';
import {
  checkProtectedToken, chunksOf, copyTokenWithin, decryptToken, getTokenWithin, httpsAgentFor, isTransient, markTransient, putProtectedToken, putToken, runWithin, sendAttempt,
  vaultHeaders, VaultConnector, withRetries,
} from './http.js';
import { MAX_TOKEN_LENGTH, StaticVaultToken, StaticVaultTokenSource, TOKEN_PURPOSE } from './token.js';

const cleanups: (() => void)[] = [];
afterEach(() => {
  for (const cleanup of cleanups.splice(0).reverse()) cleanup();
});

function makeProtector(): DataProtector {
  const ring = new KeyRing();
  ring.add(1, new RecordingKey());
  return ring.createProtector(TOKEN_PURPOSE);
}

const invalidToken = (e: unknown) => e instanceof HkdfGuardError && e.code === 'ERR_HKDFGUARD_INVALID_VAULT_TOKEN';

async function startServer(handler: (request: IncomingMessage, response: ServerResponse) => void): Promise<VaultConnector> {
  const server: Server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const connector = new VaultConnector(apiBase(`http://127.0.0.1:${(server.address() as AddressInfo).port}`, 'a token'));
  cleanups.push(() => server.close());
  cleanups.push(() => server.closeAllConnections());
  cleanups.push(() => connector.close());
  return connector;
}

async function bodyOf(response: IncomingMessage): Promise<string> {
  let body = '';
  for await (const chunk of chunksOf(response)) body += Buffer.from(chunk).toString();
  return body;
}

describe('connection', () => {
  it("splits Vault's address into its API base", () => {
    assert.deepEqual(apiBase('https://vault.example.com:8200/proxy/', 'a token'),
      { https: true, hostname: 'vault.example.com', port: 8200, prefix: '/proxy', base: '/proxy/v1/' });
    assert.deepEqual(apiBase('http://127.0.0.1:8200', 'a token'), { https: false, hostname: '127.0.0.1', port: 8200, prefix: '', base: '/v1/' });
    assert.deepEqual(apiBase('http://[::1]', 'a token'), { https: false, hostname: '::1', port: undefined, prefix: '', base: '/v1/' });
  });

  for (const address of ['http://vault.example.com', 'https://user:pw@vault.example.com', 'https://vault.example.com?x=1', 'https://vault.example.com#f',
    'vault.example.com', 'https:///vault', 'unix:///var/run/vault.sock']) {
    it(`refuses the address ${address}`, () => {
      assert.throws(() => apiBase(address, 'a token'), (e: unknown) => e instanceof InvalidArgumentError && e.code === 'ERR_HKDFGUARD_INVALID_VAULT_ADDRESS');
    });
  }

  it('allows http anywhere only when asked, as VaultClient does with allowUnencryptedHttp', () => {
    assert.equal(apiBase('http://vault.example.com', 'a token', { allowUnencryptedHttp: true }).https, false);
    assert.throws(() => apiBase('http://vault.example.com', 'a token', { allowUnencryptedHttp: false }), /or with allowUnencryptedHttp/);
    assert.throws(() => apiBase('http://vault.example.com', 'a token'), (e: unknown) => e instanceof Error && !e.message.includes('allowUnencryptedHttp'));
  });

  it('knows loopback, with or without brackets, and resolves no name', () => {
    for (const host of ['localhost', '127.0.0.1', '127.8.9.10', '::1', '[::1]']) assert.ok(isLoopback(host), host);
    for (const host of ['vault.example.com', '128.0.0.1', '::2', 'localhost.example.com']) assert.ok(!isLoopback(host), host);
  });

  it('applies the shared defaults, and checks the options every integration shares', () => {
    assert.deepEqual(checkConnectionOptions({}, 'transit'),
      { mountPath: 'transit', namespace: undefined, timeoutMs: DEFAULT_TIMEOUT_MS, retryCount: MIN_RETRY_COUNT, retryDelayMs: DEFAULT_RETRY_DELAY_MS });
    assert.equal(checkConnectionOptions({ mountPath: 'kv/team-a', retryCount: MAX_RETRY_COUNT }, 'secret').mountPath, 'kv/team-a');
    const wrong = [
      { mountPath: 42 }, { mountPath: null }, { namespace: 7 }, { namespace: null }, { timeoutMs: '30' }, { retryCount: '3' }, { retryDelayMs: null },
      { agent: 'tls' }, { tls: 'tls' }, { tls: null }, { agent: new HttpsAgent(), tls: {} }, { mountPath: '../sys' }, { retryCount: 2 },
    ] as unknown as VaultConnectionOptions[];
    for (const options of wrong) assert.throws(() => checkConnectionOptions(options, 'transit'), InvalidArgumentError, JSON.stringify(options));
  });

  it('checks paths and segments', () => {
    for (const path of ['secret', 'kv/team-a', 'a.b_c-d/e']) assert.ok(isValidPath(path), path);
    for (const path of ['', '/secret', 'secret/', 'a//b', 'a/../b', '.', 'a b', 'a?b', 42]) assert.ok(!isValidPath(path), String(path));
    assert.ok(isValidSegment('key-1'));
    assert.ok(!isValidSegment('..') && !isValidSegment('a/b'));
  });

  it('doubles the retry delay up to its limit, plus the jitter', () => {
    assert.equal(retryDelay(200, 0, 0), 200);
    assert.equal(retryDelay(200, 3, 7), 1607);
    assert.equal(retryDelay(200, 10, 0), MAX_RETRY_DELAY_MS);
    assert.equal(retryDelay(200, 1000, 50), MAX_RETRY_DELAY_MS + 50);
  });

  it('checks the shared settings', () => {
    const valid = { mountPath: 'secret', namespace: undefined, timeoutMs: 1, retryCount: MIN_RETRY_COUNT, retryDelayMs: 0 };
    checkConnectionSettings(valid);
    checkConnectionSettings({ ...valid, namespace: 'team-a/prod', timeoutMs: MAX_TIMEOUT_MS, retryCount: MAX_RETRY_COUNT, retryDelayMs: MAX_RETRY_DELAY_MS });
    for (const invalid of [{ mountPath: 'a/../b' }, { namespace: '' }, { timeoutMs: 0 }, { timeoutMs: MAX_TIMEOUT_MS + 1 }, { retryCount: 2 },
      { retryCount: 3.5 }, { retryDelayMs: -1 }, { retryDelayMs: Number.NaN }]) {
      assert.throws(() => checkConnectionSettings({ ...valid, ...invalid }), InvalidArgumentError, JSON.stringify(invalid));
    }
  });
});

describe('VaultRequestError', () => {
  it('is transient without an answer, for 429 and for a 5xx other than 501', () => {
    for (const status of [undefined, 429, 500, 502, 503, 504]) assert.ok(new VaultRequestError('x', { statusCode: status }).isTransient, String(status));
    for (const status of [400, 403, 404, 501, 307]) assert.ok(!new VaultRequestError('x', { statusCode: status }).isTransient, String(status));
    const cause = new Error('reset');
    const error = new VaultRequestError('no answer', { cause });
    assert.equal(error.code, 'ERR_HKDFGUARD_VAULT_REQUEST');
    assert.equal(error.cause, cause);
    assert.equal(error.statusCode, undefined);
  });
});

describe('withRetries', () => {
  it('retries a transient failure, up to the retry count', async () => {
    let attempts = 0;
    const result = await withRetries(async (retry) => {
      assert.equal(retry, attempts++);
      if (attempts < 3) throw markTransient(new Error('reset'));
      return 'done';
    }, 3, 0);
    assert.equal(result, 'done');

    attempts = 0;
    await assert.rejects(withRetries(async () => {
      attempts++;
      throw new VaultRequestError('sealed', { statusCode: 503 });
    }, 3, 0), VaultRequestError);
    assert.equal(attempts, 4);
  });

  it("doesn't retry a failure that isn't transient, or once stopped", async () => {
    let attempts = 0;
    await assert.rejects(withRetries(async () => {
      attempts++;
      throw new VaultRequestError('denied', { statusCode: 403 });
    }, 3, 0), VaultRequestError);
    assert.equal(attempts, 1);

    attempts = 0;
    await assert.rejects(withRetries(async () => {
      attempts++;
      throw markTransient(new Error('reset'));
    }, 3, 0, undefined, { stopped: () => attempts === 2 }), /reset/);
    assert.equal(attempts, 2);
  });

  it("rejects with the signal's reason once aborted, during an attempt or a wait", async () => {
    const controller = new AbortController();
    const reason = new Error('stop');
    let attempts = 0;
    const retrying = withRetries(async () => {
      attempts++;
      throw markTransient(new Error('reset'));
    }, 10, 5_000, controller.signal);
    setTimeout(() => controller.abort(reason), 20);
    await assert.rejects(retrying, (e: unknown) => e === reason);
    assert.equal(attempts, 1);
  });

  it('uses the caller\'s idea of transient when given', async () => {
    let attempts = 0;
    await assert.rejects(withRetries(async () => {
      attempts++;
      throw new Error('mine');
    }, 3, 0, undefined, { isTransient: () => true }));
    assert.equal(attempts, 4);
    assert.ok(!isTransient(new Error('plain')) && !isTransient('text') && isTransient(markTransient(new Error('x'))));
  });
});

describe('runWithin', () => {
  it("returns the action's result, or rejects with a TimeoutError once the timeout passes, aborting the action's signal", async () => {
    assert.equal(await runWithin(() => 7, 1000, undefined, 'slow'), 7);
    let seen: AbortSignal | undefined;
    await assert.rejects(runWithin((signal) => {
      seen = signal;
      return new Promise(() => undefined);
    }, 20, undefined, 'too slow'), (e: unknown) => e instanceof DOMException && e.name === 'TimeoutError' && e.message === 'too slow');
    assert.ok(seen?.aborted);
  });

  it("rejects with the caller's reason when the caller aborts, and with the action's failure", async () => {
    const controller = new AbortController();
    const reason = new Error('caller');
    const running = runWithin(() => new Promise(() => undefined), 10_000, controller.signal, 'slow');
    controller.abort(reason);
    await assert.rejects(running, (e: unknown) => e === reason);
    await assert.rejects(runWithin(() => { throw new Error('own'); }, 1000, undefined, 'slow'), /own/);
  });
});

describe('the token', () => {
  it('copies a source\'s token within the timeout', async () => {
    const destination = Buffer.alloc(MAX_TOKEN_LENGTH);
    assert.equal(await copyTokenWithin(new StaticVaultTokenSource('hvs.token'), destination, 1000), 9);
    assert.equal(destination.toString('latin1', 0, 9), 'hvs.token');
  });

  it('refuses a source that supplies no token, or one that isn\'t one', async () => {
    for (const copy of [() => 0, () => -1, () => MAX_TOKEN_LENGTH + 1, () => 1.5, () => 'x' as unknown as number,
      (d: Uint8Array) => { d.set(Buffer.from('a b')); return 3; }]) {
      await assert.rejects(copyTokenWithin({ copyToken: copy }, Buffer.alloc(MAX_TOKEN_LENGTH), 1000), invalidToken);
    }
    await assert.rejects(copyTokenWithin({ copyToken: () => new Promise(() => undefined) }, Buffer.alloc(MAX_TOKEN_LENGTH), 20),
      (e: unknown) => e instanceof DOMException && e.name === 'TimeoutError');
  });

  it('gets a provider\'s protected token, refusing none', async () => {
    assert.equal(await getTokenWithin(new StaticVaultToken('protected'), 1000), 'protected');
    await assert.rejects(getTokenWithin({ getToken: () => '' }, 1000), invalidToken);
    await assert.rejects(getTokenWithin({ getToken: () => 42 as unknown as string }, 1000), invalidToken);
  });

  it('decrypts a protected token, refusing one the protector did not protect without quoting it', () => {
    const protector = makeProtector();
    const { buffer, length } = decryptToken(protector, protector.encrypt('hvs.token'), 'the protector');
    assert.equal(Buffer.from(buffer.subarray(0, length)).toString('latin1'), 'hvs.token');
    assert.throws(() => decryptToken(protector, 'hvs.token', "the cache's token protector"),
      (e: unknown) => invalidToken(e) && /the cache's token protector/.test((e as Error).message) && !(e as Error).message.includes('hvs.token'));
    assert.throws(() => decryptToken(protector, makeProtector().encrypt('hvs.token'), 'the protector'), invalidToken);
    assert.throws(() => decryptToken(protector, protector.encrypt('not a token'), 'the protector'), invalidToken);
  });

  it('builds the headers every request carries, with the token', () => {
    assert.deepEqual({ ...vaultHeaders(undefined) }, { [REQUEST_HEADER]: 'true' });
    const headers = vaultHeaders('team-a', { 'Content-Type': 'application/json' });
    assert.deepEqual({ ...headers }, { 'Content-Type': 'application/json', [REQUEST_HEADER]: 'true', [NAMESPACE_HEADER]: 'team-a' });
    putToken(headers, Buffer.from('hvs.tokenXXXX'), 9);
    assert.equal(headers[TOKEN_HEADER], 'hvs.token');
    const protector = makeProtector();
    const fresh = vaultHeaders(undefined);
    putProtectedToken(fresh, protector, protector.encrypt('hvs.other'), 'the protector');
    assert.equal(fresh[TOKEN_HEADER], 'hvs.other');
  });
});

describe('sendAttempt', () => {
  it('sends the request with its body and reads the response', async () => {
    const connector = await startServer((request, response) => {
      let body = '';
      request.on('data', (chunk: Buffer) => { body += chunk.toString(); });
      request.on('end', () => response.end(`${request.method} ${request.url} ${request.headers[REQUEST_HEADER.toLowerCase()]} ${body}`));
    });
    const answer = await sendAttempt(() => connector.request('POST', '/v1/x', vaultHeaders(undefined)), Buffer.from('{"a":1}'), bodyOf, 1000,
      undefined, 'slow');
    assert.equal(answer, 'POST /v1/x true {"a":1}');
  });

  it('times out an attempt that gets no answer, as transient', async () => {
    const connector = await startServer(() => undefined);
    await assert.rejects(sendAttempt(() => connector.request('GET', '/v1/x', {}), undefined, bodyOf, 50, undefined, 'no answer in 50 ms'),
      (e: unknown) => e instanceof DOMException && e.name === 'TimeoutError' && e.message === 'no answer in 50 ms' && isTransient(e));
  });

  it("rejects with the caller's reason once aborted, abandoning the request", async () => {
    const connector = await startServer(() => undefined);
    const controller = new AbortController();
    const reason = new Error('caller');
    const sending = sendAttempt(() => connector.request('GET', '/v1/x', {}), undefined, bodyOf, 10_000, controller.signal, 'slow');
    setTimeout(() => controller.abort(reason), 20);
    await assert.rejects(sending, (e: unknown) => e === reason);
  });

  it('marks a refused connection, and a connection lost mid-response, transient', async () => {
    const refused = new VaultConnector(apiBase('http://127.0.0.1:1', 'a token'));
    cleanups.push(() => refused.close());
    await assert.rejects(sendAttempt(() => refused.request('GET', '/', {}), undefined, bodyOf, 1000, undefined, 'slow'), (e: unknown) => isTransient(e));

    const connector = await startServer((_request, response) => {
      response.writeHead(200, { 'Content-Length': 100 });
      response.write('partial');
      setTimeout(() => response.socket?.destroy(), 10);
    });
    await assert.rejects(sendAttempt(() => connector.request('GET', '/', {}), undefined, bodyOf, 1000, undefined, 'slow'), (e: unknown) => isTransient(e));
  });
});

describe('reading answers', () => {
  async function* chunks(...parts: string[]): AsyncGenerator<Uint8Array> {
    for (const part of parts) yield Buffer.from(part);
  }

  it('reads the whole body, zeroing each chunk once copied', async () => {
    const parts = [Buffer.from('{"a":'), Buffer.from('1}')];
    const body = (await readBody((async function* () {
      yield* parts;
    })()))!;
    try {
      assert.equal(body.view().toString(), '{"a":1}');
      for (const part of parts) assert.ok(part.every((b) => b === 0));
    } finally {
      body.close();
    }
  });

  it('reads nothing past the limit, and says so', async () => {
    assert.equal(await readBody(chunks('12345', '6'), 5), undefined);
    const exact = (await readBody(chunks('123', '45'), 5))!;
    assert.equal(exact.view().toString(), '12345');
    exact.close();
    assert.equal(exact.length, 0);
  });

  it("passes on the body's failure", async () => {
    const lost = new Error('lost');
    async function* failing(): AsyncGenerator<Uint8Array> {
      yield Buffer.from('partial');
      throw lost;
    }
    await assert.rejects(readBody(failing()), (e: unknown) => e === lost);
  });

  const bodies: [string, string[] | undefined][] = [
    ['{"errors":["permission denied","2 errors occurred"]}', ['permission denied', '2 errors occurred']],
    ['{"errors":[]}', []],
    ['{"request_id":"x"}', []],
    ['{"errors":[],"error":"one"}', ['one']],
    ['{"error":"one"}', ['one']],
    ['{"errors":["a",{"b":1},2]}', ['a', '{"b":1}', '2']],
    ['{"errors":"internal"}', undefined],
    ['["internal"]', undefined],
    ['<html>Not Found</html>', undefined],
    ['', undefined],
    ['{"errors":[]} trailing', undefined],
  ];
  for (const [body, errors] of bodies) {
    it(`reads the errors ${JSON.stringify(body)} lists`, () => {
      assert.deepEqual(readVaultErrors(Buffer.from(body)), errors);
    });
  }

  it("describes Vault's answer as .NET names its status", () => {
    assert.equal(describeAnswer(400, ['cipher: message authentication failed']), '400 BadRequest: cipher: message authentication failed');
    assert.equal(describeAnswer(403, ['a', 'b']), '403 Forbidden: a; b');
    assert.equal(describeAnswer(404, []), '404 NotFound');
    assert.equal(describeAnswer(299, undefined), '299');
  });

  it('reports a refusal as a VaultRequestError, transient as its status says', () => {
    const sealed = vaultRefusal(503, ['Vault is sealed'], "Couldn't read 'x'");
    assert.ok(sealed instanceof VaultRequestError);
    assert.equal(sealed.message, "Couldn't read 'x': Vault answered 503 ServiceUnavailable: Vault is sealed");
    assert.equal(sealed.statusCode, 503);
    assert.ok(sealed.isTransient);
    const denied = vaultRefusal(403, undefined);
    assert.equal(denied.message, 'Vault answered 403 Forbidden');
    assert.ok(!denied.isTransient);
  });
});

describe('agents and tokens', () => {
  it("uses the caller's agent, else one of its own", () => {
    const given = new HttpsAgent();
    cleanups.push(() => given.destroy());
    assert.deepEqual(httpsAgentFor(given, undefined), { agent: given, own: false });
    const own = httpsAgentFor(undefined, undefined);
    cleanups.push(() => own.agent.destroy());
    assert.ok(own.own && own.agent instanceof HttpsAgent && own.agent !== given);
    assert.throws(() => httpsAgentFor(given, {}), InvalidArgumentError);
  });

  it('takes a non-empty string as a protected token, and nothing else', () => {
    assert.equal(checkProtectedToken('protected'), 'protected');
    for (const token of ['', undefined, null, 42, {}]) assert.throws(() => checkProtectedToken(token), invalidToken);
  });
});

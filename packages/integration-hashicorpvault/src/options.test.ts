import { strict as assert } from 'node:assert';
import { afterEach, describe, it } from 'node:test';
import { InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';
import { VaultClientOptions } from './client-options.js';
import { VaultClient } from './client.js';
import { decrypt, harness, makeProtector, type Harness } from './fake-vault.test-support.js';

const protector = makeProtector();
const opened: VaultClient[] = [];
afterEach(() => {
  for (const client of opened.splice(0)) client.close();
});
const make = (options: VaultClientOptions) => {
  const client = new VaultClient(protector, options);
  opened.push(client);
  return client;
};

describe('VaultClient addresses and options', () => {
  for (const address of ['https://vault.example.com:8200', 'https://vault.example.com/prefix/', 'http://127.0.0.1:8200', 'http://localhost:8200',
    'http://[::1]:8200', 'https://[2001:db8::1]:8200']) {
    it(`accepts ${address}, which keeps the token safe`, () => assert.doesNotThrow(() => make({ address })));
  }

  for (const [address, why] of [['http://vault.example.com', /must be https/], ['http://10.0.0.1', /must be https/], ['unix:///var/run/vault.sock', /unix socket/],
    ['vault.example.com:8200', /isn't absolute/], ['https://user:pw@vault.example.com', /credentials/], ['https://vault.example.com/?q=1', /query/],
    ['https://vault.example.com/#f', /fragment/], ['https:///nohost', /isn't absolute/]] as const) {
    it(`refuses ${address}, naming why`, () => assert.throws(() => make({ address }), (error: InvalidArgumentError) => why.test(error.message)));
  }

  it('accepts http anywhere when allowed', () => {
    assert.doesNotThrow(() => make({ address: 'http://vault.example.com', allowUnencryptedHttp: true }));
  });

  it('refuses a missing protector, and options of the wrong type', () => {
    assert.throws(() => new VaultClient(undefined as never), TypeError);
    assert.throws(() => new VaultClient(protector, 'x' as never), TypeError);
    assert.throws(() => make({ address: 5 as never }), TypeError);
  });

  it('refuses negative times and namespaces it cannot send', () => {
    assert.throws(() => make({ requestTimeoutMs: -1 }), InvalidArgumentError);
    assert.throws(() => make({ retry: { retryWaitMinMs: -1 } }), InvalidArgumentError);
    assert.throws(() => make({ namespace: 'a\nb' }), InvalidArgumentError);
  });

  it('defaults to a local Vault, 60 seconds, and no redirects', () => {
    const client = make({});
    assert.deepEqual(client.options, {});
    assert.equal(VaultClientOptions.DEFAULT_ADDRESS, 'https://127.0.0.1:8200');
    assert.equal(VaultClientOptions.DEFAULT_REQUEST_TIMEOUT_MS, 60_000);
  });
});

describe("a request's settings", () => {
  let h: Harness;
  afterEach(async () => {
    await h.closeAll();
  });

  it('rejects what it cannot send, from the call', async () => {
    h = await harness();
    const client = h.client();
    await assert.rejects(client.read('a', { namespace: 'a\u0000' }), RangeError);
    await assert.rejects(client.read('a', { mfaCredentials: [''] }), RangeError);
    await assert.rejects(client.read('a', { customHeaders: { 'X-Vault-Thing': ['x'] } }), RangeError);
    await assert.rejects(client.read('a', { responseWrappingTtlMs: -5 }), RangeError);
    assert.equal(h.vault.requests.length, 0);
  });
});

describe('VaultClientOptions.fromEnvironment', () => {
  it('reads every variable', async () => {
    const options = VaultClientOptions.fromEnvironment(protector, {
      VAULT_ADDR: 'https://a.example.com', VAULT_AGENT_ADDR: 'http://127.0.0.1:8100', VAULT_CLIENT_TIMEOUT: '30s', VAULT_RATE_LIMIT: '5.5:3',
      VAULT_DISABLE_REDIRECTS: 'true', VAULT_TOKEN: 'hvs.env', VAULT_NAMESPACE: 'ns', VAULT_SKIP_VERIFY: '1', VAULT_CACERT: '/ca.pem',
      VAULT_CACERT_BYTES: 'PEM', VAULT_CAPATH: '/cas', VAULT_CLIENT_CERT: '/c.pem', VAULT_CLIENT_KEY: '/c.key', VAULT_TLS_SERVER_NAME: 'vault.test',
      VAULT_RETRY_WAIT_MIN: '100ms', VAULT_RETRY_WAIT_MAX: '2s', VAULT_MAX_RETRIES: '5',
    });
    assert.equal(options.address, 'http://127.0.0.1:8100');
    assert.equal(options.requestTimeoutMs, 30_000);
    assert.equal(options.rateLimiter?.requestsPerSecond, 5.5);
    assert.equal(options.rateLimiter?.burst, 3);
    assert.equal(options.followRedirects, false);
    assert.equal(options.namespace, 'ns');
    assert.equal(await decrypt(protector, await options.token!.getToken(new AbortController().signal)), 'hvs.env');
    assert.deepEqual(options.tls, {
      insecureSkipVerify: true, serverCertificateFile: '/ca.pem', serverCertificateDirectory: '/cas', clientCertificateFile: '/c.pem',
      clientCertificateKeyFile: '/c.key', serverCertificatePem: 'PEM', serverName: 'vault.test',
    });
    assert.deepEqual(options.retry, { retryWaitMinMs: 100, retryWaitMaxMs: 2000, retryMax: 5 });
  });

  it('is empty with nothing set, an empty variable being unset', () => {
    assert.deepEqual(VaultClientOptions.fromEnvironment(protector, {}), {});
    assert.deepEqual(VaultClientOptions.fromEnvironment(protector, { VAULT_ADDR: '', VAULT_TOKEN: '' }), {});
  });

  it('reads the process environment by default', () => {
    const saved = process.env.VAULT_NAMESPACE;
    process.env.VAULT_NAMESPACE = 'from-process';
    try {
      assert.equal(VaultClientOptions.fromEnvironment().namespace, 'from-process');
    } finally {
      if (saved === undefined) delete process.env.VAULT_NAMESPACE;
      else process.env.VAULT_NAMESPACE = saved;
    }
  });

  it('protects VAULT_TOKEN only given a protector', () => {
    assert.equal(VaultClientOptions.fromEnvironment(undefined, { VAULT_TOKEN: 'hvs.x' }).token, undefined);
  });

  it("refuses what isn't a value", () => {
    for (const environment of [{ VAULT_ADDR: 'vault:8200' }, { VAULT_CLIENT_TIMEOUT: '30' }, { VAULT_RATE_LIMIT: 'fast' }, { VAULT_SKIP_VERIFY: 'yes' },
      { VAULT_MAX_RETRIES: 'two' }, { VAULT_TOKEN: 'has space' }, { VAULT_NAMESPACE: 'a\u0001' }]) {
      assert.throws(() => VaultClientOptions.fromEnvironment(protector, environment), RangeError, JSON.stringify(environment));
    }
  });

  it('leaves redirects as they are for VAULT_DISABLE_REDIRECTS false, and a bare rate its own burst', () => {
    const options = VaultClientOptions.fromEnvironment(protector, { VAULT_DISABLE_REDIRECTS: 'false', VAULT_RATE_LIMIT: '2.7' });
    assert.equal(options.followRedirects, undefined);
    assert.equal(options.rateLimiter?.burst, 2);
  });
});

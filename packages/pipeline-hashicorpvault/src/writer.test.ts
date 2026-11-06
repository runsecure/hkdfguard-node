import { strict as assert } from 'node:assert';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { describe, it, type TestContext } from 'node:test';
import { ClosedError, HkdfGuardError, InvalidArgumentError, type PipelineDataProtector } from '@runsecure/hkdfguard-abstractions';
import { AesGcmPipelineDataProtector } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { DefaultFormatProvider } from '@runsecure/hkdfguard-dek';
import { MAX_RETRY_DELAY_MS } from '@runsecure/hkdfguard-integration-hashicorpvault';
import { decryptPipelineValue, PIPELINE_FORMAT_LIMIT, secretPipelineWriterContract } from '@runsecure/hkdfguard-test-support';
import {
  HashiCorpVaultSecretPipelineWriter, InvalidSecretDataError, SecretsNotFoundError, StaticVaultTokenSource, VaultKvVersion, VaultRequestError,
  type HashiCorpVaultPipelineOptions, type VaultTokenSource,
} from './index.js';

const TOKEN = 'hvs.CAESIFakeTokenForTests';

/** An answer given as it is: a status and a body ('' for none). */
interface Answer {
  status: number;
  body: string;
}

/**
 * A KV secrets engine behind Vault's HTTP API, served over plain http on 127.0.0.1 (which the writer
 * allows on loopback): a GET of a secret's read path with the expected token is answered as Vault
 * answers it - the secret, or 404 with an empty error list - for KV version 2 (the default) or 1. A
 * request without that token is refused with 403, as Vault refuses it. Any other request is recorded
 * in unexpectedRequests and refused. Paths are matched exactly, as Vault matches them.
 */
class FakeVault {
  // A secret's data object as JSON text, so it can hold a member twice.
  readonly secrets = new Map<string, string>();
  readonly deleted = new Set<string>();
  readonly reads: string[] = [];
  readonly tokens: string[] = [];
  readonly namespaces: string[] = [];
  readonly vaultRequestHeaders: string[] = [];
  readonly unexpectedRequests: string[] = [];
  /** When set, a read with the right token is answered with this. */
  answer: Answer | undefined;
  /** Answers given, one each, to the next reads with the right token, before anything else. */
  nextAnswers: Answer[] = [];
  readonly #server: Server;

  private constructor(readonly mountPath: string, readonly kvVersion: VaultKvVersion) {
    this.#server = createServer((request, response) => this.#handle(request, response));
  }

  /** A Vault on a loopback port, closed when the test ends. */
  static async start(t: TestContext, mountPath = 'secret', kvVersion: VaultKvVersion = VaultKvVersion.v2): Promise<FakeVault> {
    const vault = new FakeVault(mountPath, kvVersion);
    await new Promise<void>((resolve) => vault.#server.listen(0, '127.0.0.1', resolve));
    t.after(() => {
      vault.#server.closeAllConnections();
      vault.#server.close();
    });
    return vault;
  }

  get address(): string {
    return `http://127.0.0.1:${(this.#server.address() as { port: number }).port}`;
  }

  /** The secret's value under the default key, "value". */
  set(path: string, value: string): void {
    this.setRawData(path, JSON.stringify({ value }));
  }

  setData(path: string, data: Record<string, unknown>): void {
    this.setRawData(path, JSON.stringify(data));
  }

  setRawData(path: string, json: string): void {
    this.secrets.set(path, json);
  }

  #handle(request: IncomingMessage, response: ServerResponse): void {
    const url = request.url ?? '';
    const prefix = `/v1/${this.mountPath}/${this.kvVersion === VaultKvVersion.v2 ? 'data/' : ''}`;
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

    const secret = this.secrets.get(path);
    const next = this.nextAnswers.shift();
    if (token !== TOKEN) respond(response, { status: 403, body: '{"errors":["permission denied"]}' });
    else if (next !== undefined) respond(response, next);
    else if (this.answer !== undefined) respond(response, this.answer);
    else if (this.deleted.has(path)) respond(response, { status: 404, body: envelope('{"data":null,"metadata":{"version":3,"deletion_time":"x"}}') });
    else if (secret === undefined) respond(response, { status: 404, body: '{"errors":[]}' });
    else if (this.kvVersion === VaultKvVersion.v2) respond(response, { status: 200, body: envelope(`{"data":${secret},"metadata":{"version":3}}`) });
    else respond(response, { status: 200, body: envelope(secret) });
  }
}

function header(request: IncomingMessage, name: string): string | undefined {
  const value = request.headers[name];
  return Array.isArray(value) ? value.join(',') : value;
}

// Vault's response around a data object, given as JSON text.
function envelope(data: string): string {
  return `{"request_id":"0f3c2a8e-1b2d-4c5e-8f9a-0b1c2d3e4f5a","lease_id":"","renewable":false,"lease_duration":0,"data":${data},`
    + '"wrap_info":null,"warnings":null,"auth":null,"mount_type":"kv"}';
}

function respond(response: ServerResponse, answer: Answer): void {
  if (response.destroyed) return;
  const body = Buffer.from(answer.body);
  response.writeHead(answer.status, { 'Content-Type': 'application/json', 'Content-Length': body.length });
  response.end(body);
}

const newProtector = () => new AesGcmPipelineDataProtector(new DefaultFormatProvider(PIPELINE_FORMAT_LIMIT), 3);

interface Fixture {
  vault: FakeVault;
  token: StaticVaultTokenSource;
  protector: PipelineDataProtector;
  create(secretNames: readonly string[], options?: HashiCorpVaultPipelineOptions, vault?: FakeVault): HashiCorpVaultSecretPipelineWriter;
  decrypt(encrypted: string | undefined, fileName: string): string;
}

/** A fake Vault, a token source and a protector, and writers over them - all closed when the test ends. */
async function fixture(t: TestContext): Promise<Fixture> {
  const vault = await FakeVault.start(t);
  const token = new StaticVaultTokenSource(TOKEN);
  const protector = newProtector();
  t.after(() => {
    token.close();
    protector.close();
  });
  return {
    vault,
    token,
    protector,
    create: (secretNames, options = {}, at = vault) => {
      const writer = new HashiCorpVaultSecretPipelineWriter(at.address, token, protector, secretNames, { retryDelayMs: 0, ...options });
      t.after(() => writer.close());
      return writer;
    },
    decrypt: (encrypted, fileName) => decryptPipelineValue(protector, encrypted!, fileName),
  };
}

secretPipelineWriterContract('HashiCorpVaultSecretPipelineWriter over a fake Vault', {
  newProtector,
  setUp: async (t) => {
    const vault = await FakeVault.start(t);
    const token = new StaticVaultTokenSource(TOKEN);
    t.after(() => token.close());
    return {
      // No key ring anywhere: the token is a plain source, and the only key is the protector's.
      createWriter: (protector, secretNames) => new HashiCorpVaultSecretPipelineWriter(vault.address, token, protector, secretNames, { retryDelayMs: 0 }),
      // A name without a key reads the default key, "value".
      setText: (name, text) => vault.set(name, text),
      setKeys: (name, json) => vault.setRawData(name, json),
      failReads: () => {
        vault.answer = { status: 403, body: '{"errors":["permission denied"]}' };
      },
      isReadFailure: (error) => error instanceof VaultRequestError && error.statusCode === 403,
      reads: () => vault.reads,
    };
  },
});

describe('HashiCorpVaultSecretPipelineWriter', () => {
  it('sends the token and the Vault headers with every read', async (t) => {
    const f = await fixture(t);
    f.vault.setData('myapp/db', { username: 'app' });
    const writer = f.create(['myapp/db#username'], { namespace: 'team-a/prod' });

    await writer.pullSecrets();

    assert.equal(f.decrypt(writer.protectedSecrets.get('myapp__db__username'), 'myapp__db__username'), 'app');
    assert.deepEqual(f.vault.tokens, [TOKEN]);
    assert.deepEqual(f.vault.namespaces, ['team-a/prod']);
    assert.deepEqual(f.vault.vaultRequestHeaders, ['true']);
    assert.deepEqual(f.vault.unexpectedRequests, []);
  });

  it('reports a deleted latest version, or a body without data, missing', async (t) => {
    const f = await fixture(t);
    f.vault.deleted.add('gone');
    const writer = f.create(['gone']);
    await assert.rejects(writer.pullSecrets(), SecretsNotFoundError);

    f.vault.answer = { status: 200, body: '{"data":{"metadata":{"version":3}}}' };
    await assert.rejects(writer.pullSecrets(), (error: unknown) => error instanceof SecretsNotFoundError && error.message.includes('gone'));
  });

  it('reads the options\' default key', async (t) => {
    const f = await fixture(t);
    f.vault.setData('myapp/db', { password: 's3cret' });
    const writer = f.create(['myapp/db'], { defaultKey: 'password' });

    await writer.pullSecrets();

    assert.equal(f.decrypt(writer.protectedSecrets.get('myapp__db'), 'myapp__db'), 's3cret');
  });

  it('reads KV version 1 at the mount path', async (t) => {
    const f = await fixture(t);
    const vault = await FakeVault.start(t, 'kv', VaultKvVersion.v1);
    vault.set('item', 's3cret');
    const writer = f.create(['item'], { kvVersion: VaultKvVersion.v1, mountPath: 'kv' }, vault);

    await writer.pullSecrets();

    assert.equal(f.decrypt(writer.protectedSecrets.get('item'), 'item'), 's3cret');
    assert.deepEqual(vault.unexpectedRequests, []);
  });

  const refusals: [status: number, body: string, message: string][] = [
    [403, '{"errors":["permission denied"]}', "Couldn't read 'item': Vault answered 403 Forbidden: permission denied"],
    [404, '{"errors":["no handler for route \\"secret/data/item\\""]}', "Couldn't read 'item': Vault answered 404 NotFound: no handler for route"],
    [404, '<html>Not Found</html>', "Couldn't read 'item': Vault answered 404 NotFound"],
    [500, '', "Couldn't read 'item': Vault answered 500 InternalServerError"],
    [502, '<html>Bad Gateway</html>', "Couldn't read 'item': Vault answered 502 BadGateway"],
  ];
  for (const [status, body, message] of refusals) {
    it(`rejects with Vault's ${status}, its status and errors`, async (t) => {
      const f = await fixture(t);
      f.vault.answer = { status, body };
      const writer = f.create(['item']);

      await assert.rejects(writer.pullSecrets(), (error: unknown) => {
        assert.ok(error instanceof VaultRequestError);
        assert.equal(error.statusCode, status);
        assert.ok(error.message.startsWith(message), error.message);
        assert.ok(!error.message.includes(TOKEN));
        return true;
      });
      // A 5xx is retried, three times by default; anything else isn't.
      assert.equal(f.vault.reads.length, status >= 500 ? 4 : 1);
    });
  }

  it('retries a transient failure, and keeps what the retry read', async (t) => {
    const f = await fixture(t);
    f.vault.set('item', 's3cret');
    f.vault.nextAnswers.push({ status: 503, body: '{"errors":["Vault is sealed"]}' });
    const writer = f.create(['item']);

    await writer.pullSecrets();

    assert.equal(f.decrypt(writer.protectedSecrets.get('item'), 'item'), 's3cret');
    assert.deepEqual(f.vault.reads, ['item', 'item']);
  });

  for (const body of ['[]', '', '{"data":', '{"data":{"data":{"value":"a\\x"}}}']) {
    it(`refuses a success that isn't Vault's JSON: ${JSON.stringify(body)}`, async (t) => {
      const f = await fixture(t);
      f.vault.answer = { status: 200, body };
      const writer = f.create(['item']);

      await assert.rejects(writer.pullSecrets(), (error: unknown) => {
        assert.ok(error instanceof InvalidSecretDataError);
        assert.ok(!error.message.includes('a\\x'));
        return true;
      });
      assert.equal(writer.protectedSecrets.size, 0);
    });
  }

  it('fails the pull when the token source supplies no token', async (t) => {
    const f = await fixture(t);
    const empty: VaultTokenSource = { copyToken: () => 0 };
    const writer = new HashiCorpVaultSecretPipelineWriter(f.vault.address, empty, f.protector, ['item']);
    t.after(() => writer.close());

    await assert.rejects(writer.pullSecrets(), (error: unknown) => error instanceof HkdfGuardError && error.code === 'ERR_HKDFGUARD_INVALID_VAULT_TOKEN');
    assert.deepEqual(f.vault.reads, []);
  });

  it('refuses a pull once closed', async (t) => {
    const f = await fixture(t);
    const writer = f.create(['item']);
    await writer.close();

    await assert.rejects(writer.pullSecrets(), ClosedError);
  });

  it('copies the list', async (t) => {
    const f = await fixture(t);
    f.vault.set('item', 's3cret');
    const names = ['item'];
    const writer = f.create(names);
    names.push('other');

    await writer.pullSecrets();

    assert.deepEqual([...writer.protectedSecrets.keys()], ['item']);
  });

  for (const secretName of ['ConnectionStrings:Admin', '../escape', '.hidden', 'a//b']) {
    it(`refuses '${secretName}', which isn't a path`, async (t) => {
      const f = await fixture(t);
      assert.throws(() => f.create([secretName]), InvalidArgumentError);
    });
  }

  it('refuses a path longer than Vault reads', () => {
    const max = HashiCorpVaultSecretPipelineWriter.MAX_SECRET_NAME_LENGTH;
    assert.equal(HashiCorpVaultSecretPipelineWriter.isValidSecretName('a'.repeat(max)), true);
    assert.equal(HashiCorpVaultSecretPipelineWriter.isValidSecretName('a'.repeat(max + 1)), false);
    assert.equal(HashiCorpVaultSecretPipelineWriter.isValidSecretName(''), false);
    assert.equal(HashiCorpVaultSecretPipelineWriter.isValidSecretName(undefined), false);
  });

  it('checks the address, token source and options', async (t) => {
    const f = await fixture(t);
    const create = (address: string, tokenSource: VaultTokenSource, options?: HashiCorpVaultPipelineOptions) => {
      const writer = new HashiCorpVaultSecretPipelineWriter(address, tokenSource, f.protector, ['item'], options);
      t.after(() => writer.close());
    };
    assert.throws(() => create(f.vault.address, undefined as unknown as VaultTokenSource), InvalidArgumentError);
    assert.throws(() => create(undefined as unknown as string, f.token), TypeError);
    assert.throws(() => create('http://vault.example.com', f.token),
      (error: unknown) => error instanceof InvalidArgumentError && error.code === 'ERR_HKDFGUARD_INVALID_VAULT_ADDRESS');
    assert.throws(() => create(f.vault.address, f.token, { kvVersion: 3 as VaultKvVersion }), InvalidArgumentError);
    assert.throws(() => create(f.vault.address, f.token, { defaultKey: '' }), InvalidArgumentError);
    assert.throws(() => create(f.vault.address, f.token, { defaultKey: 'a#b' }), InvalidArgumentError);
    assert.throws(() => create(f.vault.address, f.token, { mountPath: '../x' }), InvalidArgumentError);
    assert.throws(() => create(f.vault.address, f.token, { retryCount: 2 }), InvalidArgumentError);
    assert.throws(() => create(f.vault.address, f.token, { retryDelayMs: MAX_RETRY_DELAY_MS + 1 }), InvalidArgumentError);
    assert.throws(() => create(f.vault.address, f.token, null as unknown as HashiCorpVaultPipelineOptions), TypeError);

    create('https://vault.example.com:8200', f.token);
  });
});

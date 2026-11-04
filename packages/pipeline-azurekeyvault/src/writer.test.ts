import { strict as assert } from 'node:assert';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, it, type TestContext } from 'node:test';
import { gzipSync } from 'node:zlib';
import { createDefaultHttpClient, type HttpClient, type PipelinePolicy, type PipelineRequest, type PipelineResponse } from '@azure/core-rest-pipeline';
import { SecretClient, type SecretClientOptions } from '@azure/keyvault-secrets';
import { InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';
import { AesGcmPipelineDataProtector } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { DefaultFormatProvider } from '@runsecure/hkdfguard-dek';
import { decryptPipelineValue, PIPELINE_FORMAT_LIMIT, secretPipelineWriterContract } from '@runsecure/hkdfguard-test-support';
import { AzureKeyVaultSecretPipelineWriter, InvalidSecretDataError, SecretsNotFoundError, type KeyVaultCredential } from './index.js';

const HOST = 'hkdfguard-test.vault.azure.net';
const VAULT = `https://${HOST}`;
const TOKEN = 'stub-token';
const CHALLENGE = 'Bearer authorization="https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000", resource="https://vault.azure.net"';
// The bytes the fake vault writes at a time, so a body of any size reaches the client in several chunks.
const CHUNK_LENGTH = 1000;

/**
 * Key Vault's secrets endpoint, as a loopback HTTP server reached through the Azure SDK's own Node
 * HTTP client (createDefaultHttpClient), behind a real SecretClient with no network: the
 * {@link httpClient} it gives SecretClient sends each https://hkdfguard-test.vault.azure.net request
 * to the server instead, so the body arrives as a real response stream, decompressed by the SDK. A
 * request without a bearer token gets Key Vault's 401 challenge, and an authorized Get Secret is
 * answered with the secret's JSON (names compared ignoring case, as Key Vault does) or a 404. Any
 * other request is recorded in `unexpectedRequests` and refused.
 *
 * {@link clientOptions} also installs a per-call policy recording every 200 body SecretClient was
 * given to deserialize, so a test can check the secret never reached it.
 */
class FakeKeyVault {
  readonly secrets = new Map<string, string>();
  /** The name of every authorized Get Secret, in order. */
  readonly gets: string[] = [];
  /** Whether each authorized Get Secret asked for a 200's body unread. */
  readonly streams: boolean[] = [];
  readonly unexpectedRequests: string[] = [];
  /** Every 200 body SecretClient deserialized. */
  readonly bodiesSeenBySecretClient: string[] = [];
  /** When set, an authorized Get Secret is answered with this status and an error body. */
  failWith: number | undefined;
  /** When set, an authorized Get Secret is answered with this body as it is. */
  rawBody: string | undefined;
  /** Hands every body over already read, as bodyAsText, whatever the request asks. */
  alwaysBuffer = false;
  /** Compresses every 200 body with gzip, when the request accepts it. */
  gzip = false;
  readonly httpClient: HttpClient = { sendRequest: (request) => this.#send(request) };
  readonly #transport = createDefaultHttpClient();
  readonly #server: Server;
  #port = 0;

  private constructor() {
    this.#server = createServer((request, response) => {
      response.on('error', () => undefined);
      this.#handle(request, response);
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

  #handle(request: IncomingMessage, response: ServerResponse): void {
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
    if (this.failWith !== undefined) return error(response, this.failWith, this.failWith === 403 ? 'Forbidden' : 'InternalServerError');
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
      headers['Content-Encoding'] = 'gzip';
    }
    respond(response, 200, content, headers);
  }
}

function error(response: ServerResponse, status: number, code: string): void {
  respond(response, status, Buffer.from(JSON.stringify({ error: { code, message: `${code} from the fake vault.` } })));
}

function respond(response: ServerResponse, status: number, content: Buffer, headers: Record<string, string> = {}): void {
  if (response.destroyed) return;
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': String(content.length), ...headers });
  for (let offset = 0; offset < content.length; offset += CHUNK_LENGTH) response.write(content.subarray(offset, offset + CHUNK_LENGTH));
  response.end();
}

/** A credential that hands out the fake vault's token. */
function credential(): KeyVaultCredential {
  return { getToken: async () => ({ token: TOKEN, expiresOnTimestamp: Date.now() + 3_600_000 }) };
}

const newProtector = () => new AesGcmPipelineDataProtector(new DefaultFormatProvider(PIPELINE_FORMAT_LIMIT), 3);

/** A fake vault, a protector, and writers over them - all closed when the test ends. */
async function setUp(t: TestContext) {
  const vault = await FakeKeyVault.start(t);
  const protector = newProtector();
  t.after(() => protector.close());
  const create = (secretNames: readonly string[], clientOptions: SecretClientOptions = vault.clientOptions()) => {
    const writer = new AzureKeyVaultSecretPipelineWriter(VAULT, credential(), protector, secretNames, { clientOptions });
    t.after(() => writer.close());
    return writer;
  };
  const decrypt = (encrypted: string | undefined, fileName: string) => decryptPipelineValue(protector, encrypted!, fileName);
  return { vault, protector, create, decrypt };
}

secretPipelineWriterContract('AzureKeyVaultSecretPipelineWriter over a fake Key Vault', {
  newProtector,
  setUp: async (t) => {
    const vault = await FakeKeyVault.start(t);
    return {
      // No key ring anywhere: the only key is the protector's.
      createWriter: (protector, secretNames) =>
        new AzureKeyVaultSecretPipelineWriter(VAULT, credential(), protector, secretNames, { clientOptions: vault.clientOptions() }),
      setText: (name, text) => vault.set(name, text),
      setKeys: (name, json) => vault.set(name, json),
      failReads: () => {
        vault.failWith = 403;
      },
      isReadFailure: (e) => (e as { name?: unknown }).name === 'RestError' && (e as { statusCode?: unknown }).statusCode === 403,
      reads: () => vault.gets,
    };
  },
});

describe('AzureKeyVaultSecretPipelineWriter', () => {
  it('hands SecretClient only the secret\'s identifier, and streams the body', async (t) => {
    const { vault, create, decrypt } = await setUp(t);
    vault.set('Item', 's3cret');
    const writer = create(['Item']);

    await writer.pullSecrets();

    assert.equal(decrypt(writer.protectedSecrets.get('Item'), 'Item'), 's3cret');
    assert.deepEqual(vault.bodiesSeenBySecretClient, [`{"id":"${VAULT}/secrets/Item"}`]);
    assert.deepEqual(vault.streams, [true]);
    assert.deepEqual(vault.unexpectedRequests, []);
  });

  it('captures a body the HTTP client buffered, or decompressed', async (t) => {
    const { vault, create, decrypt } = await setUp(t);
    vault.set('Item', 's3cret');
    vault.alwaysBuffer = true;
    const buffered = create(['Item']);
    await buffered.pullSecrets();
    assert.equal(decrypt(buffered.protectedSecrets.get('Item'), 'Item'), 's3cret');

    vault.alwaysBuffer = false;
    vault.gzip = true;
    const compressed = create(['Item']);
    await compressed.pullSecrets();
    assert.equal(decrypt(compressed.protectedSecrets.get('Item'), 'Item'), 's3cret');
    assert.ok(vault.bodiesSeenBySecretClient.every((b) => !b.includes('s3cret')));
  });

  it('leaves another client on the same options reading secrets as usual', async (t) => {
    const { vault, create } = await setUp(t);
    vault.set('Item', 's3cret');
    const options = vault.clientOptions();
    create(['Item'], options);
    const other = new SecretClient(VAULT, credential(), options);

    assert.equal((await other.getSecret('Item')).value, 's3cret');
    assert.equal(options.additionalPolicies?.length, 1);
  });

  it('reads the whole value for a name without a key, and its keys from the one call', async (t) => {
    const { vault, create, decrypt } = await setUp(t);
    vault.set('Db-Login', '{"user":"app"}');
    const writer = create(['Db-Login', 'Db-Login#user']);

    await writer.pullSecrets();

    assert.equal(decrypt(writer.protectedSecrets.get('Db-Login'), 'Db-Login'), '{"user":"app"}');
    assert.equal(decrypt(writer.protectedSecrets.get('Db-Login__user'), 'Db-Login__user'), 'app');
    assert.deepEqual(vault.gets, ['Db-Login']);
  });

  for (const body of ['{"value":"x" ', '["value"]', '', '{"value":"a","value":"b"}']) {
    it(`refuses a response that isn't Key Vault's JSON: ${JSON.stringify(body)}`, async (t) => {
      const { vault, create } = await setUp(t);
      vault.rawBody = body;
      const writer = create(['Item']);

      await assert.rejects(writer.pullSecrets(), InvalidSecretDataError);
      assert.equal(writer.protectedSecrets.size, 0);
    });
  }

  it('finds nothing in a response without a string value', async (t) => {
    const { vault, create } = await setUp(t);
    vault.rawBody = `{"value":5,"id":"${VAULT}/secrets/Item/1"}`;
    await assert.rejects(create(['Item']).pullSecrets(), SecretsNotFoundError);
  });

  for (const secretName of ['Db_Password', 'prod/app']) {
    it(`refuses '${secretName}', which Key Vault can't hold`, async (t) => {
      const { create } = await setUp(t);
      assert.throws(() => create([secretName]), InvalidArgumentError);
    });
  }

  it('applies Key Vault\'s name rule', () => {
    const max = AzureKeyVaultSecretPipelineWriter.MAX_SECRET_NAME_LENGTH;
    assert.equal(AzureKeyVaultSecretPipelineWriter.isValidSecretName('Db-Login-2'), true);
    assert.equal(AzureKeyVaultSecretPipelineWriter.isValidSecretName('a'.repeat(max)), true);
    assert.equal(AzureKeyVaultSecretPipelineWriter.isValidSecretName('a'.repeat(max + 1)), false);
    assert.equal(AzureKeyVaultSecretPipelineWriter.isValidSecretName(''), false);
    assert.equal(AzureKeyVaultSecretPipelineWriter.isValidSecretName(undefined), false);
  });

  it('checks the vault, the credential and the options', async (t) => {
    const { protector } = await setUp(t);
    const create = (url: string, cred: KeyVaultCredential, options?: object) =>
      new AzureKeyVaultSecretPipelineWriter(url, cred, protector, ['Item'], options);
    assert.throws(() => create(undefined as unknown as string, credential()), TypeError);
    assert.throws(() => create('', credential()), InvalidArgumentError);
    assert.throws(() => create(VAULT, undefined as unknown as KeyVaultCredential), TypeError);
    assert.throws(() => create(VAULT, credential(), null as unknown as object), TypeError);
    for (const option of ['pipeline', 'endpoint', 'baseUrl']) {
      assert.throws(() => create(VAULT, credential(), { clientOptions: { [option]: 'x' } }), InvalidArgumentError);
    }
    assert.throws(() => create(VAULT, credential(), { clientOptions: { additionalPolicies: {} } }), TypeError);

    create(VAULT, credential());
  });
});

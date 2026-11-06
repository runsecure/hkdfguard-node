import { strict as assert } from 'node:assert';
import { Readable } from 'node:stream';
import { describe, it, type TestContext } from 'node:test';
import {
  GetSecretValueCommand, SecretsManagerClient, SecretsManagerServiceException, type SecretsManagerClientConfig,
} from '@aws-sdk/client-secrets-manager';
import { HkdfGuardError, InvalidArgumentError, isZero, type PipelineDataProtector } from '@runsecure/hkdfguard-abstractions';
import { AesGcmPipelineDataProtector } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { DefaultFormatProvider } from '@runsecure/hkdfguard-dek';
import { decryptPipelineValue, PIPELINE_FORMAT_LIMIT, secretPipelineWriterContract } from '@runsecure/hkdfguard-test-support';
import { AwsSecretsManagerSecretPipelineWriter, InvalidSecretDataError, SecretsNotFoundError, type GetSecretValueClient } from './index.js';

/*
 * The writer through a real SecretsManagerClient - its serializer, middleware stack, retry and
 * deserializer included - answered by FakeSecretsManager's request handler instead of the network.
 */

const utf8 = (s: string) => new TextEncoder().encode(s);
const CREDENTIALS = { accessKeyId: 'testing', secretAccessKey: 'testing' };

interface HttpRequest {
  method: string;
  headers: Record<string, string>;
  body?: unknown;
}

/** What the request handler hands the SDK: the shape of its HttpResponse. */
interface HttpResponse {
  statusCode: number;
  reason?: string;
  headers: Record<string, string>;
  body: unknown;
}

/**
 * Secrets Manager's JSON 1.1 endpoint, as the request handler of a real SecretsManagerClient - no
 * network. A GetSecretValue is answered with the secret (names matched exactly, as AWS matches them)
 * or ResourceNotFoundException; any other operation is recorded in `unexpectedOperations` and
 * refused. A successful body is sent as a Node Readable of small chunks, as an http.IncomingMessage
 * streams one, and every chunk is kept, to check it was zeroed.
 */
class FakeSecretsManager {
  private readonly secrets = new Map<string, string>();
  /** Every SecretId GetSecretValue was called with, in order. */
  readonly gets: string[] = [];
  readonly unexpectedOperations: string[] = [];
  /** Every chunk of every successful body handed to the SDK. */
  readonly chunks: Uint8Array[] = [];
  /** When set, GetSecretValue fails with this AWS error type and HTTP status. */
  failWith: [type: string, status: number] | undefined;
  /** When set, GetSecretValue is answered with this body as it is. */
  rawBody: string | undefined;
  chunkLength = 7;

  readonly requestHandler = {
    handle: (request: HttpRequest) => Promise.resolve(this.answer(request)),
    updateHttpClientConfig() {},
    httpHandlerConfigs() {
      return {};
    },
  };

  setString(name: string, value: string): void {
    this.secrets.set(name, `"SecretString":${JSON.stringify(value)},`);
  }

  setBinary(name: string, value: Uint8Array): void {
    this.secrets.set(name, `"SecretBinary":"${Buffer.from(value).toString('base64')}",`);
  }

  setEmpty(name: string): void {
    this.secrets.set(name, '');
  }

  /** The configuration of a client sending every request here, without retries. */
  config(extra: SecretsManagerClientConfig = {}): SecretsManagerClientConfig {
    return { region: 'us-east-1', credentials: CREDENTIALS, requestHandler: this.requestHandler as never, maxAttempts: 1, ...extra };
  }

  /** A client sending every request here, destroyed when the test ends. */
  client(t: TestContext): SecretsManagerClient {
    const client = new SecretsManagerClient(this.config());
    t.after(() => client.destroy());
    return client;
  }

  private answer(request: HttpRequest): { response: HttpResponse } {
    const operation = request.headers['x-amz-target'] ?? '';
    if (operation !== 'secretsmanager.GetSecretValue') {
      this.unexpectedOperations.push(operation);
      return this.error('AccessDeniedException', 400);
    }

    const text = request.body instanceof Uint8Array ? new TextDecoder().decode(request.body) : String(request.body);
    const body = JSON.parse(text) as Record<string, unknown>;
    // No VersionId or VersionStage: AWSCURRENT.
    assert.deepEqual(Object.keys(body), ['SecretId']);
    const name = body['SecretId'] as string;
    this.gets.push(name);

    if (this.failWith !== undefined) return this.error(...this.failWith);
    if (this.rawBody !== undefined) return respond(200, utf8(this.rawBody));
    const value = this.secrets.get(name);
    if (value === undefined) return this.error('ResourceNotFoundException', 400);

    const response = `{"ARN":${JSON.stringify(`arn:aws:secretsmanager:us-east-1:123456789012:secret:${name}-AbCdEf`)},"Name":${JSON.stringify(name)},${value}`
      + '"VersionId":"a1b2c3d4-5678-90ab-cdef-EXAMPLE11111","VersionStages":["AWSCURRENT"],"CreatedDate":1700000000.0}';
    return respond(200, this.stream(utf8(response)));
  }

  private stream(body: Uint8Array): Readable {
    const chunks: Buffer[] = [];
    for (let i = 0; i < body.length; i += this.chunkLength) chunks.push(Buffer.from(body.subarray(i, i + this.chunkLength)));
    this.chunks.push(...chunks);
    return Readable.from(chunks);
  }

  private error(type: string, status: number): { response: HttpResponse } {
    return respond(status, utf8(JSON.stringify({ __type: type, Message: `${type} in a test.` })), { 'x-amzn-errortype': type });
  }
}

function respond(status: number, body: unknown, headers: Record<string, string> = {}): { response: HttpResponse } {
  return {
    response: {
      statusCode: status, reason: undefined,
      headers: { 'content-type': 'application/x-amz-json-1.1', 'x-amzn-requestid': 'request-1', ...headers },
      body,
    },
  };
}

/** Every output the client's deserializer produced, as the application's own middleware on the client saw it. */
function recordOutputs(client: SecretsManagerClient): Record<string, unknown>[] {
  const outputs: Record<string, unknown>[] = [];
  client.middlewareStack.add((next) => async (args) => {
    const result = await next(args);
    outputs.push(result.output as unknown as Record<string, unknown>);
    return result;
  }, { step: 'initialize', name: 'applicationOutputRecorder' });
  return outputs;
}

const newProtector = () => new AesGcmPipelineDataProtector(new DefaultFormatProvider(PIPELINE_FORMAT_LIMIT), 3);

/** A fake, a client sending to it, a protector, and writers over them - all closed when the test ends. */
function setUp(t: TestContext) {
  const aws = new FakeSecretsManager();
  const client = aws.client(t);
  const protector = newProtector();
  t.after(() => protector.close());
  const create = (secretNames: readonly string[]) => {
    const writer = new AwsSecretsManagerSecretPipelineWriter(protector, secretNames, client);
    t.after(() => writer.close());
    return writer;
  };
  const decrypt = (encrypted: string | undefined, fileName: string) => decryptPipelineValue(protector, encrypted!, fileName);
  return { aws, client, protector, create, decrypt };
}

secretPipelineWriterContract('AwsSecretsManagerSecretPipelineWriter over a fake Secrets Manager', {
  newProtector,
  setUp: (t) => {
    const aws = new FakeSecretsManager();
    const client = aws.client(t);
    return {
      // No key ring anywhere: the only key is the protector's.
      createWriter: (protector, secretNames) => new AwsSecretsManagerSecretPipelineWriter(protector, secretNames, client),
      setText: (name, text) => aws.setString(name, text),
      setKeys: (name, json) => aws.setString(name, json),
      failReads: () => {
        aws.failWith = ['AccessDeniedException', 400];
      },
      isReadFailure: (error) => error instanceof SecretsManagerServiceException && error.name === 'AccessDeniedException',
      reads: () => aws.gets,
    };
  },
});

describe('AwsSecretsManagerSecretPipelineWriter', () => {
  it('leaves the SDK\'s output holding nothing', async (t) => {
    const { aws, client, create } = setUp(t);
    const outputs = recordOutputs(client);
    aws.setString('item', 's3cret');
    const writer = create(['item']);

    await writer.pullSecrets();

    assert.equal(outputs.length, 1);
    assert.equal(outputs[0]!['SecretString'], undefined);
    assert.equal(outputs[0]!['SecretBinary'], undefined);
    assert.equal(outputs[0]!['ARN'], undefined);
    assert.deepEqual(aws.unexpectedOperations, []);
  });

  it('zeroes every chunk of the response stream', async (t) => {
    const { aws, create } = setUp(t);
    aws.setString('prod/app', '{"user":"app","password":"s3cret"}');
    const writer = create(['prod/app#password']);

    await writer.pullSecrets();

    assert.ok(aws.chunks.length > 10);
    assert.ok(aws.chunks.every(isZero));
  });

  it('leaves another request on the writer\'s client as it is', async (t) => {
    const { aws, client, create } = setUp(t);
    aws.setString('item', 's3cret');
    const writer = create(['item']);
    await writer.pullSecrets();

    const response = await client.send(new GetSecretValueCommand({ SecretId: 'item' }));

    assert.equal(response.SecretString, 's3cret');
  });

  it('reads the whole SecretString for a name without a key, and its keys from the one call', async (t) => {
    const { aws, create, decrypt } = setUp(t);
    aws.setString('prod/app', '{"user":"app"}');
    const writer = create(['prod/app', 'prod/app#user']);

    await writer.pullSecrets();

    assert.equal(decrypt(writer.protectedSecrets.get('prod__app'), 'prod__app'), '{"user":"app"}');
    assert.equal(decrypt(writer.protectedSecrets.get('prod__app__user'), 'prod__app__user'), 'app');
    assert.deepEqual(aws.gets, ['prod/app']);
  });

  it('reports an empty secret missing', async (t) => {
    const { aws, create } = setUp(t);
    aws.setEmpty('empty');
    await assert.rejects(create(['empty']).pullSecrets(), SecretsNotFoundError);
  });

  it('refuses a SecretBinary', async (t) => {
    const { aws, create } = setUp(t);
    aws.setBinary('binary', new Uint8Array([1, 2, 3]));
    const writer = create(['binary']);

    await assert.rejects(writer.pullSecrets(), InvalidSecretDataError);
    assert.equal(writer.protectedSecrets.size, 0);
  });

  for (const body of ['{"SecretString":"x" ', '["SecretString"]', '', '{"SecretString":"a","SecretString":"b"}']) {
    it(`refuses a response that isn't Secrets Manager's JSON: ${JSON.stringify(body)}`, async (t) => {
      const { aws, create } = setUp(t);
      aws.rawBody = body;
      const writer = create(['item']);

      await assert.rejects(writer.pullSecrets(), InvalidSecretDataError);
      assert.equal(writer.protectedSecrets.size, 0);
    });
  }

  it('refuses a client whose send never runs the command\'s middleware', async (t) => {
    const { protector } = setUp(t);
    const canned: GetSecretValueClient = { send: async () => ({ SecretString: 's3cret' }) };
    const writer = new AwsSecretsManagerSecretPipelineWriter(protector, ['item'], canned);

    await assert.rejects(writer.pullSecrets(), (error: unknown) => error instanceof HkdfGuardError && error.code === 'ERR_HKDFGUARD_INVALID_STATE');
    assert.equal(writer.protectedSecrets.size, 0);
  });

  it('makes a client of its own with create, and destroys it on close', async (t) => {
    const { aws, protector, decrypt } = setUp(t);
    aws.setString('item', 's3cret');
    const destroy = t.mock.method(SecretsManagerClient.prototype, 'destroy');
    const writer = AwsSecretsManagerSecretPipelineWriter.create(protector, ['item'], aws.config());

    await writer.pullSecrets();
    assert.equal(decrypt(writer.protectedSecrets.get('item'), 'item'), 's3cret');
    await writer.close();

    assert.equal(destroy.mock.callCount(), 1);
    assert.throws(() => AwsSecretsManagerSecretPipelineWriter.create(protector, ['a:b'], aws.config()), InvalidArgumentError);
    assert.equal(destroy.mock.callCount(), 2);
  });

  it('leaves a client passed in undestroyed', async (t) => {
    const { create } = setUp(t);
    const destroy = t.mock.method(SecretsManagerClient.prototype, 'destroy');
    await create(['item']).close();
    assert.equal(destroy.mock.callCount(), 0);
  });

  for (const secretName of ['ConnectionStrings:Admin', 'user@example', 'a+b', 'a=b', '.hidden']) {
    it(`refuses '${secretName}', which no file name can be`, (t) => {
      const { create } = setUp(t);
      assert.throws(() => create([secretName]), InvalidArgumentError);
    });
  }

  it('checks the client', (t) => {
    const { protector } = setUp(t);
    assert.throws(() => new AwsSecretsManagerSecretPipelineWriter(protector, ['item'], undefined as unknown as GetSecretValueClient), TypeError);
    assert.throws(() => new AwsSecretsManagerSecretPipelineWriter(protector, ['item'], {} as GetSecretValueClient), TypeError);
  });

  it('applies Secrets Manager\'s name rule', () => {
    const max = AwsSecretsManagerSecretPipelineWriter.MAX_SECRET_NAME_LENGTH;
    assert.equal(AwsSecretsManagerSecretPipelineWriter.isValidSecretName('prod/a_b+c=d.e@f-g'), true);
    assert.equal(AwsSecretsManagerSecretPipelineWriter.isValidSecretName('a'.repeat(max)), true);
    assert.equal(AwsSecretsManagerSecretPipelineWriter.isValidSecretName('a'.repeat(max + 1)), false);
    assert.equal(AwsSecretsManagerSecretPipelineWriter.isValidSecretName(''), false);
    assert.equal(AwsSecretsManagerSecretPipelineWriter.isValidSecretName(undefined), false);
    assert.equal(AwsSecretsManagerSecretPipelineWriter.isValidSecretName('a:b'), false);
  });
});

import { GetSecretValueCommand, SecretsManagerClient, type SecretsManagerClientConfig } from '@aws-sdk/client-secrets-manager';
import { HkdfGuardError, wipe, type PipelineDataProtector } from '@runsecure/hkdfguard-abstractions';
import { JsonReader, JsonToken, MalformedJsonError } from '@runsecure/hkdfguard-abstractions/internal';
import { InvalidSecretDataError, SecretPipelineWriter, type SecretRequest } from '@runsecure/hkdfguard-pipeline';
import { SecretCapture } from './capture.js';

const NOT_FOUND = 'ResourceNotFoundException';
const NAME_PATTERN = /^[A-Za-z0-9/_+=.@-]+$/;

/**
 * What {@link AwsSecretsManagerSecretPipelineWriter} needs of a Secrets Manager client: `send`, as the
 * AWS SDK for JavaScript v3 defines it, running the command's own middleware stack. A
 * `SecretsManagerClient` from @aws-sdk/client-secrets-manager is one. A test double whose `send`
 * doesn't run the command's middleware can be passed, but every read through it is refused.
 */
export interface GetSecretValueClient {
  send(command: GetSecretValueCommand, options?: { abortSignal?: AbortSignal }): Promise<unknown>;
}

/**
 * The end of a provisioning pipeline - the Node port of .NET's AwsSecretsManagerSecretPipelineWriter:
 * pulls a fixed list of secrets from AWS Secrets Manager, encrypts each with a PipelineDataProtector
 * as soon as it is read, and writes them out as one file per secret - the folder layout
 * FilePerSecretCache reads at runtime. It is independent of
 * @runsecure/hkdfguard-cache-awssecretsmanager's runtime cache, and of any key ring. Naming,
 * encrypting, keeping and writing are SecretPipelineWriter's.
 *
 * A secret name is a Secrets Manager secret name, optionally with a key after '#': "prod/api-key"
 * reads the secret's whole SecretString, and "prod/app#password" the password member of a key/value
 * secret - a SecretString holding a JSON object, as the console stores one (written as prod__api-key
 * and prod__app__password). A member's string is read as its text; a number, true or false as its
 * JSON text. Each secret's current version (AWSCURRENT) is read with GetSecretValue, so the
 * principal needs only `secretsmanager:GetSecretValue` on them (and `kms:Decrypt` on a customer
 * managed key that encrypts them). A name holding '+', '=' or '@', which no file name can, is
 * refused. A SecretBinary is refused with InvalidSecretDataError: the protector encrypts text.
 *
 * A secret that doesn't exist (ResourceNotFoundException) or whose value is empty is missing. Any
 * other failure (access denied, a secret scheduled for deletion, AWS unreachable, no credentials)
 * rejects with the SDK's own error, unchanged; a response body that isn't Secrets Manager's JSON, or
 * a key/value secret holding a key twice, with InvalidSecretDataError.
 *
 * The secret never becomes a string. Each GetSecretValueCommand the writer sends carries a middleware
 * of its own (on the command's stack, never the client's), innermost in the call, which reads the
 * response body off the network into a buffer of the library's own and hands the SDK's deserializer
 * an empty object in its place - so the parsed output, the SDK's logger and every middleware the
 * application added to the client hold nothing; every buffer holding the value is zeroed. What can't
 * be zeroed is below the middleware: the HTTP stack's own buffers. Timeouts and retries are the
 * client's.
 */
export class AwsSecretsManagerSecretPipelineWriter extends SecretPipelineWriter {
  /** The longest name Secrets Manager accepts for a secret. */
  static readonly MAX_SECRET_NAME_LENGTH = 512;

  readonly #client: GetSecretValueClient;
  #ownClient: SecretsManagerClient | undefined;

  /**
   * A writer reading through a client the caller created, and destroys.
   * @param protector encrypts every value read. Owned by the caller: the writer never closes it.
   * @param secretNames the secrets to pull, each a secret name with the key to read after '#' if
   *   any. Copied: a later change to the array isn't seen.
   * @param client the Secrets Manager client every call is made through (a `SecretsManagerClient`:
   *   region, credentials, retries, timeouts). Never destroyed by the writer.
   * @throws TypeError protector or secretNames is missing, or client has no `send`
   * @throws InvalidArgumentError secretNames is empty, or holds something that isn't a string, a name
   *   Secrets Manager can't hold (with a key), one whose file name isn't one FilePerSecretCache can
   *   read, or two with the same file name, in any case
   */
  constructor(protector: PipelineDataProtector, secretNames: readonly string[], client: GetSecretValueClient) {
    super(protector, secretNames, AwsSecretsManagerSecretPipelineWriter.isValidSecretName);
    if (typeof client !== 'object' || client === null || typeof client.send !== 'function') {
      throw new TypeError('client must be a Secrets Manager client (a SecretsManagerClient from @aws-sdk/client-secrets-manager).');
    }
    this.#client = client;
  }

  /**
   * A writer reading through a new SecretsManagerClient of its own, which {@link close} destroys - as
   * .NET's writer makes its own client.
   * @param config the client's configuration (region, credentials, retries, timeouts...); omitted for
   *   the SDK's defaults, which take the region from the environment or profile and the credentials
   *   from the default chain (environment, profile, IRSA or EKS Pod Identity, instance role...)
   * @throws as the constructor
   */
  static create(protector: PipelineDataProtector, secretNames: readonly string[], config: SecretsManagerClientConfig = {}): AwsSecretsManagerSecretPipelineWriter {
    const client = new SecretsManagerClient(config);
    try {
      const writer = new AwsSecretsManagerSecretPipelineWriter(protector, secretNames, client);
      writer.#ownClient = client;
      return writer;
    } catch (error) {
      client.destroy();
      throw error;
    }
  }

  /** Whether Secrets Manager accepts `name` as a secret name: 1-512 ASCII letters, digits and /_+=.@- */
  static isValidSecretName(name: string | undefined | null): boolean {
    return typeof name === 'string' && name.length <= AwsSecretsManagerSecretPipelineWriter.MAX_SECRET_NAME_LENGTH && NAME_PATTERN.test(name);
  }

  /** Destroys the client {@link create} made; a client passed in is left as it is. */
  protected override closeStore(): void {
    this.#ownClient?.destroy();
  }

  /**
   * @throws SecretsManagerServiceException (rejecting) any AWS failure but ResourceNotFoundException
   *   (access denied, a secret scheduled for deletion), or the SDK's own error (no credentials, AWS unreachable)
   * @throws InvalidSecretDataError (rejecting) the secret is a SecretBinary, the response isn't
   *   Secrets Manager's JSON, or a key/value secret holds a key twice
   */
  protected override async readSecret(name: string, requests: readonly SecretRequest[], values: Map<string, string>, signal?: AbortSignal): Promise<void> {
    // Filled by the command's capture, from the body in a buffer of the library's own, once per
    // attempt; the output the SDK parses holds nothing, so it isn't read here.
    const read = new Map<string, string>();
    const command = new GetSecretValueCommand({ SecretId: name });
    const capture = new SecretCapture((buffer, length) => {
      read.clear();
      this.#protectValues(buffer, length, requests, read);
    }, signal);
    capture.attachTo(command);

    try {
      // Options are always passed, even empty: a client created with cacheMiddleware: true reuses
      // the handler it resolved for a command class - capture and all - only for calls made without.
      await this.#client.send(command, signal === undefined ? {} : { abortSignal: signal });
    } catch (error) {
      // A body the capture refused fails the call with the capture's own error; report that one,
      // whatever a middleware outside it made of it.
      if (capture.failed) throw capture.failure;
      // Missing: nothing handed over.
      if (isNotFound(error)) return;
      throw error;
    }

    // A successful response whose body never passed through the capture may hold the secret as a
    // string in its output; refuse it rather than report the secret missing.
    if (!capture.captured) {
      throw new HkdfGuardError('ERR_HKDFGUARD_INVALID_STATE', "The GetSecretValue response wasn't captured: the client's send never ran "
        + "the command's middleware (a test double that answers by itself, say), so the secret may be in its output as a string.");
    }
    for (const [fileName, value] of read) values.set(fileName, value);
  }

  // Encrypts the top-level SecretString of a GetSecretValue body, and each requested key it holds.
  #protectValues(body: Uint8Array, length: number, requests: readonly SecretRequest[], values: Map<string, string>): void {
    const reader = new JsonReader(body, length);
    try {
      if (!SecretPipelineWriter.startsObject(reader)) throw new InvalidSecretDataError("The response body isn't a JSON object.");

      let protectedOnce = false;
      while (SecretPipelineWriter.nextProperty(reader)) {
        const isText = reader.valueTextEquals('SecretString');
        const isBinary = !isText && reader.valueTextEquals('SecretBinary');
        reader.read();
        if (reader.token() !== JsonToken.String || reader.valueLength === 0 || !(isText || isBinary)) {
          reader.skip();
          continue;
        }

        if (isBinary) throw new InvalidSecretDataError("A SecretBinary can't be protected: the pipeline protector encrypts text.");
        if (protectedOnce) throw new InvalidSecretDataError('The response body holds more than one secret value.');
        this.#protectSecretString(reader, requests, values);
        protectedOnce = true;
      }
    } catch (error) {
      // Never chained, and never quoting the byte rejected, which may be in the secret.
      if (error instanceof MalformedJsonError) {
        throw new InvalidSecretDataError(`The response body isn't valid JSON (at byte ${error.position} of line ${error.line}).`);
      }
      throw error;
    }
  }

  // Unescapes the SecretString reader is at into a buffer of its own, and encrypts it whole and each
  // requested key it holds.
  #protectSecretString(reader: JsonReader, requests: readonly SecretRequest[], values: Map<string, string>): void {
    // Unescaped, a string is never longer than it is escaped.
    const text = new Uint8Array(reader.valueLength);
    try {
      this.protectSecret(text.subarray(0, reader.copyString(text)), requests, values);
    } finally {
      wipe(text);
    }
  }
}

// Whether error is Secrets Manager's answer for a secret that doesn't exist: the SDK names its
// errors by their error code, modeled or not.
function isNotFound(error: unknown): boolean {
  return typeof error === 'object' && error !== null && (error as { name?: unknown }).name === NOT_FOUND;
}

import { GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { HkdfGuardError, wipe, type KeyRing } from '@runsecure/hkdfguard-abstractions';
import { RemoteSecretCache, SecretNameMatching, type SecretValueSink } from '@runsecure/hkdfguard-cache';
import type { Logger } from '@runsecure/hkdfguard-diagnostics';
import { SecretCapture } from './capture.js';

const NOT_FOUND = 'ResourceNotFoundException';
const NAME_PATTERN = /^[A-Za-z0-9/_+=.@-]+$/;

/**
 * What {@link AwsSecretsManagerSecretCache} needs of a Secrets Manager client: `send`, as the AWS
 * SDK for JavaScript v3 defines it, running the command's own middleware stack. A
 * `SecretsManagerClient` from @aws-sdk/client-secrets-manager is one - whichever copy of the SDK the
 * application installed. A test double whose `send` doesn't run the command's middleware (such as
 * one that answers with a canned output) can be passed, but every fetch through it is refused.
 */
export interface GetSecretValueClient {
  send(command: GetSecretValueCommand, options?: { abortSignal?: AbortSignal }): Promise<unknown>;
}

/**
 * A ProtectedReadOnlyCache over the secrets in AWS Secrets Manager - the Node port of the .NET
 * HkdfGuard.Cache.AwsSecretsManager library. The first lookup of a name that isn't cached yet reads
 * that one secret's current version (AWSCURRENT) with GetSecretValue; fetching, encryption, caching
 * and telemetry are RemoteSecretCache's. This class never lists secrets (ListSecrets,
 * BatchGetSecretValue), so the principal needs only `secretsmanager:GetSecretValue` on the secrets
 * it reads (and `kms:Decrypt` on a customer managed key that encrypts them).
 *
 * Names are matched exactly, as Secrets Manager matches them: "prod/Db" and "prod/db" are two
 * secrets and two entries. A name Secrets Manager can't hold - anything but 1-512 ASCII letters,
 * digits and /_+=.@- , such as the configuration path "ConnectionStrings:Admin" - is reported missing
 * without a call. ARNs aren't accepted (':' isn't a name character): look secrets up by name.
 *
 * A secret that doesn't exist (ResourceNotFoundException) or whose value is empty is reported
 * missing. Any other failure (access denied, a secret scheduled for deletion, a decryption failure,
 * AWS unreachable, no credentials) rejects with the SDK's own error, unchanged - a modeled
 * exception such as InvalidRequestException, or a SecretsManagerServiceException carrying the
 * error's name, for an error response - and a response body that can't be trusted as Secrets
 * Manager's rejects with InvalidSecretDataError. A SecretString is cached as its UTF-8 bytes; a
 * SecretBinary as its bytes.
 *
 * A key/value secret - a SecretString holding a JSON object, as the console stores one - is cached
 * whole under its name and each member under "name#key" - "prod/app#password" - all from one
 * GetSecretValue (see RemoteSecretCache). A SecretBinary is never split.
 *
 * The secret never becomes a string. Each GetSecretValueCommand the cache sends carries a
 * middleware of its own (on the command's stack, never the client's), innermost in the call, which
 * takes SecretString or SecretBinary out of a successful response's body (SecretJsonBody) and hands
 * the SDK's deserializer the body with both replaced by "" - so the parsed output, the SDK's logger
 * and every middleware the application added to the client hold nothing secret. The application's
 * own calls on the client, and this cache's concurrent calls, each see only their own response.
 * Every chunk of the response stream, and every buffer of this library's that held the value, is
 * zeroed. What can't be zeroed is below the middleware: the HTTP stack's own buffers (TLS
 * decryption, socket reads) - and a request handler the application supplies that buffers the body
 * before handing it over.
 *
 * The client is the application's: it creates it (credentials, region, retries, timeouts), keeps it
 * for as long as anything uses this cache, and destroys it. This cache never destroys it, and
 * changes nothing on it. A lookup's `signal` is passed to the SDK, which aborts the request; the
 * abort is rethrown as the SDK reports it.
 */
export class AwsSecretsManagerSecretCache extends RemoteSecretCache {
  /** The longest name Secrets Manager accepts for a secret. */
  static readonly MAX_SECRET_NAME_LENGTH = 512;

  readonly #client: GetSecretValueClient;

  /**
   * @param client the Secrets Manager client every call is made through (a `SecretsManagerClient`).
   *   Never destroyed by this cache; its owner, the application, destroys it.
   * @param ring supplies the key every fetched secret is encrypted under; owned by the caller - the
   *   cache never closes keys
   * @param logger see RemoteSecretCache
   * @throws TypeError client has no `send`, or ring is missing
   */
  constructor(client: GetSecretValueClient, ring: KeyRing, logger?: Logger) {
    if (typeof client !== 'object' || client === null || typeof client.send !== 'function') {
      throw new TypeError('client must be a Secrets Manager client (a SecretsManagerClient from @aws-sdk/client-secrets-manager).');
    }
    super(ring, SecretNameMatching.exact, logger);
    this.#client = client;
  }

  /**
   * Whether Secrets Manager accepts `name` as a secret name: 1-{@link MAX_SECRET_NAME_LENGTH} ASCII
   * letters, digits and /_+=.@- . Anything but a string is not one.
   */
  static isValidSecretName(name: string | undefined | null): boolean {
    return typeof name === 'string' && name.length <= AwsSecretsManagerSecretCache.MAX_SECRET_NAME_LENGTH && NAME_PATTERN.test(name);
  }

  protected override isValidName(name: string): boolean {
    return AwsSecretsManagerSecretCache.isValidSecretName(name);
  }

  protected override async fetch(name: string, sink: SecretValueSink, signal?: AbortSignal): Promise<void> {
    // The value reaches the sink through the command's capture; the output holds it as "", so it isn't read here.
    const command = new GetSecretValueCommand({ SecretId: name });
    const capture = new SecretCapture(sink, signal);
    capture.attachTo(command);

    let output: unknown;
    try {
      // Options are always passed, even empty: a client created with cacheMiddleware: true reuses
      // the handler it resolved for a command class - capture and all - only for calls made without.
      output = await this.#client.send(command, signal === undefined ? {} : { abortSignal: signal });
    } catch (error) {
      // A body the capture refused fails the call with the capture's own error; report that one,
      // whatever a middleware outside it made of it.
      if (capture.failed) throw capture.failure;
      if (isNotFound(error)) return;
      throw error;
    }

    // A successful response whose body never passed through the capture held the secret, and
    // nothing was cached; refuse it rather than report the secret missing.
    if (!capture.captured) {
      throw new HkdfGuardError('ERR_HKDFGUARD_INVALID_STATE', "The GetSecretValue response wasn't captured: the client's send never ran "
        + "the command's middleware (a test double that answers by itself, say), so the secret may be in its output as a string.");
    }
    // Decoded from "", so empty; zeroed whatever it holds.
    const binary = (output as { SecretBinary?: unknown } | undefined)?.SecretBinary;
    if (binary instanceof Uint8Array) wipe(binary);
  }
}

// Whether error is Secrets Manager's answer for a secret that doesn't exist: the SDK names its
// errors by their error code, modeled or not.
function isNotFound(error: unknown): boolean {
  return typeof error === 'object' && error !== null && (error as { name?: unknown }).name === NOT_FOUND;
}

import { SecretClient, type SecretClientOptions } from '@azure/keyvault-secrets';
import { HkdfGuardError, InvalidArgumentError, wipe, type PipelineDataProtector } from '@runsecure/hkdfguard-abstractions';
import { JsonReader, JsonToken, MalformedJsonError } from '@runsecure/hkdfguard-abstractions/internal';
import { InvalidSecretDataError, SecretPipelineWriter, type SecretRequest } from '@runsecure/hkdfguard-pipeline';
import { Capture, captureWithin, secretCapturePolicy } from './capture.js';

/**
 * What authenticates every call to Key Vault: an Azure `TokenCredential` (@azure/core-auth), such as
 * @azure/identity's WorkloadIdentityCredential or ManagedIdentityCredential, or DefaultAzureCredential.
 */
export type KeyVaultCredential = ConstructorParameters<typeof SecretClient>[1];

/** The options of an {@link AzureKeyVaultSecretPipelineWriter}. */
export interface AzureKeyVaultSecretPipelineWriterOptions {
  /**
   * Options for the writer's SecretClient - `serviceVersion`, `retryOptions`, `httpClient`,
   * `additionalPolicies`, proxy and telemetry options; copied, so the caller's object (and its
   * `additionalPolicies` array) is left as it is. The capture policy is added after the caller's
   * per-retry policies. Options that would replace the pipeline the policy is in, or the vault URL,
   * are refused: `pipeline`, `endpoint` and `baseUrl`.
   */
  readonly clientOptions?: SecretClientOptions;
}

// Client options the SDK honours although its types don't declare them all, which would replace the
// pipeline the capture policy is in, or send the writer's requests elsewhere.
const REFUSED_OPTIONS: Readonly<Record<string, string>> = {
  pipeline: 'it replaces the pipeline, the capture policy with it',
  endpoint: 'the writer passes the vault URL itself',
  baseUrl: 'the writer passes the vault URL itself',
};

const SECRET_NAME = /^[A-Za-z0-9-]+$/;

/**
 * The end of a provisioning pipeline - the Node port of .NET's AzureKeyVaultSecretPipelineWriter:
 * pulls a fixed list of secrets from one Azure Key Vault, encrypts each with a PipelineDataProtector
 * as soon as it is read, and writes them out as one file per secret - the folder layout
 * FilePerSecretCache reads at runtime. It is independent of
 * @runsecure/hkdfguard-cache-azurekeyvault's runtime cache, and of any key ring, with its own
 * SecretClient. Naming, encrypting, keeping and writing are SecretPipelineWriter's.
 *
 * A secret name is a Key Vault secret name - 1-127 ASCII letters, digits and hyphens - optionally
 * with a key after '#': "Api-Key" reads the secret's whole value, and "Db-Login#password" the
 * password member of a secret whose value is a JSON object (written as Api-Key and
 * Db-Login__password). A member's string is read as its text; a number, true or false as its JSON
 * text. Each secret's current version is read with Get Secret, so the identity needs only `get` on
 * secrets (the Key Vault Secrets User role), never `list`. Key Vault compares names ignoring case; so
 * do file names, so two names differing only in case are refused.
 *
 * A secret that doesn't exist (HTTP 404) or whose value is empty is missing. Any other failure
 * (access denied, a disabled secret, the vault unreachable) rejects with the Azure SDK's RestError, a
 * credential that can't get a token with the credential's own error, and a response that isn't Key
 * Vault's JSON - or a JSON object value holding a key twice - with InvalidSecretDataError.
 *
 * The secret never becomes a JavaScript string. The writer's SecretClient has a pipeline policy that
 * reads the response body off the network into a buffer of the library's own and hands SecretClient
 * only the secret's identifier in its place; every buffer holding the value is zeroed. The capture
 * travels with each read's asynchronous context, never on the client. The SDK's logging policy logs
 * headers only, never a body, so there is no content logging to refuse, as .NET must. Retries and
 * timeouts are the client options'. On AKS, Microsoft Entra Workload Identity supplies the
 * credential through DefaultAzureCredential or WorkloadIdentityCredential. The client holds no
 * resources that need releasing.
 */
export class AzureKeyVaultSecretPipelineWriter extends SecretPipelineWriter {
  /** The longest name Key Vault accepts for a secret. */
  static readonly MAX_SECRET_NAME_LENGTH = 127;

  readonly #client: SecretClient;

  /**
   * @param vaultUrl the vault to read secrets from: `https://{vault}.vault.azure.net/`
   * @param credential authenticates every call to Key Vault, e.g. a managed or workload identity
   * @param protector encrypts every value read. Owned by the caller: the writer never closes it.
   * @param secretNames the secrets to pull, each a secret name with the key to read after '#' if
   *   any. Copied: a later change to the array isn't seen.
   * @param options the writer's SecretClient's options
   * @throws TypeError protector or secretNames is missing, vaultUrl isn't a string, credential has no
   *   `getToken`, or options, clientOptions or its additionalPolicies isn't an object (an array)
   * @throws InvalidArgumentError secretNames is empty, or holds something that isn't a string, a name
   *   Key Vault can't hold (with a key), one whose file name isn't one FilePerSecretCache can read, or
   *   two with the same file name, in any case; vaultUrl is empty or isn't a URL; or clientOptions
   *   sets an option the writer refuses
   */
  constructor(
    vaultUrl: string, credential: KeyVaultCredential, protector: PipelineDataProtector, secretNames: readonly string[],
    options: AzureKeyVaultSecretPipelineWriterOptions = {},
  ) {
    super(protector, secretNames, AzureKeyVaultSecretPipelineWriter.isValidSecretName);
    if (typeof vaultUrl !== 'string') throw new TypeError('vaultUrl must be a string.');
    if (vaultUrl === '' || !URL.canParse(vaultUrl)) {
      throw new InvalidArgumentError('vaultUrl must be the vault\'s URL: https://{vault}.vault.azure.net/');
    }
    if (typeof credential !== 'object' || credential === null || typeof credential.getToken !== 'function') {
      throw new TypeError('credential must be an Azure TokenCredential (from @azure/identity, for example).');
    }
    if (typeof options !== 'object' || options === null) throw new TypeError('AzureKeyVaultSecretPipelineWriter options must be an object.');
    this.#client = new SecretClient(vaultUrl, credential, clientOptionsWithCapture(options.clientOptions ?? {}));
  }

  /** Whether Key Vault accepts `name` as a secret name: 1-127 ASCII letters, digits and hyphens. */
  static isValidSecretName(name: string | undefined | null): boolean {
    return typeof name === 'string' && name.length <= AzureKeyVaultSecretPipelineWriter.MAX_SECRET_NAME_LENGTH && SECRET_NAME.test(name);
  }

  /**
   * @throws RestError (rejecting) any Key Vault failure but 404 (access denied, a disabled secret, the
   *   vault unreachable); a credential that can't get a token rejects with its own error
   * @throws InvalidSecretDataError (rejecting) the response isn't Key Vault's JSON, or a JSON object
   *   value holds a key twice
   */
  protected override async readSecret(name: string, requests: readonly SecretRequest[], values: Map<string, string>, signal?: AbortSignal): Promise<void> {
    // Filled by the client's capture policy, from the body in a buffer of the library's own, once
    // per attempt; what SecretClient returns holds nothing, so it isn't read here.
    const read = new Map<string, string>();
    const capture = new Capture((buffer, length) => {
      read.clear();
      this.#protectValues(buffer, length, requests, read);
    });
    try {
      await captureWithin(capture, () => this.#client.getSecret(name, { abortSignal: signal }));
    } catch (error) {
      // Missing: nothing handed over.
      if (isRestError(error) && error.statusCode === 404) return;
      throw error;
    }
    if (!capture.captured) {
      throw new HkdfGuardError('ERR_HKDFGUARD_INVALID_STATE', 'Key Vault\'s response didn\'t pass through the writer\'s capture policy.');
    }
    for (const [fileName, value] of read) values.set(fileName, value);
  }

  // Encrypts the top-level value of a Get Secret body, and each requested key it holds.
  #protectValues(body: Uint8Array, length: number, requests: readonly SecretRequest[], values: Map<string, string>): void {
    const reader = new JsonReader(body, length);
    try {
      if (!SecretPipelineWriter.startsObject(reader)) throw new InvalidSecretDataError("The response body isn't a JSON object.");

      let protectedOnce = false;
      while (SecretPipelineWriter.nextProperty(reader)) {
        const isValue = reader.valueTextEquals('value');
        reader.read();
        if (!isValue || reader.token() !== JsonToken.String) {
          reader.skip();
          continue;
        }
        if (protectedOnce) throw new InvalidSecretDataError('The response body holds more than one secret value.');
        protectedOnce = true;

        // Unescaped, a string is never longer than it is escaped.
        const text = new Uint8Array(reader.valueLength);
        try {
          this.protectSecret(text.subarray(0, reader.copyString(text)), requests, values);
        } finally {
          wipe(text);
        }
      }
    } catch (error) {
      // Never chained, and never quoting the byte rejected, which may be in the secret.
      if (error instanceof MalformedJsonError) {
        throw new InvalidSecretDataError(`The response body isn't valid JSON (at byte ${error.position} of line ${error.line}).`);
      }
      throw error;
    }
  }
}

// A copy of the caller's client options, with the capture policy after every per-retry policy of theirs.
function clientOptionsWithCapture(clientOptions: SecretClientOptions): SecretClientOptions {
  if (typeof clientOptions !== 'object' || clientOptions === null) throw new TypeError('clientOptions must be an object.');
  for (const [name, reason] of Object.entries(REFUSED_OPTIONS)) {
    if (name in clientOptions) throw new InvalidArgumentError(`clientOptions must not set ${name}: ${reason}.`);
  }
  const additional = clientOptions.additionalPolicies ?? [];
  if (!Array.isArray(additional)) throw new TypeError('clientOptions.additionalPolicies must be an array.');
  return { ...clientOptions, additionalPolicies: [...additional, { policy: secretCapturePolicy, position: 'perRetry' }] };
}

// The SDK's RestError (@azure/core-rest-pipeline), recognized by name as the SDK's own isRestError
// does, so any copy of the SDK the application installed is recognized.
function isRestError(error: unknown): error is { name: 'RestError'; statusCode?: number } {
  return typeof error === 'object' && error !== null && (error as { name?: unknown }).name === 'RestError';
}

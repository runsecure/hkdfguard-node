import { SecretClient, type SecretClientOptions } from '@azure/keyvault-secrets';
import { HkdfGuardError, InvalidArgumentError, type KeyRing } from '@runsecure/hkdfguard-abstractions';
import { RemoteSecretCache, SecretNameMatching, type SecretValueSink } from '@runsecure/hkdfguard-cache';
import type { Logger } from '@runsecure/hkdfguard-diagnostics';
import { Capture, captureWithin, secretCapturePolicy } from './capture.js';

/**
 * What authenticates every call to Key Vault: an Azure `TokenCredential` (@azure/core-auth), such as
 * @azure/identity's ManagedIdentityCredential, or DefaultAzureCredential, which finds it.
 */
export type KeyVaultCredential = ConstructorParameters<typeof SecretClient>[1];

/** The options of an {@link AzureKeyVaultSecretCache}. */
export interface AzureKeyVaultSecretCacheOptions {
  /**
   * Options for the cache's SecretClient - `serviceVersion`, `retryOptions`, `httpClient`,
   * `additionalPolicies`, proxy and telemetry options; copied at construction, so the caller's object
   * (and its `additionalPolicies` array) is left as it is. The capture policy is added after the
   * application's per-retry policies, so every policy of the application's sees only redacted bodies.
   * Options that would replace the pipeline the policy is in, or the vault URL, are refused:
   * `pipeline`, `endpoint` and `baseUrl`.
   */
  readonly clientOptions?: SecretClientOptions;
}

// Client options the SDK honours although its types don't declare them all, which would replace the
// pipeline the capture policy is in, or send the cache's requests elsewhere.
const REFUSED_OPTIONS: Readonly<Record<string, string>> = {
  pipeline: 'it replaces the pipeline, the capture policy with it',
  endpoint: 'the cache passes the vault URL itself',
  baseUrl: 'the cache passes the vault URL itself',
};

const SECRET_NAME = /^[A-Za-z0-9-]+$/;

/**
 * A ProtectedReadOnlyCache over the secrets in one Azure Key Vault - the Node port of the .NET
 * HkdfGuard.Cache.AzureKeyVault library. The first lookup of a name that isn't cached yet reads that
 * one secret (its current version) with Get Secret; fetching, encryption, caching and telemetry are
 * RemoteSecretCache's. This class never lists the vault's secrets, so the identity needs only `get`
 * on secrets (the Key Vault Secrets User role), never `list`.
 *
 * Key Vault secret names are 1-{@link MAX_SECRET_NAME_LENGTH} ASCII letters, digits and hyphens,
 * compared ignoring case, so "Db-Password" and "DB-PASSWORD" are one entry and one secret. Any other
 * name (a configuration path such as "ConnectionStrings:Admin", say) is reported missing without a
 * call - and is never spliced into a request URL, so the cache can sit in a ProtectedCacheCollection
 * beside sources with other naming rules.
 *
 * A secret whose value is a JSON object, such as {"username":"app","password":"..."}, is cached whole
 * under its name and each member under "name#key" - "Db-Login#password" - all from one call (see
 * RemoteSecretCache). Keys are matched exactly, though secret names aren't. The secret's content type
 * isn't consulted: any value that isn't one JSON object is cached whole only.
 *
 * A secret that doesn't exist (HTTP 404) or whose value is empty is reported missing. Any other
 * failure (access denied, a disabled secret, the vault unreachable, a credential that can't get a
 * token) rejects with the Azure SDK's own error - a RestError (its `statusCode` and `code` say
 * which), or the credential's error - and an aborted lookup with the SDK's AbortError. A response
 * that isn't the JSON object Key Vault sends rejects with InvalidSecretDataError.
 *
 * The secret never becomes a JavaScript string. The cache builds its own SecretClient with a pipeline
 * policy that has the HTTP client hand a Get Secret response's body over as a stream, reads it into a
 * buffer of the library's own, takes the value out of it, and hands SecretClient the body with the
 * value blanked; every buffer holding the value, and every chunk the stream yielded, is zeroed. What
 * can't be zeroed is below the pipeline: the HTTP stack's own buffers (TLS decryption, socket reads).
 * The capture travels with each fetch's asynchronous context, never on the client, so concurrent
 * fetches through the one client each capture their own response. The SDK's logging policy logs
 * headers only, never a body, so Azure SDK logging is safe at any level.
 *
 * A lookup's `signal` is passed to getSecret: aborting the lookup that started a fetch aborts the
 * request (see RemoteSecretCache). The client holds no resources that need releasing.
 */
export class AzureKeyVaultSecretCache extends RemoteSecretCache {
  /** The longest name Key Vault accepts for a secret. */
  static readonly MAX_SECRET_NAME_LENGTH = 127;

  readonly #client: SecretClient;

  /**
   * A cache over the vault at `vaultUrl`. No call is made until a secret is requested.
   *
   * @param vaultUrl the vault to read secrets from: `https://{vault}.vault.azure.net/`
   * @param credential authenticates every call to Key Vault, e.g. a managed identity
   * @param keyRing supplies the key every fetched secret is encrypted under; owned by the caller -
   *   the cache never closes keys
   * @param logger optional; see RemoteSecretCache
   * @throws TypeError vaultUrl isn't a string, credential has no `getToken`, keyRing is missing, or
   *   options, clientOptions or its additionalPolicies isn't an object (an array)
   * @throws InvalidArgumentError vaultUrl is empty or isn't a URL, or clientOptions sets an option
   *   the cache refuses
   */
  constructor(vaultUrl: string, credential: KeyVaultCredential, keyRing: KeyRing, logger?: Logger, options: AzureKeyVaultSecretCacheOptions = {}) {
    super(keyRing, SecretNameMatching.ignoreAsciiCase, logger);
    if (typeof vaultUrl !== 'string') throw new TypeError('vaultUrl must be a string.');
    if (vaultUrl === '' || !URL.canParse(vaultUrl)) {
      throw new InvalidArgumentError('vaultUrl must be the vault\'s URL: https://{vault}.vault.azure.net/');
    }
    if (typeof credential !== 'object' || credential === null || typeof credential.getToken !== 'function') {
      throw new TypeError('credential must be an Azure TokenCredential (from @azure/identity, for example).');
    }
    if (typeof options !== 'object' || options === null) throw new TypeError('AzureKeyVaultSecretCache options must be an object.');
    this.#client = new SecretClient(vaultUrl, credential, clientOptionsWithCapture(options.clientOptions ?? {}));
  }

  /** Whether Key Vault accepts `name` as a secret name: 1-127 ASCII letters, digits and hyphens. */
  static isValidSecretName(name: string | undefined | null): boolean {
    return typeof name === 'string' && name.length <= AzureKeyVaultSecretCache.MAX_SECRET_NAME_LENGTH && SECRET_NAME.test(name);
  }

  protected override isValidName(name: string): boolean {
    return AzureKeyVaultSecretCache.isValidSecretName(name);
  }

  protected override async fetch(name: string, sink: SecretValueSink, signal?: AbortSignal): Promise<void> {
    // The value reaches the sink through the capture policy; what SecretClient returns holds it
    // blanked, so it isn't read here.
    const capture = new Capture(sink);
    try {
      await captureWithin(capture, () => this.#client.getSecret(name, { abortSignal: signal }));
    } catch (error) {
      // Missing: nothing handed over.
      if (isRestError(error) && error.statusCode === 404) return;
      throw error;
    }
    if (!capture.captured) {
      throw new HkdfGuardError('ERR_HKDFGUARD_INVALID_STATE', 'Key Vault\'s response didn\'t pass through the cache\'s capture policy.');
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

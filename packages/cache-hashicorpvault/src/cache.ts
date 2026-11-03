import { ClosedError, InvalidArgumentError, type DataProtector, type KeyRing } from '@runsecure/hkdfguard-abstractions';
import { RemoteSecretCache, SecretJsonBody, SecretNameMatching, type SecretValueSink } from '@runsecure/hkdfguard-cache';
import {
  apiBase, checkConnectionOptions, chunksOf, getTokenWithin, isValidPath, MAX_ERROR_BODY_LENGTH, putProtectedToken, readBody, readVaultErrors,
  sendAttempt, vaultHeaders, VaultConnector, vaultRefusal, withRetries, type VaultConnectionSettings, type VaultTokenProvider,
} from '@runsecure/hkdfguard-integration-hashicorpvault';
import { VaultKvVersion, type HashiCorpVaultSecretCacheOptions } from './options.js';

/**
 * A ProtectedReadOnlyCache over the secrets in one HashiCorp Vault KV secrets engine. The first
 * lookup of a name that isn't cached yet reads that one secret (GET on its path; for KV version 2,
 * its latest version); fetching, encryption, caching and telemetry are RemoteSecretCache's. This
 * class never lists secrets, so the token's policy needs only `read` on the paths it reads, never
 * `list`.
 *
 * A name is a secret's path within the engine, with the key to read after '#': "myapp/db#password"
 * reads the password key of the secret at myapp/db, and "myapp/db" reads its
 * {@link HashiCorpVaultSecretCacheOptions.defaultKey}. One read caches every key the secret holds, so
 * the first lookup of any of them reads the secret once and the rest are already cached. A string is
 * cached as its UTF-8 bytes; a number, true or false as its JSON text; a null, object or array value
 * isn't cached. Paths are matched exactly, as Vault matches them, and so are keys. A path that isn't
 * one - segments of ASCII letters, digits, '-', '_' and '.', no segment "." or "..", at most
 * {@link MAX_SECRET_NAME_LENGTH} characters, such as the configuration path "ConnectionStrings:Admin"
 * - is reported missing without a call.
 *
 * A secret that doesn't exist (404 with no errors, as Vault answers), whose latest version is
 * deleted or destroyed, or that has no such key, or whose value there is empty or isn't cached, is
 * reported missing. Any other answer (403 for a token that is invalid or not allowed to read the
 * path, a 404 naming an error such as a mount that doesn't exist, a redirect, Vault sealed) rejects
 * with a {@link VaultRequestError} carrying Vault's status and errors. A request that fails
 * transiently - no answer, a connection lost mid-response, a timed-out attempt, 429 or a 5xx other
 * than 501 - is first retried {@link HashiCorpVaultSecretCacheOptions.retryCount} times (3-10),
 * waiting {@link HashiCorpVaultSecretCacheOptions.retryDelayMs} and doubling, up to 10 seconds, plus
 * a random 0-100 ms each time so clients reconnecting together spread out. Once the retries are
 * spent, a failure without an answer rejects with Node's own network error (ECONNREFUSED,
 * ECONNRESET, ENOTFOUND...), or a DOMException named TimeoutError for a timed-out attempt.
 *
 * Authentication isn't the cache's: every fetch asks its {@link VaultTokenProvider} for a token,
 * once, so a provider can log in, renew and replace tokens however it likes. A provider's failure
 * propagates as it is, and isn't retried; a provider that hasn't answered within the timeout fails
 * the fetch with a TimeoutError. The token is handed over protected - encrypted by the cache's token
 * protector, a protector on the key ring (`keyRing.createProtector(TOKEN_PURPOSE)`) - and a fetch
 * given one that isn't fails with an HkdfGuardError (ERR_HKDFGUARD_INVALID_VAULT_TOKEN), quoting and
 * chaining nothing. It is decrypted only as each request is built, into a buffer that is zeroed as
 * soon as the request has its headers. Node takes header values only as strings, though, which
 * JavaScript can't erase: each request leaves the token in two strings - the header's value and the
 * request head Node builds from it - referenced by nothing once the request is sent, which stay in
 * memory until the garbage collector reuses it. So do the socket's and, over TLS, OpenSSL's
 * buffers, which this class can't reach.
 *
 * Requests go to /v1/ under Vault's address, which must be https except on loopback, through Node's
 * own http and https clients: no proxy unless the agent given is one, and no redirect is ever
 * followed, which would carry the token elsewhere - Vault's standbys forward requests to the active
 * node themselves, so a redirect is answered as an error. Each attempt - one request and Vault's
 * whole response - must finish within {@link HashiCorpVaultSecretCacheOptions.timeoutMs}. Aborting
 * the lookup that started a fetch abandons it: the provider's signal is aborted, or the request is
 * destroyed, and no retry follows; nothing it read is kept.
 *
 * The secret never becomes a string. The response body is streamed into a buffer of the library's
 * own (each chunk zeroed once copied), and the value is unescaped into another and encrypted from
 * there (SecretJsonBody.captureKeysAsync); every buffer holding it is zeroed. What can't be zeroed
 * is below that: the socket's and OpenSSL's buffers. {@link close} the cache to release its
 * connections.
 */
export class HashiCorpVaultSecretCache extends RemoteSecretCache {
  /** The longest secret path looked up. */
  static readonly MAX_SECRET_NAME_LENGTH = 512;

  /**
   * The purpose to create the token protector with - `keyRing.createProtector(TOKEN_PURPOSE)` - so a
   * token protected for the cache can't be decrypted as anything else, nor anything else as it.
   */
  static readonly TOKEN_PURPOSE = 'HkdfGuard.Cache.HashiCorpVault.Token';

  readonly #tokenProvider: VaultTokenProvider;
  readonly #tokenProtector: DataProtector;
  readonly #connector: VaultConnector;
  readonly #readBase: string;
  readonly #dataPath: readonly string[];
  readonly #defaultKey: string;
  readonly #namespace: string | undefined;
  readonly #timeoutMs: number;
  readonly #retryCount: number;
  readonly #retryDelayMs: number;
  #closed = false;

  /**
   * @param address Vault's address, e.g. https://vault.example.com:8200 - the same value as
   *   VAULT_ADDR. Must be https, except on a loopback address (a local Vault Agent or dev server). A
   *   path, if any, is kept as a prefix (Vault behind a reverse proxy).
   * @param tokenProvider supplies the token every read is made with, protected by tokenProtector
   * @param tokenProtector decrypts the token tokenProvider supplies: a protector on the key ring,
   *   `keyRing.createProtector(TOKEN_PURPOSE)`
   * @param keyRing supplies the key every fetched secret is encrypted under; owned by the caller -
   *   the cache never closes keys
   * @param options the KV engine read and how to reach it; omitted for KV version 2 at "secret",
   *   reading the key "value"
   * @throws TypeError address, tokenProvider, tokenProtector or keyRing is missing, or an option is
   *   of the wrong type
   * @throws InvalidArgumentError address isn't https (or http on loopback), or holds credentials, a
   *   query or a fragment (ERR_HKDFGUARD_INVALID_VAULT_ADDRESS); or the mount path, default key or
   *   namespace isn't one, the KV version isn't, the timeout isn't positive, the retry count isn't
   *   3-10 or the retry delay isn't zero to 10 seconds
   */
  constructor(
    address: string | URL, tokenProvider: VaultTokenProvider, tokenProtector: DataProtector, keyRing: KeyRing,
    options: HashiCorpVaultSecretCacheOptions = {},
  ) {
    if (address === undefined || address === null) throw new TypeError('address must not be undefined.');
    if (tokenProvider === undefined || tokenProvider === null || typeof tokenProvider.getToken !== 'function') {
      throw new TypeError('tokenProvider must be a VaultTokenProvider.');
    }
    if (tokenProtector === undefined || tokenProtector === null) throw new TypeError('tokenProtector must not be undefined.');
    if (options === null || typeof options !== 'object') throw new TypeError('options must be a HashiCorpVaultSecretCacheOptions object.');
    super(keyRing, SecretNameMatching.exact, options.logger);

    const text = address instanceof URL ? address.href : address;
    if (typeof text !== 'string') throw new TypeError('address must be a string or a URL.');
    const api = apiBase(text, 'a token');
    const settings = checked(options);
    this.#tokenProvider = tokenProvider;
    this.#tokenProtector = tokenProtector;
    this.#connector = new VaultConnector(api, options.agent, options.tls);
    this.#defaultKey = settings.defaultKey;
    this.#namespace = settings.namespace;
    this.#timeoutMs = settings.timeoutMs;
    this.#retryCount = settings.retryCount;
    this.#retryDelayMs = settings.retryDelayMs;
    if (settings.kvVersion === VaultKvVersion.v2) {
      this.#readBase = `${api.base}${settings.mountPath}/data/`;
      this.#dataPath = ['data', 'data'];
    } else {
      this.#readBase = `${api.base}${settings.mountPath}/`;
      this.#dataPath = ['data'];
    }
  }

  /**
   * Whether `name` is a secret's path: '/'-separated segments of ASCII letters, digits, '-', '_' and
   * '.', no segment "." or "..", at most {@link MAX_SECRET_NAME_LENGTH} characters. A key to read
   * follows it in a lookup, after '#' (see {@link RemoteSecretCache.isValidKey}).
   */
  static isValidSecretName(name: string | undefined | null): boolean {
    return typeof name === 'string' && name.length > 0 && name.length <= HashiCorpVaultSecretCache.MAX_SECRET_NAME_LENGTH
      && isValidPath(name);
  }

  /**
   * Stops the cache reading Vault, and closes its connections (and its own agent; one given in the
   * options is the caller's). Cached secrets can still be read afterwards, but a lookup that would
   * read Vault rejects with ClosedError. Safe to call more than once.
   */
  close(): void {
    this.#closed = true;
    this.#connector.close();
  }

  protected override defaultKey(): string {
    return this.#defaultKey;
  }

  protected override isValidName(name: string): boolean {
    return HashiCorpVaultSecretCache.isValidSecretName(name);
  }

  protected override async fetch(name: string, sink: SecretValueSink, signal?: AbortSignal): Promise<void> {
    this.#ensureOpen();
    // Asked for once per fetch; a provider's failure is its own to retry, so isn't retried here.
    const protectedToken = await getTokenWithin(this.#tokenProvider, this.#timeoutMs, signal);
    // A failed attempt has handed nothing to sink: the body is read whole before anything is parsed
    // out of it, and a parse failure isn't transient.
    await withRetries(async () => {
      this.#ensureOpen();
      await sendAttempt(() => this.#send(name, protectedToken), undefined,
        (response, either) => this.#readResponse(name, response.statusCode ?? 0, chunksOf(response), sink, either),
        this.#timeoutMs, signal, `Vault's response to the read of '${name}' took longer than ${this.#timeoutMs} ms.`);
    }, this.#retryCount, this.#retryDelayMs, signal, { stopped: () => this.#closed });
  }

  #ensureOpen(): void {
    if (this.#closed) throw new ClosedError('This HashiCorp Vault secret cache has been closed.');
  }

  // The request for path's secret, with the token protectedToken holds - decrypted into a buffer
  // zeroed once Node has the header's string.
  #send(path: string, protectedToken: string) {
    const headers = vaultHeaders(this.#namespace);
    putProtectedToken(headers, this.#tokenProtector, protectedToken, "the cache's token protector");
    return this.#connector.request('GET', this.#readBase + path, headers);
  }

  async #readResponse(path: string, status: number, body: AsyncIterable<Uint8Array>, sink: SecretValueSink, signal: AbortSignal): Promise<void> {
    if (status >= 200 && status < 300) {
      await SecretJsonBody.captureKeysAsync(body, sink, this.#dataPath, signal);
      return;
    }

    // A refusal holds no secret; one over the limit isn't Vault's, and is read as no errors.
    const refusal = await readBody(body, MAX_ERROR_BODY_LENGTH);
    let errors: string[] | undefined;
    try {
      errors = refusal === undefined ? undefined : readVaultErrors(refusal.view());
    } finally {
      refusal?.close();
    }
    signal.throwIfAborted();

    // Nothing at the path: Vault answers 404 with an empty error list - or, for a KV version 2
    // secret whose latest version is deleted, with its metadata and none. A 404 naming an error (no
    // such mount) or that isn't Vault's JSON (a proxy's page) is a failure.
    if (status === 404 && errors !== undefined && errors.length === 0) return;
    throw vaultRefusal(status, errors, `Couldn't read '${path}'`);
  }
}

interface Settings extends VaultConnectionSettings {
  kvVersion: VaultKvVersion;
  defaultKey: string;
}

function checked(options: HashiCorpVaultSecretCacheOptions): Settings {
  // Only an undefined member takes its default: null is a value of the wrong type.
  const or = <T>(value: T | undefined, fallback: T): T => (value === undefined ? fallback : value);
  const settings: Settings = {
    ...checkConnectionOptions(options, 'secret'),
    kvVersion: or(options.kvVersion, VaultKvVersion.v2),
    defaultKey: or(options.defaultKey, 'value'),
  };
  if (typeof settings.defaultKey !== 'string') throw new InvalidArgumentError('defaultKey must be a string.');
  if (typeof settings.kvVersion !== 'number') throw new InvalidArgumentError('kvVersion must be a number.');
  if (!RemoteSecretCache.isValidKey(settings.defaultKey)) {
    throw new InvalidArgumentError(`The default key '${settings.defaultKey}' isn't a key: 1-${RemoteSecretCache.MAX_KEY_LENGTH} printable ASCII `
      + "characters other than space, '!' and '#'.");
  }
  if (settings.kvVersion !== VaultKvVersion.v1 && settings.kvVersion !== VaultKvVersion.v2) {
    throw new InvalidArgumentError(`The KV version must be 1 or 2; it is ${settings.kvVersion}.`);
  }
  return settings;
}

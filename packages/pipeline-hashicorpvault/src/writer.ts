import type { IncomingMessage } from 'node:http';
import { ClosedError, InvalidArgumentError, wipe, type PipelineDataProtector } from '@runsecure/hkdfguard-abstractions';
import { JsonReader, JsonToken, MalformedJsonError } from '@runsecure/hkdfguard-abstractions/internal';
import {
  apiBase, checkConnectionOptions, chunksOf, copyTokenWithin, isValidPath, MAX_ERROR_BODY_LENGTH, MAX_TOKEN_LENGTH, putToken, readBody,
  readVaultErrors, sendAttempt, vaultHeaders, VaultConnector, vaultRefusal, withRetries, type VaultTokenSource,
} from '@runsecure/hkdfguard-integration-hashicorpvault';
import { InvalidSecretDataError, PinnedBody, SecretPipelineWriter, type SecretRequest } from '@runsecure/hkdfguard-pipeline';
import { VaultKvVersion, type HashiCorpVaultPipelineOptions } from './options.js';

const DEFAULT_KEY = 'value';

/**
 * The end of a provisioning pipeline - the Node port of .NET's HashiCorpVaultSecretPipelineWriter:
 * pulls a fixed list of secrets from one HashiCorp Vault KV secrets engine, encrypts each with a
 * PipelineDataProtector as soon as it is read, and writes them out as one file per secret - the
 * folder layout FilePerSecretCache reads at runtime. It is independent of
 * @runsecure/hkdfguard-cache-hashicorpvault's runtime cache, and of any key ring. Naming, encrypting,
 * keeping and writing are SecretPipelineWriter's.
 *
 * A secret name is a path within the engine, with the key to read after '#': "myapp/db#password"
 * reads the password key of the secret at myapp/db, and "myapp/db" reads its
 * {@link HashiCorpVaultPipelineOptions.defaultKey} (written as myapp__db__password and myapp__db). A
 * string is read as its text; a number, true or false as its JSON text. The token's policy needs only
 * `read` on the paths read, never `list`.
 *
 * A secret that doesn't exist (404 with no errors, as Vault answers), whose latest version is deleted
 * or destroyed, or that has no such key, or whose value there is empty or isn't a value, is missing.
 * Any other answer (403, a 404 naming an error such as a mount that doesn't exist, a redirect, Vault
 * sealed) rejects with a VaultRequestError carrying Vault's status and errors; a response that isn't
 * Vault's JSON, or holds a key twice, with InvalidSecretDataError. A request that fails transiently
 * is retried as {@link HashiCorpVaultPipelineOptions} says, as every HkdfGuard Vault integration
 * retries.
 *
 * The token comes from a VaultTokenSource - plaintext, as the transit key wrapper's does, since a
 * pipeline has no key ring yet - asked once per secret read and copied into a buffer zeroed once the
 * read is done. Node takes header values only as strings, which JavaScript can't erase: each request
 * leaves the token in the header's string and the request head Node builds from it. Requests go to
 * /v1/ under Vault's address, which must be https except on loopback; no redirect is ever followed.
 *
 * The secret never becomes a string. Vault's response is streamed into a buffer of the library's own
 * (each chunk zeroed once copied - PinnedBody), the value of each requested key is unescaped into
 * another and encrypted from there, and every buffer holding it is zeroed. What can't be zeroed is
 * below that: the socket's and OpenSSL's buffers. {@link close} the writer to release its connections.
 */
export class HashiCorpVaultSecretPipelineWriter extends SecretPipelineWriter {
  /** The longest secret path read. */
  static readonly MAX_SECRET_NAME_LENGTH = 512;

  readonly #tokenSource: VaultTokenSource;
  readonly #connector: VaultConnector;
  readonly #readBase: string;
  readonly #dataPath: readonly string[];
  readonly #namespace: string | undefined;
  readonly #timeoutMs: number;
  readonly #retryCount: number;
  readonly #retryDelayMs: number;
  #closed = false;

  /**
   * @param address Vault's address, e.g. https://vault.example.com:8200 - the same value as
   *   VAULT_ADDR. Must be https, except on a loopback address. A path, if any, is kept as a prefix.
   * @param tokenSource supplies the token every read is made with. Owned by the caller: the writer
   *   never closes it.
   * @param protector encrypts every value read. Owned by the caller: the writer never closes it.
   * @param secretNames the secrets to pull, each a path with the key to read after '#' if any.
   *   Copied: a later change to the array isn't seen.
   * @param options the KV engine read and how to reach it; omitted for KV version 2 at "secret",
   *   reading the key "value"
   * @throws TypeError address, protector or secretNames is missing, or options isn't an object
   * @throws InvalidArgumentError tokenSource isn't a VaultTokenSource; secretNames is empty, or holds
   *   something that isn't a string, a name that isn't a path (with a key), one whose file name isn't
   *   one FilePerSecretCache can read, or two with the same file name, in any case; address isn't
   *   https (or http on loopback), or holds credentials, a query or a fragment
   *   (ERR_HKDFGUARD_INVALID_VAULT_ADDRESS); or an option is invalid: a mount path, default key or
   *   namespace that isn't one, a KV version that isn't 1 or 2, a timeout that isn't positive, a
   *   retry count that isn't 3-10 or a retry delay that isn't zero to 10 seconds, agent and tls both set
   */
  constructor(
    address: string | URL, tokenSource: VaultTokenSource, protector: PipelineDataProtector, secretNames: readonly string[],
    options: HashiCorpVaultPipelineOptions = {},
  ) {
    if (options === null || typeof options !== 'object') throw new TypeError('options must be a HashiCorpVaultPipelineOptions object.');
    const defaultKey = options.defaultKey === undefined ? DEFAULT_KEY : options.defaultKey;
    if (typeof defaultKey !== 'string') throw new InvalidArgumentError('defaultKey must be a string.');
    super(protector, secretNames, HashiCorpVaultSecretPipelineWriter.isValidSecretName, defaultKey);

    if (typeof tokenSource !== 'object' || tokenSource === null || typeof tokenSource.copyToken !== 'function') {
      throw new InvalidArgumentError('tokenSource must be a VaultTokenSource.');
    }
    if (address === undefined || address === null) throw new TypeError('address must not be undefined.');
    const text = address instanceof URL ? address.href : address;
    if (typeof text !== 'string') throw new TypeError('address must be a string or a URL.');
    const api = apiBase(text, 'a token');
    const settings = checkConnectionOptions(options, 'secret');
    const kvVersion = options.kvVersion === undefined ? VaultKvVersion.v2 : options.kvVersion;
    if (kvVersion !== VaultKvVersion.v1 && kvVersion !== VaultKvVersion.v2) {
      throw new InvalidArgumentError(`The KV version must be 1 or 2; it is ${String(kvVersion)}.`);
    }

    this.#tokenSource = tokenSource;
    this.#namespace = settings.namespace;
    this.#timeoutMs = settings.timeoutMs;
    this.#retryCount = settings.retryCount;
    this.#retryDelayMs = settings.retryDelayMs;
    if (kvVersion === VaultKvVersion.v2) {
      this.#readBase = `${api.base}${settings.mountPath}/data/`;
      this.#dataPath = ['data', 'data'];
    } else {
      this.#readBase = `${api.base}${settings.mountPath}/`;
      this.#dataPath = ['data'];
    }
    // Last: it may build an agent, which nothing would close if a check above failed.
    this.#connector = new VaultConnector(api, options.agent, options.tls);
  }

  /** Whether `path` is a secret's path: at most {@link MAX_SECRET_NAME_LENGTH} characters, as Vault takes it. */
  static isValidSecretName(path: string | undefined | null): boolean {
    return typeof path === 'string' && path.length > 0 && path.length <= HashiCorpVaultSecretPipelineWriter.MAX_SECRET_NAME_LENGTH
      && isValidPath(path);
  }

  /** Closes the writer's connections, and its own agent (one given in the options is the caller's). */
  protected override closeStore(): void {
    this.#closed = true;
    this.#connector.close();
  }

  /**
   * @throws VaultRequestError (rejecting) Vault refused the read, or couldn't be reached
   * @throws InvalidSecretDataError (rejecting) the response isn't Vault's JSON, or holds a key twice
   * @throws HkdfGuardError (rejecting; ERR_HKDFGUARD_INVALID_VAULT_TOKEN) the token source supplied no token
   */
  protected override async readSecret(name: string, requests: readonly SecretRequest[], values: Map<string, string>, signal?: AbortSignal): Promise<void> {
    // Buffer.alloc, never the shared pool, and zeroed once the read is done. Asked for once per
    // secret; a source's failure is its own to retry, so isn't retried here.
    const token = Buffer.alloc(MAX_TOKEN_LENGTH);
    try {
      const tokenLength = await copyTokenWithin(this.#tokenSource, token, this.#timeoutMs, signal);
      // An attempt encrypts nothing until it has read the whole body, and a parse failure isn't
      // transient, so a failed attempt hands nothing over.
      const read = await withRetries(() => {
        this.#ensureOpen();
        return sendAttempt(() => this.#request(name, token, tokenLength), undefined,
          (response, either) => this.#readResponse(name, response, requests, either),
          this.#timeoutMs, signal, `Vault's response to the read of '${name}' took longer than ${this.#timeoutMs} ms.`);
      }, this.#retryCount, this.#retryDelayMs, signal, { stopped: () => this.#closed });
      for (const [fileName, value] of read) values.set(fileName, value);
    } finally {
      wipe(token);
    }
  }

  #ensureOpen(): void {
    if (this.#closed) throw new ClosedError('This HashiCorp Vault secret pipeline writer has been closed.');
  }

  // The request for path's secret. Checked by copyTokenWithin - printable ASCII - so latin1 is the token exactly.
  #request(path: string, token: Buffer, tokenLength: number) {
    const headers = vaultHeaders(this.#namespace);
    putToken(headers, token, tokenLength);
    return this.#connector.request('GET', this.#readBase + path, headers);
  }

  // One attempt's response: the requested keys encrypted, by file name; none for a missing secret.
  async #readResponse(path: string, response: IncomingMessage, requests: readonly SecretRequest[], signal: AbortSignal): Promise<Map<string, string>> {
    const status = response.statusCode ?? 0;
    if (status >= 200 && status < 300) {
      // A connection lost mid-response is transient (chunksOf).
      const { buffer, length } = await PinnedBody.read(chunksOf(response), signal);
      try {
        return this.#protectValues(buffer, length, requests);
      } finally {
        wipe(buffer);
      }
    }

    // A refusal holds no secret; one over the limit isn't Vault's, and is read as no errors.
    const refusal = await readBody(chunksOf(response), MAX_ERROR_BODY_LENGTH);
    let errors: string[] | undefined;
    try {
      errors = refusal === undefined ? undefined : readVaultErrors(refusal.view());
    } finally {
      refusal?.close();
    }

    // Nothing at the path: Vault answers 404 with an empty error list - or, for a KV version 2
    // secret whose latest version is deleted, with its metadata and none. A 404 naming an error (no
    // such mount) or that isn't Vault's JSON (a proxy's page) is a failure.
    if (status === 404 && errors !== undefined && errors.length === 0) return new Map();
    throw vaultRefusal(status, errors, `Couldn't read '${path}'`);
  }

  // Encrypts the value of each requested key in the secret's data object, by file name.
  #protectValues(json: Uint8Array, length: number, requests: readonly SecretRequest[]): Map<string, string> {
    const values = new Map<string, string>();
    const reader = new JsonReader(json, length);
    try {
      if (!SecretPipelineWriter.startsObject(reader)) throw new InvalidSecretDataError("Vault's response isn't a JSON object.");
      if (moveToObject(reader, this.#dataPath)) this.protectKeysAt(reader, requests, values);
      return values;
    } catch (error) {
      // Never chained, and never quoting the byte rejected, which may be in the secret.
      if (error instanceof MalformedJsonError) {
        throw new InvalidSecretDataError(`Vault's response isn't valid JSON (at byte ${error.position} of line ${error.line}).`);
      }
      throw error;
    }
  }
}

// Leaves reader at the start of the object path leads to; false if it leads to none.
function moveToObject(reader: JsonReader, path: readonly string[]): boolean {
  for (const name of path) {
    let found = false;
    while (!found && reader.read() && reader.token() === JsonToken.PropertyName) {
      const isNext = reader.valueTextEquals(name);
      reader.read();
      if (isNext && reader.token() === JsonToken.StartObject) found = true;
      else reader.skip();
    }
    if (!found) return false;
  }
  return true;
}

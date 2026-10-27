import { createHash, randomFillSync } from 'node:crypto';
import { CryptographyClient, KeyClient, type CryptographyClientOptions, type KeyVaultKey } from '@azure/keyvault-keys';
import { HkdfGuardError, InvalidArgumentError, MAX_WRAPPED_KEY_BYTES, wipe, type KeyWrapper } from '@runsecure/hkdfguard-abstractions';
import { KeyFileTrust, readTrustedKeyFile } from '@runsecure/hkdfguard-securefile';
import * as envelope from './envelope.js';
import { AzureKeyVaultError } from './errors.js';
import { KeyVaultKeyId } from './keyId.js';

/** The length of the DEK {@link AzureKeyVaultKeyWrapper.generateAndWrap} generates: 32 bytes (AES-256). */
export const GENERATED_KEY_LENGTH = 32;

/** The largest plaintext RSA-OAEP-256 wraps under a 2048-bit key, in bytes. */
export const MAX_PLAINTEXT_LENGTH = 190;

/**
 * What authenticates every call to Key Vault: an Azure `TokenCredential` (@azure/core-auth), such as
 * @azure/identity's ManagedIdentityCredential, or DefaultAzureCredential, which finds it.
 */
export type KeyVaultCredential = ConstructorParameters<typeof KeyClient>[1];

/** The options of an {@link AzureKeyVaultKeyWrapper}. */
export interface AzureKeyVaultKeyWrapperOptions {
  /**
   * Bound into every wrapped DEK's signature and required again to reveal it; omitted or empty binds
   * none. Use one value per application, so a key file made for one can't be used by another that
   * shares the keys. Not secret.
   */
  readonly context?: string;
  /**
   * Who besides the operating system's administrators may have written a key file
   * {@link AzureKeyVaultKeyWrapper.readKeyFile} reads; omitted trusts administrators only
   * (KeyFileTrust.administratorsOnly).
   */
  readonly keyFileTrust?: KeyFileTrust;
  /**
   * Options for every Key Vault client the wrapper creates - `serviceVersion`, `retryOptions`,
   * `httpClient`, proxy and logging options; copied at construction.
   */
  readonly clientOptions?: CryptographyClientOptions;
}

type Operation = 'wrap' | 'sign' | 'verify' | 'unwrap';

/**
 * A {@link KeyWrapper} that protects (wraps) and reveals (unwraps) a DEK under an RSA key in Azure
 * Key Vault, and signs every wrapped DEK with a second, EC P-256 key in the vault. The private keys
 * never enter this process; every call is a round trip to Key Vault, authorized by the caller's Azure
 * credential. The Node port of the .NET HkdfGuard.KeyWrapping.AzureKeyVault library.
 *
 * Why two keys: RSA-OAEP wrapping needs only the public key, which isn't secret, so without the
 * signature anyone could produce a wrapped DEK this wrapper would accept - holding a DEK they chose,
 * which the application would then encrypt new data under. Signing needs the signing key's private
 * half, held in Key Vault and usable only by principals granted `sign`. Unwrap checks the signature
 * before it unwraps anything, so a wrapped DEK proves it was made by a principal allowed to sign: give
 * that permission to the pipeline that creates key files, never to the application. Each key does one
 * job; the wrapper refuses the same key for both.
 *
 * Both keys are pinned: a wrapped DEK records only the key versions it was made with, and the vault
 * and key names always come from the constructor. Rotating either key in Key Vault therefore needs
 * nothing here - existing key files keep naming the version that made them, which must stay enabled
 * while they're in use. Wrapped DEKs are byte for byte those of the .NET, Java and Python wrappers, so
 * a key file made by any of them is read by the others, given the same keys and context.
 *
 * Every operation goes to a named key version. A key identifier given without a version is resolved
 * to the key's current version on first use - a `get` on the key - and that version is kept for as
 * long as the wrapper lives; a new wrapper picks up a rotation. Without `get`, a key identifier must
 * name its version. The Azure SDK for JavaScript has no local RSA-OAEP-256 or ES256, so wrapping and
 * verifying are Key Vault calls too, as unwrapping and signing always are.
 *
 * The optional context is bound into the signature, and must be given again, exactly, to reveal the
 * DEK. Key Vault has no "generate data key", so {@link generateAndWrap} generates the DEK in this
 * process and wraps it.
 *
 * Plaintext key bytes this class owns are zeroed once used: its copy of a key it wraps, once the call
 * has completed, and the buffer the SDK decodes an unwrapped key into, once it is copied into `result`
 * - as is `result` itself whenever an unwrap fails. One copy is beyond its reach: the SDK
 * base64-encodes the key sent to wrapKey, and receives unwrapKey's answer, as text in a JSON body -
 * JavaScript strings, which can't be zeroed and live until collected. Process hardening (hardenProcess
 * in @runsecure/hkdfguard-keywrapping-native-v1) is what keeps such copies out of reach of a debugger
 * or a crash dump.
 *
 * The wrapper creates one Key Vault client per key version it uses, and keeps it; the clients hold no
 * resources that need releasing. A `signal` is checked before each call and passed to the SDK, which
 * aborts the request; an abort is rethrown as the SDK reports it. Argument errors throw
 * InvalidArgumentError; a Key Vault refusal, an unreachable vault or a credential that can't get a
 * token rejects with {@link AzureKeyVaultError}, naming the operation, the key, and Key Vault's error
 * code and HTTP status, with the SDK's error as its `cause`.
 */
export class AzureKeyVaultKeyWrapper implements KeyWrapper {
  /** The RSA key that wraps every DEK, as given. */
  readonly wrappingKeyId: string;
  /** The EC P-256 key that signs every wrapped DEK, as given. */
  readonly signingKeyId: string;
  private readonly wrappingKey: KeyVaultKeyId;
  private readonly signingKey: KeyVaultKeyId;
  private readonly credential: KeyVaultCredential;
  private readonly clientOptions: CryptographyClientOptions;
  private readonly context: Uint8Array;
  private readonly keyFileTrust: KeyFileTrust;
  // One client per key version, by its identifier; and the version each key given without one resolved to.
  private readonly clients = new Map<string, CryptographyClient>();
  private readonly currentVersions = new Map<string, KeyVaultKeyId>();
  private readonly keyClients = new Map<string, KeyClient>();

  /**
   * A wrapper over an RSA wrapping key and an EC P-256 signing key. No call is made until it is used.
   *
   * @param wrappingKeyId The RSA key that wraps every DEK (2048 or 3072 bits), as its key identifier:
   *   `https://{vault}.vault.azure.net/keys/{name}`, optionally with `/{version}` to wrap under that
   *   version rather than the current one.
   * @param signingKeyId The EC P-256 key that signs every wrapped DEK, in the same form.
   * @param credential Authenticates every call to Key Vault, e.g. a managed identity.
   * @throws InvalidArgumentError a key identifier isn't a Key Vault key's, both name the same key,
   *   `credential` has no `getToken`, the context isn't a string, is too long or isn't well-formed
   *   text, `keyFileTrust` isn't a KeyFileTrust, or `clientOptions` isn't an object.
   */
  constructor(wrappingKeyId: string, signingKeyId: string, credential: KeyVaultCredential, options: AzureKeyVaultKeyWrapperOptions = {}) {
    const wrappingKey = KeyVaultKeyId.parse(wrappingKeyId);
    const signingKey = KeyVaultKeyId.parse(signingKeyId);
    if (wrappingKey.sameKey(signingKey)) {
      throw new InvalidArgumentError(`The wrapping and signing keys are both '${wrappingKey.name}'; use an RSA key to wrap and a separate EC P-256 key to sign.`);
    }
    if (typeof credential !== 'object' || credential === null || typeof credential.getToken !== 'function') {
      throw new InvalidArgumentError('credential must be an Azure TokenCredential (from @azure/identity, for example).');
    }
    if (typeof options !== 'object' || options === null) throw new InvalidArgumentError('AzureKeyVaultKeyWrapper options must be an object.');
    const trust = options.keyFileTrust ?? KeyFileTrust.administratorsOnly;
    if (!(trust instanceof KeyFileTrust)) throw new InvalidArgumentError('keyFileTrust must be a KeyFileTrust.');
    const clientOptions = options.clientOptions ?? {};
    if (typeof clientOptions !== 'object' || clientOptions === null) throw new InvalidArgumentError('clientOptions must be an object.');

    this.wrappingKeyId = wrappingKeyId;
    this.signingKeyId = signingKeyId;
    this.wrappingKey = wrappingKey;
    this.signingKey = signingKey;
    this.credential = credential;
    this.clientOptions = { ...clientOptions };
    this.context = envelope.encodeContext(options.context);
    this.keyFileTrust = trust;
  }

  /**
   * Wraps a key under the wrapping key (RSA-OAEP-256), then has the signing key sign the result
   * (ES256), writing the wrapped DEK to `result`. `plaintext` is not modified - it is the caller's to zero.
   *
   * @throws InvalidArgumentError `plaintext` is empty or over MAX_PLAINTEXT_LENGTH bytes, or `result`
   *   is too small for the wrapped DEK.
   * @throws AzureKeyVaultError Key Vault refused a request or could not be reached, answered for a key
   *   other than the one asked, or the wrapped DEK would be over MAX_WRAPPED_KEY_BYTES (an RSA key
   *   over 3072 bits) or its signature isn't ES256's.
   */
  async wrap(plaintext: Uint8Array, result: Uint8Array, signal?: AbortSignal): Promise<number> {
    signal?.throwIfAborted();
    requireBytes(plaintext, 'plaintext');
    requireBytes(result, 'result');
    if (plaintext.length === 0 || plaintext.length > MAX_PLAINTEXT_LENGTH) {
      throw new InvalidArgumentError(`Azure Key Vault wraps 1-${MAX_PLAINTEXT_LENGTH} bytes; got ${plaintext.length}.`);
    }

    // A copy this wrapper owns, so it can be zeroed whatever the caller does with theirs meanwhile.
    const buffer = Uint8Array.from(plaintext);
    try {
      return await this.wrapOwned(buffer, result, signal);
    } finally {
      wipe(buffer);
    }
  }

  /**
   * Verifies the wrapped DEK's signature under the signing key version it records, and only then
   * unwraps it under the recorded wrapping key version, into `result`. On any failure `result` is zeroed.
   *
   * @throws InvalidArgumentError `result` is too small for the revealed key.
   * @throws AzureKeyVaultError `wrapped` isn't a wrapped DEK this wrapper wrote, its signature doesn't
   *   verify (forged, tampered with, or under a different context), Key Vault refused it, or Key
   *   Vault could not be reached.
   */
  async unwrap(wrapped: Uint8Array, result: Uint8Array, signal?: AbortSignal): Promise<number> {
    requireBytes(result, 'result');
    try {
      signal?.throwIfAborted();
      requireBytes(wrapped, 'wrapped');
      // A copy, so what is verified is what is unwrapped, whatever the caller does with theirs meanwhile.
      const data = Uint8Array.from(wrapped);
      const parts = envelope.parse(data, this.fail('unwrap', this.wrappingKey));

      // The signature first: nothing reaches unwrapKey that a principal allowed to sign didn't make.
      const digest = sha256(envelope.signedData(data.subarray(0, parts.unsignedLength), this.context));
      const signedBy = this.signingKey.withVersion(parts.signingKeyVersion);
      const verified = await this.call(signedBy, 'verify', (client) => client.verify('ES256', digest, parts.signature, { abortSignal: signal }));
      if (verified.result !== true) {
        throw new AzureKeyVaultError('verify', signedBy.toString(), `The wrapped DEK's signature doesn't verify under '${this.signingKey.name}' version `
          + `${parts.signingKeyVersion}: it was tampered with, wrapped under a different context, or not made by a principal allowed to sign.`);
      }

      const wrappedBy = this.wrappingKey.withVersion(parts.wrappingKeyVersion);
      const unwrapped = await this.call(wrappedBy, 'unwrap', (client) => client.unwrapKey('RSA-OAEP-256', parts.wrappedDek, { abortSignal: signal }));
      const revealed = unwrapped.result;
      if (!(revealed instanceof Uint8Array) || revealed.length === 0) {
        throw new AzureKeyVaultError('unwrap', wrappedBy.toString(), `Azure Key Vault unwrap for key '${this.wrappingKey.name}' returned no key.`);
      }
      try {
        if (revealed.length > result.length) {
          throw new InvalidArgumentError(`The revealed key is ${revealed.length} bytes; result holds ${result.length}.`);
        }
        result.set(revealed);
        return revealed.length;
      } finally {
        // The SDK decoded it into a buffer of its own, which nothing else holds: zeroed once copied.
        wipe(revealed);
      }
    } catch (error) {
      // Whatever a failed call left in the DEK buffer is erased.
      wipe(result);
      throw error;
    }
  }

  /**
   * Generates a fresh GENERATED_KEY_LENGTH-byte DEK in this process, and wraps and signs it - it is
   * never returned.
   *
   * @throws InvalidArgumentError `result` is too small for the wrapped DEK.
   * @throws AzureKeyVaultError as {@link wrap}.
   */
  async generateAndWrap(result: Uint8Array, signal?: AbortSignal): Promise<number> {
    signal?.throwIfAborted();
    requireBytes(result, 'result');
    // Filled in place, never a pooled Buffer that other allocations share.
    const dek = randomFillSync(new Uint8Array(GENERATED_KEY_LENGTH));
    try {
      return await this.wrapOwned(dek, result, signal);
    } finally {
      wipe(dek);
    }
  }

  /**
   * Reads a key file this wrapper wrote, still wrapped, refusing one that an account other than the
   * operating system's administrators and the KeyFileTrust given at construction could have written
   * or replaced - the TypeScript equivalent of the native library's checks (readTrustedKeyFile in
   * @runsecure/hkdfguard-securefile). On Windows the file must be on a local fixed drive, reached
   * through real folders (no symbolic link, junction or substituted drive), and it and every folder
   * above it must be owned by, and modifiable only by, trusted principals. On Linux and macOS it and
   * every directory above it must be owned by root or a trusted user and writable by nobody else (by
   * its group only if that group is trusted), and only symbolic links a trusted user owns are
   * followed. It is also refused if it is empty, over MAX_WRAPPED_KEY_BYTES, or looks like an
   * unwrapped key. No Key Vault call is made.
   *
   * @throws KeyFileError (from @runsecure/hkdfguard-securefile) with `code` 'ENOENT', 'EACCES' (not
   *   readable, or not trusted), ERR_HKDFGUARD_INVALID_KEY_FILE, 'EBUSY' or another fs code.
   * @throws InvalidArgumentError the path is empty, or the KeyFileTrust names a Windows principal that can't be trusted.
   * @throws UnsupportedPlatformError not Windows, Linux or an Apple silicon Mac.
   */
  async readKeyFile(path: string, signal?: AbortSignal): Promise<Uint8Array> {
    return readTrustedKeyFile(path, this.keyFileTrust, signal);
  }

  private async wrapOwned(key: Uint8Array, result: Uint8Array, signal: AbortSignal | undefined): Promise<number> {
    const wrappingKey = await this.resolve(this.wrappingKey, 'wrap', signal);
    const wrapped = await this.call(wrappingKey, 'wrap', (client) => client.wrapKey('RSA-OAEP-256', key, { abortSignal: signal }));
    const ciphertext = wrapped.result instanceof Uint8Array ? wrapped.result : new Uint8Array(0);
    const unsigned = envelope.buildUnsigned(wrappingKey.version, ciphertext, this.fail('wrap', wrappingKey));
    const length = unsigned.length + envelope.KEY_VERSION_LENGTH + envelope.SIGNATURE_LENGTH;
    if (length > MAX_WRAPPED_KEY_BYTES) {
      throw new AzureKeyVaultError('wrap', wrappingKey.toString(), `The wrapped DEK would be ${length} bytes; a wrapped DEK is at most `
        + `${MAX_WRAPPED_KEY_BYTES}. Use a 2048- or 3072-bit RSA key for '${this.wrappingKey.name}'.`);
    }

    // ES256 signs the SHA-256 digest of the data, which the SDK takes already computed.
    const digest = sha256(envelope.signedData(unsigned, this.context));
    const signingKey = await this.resolve(this.signingKey, 'sign', signal);
    const signed = await this.call(signingKey, 'sign', (client) => client.sign('ES256', digest, { abortSignal: signal }));
    const signature = signed.result instanceof Uint8Array ? signed.result : new Uint8Array(0);
    return envelope.write(unsigned, signingKey.version, signature, result, this.fail('sign', signingKey));
  }

  // The version of `key` every operation goes to: the one named, or else the key's current version,
  // read once with a get and kept. The SDK's own clients can't be relied on for this: given an
  // identifier without a version, they report the version their get saw, but send each operation to
  // whichever is current when it arrives - after a rotation, not the same one.
  private async resolve(key: KeyVaultKeyId, operation: Operation, signal: AbortSignal | undefined): Promise<KeyVaultKeyId> {
    if (key.version !== undefined) return key;
    const known = this.currentVersions.get(key.toString());
    if (known !== undefined) return known;

    let current: KeyVaultKey;
    try {
      current = await this.keyClient(key.vault).getKey(key.name, { abortSignal: signal });
    } catch (error) {
      const translated = this.translate(error, operation, key);
      if (isRestError(error) && error.statusCode === 403) {
        throw new AzureKeyVaultError(operation, key.toString(), `Azure Key Vault ${operation} for key '${key.name}' couldn't read its current version: `
          + `${restErrorCode(error)} (HTTP 403). Give the identity get on the key, or name a version in its key identifier.`, { cause: error });
      }
      throw translated;
    }

    const version = this.versionOf(current.id, key, operation);
    // The client works with the key just read - its public half, permitted operations and validity -
    // and sends every operation to that version.
    if (!this.clients.has(version.toString())) this.clients.set(version.toString(), new CryptographyClient(current, this.credential, this.options()));
    this.currentVersions.set(key.toString(), version);
    return version;
  }

  // The version of the key Key Vault reports having read, refusing an answer for any other key.
  private versionOf(keyId: string | undefined, expected: KeyVaultKeyId, operation: Operation): KeyVaultKeyId {
    let used: KeyVaultKeyId;
    try {
      used = KeyVaultKeyId.parse(keyId!);
    } catch {
      throw new AzureKeyVaultError(operation, expected.toString(),
        `Azure Key Vault ${operation} for key '${expected.name}' reported key ${JSON.stringify(keyId) ?? 'undefined'}, which isn't a key identifier.`);
    }
    if (!used.sameKey(expected)) {
      throw new AzureKeyVaultError(operation, expected.toString(), `Azure Key Vault ${operation} for key '${expected.name}' reported key '${keyId}' instead.`);
    }
    if (used.version === undefined) {
      throw new AzureKeyVaultError(operation, expected.toString(), `Azure Key Vault ${operation} for key '${expected.name}' didn't report which version is current.`);
    }
    return expected.withVersion(used.version);
  }

  private async call<T>(key: KeyVaultKeyId, operation: Operation, call: (client: CryptographyClient) => Promise<T>): Promise<T> {
    try {
      return await call(this.client(key));
    } catch (error) {
      throw this.translate(error, operation, key);
    }
  }

  // Turns Azure failures into the AzureKeyVaultError every operation fails with: a service refusal (a
  // RestError with an HTTP status, naming Key Vault's error code), or a failure on the way (a credential
  // that can't get a token, a refused connection, a key the SDK refuses to use: its message). An abort,
  // and this package's own errors, are left as they are.
  private translate(error: unknown, operation: Operation, key: KeyVaultKeyId): unknown {
    if (error instanceof HkdfGuardError || typeof error !== 'object' || error === null) return error;
    const failure = error as { name?: unknown; message?: unknown; code?: unknown };
    if (failure.name === 'AbortError') return error;
    if (isRestError(error) && typeof error.statusCode === 'number') {
      return new AzureKeyVaultError(operation, key.toString(),
        `Azure Key Vault ${operation} failed for key '${key.name}': ${restErrorCode(error)} (HTTP ${error.statusCode}).`, { cause: error });
    }
    // A request that never got an answer has the socket's error code (ECONNREFUSED, say), and may have
    // no message: a connection refused on every address a name resolves to is reported without one.
    const message = [failure.message, failure.code, failure.name].find((part) => typeof part === 'string' && part !== '') ?? error.constructor.name;
    return new AzureKeyVaultError(operation, key.toString(), `Azure Key Vault ${operation} failed for key '${key.name}': ${message}`, { cause: error });
  }

  private fail(operation: Operation, key: KeyVaultKeyId): envelope.Fail {
    return (message) => new AzureKeyVaultError(operation, key.toString(), message);
  }

  // A client for a key version, created on first use: it reads the key (falling back to doing
  // everything in the vault if it may not) and sends every operation to that version.
  private client(key: KeyVaultKeyId): CryptographyClient {
    const id = key.toString();
    let client = this.clients.get(id);
    if (client === undefined) {
      client = new CryptographyClient(id, this.credential, this.options());
      this.clients.set(id, client);
    }
    return client;
  }

  private keyClient(vault: string): KeyClient {
    let client = this.keyClients.get(vault);
    if (client === undefined) {
      client = new KeyClient(vault, this.credential, this.options());
      this.keyClients.set(vault, client);
    }
    return client;
  }

  // A fresh copy for each client: the SDK writes its user agent into the options it is given.
  private options(): CryptographyClientOptions {
    return { ...this.clientOptions };
  }
}

interface RestErrorLike {
  name: 'RestError';
  statusCode?: number;
  code?: string;
}

// The SDK's RestError (@azure/core-rest-pipeline), recognized by name as the SDK's own isRestError
// does, so any copy of the SDK the application installed is recognized.
function isRestError(error: unknown): error is RestErrorLike {
  return typeof error === 'object' && error !== null && (error as { name?: unknown }).name === 'RestError';
}

function restErrorCode(error: RestErrorLike): string {
  return typeof error.code === 'string' && error.code !== '' ? error.code : 'error';
}

function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

function requireBytes(value: unknown, name: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) throw new InvalidArgumentError(`${name} must be a Uint8Array.`);
}

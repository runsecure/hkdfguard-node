import { DecryptCommand, EncryptCommand, GenerateDataKeyWithoutPlaintextCommand } from '@aws-sdk/client-kms';
import { InvalidArgumentError, MAX_WRAPPED_KEY_BYTES, wipe, type KeyWrapper } from '@runsecure/hkdfguard-abstractions';
import { KeyFileTrust, readTrustedKeyFile } from '@runsecure/hkdfguard-securefile';
import { AwsKmsError } from './errors.js';

/** The length of the DEK {@link AwsKmsKeyWrapper.generateAndWrap} generates: 32 bytes (AES-256). */
export const GENERATED_KEY_LENGTH = 32;

/** The largest plaintext KMS's Encrypt accepts, in bytes. */
export const MAX_PLAINTEXT_LENGTH = 4096;

/** One of the three commands {@link AwsKmsKeyWrapper} sends. */
export type KmsCommand = EncryptCommand | DecryptCommand | GenerateDataKeyWithoutPlaintextCommand;

/**
 * What {@link AwsKmsKeyWrapper} needs of a KMS client: `send`, as the AWS SDK for JavaScript v3
 * defines it. A `KMSClient` from @aws-sdk/client-kms is one - whichever copy of the SDK the
 * application installed - and so is a test double. Every response is checked before it is used.
 */
export interface KmsClient {
  send(command: KmsCommand, options?: { abortSignal?: AbortSignal }): Promise<unknown>;
}

/** The options of an {@link AwsKmsKeyWrapper}. */
export interface AwsKmsKeyWrapperOptions {
  /**
   * Bound into every wrapped DEK and required again to reveal it. Copied at construction; omitted or
   * empty binds none. Logged in plaintext by CloudTrail, so it must not hold secrets.
   */
  readonly encryptionContext?: Readonly<Record<string, string>> | ReadonlyMap<string, string>;
  /**
   * Who besides the operating system's administrators may have written a key file
   * {@link AwsKmsKeyWrapper.readKeyFile} reads; omitted trusts administrators only
   * (KeyFileTrust.administratorsOnly).
   */
  readonly keyFileTrust?: KeyFileTrust;
}

/**
 * A {@link KeyWrapper} that protects (Encrypt) and reveals (Decrypt) a DEK under one symmetric AWS
 * KMS key, and generates fresh DEKs with GenerateDataKeyWithoutPlaintext - so on that path the
 * plaintext DEK never leaves KMS. The KEK never enters this process; every call is a network round
 * trip, authorized by the caller's IAM credentials and recorded in CloudTrail. The Node port of the
 * .NET HkdfGuard.KeyWrapping.AwsKms library: the three send KMS the same requests, so a key file
 * wrapped by any of them unwraps with the others under the same key and encryption context.
 *
 * The key is pinned on every Decrypt. A symmetric ciphertext blob names its own key and KMS would
 * otherwise decrypt it under whichever key it names, so a substituted key file wrapped under any
 * other key this principal may use would be revealed. With the key pinned KMS refuses it
 * (IncorrectKeyException). Prefer a key ARN to an alias: Decrypt resolves an alias when it is called,
 * so re-pointing the alias at a new key makes every DEK wrapped under the old one unreadable. KMS's
 * own automatic key rotation keeps the key ARN and is transparent here.
 *
 * The encryption context, if any, is bound into every wrapped DEK as authenticated data: Decrypt
 * fails unless it is presented again exactly, and key policies can require it
 * (kms:EncryptionContext:*). It is logged in plaintext by CloudTrail, so it must not hold secrets.
 *
 * Key files are read only from where an untrusted account can't have written or replaced them (see
 * {@link readKeyFile} and KeyFileTrust). Pinning the key stops a key file wrapped under another key;
 * this stops one wrapped under this key by anyone who may call kms:Encrypt, which would otherwise
 * choose the DEK new data is encrypted under.
 *
 * Plaintext key bytes this class owns are zeroed once used: its copy of the key sent to Encrypt,
 * once the call has completed, and the buffer the SDK decodes Decrypt's plaintext into, once it is
 * copied into `result` - as is `result` itself whenever an unwrap fails. One copy is beyond its
 * reach: the SDK base64-encodes the key sent to Encrypt, and receives Decrypt's plaintext, as text
 * in a JSON body - JavaScript strings, which can't be zeroed and live until collected. Process
 * hardening (hardenProcess in @runsecure/hkdfguard-keywrapping-native-v1) is what keeps such copies
 * out of reach of a debugger or a crash dump.
 *
 * The client is the application's: it creates it (credentials, region, retries, timeouts), keeps it
 * for as long as anything uses this wrapper - a key ring's background refresh included - and
 * destroys it. This wrapper never creates or destroys one. A `signal` is checked before each call
 * and passed to the SDK, which aborts the request; an abort is rethrown as the SDK reports it.
 * Argument errors throw InvalidArgumentError; a KMS refusal or an unreachable KMS rejects with
 * {@link AwsKmsError}, the SDK's error as its `cause`.
 */
export class AwsKmsKeyWrapper implements KeyWrapper {
  /** The symmetric KMS key that wraps every DEK, as given. */
  readonly keyId: string;
  private readonly client: KmsClient;
  private readonly encryptionContext: Readonly<Record<string, string>> | undefined;
  private readonly keyFileTrust: KeyFileTrust;

  /**
   * @param client The KMS client every call is made through (a `KMSClient`). Never destroyed by this
   *   wrapper; its owner, the application, destroys it.
   * @param keyId The symmetric KMS key that wraps every DEK: a key ARN (preferred), key ID, alias
   *   name ("alias/...") or alias ARN.
   * @throws InvalidArgumentError `client` has no `send`, `keyId` is empty or whitespace, the
   *   encryption context isn't an object or Map of non-empty string keys to string values, or
   *   `keyFileTrust` isn't a KeyFileTrust.
   */
  constructor(client: KmsClient, keyId: string, options: AwsKmsKeyWrapperOptions = {}) {
    if (typeof client !== 'object' || client === null || typeof client.send !== 'function') {
      throw new InvalidArgumentError('client must be a KMS client (a KMSClient from @aws-sdk/client-kms).');
    }
    if (typeof keyId !== 'string' || keyId.trim() === '') throw new InvalidArgumentError('keyId must not be empty or whitespace.');
    if (typeof options !== 'object' || options === null) throw new InvalidArgumentError('AwsKmsKeyWrapper options must be an object.');
    const trust = options.keyFileTrust ?? KeyFileTrust.administratorsOnly;
    if (!(trust instanceof KeyFileTrust)) throw new InvalidArgumentError('keyFileTrust must be a KeyFileTrust.');

    this.client = client;
    this.keyId = keyId;
    this.keyFileTrust = trust;
    this.encryptionContext = copyContext(options.encryptionContext);
  }

  /**
   * Protects a key with KMS's Encrypt, writing the ciphertext blob to `result`. `plaintext` is not
   * modified - it is the caller's to zero.
   *
   * @throws InvalidArgumentError `plaintext` is empty or over MAX_PLAINTEXT_LENGTH bytes, or `result`
   *   is too small for the wrapped DEK.
   * @throws AwsKmsError KMS refused the request or could not be reached, or returned a wrapped DEK
   *   over MAX_WRAPPED_KEY_BYTES.
   */
  async wrap(plaintext: Uint8Array, result: Uint8Array, signal?: AbortSignal): Promise<number> {
    signal?.throwIfAborted();
    requireBytes(plaintext, 'plaintext');
    requireBytes(result, 'result');
    if (plaintext.length === 0 || plaintext.length > MAX_PLAINTEXT_LENGTH) {
      throw new InvalidArgumentError(`KMS wraps 1-${MAX_PLAINTEXT_LENGTH} bytes; got ${plaintext.length}.`);
    }

    // A copy this wrapper owns, so it can be zeroed whatever the caller does with theirs meanwhile.
    const buffer = Uint8Array.from(plaintext);
    try {
      const response = await this.call(new EncryptCommand(this.request({ KeyId: this.keyId, Plaintext: buffer, EncryptionAlgorithm: 'SYMMETRIC_DEFAULT' })),
        'wrap', signal);
      return this.copyWrapped(response['CiphertextBlob'], result, 'wrap');
    } finally {
      // The SDK serializes the request inside the call, so it has been sent - or failed - by now.
      wipe(buffer);
    }
  }

  /**
   * Reveals a key with KMS's Decrypt, the key pinned, into `result`. On any failure `result` is zeroed.
   *
   * @throws InvalidArgumentError `result` is too small for the revealed key.
   * @throws AwsKmsError `wrapped` is empty or over MAX_WRAPPED_KEY_BYTES (refused without calling
   *   KMS), or KMS refused it - tampered with, wrapped under another key, or under a different
   *   encryption context - or could not be reached, or returned no plaintext.
   */
  async unwrap(wrapped: Uint8Array, result: Uint8Array, signal?: AbortSignal): Promise<number> {
    requireBytes(result, 'result');
    try {
      signal?.throwIfAborted();
      requireBytes(wrapped, 'wrapped');
      // Refused locally: no ciphertext this wrapper produced is outside these bounds.
      if (wrapped.length === 0 || wrapped.length > MAX_WRAPPED_KEY_BYTES) {
        throw new AwsKmsError('unwrap', this.keyId, `A wrapped DEK is 1-${MAX_WRAPPED_KEY_BYTES} bytes; got ${wrapped.length}.`);
      }

      const response = await this.call(new DecryptCommand(this.request({
        KeyId: this.keyId, CiphertextBlob: Uint8Array.from(wrapped), EncryptionAlgorithm: 'SYMMETRIC_DEFAULT',
      })), 'unwrap', signal);
      const revealed = response['Plaintext'];
      if (!(revealed instanceof Uint8Array) || revealed.length === 0) {
        throw new AwsKmsError('unwrap', this.keyId, `AWS KMS unwrap for key '${this.keyId}' returned no plaintext.`);
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
   * Has KMS generate a fresh GENERATED_KEY_LENGTH-byte DEK and return it wrapped only
   * (GenerateDataKeyWithoutPlaintext) - the plaintext DEK never leaves KMS on this call.
   *
   * @throws InvalidArgumentError `result` is too small for the wrapped DEK.
   * @throws AwsKmsError KMS refused the request or could not be reached, or returned a wrapped DEK
   *   over MAX_WRAPPED_KEY_BYTES.
   */
  async generateAndWrap(result: Uint8Array, signal?: AbortSignal): Promise<number> {
    signal?.throwIfAborted();
    requireBytes(result, 'result');
    const response = await this.call(new GenerateDataKeyWithoutPlaintextCommand(this.request({ KeyId: this.keyId, KeySpec: 'AES_256' })),
      'generate-and-wrap', signal);
    return this.copyWrapped(response['CiphertextBlob'], result, 'generate-and-wrap');
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
   * unwrapped key. No KMS call is made.
   *
   * @throws KeyFileError (from @runsecure/hkdfguard-securefile) with `code` 'ENOENT', 'EACCES' (not
   *   readable, or not trusted), ERR_HKDFGUARD_INVALID_KEY_FILE, 'EBUSY' or another fs code.
   * @throws InvalidArgumentError the path is empty, or the KeyFileTrust names a Windows principal that can't be trusted.
   * @throws UnsupportedPlatformError not Windows, Linux or an Apple silicon Mac.
   */
  async readKeyFile(path: string, signal?: AbortSignal): Promise<Uint8Array> {
    return readTrustedKeyFile(path, this.keyFileTrust, signal);
  }

  // A fresh context per request, so nothing the SDK (or a middleware the application added to the
  // client) does to one request's input can change what later requests bind. None is left out
  // entirely, as the other ports leave it out, rather than sent empty.
  private request<T extends object>(parameters: T): T & { EncryptionContext?: Record<string, string> } {
    return this.encryptionContext === undefined ? parameters : { ...parameters, EncryptionContext: { ...this.encryptionContext } };
  }

  // Turns the SDK's failures into the AwsKmsError every operation fails with: a service refusal (a
  // ServiceException, KMS's own error name and HTTP status), or a failure on the way (no credentials,
  // a refused connection, a timeout: any error the SDK's middleware stack has stamped with its
  // $metadata). An abort, and anything else - a bug in a test double or a middleware - is left as it is.
  private async call(command: KmsCommand, operation: string, signal: AbortSignal | undefined): Promise<Record<string, unknown>> {
    let response: unknown;
    try {
      response = await this.client.send(command, signal === undefined ? undefined : { abortSignal: signal });
    } catch (error) {
      throw this.classify(error, operation);
    }
    if (typeof response !== 'object' || response === null) {
      throw new AwsKmsError(operation, this.keyId, `AWS KMS ${operation} for key '${this.keyId}' returned no response.`);
    }
    return response as Record<string, unknown>;
  }

  private classify(error: unknown, operation: string): unknown {
    if (typeof error !== 'object' || error === null) return error;
    const failure = error as { name?: unknown; message?: unknown; $fault?: unknown; $metadata?: { httpStatusCode?: unknown } };
    if (failure.name === 'AbortError') return error;
    if (failure.$fault === 'client' || failure.$fault === 'server') {
      const name = typeof failure.name === 'string' && failure.name !== '' ? failure.name : error.constructor.name;
      const status = failure.$metadata?.httpStatusCode ?? 'unknown';
      return new AwsKmsError(operation, this.keyId, `AWS KMS ${operation} failed for key '${this.keyId}': ${name} (HTTP ${String(status)}).`, { cause: error });
    }
    if (failure.$metadata !== undefined || isSdkClientError(failure.name)) {
      const message = typeof failure.message === 'string' && failure.message !== '' ? failure.message : String(failure.name);
      return new AwsKmsError(operation, this.keyId, `AWS KMS ${operation} failed for key '${this.keyId}': ${message}`, { cause: error });
    }
    return error;
  }

  private copyWrapped(ciphertext: unknown, result: Uint8Array, operation: string): number {
    if (!(ciphertext instanceof Uint8Array) || ciphertext.length === 0) {
      throw new AwsKmsError(operation, this.keyId, `AWS KMS ${operation} for key '${this.keyId}' returned no ciphertext.`);
    }
    // A key file over the limit would be refused when read back, so refuse to produce one.
    if (ciphertext.length > MAX_WRAPPED_KEY_BYTES) {
      throw new AwsKmsError(operation, this.keyId,
        `AWS KMS ${operation} for key '${this.keyId}' returned ${ciphertext.length} bytes; a wrapped DEK is at most ${MAX_WRAPPED_KEY_BYTES}.`);
    }
    if (ciphertext.length > result.length) {
      throw new InvalidArgumentError(`The wrapped DEK is ${ciphertext.length} bytes; result holds ${result.length}.`);
    }
    result.set(ciphertext);
    return ciphertext.length;
  }
}

// Errors the SDK's credential and token providers throw, which can surface before its retry
// middleware has stamped them: client-side failures, like a refused connection.
function isSdkClientError(name: unknown): boolean {
  return name === 'CredentialsProviderError' || name === 'TokenProviderError' || name === 'ProviderError';
}

function requireBytes(value: unknown, name: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) throw new InvalidArgumentError(`${name} must be a Uint8Array.`);
}

// Sorted by key (ordinal), so every request lists it the same way, and copied with
// Object.fromEntries so a "__proto__" key is an ordinary entry, never the object's prototype.
function copyContext(context: AwsKmsKeyWrapperOptions['encryptionContext']): Readonly<Record<string, string>> | undefined {
  if (context === undefined || context === null) return undefined;
  if (typeof context !== 'object' || Array.isArray(context)) {
    throw new InvalidArgumentError('encryptionContext must be an object (or Map) of string keys to string values.');
  }
  const entries: [string, unknown][] = context instanceof Map ? [...(context as ReadonlyMap<unknown, unknown>).entries()] as [string, unknown][]
    : Object.entries(context);
  if (entries.length === 0) return undefined;
  for (const [key, value] of entries) {
    if (typeof key !== 'string') throw new InvalidArgumentError(`Encryption context keys must be strings; ${String(key)} is not.`);
    if (key === '') throw new InvalidArgumentError('Encryption context keys must not be empty.');
    if (typeof value !== 'string') throw new InvalidArgumentError(`encryptionContext["${key}"] must be a string.`);
  }
  entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return Object.freeze(Object.fromEntries(entries) as Record<string, string>);
}

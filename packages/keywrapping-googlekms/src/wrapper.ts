import { randomFillSync } from 'node:crypto';
import type { protos } from '@google-cloud/kms';
import { InvalidArgumentError, isWellFormed, MAX_WRAPPED_KEY_BYTES, wipe, type KeyWrapper } from '@runsecure/hkdfguard-abstractions';
import { KeyFileTrust, readTrustedKeyFile } from '@runsecure/hkdfguard-securefile';
import { crc32c } from './crc32c.js';
import { GoogleKmsError } from './errors.js';

/** The length of the DEK {@link GoogleKmsKeyWrapper.generateAndWrap} generates: 32 bytes (AES-256). */
export const GENERATED_KEY_LENGTH = 32;

/** The largest plaintext Cloud KMS's Encrypt accepts, in bytes. */
export const MAX_PLAINTEXT_LENGTH = 64 * 1024;

/**
 * The longest context, in UTF-8 bytes: what Cloud KMS's additional authenticated data allows, less
 * the HkdfGuard label.
 */
export const MAX_CONTEXT_LENGTH = 64 * 1024 - 32;

/** An Encrypt request, as the Cloud KMS client takes it. */
export type EncryptRequest = protos.google.cloud.kms.v1.IEncryptRequest;

/** A Decrypt request, as the Cloud KMS client takes it. */
export type DecryptRequest = protos.google.cloud.kms.v1.IDecryptRequest;

/**
 * What {@link GoogleKmsKeyWrapper} needs of a Cloud KMS client: `encrypt` and `decrypt`, each
 * resolving to `[response, ...]`, and optionally `initialize`. A `KeyManagementServiceClient` from
 * @google-cloud/kms is one - over gRPC or REST, whichever copy of the library the application
 * installed - and so is a test double. Every response is checked before it is used.
 */
export interface CloudKmsClient {
  encrypt(request: EncryptRequest): Promise<unknown>;
  decrypt(request: DecryptRequest): Promise<unknown>;
  /** Signs in and connects; awaited before every call, so a failure rejects that call (see the class comment). */
  initialize?(): Promise<unknown>;
}

/** The options of a {@link GoogleKmsKeyWrapper}. */
export interface GoogleKmsKeyWrapperOptions {
  /**
   * Bound into every wrapped DEK and required again to reveal it; omitted or empty binds none. Use
   * one value per application, so a key file made for one can't be used by another that shares the
   * key. Not secret.
   */
  readonly context?: string;
  /**
   * Who besides the operating system's administrators may have written a key file
   * {@link GoogleKmsKeyWrapper.readKeyFile} reads; omitted trusts administrators only
   * (KeyFileTrust.administratorsOnly).
   */
  readonly keyFileTrust?: KeyFileTrust;
}

// A key's resource name, every part present and none a path of its own: a key version's name, which
// Decrypt doesn't take, doesn't match.
const KEY_NAME = /^projects\/[^/]+\/locations\/[^/]+\/keyRings\/[^/]+\/cryptoKeys\/[^/]+$/;

// Prefixed to every wrapped DEK's additional authenticated data. Changing it makes every existing key
// file unreadable.
const AAD_LABEL = new TextEncoder().encode('HkdfGuard-GoogleKms-wrap-v1\0');

// gRPC status names, by code, as the .NET, Java and Python wrappers name them.
const STATUS_NAMES = [
  'OK', 'CANCELLED', 'UNKNOWN', 'INVALID_ARGUMENT', 'DEADLINE_EXCEEDED', 'NOT_FOUND', 'ALREADY_EXISTS', 'PERMISSION_DENIED',
  'RESOURCE_EXHAUSTED', 'FAILED_PRECONDITION', 'ABORTED', 'OUT_OF_RANGE', 'UNIMPLEMENTED', 'INTERNAL', 'UNAVAILABLE', 'DATA_LOSS',
  'UNAUTHENTICATED',
];

/**
 * A {@link KeyWrapper} that protects (Encrypt) and reveals (Decrypt) a DEK under one symmetric
 * Google Cloud KMS key (purpose ENCRYPT_DECRYPT). The KEK never enters this process; every call is a
 * network round trip, authorized by the caller's Google credential through IAM and recorded in Cloud
 * Audit Logs. The Node port of the .NET HkdfGuard.KeyWrapping.GoogleKms library: wrapped DEKs are
 * byte for byte those of the .NET, Java and Python wrappers, so a key file made by any of them is read
 * by the others, given the same key and context.
 *
 * The key is pinned: Decrypt is always called against the key given at construction, and Cloud KMS
 * refuses a ciphertext made under any other key, so a substituted key file wrapped under another key
 * this principal may use is never revealed. A ciphertext names the key version that made it, so Cloud
 * KMS's own key rotation is transparent here - each key file keeps decrypting under its version, which
 * must stay enabled while the file is in use.
 *
 * Every wrapped DEK is bound, as additional authenticated data, to a fixed HkdfGuard label and the
 * optional context: Decrypt fails unless both are presented again exactly. The label stops a
 * ciphertext the same key made for some other purpose being accepted as a DEK; the context stops a key
 * file made for one application being used by another that shares the key. Neither is secret.
 *
 * Symmetric encryption needs no secret beyond permission to use the key, so anyone allowed
 * `cloudkms.cryptoKeyVersions.useToEncrypt` can make a key file this wrapper accepts. Give the
 * application decrypt only (`roles/cloudkms.cryptoKeyDecrypter`) and the pipeline that creates key
 * files encrypt only; and key files are read only from where an untrusted account can't have written
 * or replaced them (see {@link readKeyFile} and KeyFileTrust).
 *
 * Every request and response carries a CRC32C checksum, as Google recommends, so data corrupted in
 * transit is refused rather than stored or used. A response naming a version of any other key is
 * refused too. Cloud KMS has no "generate data key", so {@link generateAndWrap} generates the DEK in
 * this process and wraps it.
 *
 * Plaintext key bytes this class owns are zeroed once used: its copy of a key it wraps, once the
 * client is done with the request, and the buffer the client decodes Decrypt's plaintext into, once
 * it is copied into `result` - as is `result` itself whenever an unwrap fails. Copies the client makes
 * are beyond its reach: the serialized request (a protobuf buffer over gRPC, base64 text in JSON over
 * REST), and anything its debug logging writes - which, when GOOGLE_SDK_NODE_LOGGING names this
 * client, includes every request and response, keys and all. Process hardening (hardenProcess in
 * @runsecure/hkdfguard-keywrapping-native-v1) is what keeps such copies out of reach of a debugger or
 * a crash dump; logging must stay off.
 *
 * The client is the application's: it creates it (credentials, transport, retries), keeps it for as
 * long as anything uses this wrapper - a key ring's background refresh included - and closes it. This
 * wrapper never creates or closes one. Before each call it awaits the client's `initialize`, which
 * signs in: when that fails - no credential, say - the call rejects with it, rather than the client
 * also raising an unhandled rejection that would end the process. The client can't cancel a call, so
 * a `signal` that aborts stops this wrapper waiting - it rejects with the signal's reason - while the
 * request runs on to completion or the client's timeout; a key it then reveals is zeroed unused.
 * Argument errors throw InvalidArgumentError; a Cloud KMS refusal, an unreachable service or a
 * credential that can't get a token rejects with {@link GoogleKmsError}, naming the operation, the
 * key, and the gRPC status (`INVALID_ARGUMENT: Decryption failed.`), with the client's error as its
 * `cause`.
 */
export class GoogleKmsKeyWrapper implements KeyWrapper {
  /** The symmetric key that wraps every DEK: its resource name, as given. */
  readonly keyName: string;
  private readonly client: CloudKmsClient;
  private readonly aad: Uint8Array;
  private readonly aadCrc32c: number;
  private readonly keyFileTrust: KeyFileTrust;

  /**
   * A wrapper over one key. No call is made until it is used.
   *
   * @param client The Cloud KMS client every call is made through (a `KeyManagementServiceClient`).
   *   Never closed by this wrapper; its owner, the application, closes it.
   * @param keyName The symmetric key that wraps every DEK, as its resource name:
   *   `projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}`. Not a key
   *   version: Decrypt takes the key, and Encrypt uses its primary version.
   * @throws InvalidArgumentError `client` has no `encrypt` or `decrypt`, `keyName` isn't a Cloud KMS
   *   key's resource name, the context isn't a string, is over MAX_CONTEXT_LENGTH bytes in UTF-8 or
   *   isn't well-formed text, or `keyFileTrust` isn't a KeyFileTrust.
   */
  constructor(client: CloudKmsClient, keyName: string, options: GoogleKmsKeyWrapperOptions = {}) {
    if (typeof client !== 'object' || client === null || typeof client.encrypt !== 'function' || typeof client.decrypt !== 'function') {
      throw new InvalidArgumentError('client must be a Cloud KMS client (a KeyManagementServiceClient from @google-cloud/kms).');
    }
    if (typeof keyName !== 'string' || !KEY_NAME.test(keyName)) {
      throw new InvalidArgumentError(`${JSON.stringify(keyName) ?? String(keyName)} isn't a Cloud KMS key's resource name: `
        + 'projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}, without a key version.');
    }
    if (typeof options !== 'object' || options === null) throw new InvalidArgumentError('GoogleKmsKeyWrapper options must be an object.');
    const trust = options.keyFileTrust ?? KeyFileTrust.administratorsOnly;
    if (!(trust instanceof KeyFileTrust)) throw new InvalidArgumentError('keyFileTrust must be a KeyFileTrust.');

    const context = encodeContext(options.context);
    this.client = client;
    this.keyName = keyName;
    this.aad = new Uint8Array(AAD_LABEL.length + context.length);
    this.aad.set(AAD_LABEL);
    this.aad.set(context, AAD_LABEL.length);
    this.aadCrc32c = crc32c(this.aad);
    this.keyFileTrust = trust;
  }

  /**
   * Protects a DEK with Cloud KMS's Encrypt, writing the ciphertext to `result`. `plaintext` is not
   * modified - it is the caller's to zero.
   *
   * @throws InvalidArgumentError `plaintext` is empty or over MAX_PLAINTEXT_LENGTH bytes, or `result`
   *   is too small for the wrapped DEK.
   * @throws GoogleKmsError Cloud KMS refused the request or could not be reached, the request or
   *   response was corrupted in transit, it answered for a key other than this one, or the wrapped DEK
   *   is over MAX_WRAPPED_KEY_BYTES.
   */
  async wrap(plaintext: Uint8Array, result: Uint8Array, signal?: AbortSignal): Promise<number> {
    signal?.throwIfAborted();
    requireBytes(plaintext, 'plaintext');
    requireBytes(result, 'result');
    if (plaintext.length === 0 || plaintext.length > MAX_PLAINTEXT_LENGTH) {
      throw new InvalidArgumentError(`Cloud KMS wraps 1-${MAX_PLAINTEXT_LENGTH} bytes; got ${plaintext.length}.`);
    }
    // A copy this wrapper owns, so it can be zeroed whatever the caller does with theirs meanwhile.
    return this.wrapKey(Uint8Array.from(plaintext), result, signal);
  }

  /**
   * Reveals a DEK with Cloud KMS's Decrypt, the key pinned, into `result`. On any failure `result` is
   * zeroed.
   *
   * @throws InvalidArgumentError `result` is too small for the revealed key.
   * @throws GoogleKmsError `wrapped` is empty or over MAX_WRAPPED_KEY_BYTES (refused without calling
   *   Cloud KMS), or Cloud KMS refused it - tampered with, wrapped under another key, or under a
   *   different context - or could not be reached, or the response was corrupted in transit.
   */
  async unwrap(wrapped: Uint8Array, result: Uint8Array, signal?: AbortSignal): Promise<number> {
    requireBytes(result, 'result');
    try {
      signal?.throwIfAborted();
      requireBytes(wrapped, 'wrapped');
      // Refused locally: no ciphertext this wrapper produced is outside these bounds.
      if (wrapped.length === 0 || wrapped.length > MAX_WRAPPED_KEY_BYTES) {
        throw new GoogleKmsError('unwrap', this.keyName, `A wrapped DEK is 1-${MAX_WRAPPED_KEY_BYTES} bytes; got ${wrapped.length}.`);
      }

      const ciphertext = Uint8Array.from(wrapped);
      const request: DecryptRequest = {
        name: this.keyName, ciphertext, ciphertextCrc32c: { value: crc32c(ciphertext) },
        additionalAuthenticatedData: Uint8Array.from(this.aad), additionalAuthenticatedDataCrc32c: { value: this.aadCrc32c },
      };
      // A plaintext that arrives after an abort is nobody's: zeroed unused.
      const response = await this.call('unwrap', () => this.client.decrypt(request), signal, (late) => wipeBytes(late['plaintext']));

      // The client decoded it into a buffer of its own, which nothing else holds: zeroed once copied.
      const revealed = response['plaintext'];
      try {
        if (!(revealed instanceof Uint8Array) || revealed.length === 0) {
          throw new GoogleKmsError('unwrap', this.keyName, `Cloud KMS unwrap for key '${this.keyName}' returned no plaintext.`);
        }
        if (checksum(response['plaintextCrc32c']) !== crc32c(revealed)) {
          throw new GoogleKmsError('unwrap', this.keyName,
            `Cloud KMS unwrap for key '${this.keyName}' returned a plaintext that doesn't match its checksum: it was corrupted in transit.`);
        }
        if (revealed.length > result.length) {
          throw new InvalidArgumentError(`The revealed key is ${revealed.length} bytes; result holds ${result.length}.`);
        }
        result.set(revealed);
        return revealed.length;
      } finally {
        wipeBytes(revealed);
      }
    } catch (error) {
      // Whatever a failed call left in the DEK buffer is erased.
      wipe(result);
      throw error;
    }
  }

  /**
   * Generates a fresh GENERATED_KEY_LENGTH-byte DEK in this process and wraps it - it is never
   * returned. Cloud KMS has no "generate data key".
   *
   * @throws InvalidArgumentError `result` is too small for the wrapped DEK.
   * @throws GoogleKmsError as {@link wrap}.
   */
  async generateAndWrap(result: Uint8Array, signal?: AbortSignal): Promise<number> {
    signal?.throwIfAborted();
    requireBytes(result, 'result');
    return this.wrapKey(randomFillSync(new Uint8Array(GENERATED_KEY_LENGTH)), result, signal);
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
   * unwrapped key. No Cloud KMS call is made.
   *
   * @throws KeyFileError (from @runsecure/hkdfguard-securefile) with `code` 'ENOENT', 'EACCES' (not
   *   readable, or not trusted), ERR_HKDFGUARD_INVALID_KEY_FILE, 'EBUSY' or another fs code.
   * @throws InvalidArgumentError the path is empty, or the KeyFileTrust names a Windows principal that can't be trusted.
   * @throws UnsupportedPlatformError not Windows, Linux or an Apple silicon Mac.
   */
  async readKeyFile(path: string, signal?: AbortSignal): Promise<Uint8Array> {
    return readTrustedKeyFile(path, this.keyFileTrust, signal);
  }

  // Encrypts `key` - this wrapper's own buffer, zeroed once the client is done with the request,
  // whether or not the caller still waits for it - and checks the answer before using it.
  private async wrapKey(key: Uint8Array, result: Uint8Array, signal: AbortSignal | undefined): Promise<number> {
    const request: EncryptRequest = {
      name: this.keyName, plaintext: key, plaintextCrc32c: { value: crc32c(key) },
      additionalAuthenticatedData: Uint8Array.from(this.aad), additionalAuthenticatedDataCrc32c: { value: this.aadCrc32c },
    };
    const response = await this.call('wrap', () => this.client.encrypt(request), signal, () => {}, () => wipe(key));

    // The version that made it must be one of this key's: a response for any other key would produce
    // a key file this wrapper can't read back.
    const name = response['name'];
    const prefix = `${this.keyName}/cryptoKeyVersions/`;
    if (typeof name !== 'string' || !name.startsWith(prefix) || name.length === prefix.length || name.includes('/', prefix.length)) {
      throw this.error('wrap', `Cloud KMS wrap for key '${this.keyName}' reported key version '${String(name)}' instead.`);
    }
    if (response['verifiedPlaintextCrc32c'] !== true || response['verifiedAdditionalAuthenticatedDataCrc32c'] !== true) {
      throw this.error('wrap', `Cloud KMS wrap for key '${this.keyName}' didn't verify the request's checksums: it was corrupted in transit.`);
    }

    const ciphertext = response['ciphertext'];
    if (!(ciphertext instanceof Uint8Array) || ciphertext.length === 0) {
      throw this.error('wrap', `Cloud KMS wrap for key '${this.keyName}' returned no ciphertext.`);
    }
    if (checksum(response['ciphertextCrc32c']) !== crc32c(ciphertext)) {
      throw this.error('wrap', `Cloud KMS wrap for key '${this.keyName}' returned a ciphertext that doesn't match its checksum: it was corrupted in transit.`);
    }
    // A key file over the limit would be refused when read back, so refuse to produce one.
    if (ciphertext.length > MAX_WRAPPED_KEY_BYTES) {
      throw this.error('wrap', `Cloud KMS wrap for key '${this.keyName}' returned ${ciphertext.length} bytes; a wrapped DEK is at most ${MAX_WRAPPED_KEY_BYTES}.`);
    }
    if (ciphertext.length > result.length) {
      throw new InvalidArgumentError(`The wrapped DEK is ${ciphertext.length} bytes; result holds ${result.length}.`);
    }
    result.set(ciphertext);
    return ciphertext.length;
  }

  // Makes one call - the client initialized first - and waits for it, or for `signal` to abort.
  // `discard` gets a response that arrives once nobody waits for it; `settled` runs once the client is
  // done with the request, either way. Failures become the GoogleKmsError every operation fails with,
  // except the signal's own reason, which is rethrown as it is.
  private async call(operation: string, send: () => Promise<unknown>, signal: AbortSignal | undefined,
    discard: (response: Record<string, unknown>) => void, settled?: () => void): Promise<Record<string, unknown>> {
    const pending = (async () => {
      try {
        if (typeof this.client.initialize === 'function') await this.client.initialize();
        return await send();
      } finally {
        settled?.();
      }
    })();

    let reply: unknown;
    try {
      reply = await untilAborted(pending, signal, (late) => {
        const response = responseOf(late);
        if (response !== undefined) discard(response);
      });
    } catch (error) {
      if (signal?.aborted === true && error === signal.reason) throw error;
      throw this.failure(error, operation);
    }
    const response = responseOf(reply);
    if (response === undefined) throw this.error(operation, `Cloud KMS ${operation} for key '${this.keyName}' returned no response.`);
    return response;
  }

  // A refusal (any error carrying a gRPC status code, over gRPC or REST) names the status and Google's
  // description; anything else - no credential, a bug in a test double - its message. An abort the
  // client reports is left as it is.
  private failure(error: unknown, operation: string): unknown {
    if (error instanceof GoogleKmsError) return error;
    if (typeof error === 'object' && error !== null && (error as { name?: unknown }).name === 'AbortError') return error;
    const failure = (typeof error === 'object' && error !== null ? error : {}) as { code?: unknown; details?: unknown; message?: unknown };
    const message = typeof failure.message === 'string' ? failure.message : String(error);
    const status = typeof failure.code === 'number' ? STATUS_NAMES[failure.code] : undefined;
    if (status !== undefined) {
      // The message repeats the status ("3 INVALID_ARGUMENT: Decryption failed."); the details don't.
      const details = typeof failure.details === 'string' && failure.details !== '' ? failure.details
        : message.startsWith(`${String(failure.code)} ${status}: `) ? message.slice(`${String(failure.code)} ${status}: `.length) : message;
      return new GoogleKmsError(operation, this.keyName, `Cloud KMS ${operation} failed for key '${this.keyName}': ${status}: ${details}`, { cause: error });
    }
    return new GoogleKmsError(operation, this.keyName, `Cloud KMS ${operation} failed for key '${this.keyName}': ${message}`, { cause: error });
  }

  private error(operation: string, message: string): GoogleKmsError {
    return new GoogleKmsError(operation, this.keyName, message);
  }
}

// The UTF-8 context, refusing a lone surrogate, which .NET would encode differently (as U+FFFD).
function encodeContext(context: unknown): Uint8Array {
  if (context === undefined || context === null) return new Uint8Array(0);
  if (typeof context !== 'string') throw new InvalidArgumentError('context must be a string.');
  if (!isWellFormed(context)) throw new InvalidArgumentError('The context isn\'t well-formed text: it holds a lone surrogate.');
  const encoded = new TextEncoder().encode(context);
  if (encoded.length > MAX_CONTEXT_LENGTH) {
    throw new InvalidArgumentError(`The context is ${encoded.length} bytes in UTF-8; at most ${MAX_CONTEXT_LENGTH} are allowed.`);
  }
  return encoded;
}

// `pending`, or the signal's reason as soon as it aborts; what `pending` resolves to after that goes to `late`.
function untilAborted(pending: Promise<unknown>, signal: AbortSignal | undefined, late: (value: unknown) => void): Promise<unknown> {
  if (signal === undefined) return pending;
  return new Promise((resolve, reject) => {
    const onAbort = () => {
      reject(signal.reason);
      pending.then(late, () => {});
    };
    signal.addEventListener('abort', onAbort, { once: true });
    pending.then(
      (value) => { signal.removeEventListener('abort', onAbort); resolve(value); },
      (error: unknown) => { signal.removeEventListener('abort', onAbort); reject(error); });
  });
}

// The client resolves to [response, request, rawResponse].
function responseOf(reply: unknown): Record<string, unknown> | undefined {
  const response: unknown = Array.isArray(reply) ? reply[0] : undefined;
  return typeof response === 'object' && response !== null ? response as Record<string, unknown> : undefined;
}

// A checksum field (an Int64Value): its value, or undefined if it is missing or isn't a 32-bit
// checksum. The client decodes 64-bit integers to decimal text, over gRPC and REST alike; a number,
// bigint or Long (from other decoders) reads the same through String.
function checksum(field: unknown): number | undefined {
  if (typeof field !== 'object' || field === null) return undefined;
  const value = (field as { value?: unknown }).value;
  if (value === undefined || value === null || typeof value === 'symbol' || typeof value === 'function' || typeof value === 'boolean') return undefined;
  const text = String(value);
  return /^\d{1,10}$/.test(text) ? Number(text) : undefined;
}

function wipeBytes(value: unknown): void {
  if (value instanceof Uint8Array) wipe(value);
}

function requireBytes(value: unknown, name: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) throw new InvalidArgumentError(`${name} must be a Uint8Array.`);
}

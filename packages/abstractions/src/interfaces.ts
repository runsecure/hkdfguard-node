import type { Writable } from 'node:stream';
import type { RefreshFailurePolicy } from './policy.js';

/**
 * Protects (wrap) and reveals (unwrap) an encryption key against a single, implicitly identified
 * KEK - a native KMS-backed key identified by service name, or a remote KMS/HSM key. unwrap takes
 * the wrapped payload as an argument, so one instance can reveal any number of wrapped keys sharing
 * the same KEK. Asynchronous so network-backed KEKs can be awaited; `signal` cancels.
 */
export interface KeyWrapper {
  /** Wraps `plaintext` into `result`, resolving to the number of bytes written. */
  wrap(plaintext: Uint8Array, result: Uint8Array, signal?: AbortSignal): Promise<number>;

  /**
   * Reveals a wrapped key into `result`, resolving to its exact length. Implementations must write
   * the complete key, must fail (never return unauthenticated bytes) when `wrapped` was tampered
   * with, and should zero `result` on failure.
   */
  unwrap(wrapped: Uint8Array, result: Uint8Array, signal?: AbortSignal): Promise<number>;

  /**
   * Generates a fresh key and wraps it under the same KEK, into `result` - the plaintext key never
   * leaves this call. Resolves to the number of bytes written.
   */
  generateAndWrap(result: Uint8Array, signal?: AbortSignal): Promise<number>;

  /**
   * Reads a key file holding a key this wrapper wrapped, resolving to its bytes still wrapped -
   * ready for unwrap. buildKeyRing reads every key file through its key wrapper, and there is no
   * fallback: whoever can replace a key file chooses the key new data is encrypted under, so an
   * implementation must refuse a file that an account other than a trusted one could have written
   * or replaced, as well as anything that isn't a wrapped key. The native key wrapper does this
   * through the native library's hkdfguard_open_file, which also refuses a file holding what looks
   * like an unwrapped key.
   *
   * Failures follow Node's fs errors where they match - `code` 'ENOENT' for a missing file,
   * 'EACCES' for one this account may not read or the wrapper doesn't trust - and
   * ERR_HKDFGUARD_INVALID_KEY_FILE for a file that isn't a wrapped key.
   */
  readKeyFile(path: string, signal?: AbortSignal): Promise<Uint8Array>;
}

/**
 * Owns one revealed DEK - how it is revealed, refreshed and eventually zeroed - and performs the
 * AEAD with it. close() zeroes the key and stops any background refresh.
 *
 * Implementations must zero `plaintext` in every encrypt, before returning and on every failure
 * path - including when the key is unavailable and the call fails before any encryption happens.
 * decrypt never modifies its ciphertext. An omitted `aad` means none.
 */
export interface CryptoProvider {
  /**
   * Encrypts `plaintext` bound to `aad` into `result`, returning the number of bytes written.
   * `plaintext` must not share memory with the bytes written to `result`: it is zeroed afterwards.
   */
  encrypt(plaintext: Uint8Array, result: Uint8Array, aad?: Uint8Array): number;

  /** Decrypts `ciphertext` encrypted with the same `aad` into `result`, returning the number of bytes written. */
  decrypt(ciphertext: Uint8Array, result: Uint8Array, aad?: Uint8Array): number;

  /** How many bytes `result` must hold to encrypt a plaintext of `plaintextLength` bytes. */
  encryptedAllocationLength(plaintextLength: number): number;

  /** How many bytes `result` must hold to decrypt a ciphertext of `ciphertextLength` bytes; never negative. */
  decryptedAllocationLength(ciphertextLength: number): number;

  /** Stops any background refresh (awaiting one in flight) and zeroes the key. Safe to call more than once. */
  close(): Promise<void>;
}

/** How a crypto provider refreshes its key. */
export interface CryptoProviderOptions {
  /** Session lifetime and background refresh interval, in seconds: 1 to 300. */
  expirySeconds: number;
  /** Defaults to {@link RefreshFailurePolicy.default}: fail closed after 3 consecutive failures. */
  refreshFailurePolicy?: RefreshFailurePolicy;
  /** Cancels creating the provider (the first key reveal). */
  signal?: AbortSignal;
}

/**
 * Mints crypto providers for a key ring - the cipher. Creating one reveals its first key through the
 * key wrapper, which may be a network call, so creation is asynchronous.
 */
export interface CryptoProviderFactory {
  /** A provider for an existing wrapped DEK, revealed through `wrapper`. The provider owns `wrapped` and zeroes it when closed. */
  create(wrapper: KeyWrapper, wrapped: Uint8Array, options: CryptoProviderOptions): Promise<CryptoProvider>;

  /** A provider for a fresh DEK that `wrapper` generates and wraps. */
  createEphemeral(wrapper: KeyWrapper, options: CryptoProviderOptions): Promise<CryptoProvider>;
}

/**
 * One data encryption key: AEAD-encrypts and decrypts under it, bound to optional AAD. encrypt
 * consumes its plaintext - the buffer is zeroed before encrypt returns or throws, so callers that
 * still need the value must pass a copy.
 */
export interface DataEncryptionKey {
  /** Encrypts `plaintext` bound to `aad`, returning the ciphertext. `plaintext` is zeroed. */
  encrypt(plaintext: Uint8Array, aad?: Uint8Array): Uint8Array;

  /** Decrypts `ciphertext` encrypted with the same `aad` into `result`, returning the number of bytes written. */
  decrypt(ciphertext: Uint8Array, result: Uint8Array, aad?: Uint8Array): number;
}

/**
 * Data encryption keys tracked by version, one of which is current. Encrypting asks for the current
 * key on every operation, so it follows rotation; decrypting asks for the exact version a value
 * names, so values encrypted before a rotation still decrypt.
 */
export interface KeyRing {
  /** The version new values are encrypted under - the highest registered. @throws NoCurrentKeyError */
  readonly currentVersion: number;

  /** The current version together with its key, read atomically. @throws NoCurrentKeyError */
  getCurrent(): { version: number; key: DataEncryptionKey };

  /** The key registered for `version`. @throws KeyNotFoundError */
  get(version: number): DataEncryptionKey;

  /** The key registered for `version`, or undefined. */
  tryGet(version: number): DataEncryptionKey | undefined;
}

/** An encrypted value together with the key version it was encrypted under. */
export interface KeyTrackingValue {
  keyVersion: number;
  value: Uint8Array;
}

/** Converts between a {@link KeyTrackingValue} and the string it is stored as. */
export interface EncryptedFormatProvider {
  format(value: KeyTrackingValue): string;
  parse(encrypted: string): KeyTrackingValue;
  /** An upper bound on the decrypted plaintext's length, from the encoded payload's length alone. */
  maxDecryptedLength(encrypted: string): number;
}

/**
 * A named, string-level protector: its name is the AAD of every value it protects, binding each
 * value to its purpose. Keys come from a key ring.
 */
export interface DataProtector {
  /** Encrypts `plaintext` (a string is taken as UTF-8) and formats the result. The caller's plaintext is not zeroed. */
  encrypt(plaintext: Uint8Array | string): string;

  /** Parses and decrypts `encrypted` into `result`, returning the number of bytes written. Size `result` with maxDecryptedLength. */
  decrypt(encrypted: string, result: Uint8Array): number;

  /** An upper bound on how many bytes decrypt writes for `encrypted`. */
  maxDecryptedLength(encrypted: string): number;
}

/**
 * A short-lived protector for a pipeline that must encrypt secrets before a durable KEK exists. Each
 * value is bound to its secret identifier - the configuration key it will be stored under - via
 * configurationAad, so once this key is wrapped and registered at keyVersion, encrypted
 * configuration reveals it. close() zeroes the key.
 */
export interface PipelineDataProtector {
  /** The version stamped on every value. */
  readonly keyVersion: number;

  /** Encrypts `plaintext` bound to `secretIdentifier` and formats the result. */
  encrypt(plaintext: Uint8Array | string, secretIdentifier: string): string;

  /** Decrypts a value encrypted for `secretIdentifier` into `result`, returning the number of bytes written. */
  decrypt(encrypted: string, secretIdentifier: string, result: Uint8Array): number;

  /** An upper bound on how many bytes decrypt writes for `encrypted`. */
  maxDecryptedLength(encrypted: string): number;

  /**
   * The key, base64-encoded as ASCII bytes, for the native wrap process at the end of the pipeline.
   * The buffer is owned by the protector and zeroed on close: never convert it to a string, and
   * pass it to the wrap tool on standard input, never as an argument or environment variable.
   */
  keyBase64(): Uint8Array;

  /**
   * Writes the key to `destination` exactly as the wrap tool's `--dek-stdin` reads it - its base64
   * form as ASCII, with no line ending - resolving once the stream has accepted it: the stdin of
   * `hkdfguard wrap ... --dek-stdin`, or of `ssh -T host sudo -n hkdfguard wrap ... --dek-stdin`.
   * The bytes are written from a buffer of their own, zeroed once the write completes; no string is
   * ever made of them. `destination` is left open: end it afterwards, so the tool sees the end of
   * its input. The stream must be done with the bytes when its write calls back, as a process's
   * stdin, a socket or a file stream is - not one that hands the same buffer on, such as a PassThrough.
   * @param destination where to write the key: a process's standard input
   * @param signal cancels the write; the destination is then unusable - destroy it
   * @throws TypeError (rejecting) destination isn't a Writable
   * @throws ClosedError (rejecting) the protector has been closed
   * @throws HkdfGuardError (rejecting; ERR_HKDFGUARD_INVALID_STATE) destination has already ended or been destroyed
   */
  writeDek(destination: Writable, signal?: AbortSignal): Promise<void>;

  close(): void;
}

/**
 * The end of a provisioning pipeline that delivers secrets from a secret store as one encrypted file
 * per secret - the folder layout FilePerSecretCache reads at runtime - before a durable KEK exists.
 * An implementation is given the secrets to pull and a {@link PipelineDataProtector} when it is
 * created; {@link pullSecrets} reads each secret and encrypts it at once, bound to its file name,
 * keeping only the encrypted value; {@link writeProtectedSecretFiles} then writes one file per
 * secret, or {@link writeJsonSecrets} one JSON file of them all - each also to a stream
 * ({@link writeProtectedSecretFilesTo}, {@link writeJsonSecretsTo}), for a remote command's stdin. No key ring is involved: the protector's key is the only one, and it is handed to the
 * native platform's wrap process once the files are written.
 *
 * The protector belongs to the caller and is never closed by the writer. Closing the writer
 * releases its connection to the secret store.
 */
export interface SecretPipelineWriter {
  /**
   * Every secret pulled, by file name: its value encrypted by the protector and formatted, as its
   * file will hold it. Empty until {@link pullSecrets} completes.
   */
  readonly protectedSecrets: ReadonlyMap<string, string>;

  /**
   * Reads every secret the writer was created with and encrypts each value, keeping it in
   * {@link protectedSecrets} - replacing whatever an earlier pull kept.
   * @param signal cancels the reads
   * @throws SecretsNotFoundError (rejecting; ERR_HKDFGUARD_SECRETS_NOT_FOUND) a secret has no value;
   *   every other secret is kept
   */
  pullSecrets(signal?: AbortSignal): Promise<void>;

  /**
   * Writes every secret in {@link protectedSecrets} as a file in `folderPath`, creating the folder if
   * it doesn't exist: the file named for it, holding its encrypted, formatted value as UTF-8.
   * @param folderPath the folder to write to, absolute or relative to the working directory
   * @throws TypeError (rejecting) folderPath isn't a string
   * @throws InvalidArgumentError (rejecting) folderPath is empty
   * @throws HkdfGuardError (rejecting; ERR_HKDFGUARD_INVALID_STATE) no pull has completed
   */
  writeProtectedSecretFiles(folderPath: string): Promise<void>;

  /**
   * Writes every secret in {@link protectedSecrets} to one JSON file at `filePath`, creating its
   * folder if it doesn't exist: a single object with a member per secret, its file name mapped to
   * its encrypted, formatted value. A file already there is replaced.
   * @param filePath the file to write, absolute or relative to the working directory
   * @throws TypeError (rejecting) filePath isn't a string
   * @throws InvalidArgumentError (rejecting) filePath is empty
   * @throws HkdfGuardError (rejecting; ERR_HKDFGUARD_INVALID_STATE) no pull has completed
   */
  writeJsonSecrets(filePath: string): Promise<void>;

  /**
   * Writes every secret in {@link protectedSecrets} to `destination` as a tar archive of the files
   * {@link writeProtectedSecretFiles} would write - for a remote tar to unpack, e.g. the stdin of
   * `ssh -T host sudo -n tar -x --no-same-owner -f - -C folder` - resolving once the stream has
   * accepted all of it. `destination` is left open: end it afterwards, so tar sees the end of its input.
   * @param destination where to write the archive: a process's standard input
   * @param signal cancels the write; the destination then holds part of an archive - destroy it
   * @throws TypeError (rejecting) destination isn't a Writable
   * @throws HkdfGuardError (rejecting; ERR_HKDFGUARD_INVALID_STATE) no pull has completed, or
   *   destination has already ended or been destroyed
   */
  writeProtectedSecretFilesTo(destination: Writable, signal?: AbortSignal): Promise<void>;

  /**
   * Writes every secret in {@link protectedSecrets} to `destination` as the JSON object
   * {@link writeJsonSecrets} would write - for a remote command to store, e.g. the stdin of
   * `ssh -T host sudo -n tee /etc/app/secrets.json` - resolving once the stream has accepted it.
   * `destination` is left open: end it afterwards, so the remote command sees the end of its input.
   * @param destination where to write the JSON: a process's standard input
   * @param signal cancels the write
   * @throws TypeError (rejecting) destination isn't a Writable
   * @throws HkdfGuardError (rejecting; ERR_HKDFGUARD_INVALID_STATE) no pull has completed, or
   *   destination has already ended or been destroyed
   */
  writeJsonSecretsTo(destination: Writable, signal?: AbortSignal): Promise<void>;

  /** Releases the writer's connection to the secret store. Safe to call more than once. */
  close(): Promise<void>;
}

/**
 * The read surface of a name -> encrypted-value cache. Names match ignoring ASCII case only, and each
 * value is bound to its name. Reads are asynchronous because a cache may fetch a missing value from a
 * remote store.
 */
export interface ProtectedReadOnlyCache {
  /** Decrypts the value stored under `name` into `result`, resolving to the bytes written, or 0 if none is stored. */
  decrypt(name: string, result: Uint8Array, signal?: AbortSignal): Promise<number>;

  /** An upper bound on how many bytes decrypt writes for `name`, or undefined if nothing is stored. */
  maxDecryptedLength(name: string, signal?: AbortSignal): Promise<number | undefined>;
}

/** A {@link ProtectedReadOnlyCache} values can be added to. */
export interface ProtectedCache extends ProtectedReadOnlyCache {
  /** Encrypts and stores `plaintext` under `name`; `plaintext` is zeroed. @throws AlreadyExistsError */
  add(name: string, plaintext: Uint8Array): void;

  /** Encrypts and stores `plaintext` under `name`, replacing any value there; `plaintext` is zeroed. */
  addOrUpdate(name: string, plaintext: Uint8Array): void;
}

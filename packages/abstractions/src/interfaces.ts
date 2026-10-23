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
  /** Encrypts `plaintext` bound to `aad` into `result`, returning the number of bytes written. */
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

  close(): void;
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

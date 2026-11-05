import { constants as bufferConstants, isUtf8 } from 'node:buffer';
import { statSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  configurationAad, InvalidArgumentError, wipe, type EncryptedFormatProvider, type KeyRing, type KeyTrackingValue, type ProtectedReadOnlyCache,
} from '@runsecure/hkdfguard-abstractions';
import { JsonReader, JsonToken, MalformedJsonError, untilAborted } from '@runsecure/hkdfguard-abstractions/internal';
import { FilePerSecretCache, InvalidSecretDataError } from '@runsecure/hkdfguard-cache';
import { AttributeNames, CacheMetrics, HkdfGuardLog, HkdfGuardTelemetry, Results, SpanNames, type Logger } from '@runsecure/hkdfguard-diagnostics';
import { KeyFileError, KeyFileTrust, readTrustedFile } from '@runsecure/hkdfguard-securefile';

const DEFAULT_MAX_FILE_LENGTH = 1024 * 1024;

const TOKEN_NAMES: Partial<Record<JsonToken, string>> = {
  [JsonToken.StartArray]: 'an array',
  [JsonToken.String]: 'a string',
  [JsonToken.Number]: 'a number',
  [JsonToken.True]: 'true',
  [JsonToken.False]: 'false',
  [JsonToken.Null]: 'null',
};

/** Options for a {@link JsonSecretsFileReadOnlyCache}. */
export interface JsonSecretsFileCacheOptions {
  /**
   * The longest file read, in bytes: a positive integer, {@link JsonSecretsFileReadOnlyCache.DEFAULT_MAX_FILE_LENGTH}
   * by default. The read buffer is this large, so keep it close to the largest file expected.
   */
  maxFileLength?: number;
  /**
   * Receives a debug entry per load of the file while sensitive logging is enabled (its path, never
   * a value), and an error entry per failed load.
   */
  logger?: Logger;
}

/**
 * A ProtectedReadOnlyCache over one JSON file holding every secret, as a pipeline's
 * SecretPipelineWriter.writeJsonSecrets (@runsecure/hkdfguard-pipeline) writes it: a single object
 * whose members map each secret's name to its value, already encrypted under the key ring and
 * formatted (enc::v{version}::{base64}) - the Node port of .NET's
 * HkdfGuard.Cache.JsonSecretsFile.JsonSecretsFileReadOnlyCache. Nothing is read up front: the first
 * lookup reads the whole file, authenticates every value in it, and keeps them - still encrypted,
 * exactly as the file holds them - so every later lookup is served from memory without touching
 * the disk.
 *
 * **The file is read through readTrustedFile** (@runsecure/hkdfguard-securefile). It is refused -
 * with a KeyFileError 'EACCES', and nothing kept - unless it and every folder above it are owned,
 * and modifiable, only by the operating system's administrators and the principals the
 * {@link KeyFileTrust} adds, with no untrusted symbolic link on the way. Add the account that
 * deploys secrets, never the one the application runs as.
 *
 * **Every value is bound to its name.** A member's value must be encrypted with the purpose
 * configurationPurpose(name) - as a PipelineDataProtector's encrypt(value, name) writes it - and a
 * value moved under any other name fails authentication. The file is delivered as one, so it is
 * loaded as one: a value that fails authentication (AuthenticationFailedError), names a key version
 * the ring doesn't hold (KeyNotFoundError) or isn't in the format (the format provider's error)
 * fails the whole load, and nothing is kept, so the file is read again on the next lookup.
 *
 * **The file must be exactly that object** - one member per secret, each name a valid
 * FilePerSecretCache name ({@link FilePerSecretCache.isValidName}), no name twice ignoring case,
 * each value a non-empty string, in UTF-8 JSON as strict as .NET's Utf8JsonReader - or it is
 * refused with an InvalidSecretDataError (ERR_HKDFGUARD_INVALID_SECRET_DATA), which names the file
 * and the member but never quotes a value. Names are looked up ignoring ASCII case, as the values
 * are bound; any name that couldn't be one is reported missing - decrypt resolves to 0 - so the cache
 * can sit in a ProtectedCacheCollection beside sources with other naming rules. A missing file (or
 * folder) reports every secret missing, and isn't remembered: it is looked for again on the next
 * lookup. A file longer than the maximum given is refused with a KeyFileError
 * ERR_HKDFGUARD_FILE_TOO_LARGE, reading no more than one byte past it; any other failure to read it
 * propagates. Concurrent lookups share one load of the file; aborting a lookup's signal stops that
 * lookup, never the load others wait on.
 *
 * The values loaded are kept for the life of the instance: a file changed after it was loaded is
 * picked up by a new cache instance. Each value decrypts with the key version it names, so it keeps
 * decrypting after a key rotation for as long as the ring holds that version.
 *
 * Telemetry: each load of the file is a {@link SpanNames.cache.populate} span on
 * HkdfGuardTelemetry.cache, counted in CacheMetrics.operations as "success", "not_found" or "error";
 * each lookup is a {@link SpanNames.cache.decrypt} span. With sensitive logging on, the file's path
 * and each looked-up name (never a value) are logged. A failed load is logged as an error.
 */
export class JsonSecretsFileReadOnlyCache implements ProtectedReadOnlyCache {
  /** The longest file read by default, in bytes: room for hundreds of formatted secrets. */
  static readonly DEFAULT_MAX_FILE_LENGTH = DEFAULT_MAX_FILE_LENGTH;

  /** The full path of the JSON file the secrets are read from. */
  readonly filePath: string;

  readonly #trust: KeyFileTrust;
  readonly #ring: KeyRing;
  readonly #formatProvider: EncryptedFormatProvider;
  readonly #maxFileLength: number;
  readonly #logger: Logger | undefined;

  // Every value, by its name in ASCII lower case, once a load has succeeded; kept from then on.
  #values: Map<string, KeyTrackingValue> | undefined;
  // The load in flight, shared by every lookup that arrives while it runs.
  #loading: Promise<Map<string, KeyTrackingValue> | undefined> | undefined;

  /**
   * @param filePath the JSON file holding the secrets, absolute or relative to the working directory
   * @param trust who besides administrators is trusted to have written the file and the folders
   *   above it; {@link KeyFileTrust.administratorsOnly} for no one
   * @param ring supplies the key each value names; owned by the caller - the cache never closes keys
   * @param formatProvider parses each formatted value - the same format the values were written in
   * @param options the longest file read, and a logger
   * @throws TypeError filePath isn't a string, trust isn't a KeyFileTrust, or ring or formatProvider is missing
   * @throws InvalidArgumentError filePath is empty, or maxFileLength isn't a positive integer below Node's largest buffer
   * @throws KeyFileError 'ENOENT' filePath doesn't name an existing file
   */
  constructor(filePath: string, trust: KeyFileTrust, ring: KeyRing, formatProvider: EncryptedFormatProvider,
    options: JsonSecretsFileCacheOptions = {}) {
    if (typeof filePath !== 'string') throw new TypeError('filePath must be a string.');
    if (filePath === '') throw new InvalidArgumentError('A secrets file path is required.');
    if (!(trust instanceof KeyFileTrust)) throw new TypeError('trust must be a KeyFileTrust.');
    if (ring === undefined || ring === null) throw new TypeError('ring must not be undefined.');
    if (formatProvider === undefined || formatProvider === null) throw new TypeError('formatProvider must not be undefined.');
    const maxFileLength = options.maxFileLength ?? DEFAULT_MAX_FILE_LENGTH;
    if (!Number.isSafeInteger(maxFileLength) || maxFileLength <= 0 || maxFileLength >= bufferConstants.MAX_LENGTH) {
      throw new InvalidArgumentError(`The maximum file length must be a positive integer below ${bufferConstants.MAX_LENGTH}, got ${maxFileLength}.`);
    }

    this.filePath = resolve(filePath);
    if (statSync(this.filePath, { throwIfNoEntry: false })?.isFile() !== true) {
      throw new KeyFileError('ENOENT', this.filePath, `The secrets file '${this.filePath}' doesn't exist.`);
    }

    this.#trust = trust;
    this.#ring = ring;
    this.#formatProvider = formatProvider;
    this.#maxFileLength = maxFileLength;
    this.#logger = options.logger;
  }

  /**
   * Decrypts `name`'s value into `result`, resolving to the bytes written, or 0 if the file holds no
   * such secret (or is missing).
   * @throws TypeError (rejecting) name isn't a string
   * @throws InvalidSecretDataError (rejecting) the file isn't the secrets object
   * @throws AuthenticationFailedError (rejecting) a value in the file wasn't encrypted for its name, or was altered
   * @throws KeyFileError (rejecting) the file's location isn't trusted, this account may not read it, or it is too long
   * @throws KeyNotFoundError (rejecting) a value's key version isn't in the ring
   */
  decrypt(name: string, result: Uint8Array, signal?: AbortSignal): Promise<number> {
    const telemetry = HkdfGuardTelemetry.cache;
    return telemetry.withSpan(SpanNames.cache.decrypt, async (span) => {
      telemetry.logSensitiveOperation(span, SpanNames.cache.decrypt, { [AttributeNames.name]: name });
      const value = await this.#value(name, signal);
      return value === undefined ? 0 : this.#decryptValue(name, value, result);
    });
  }

  /**
   * An upper bound on how many bytes decrypt writes for `name`, or undefined if the file holds no
   * such secret (or is missing).
   * @throws TypeError (rejecting) name isn't a string
   * @throws InvalidSecretDataError, AuthenticationFailedError, KeyFileError, KeyNotFoundError (rejecting) as decrypt, when the file is loaded
   */
  async maxDecryptedLength(name: string, signal?: AbortSignal): Promise<number | undefined> {
    return (await this.#value(name, signal))?.value.length;
  }

  #decryptValue(name: string, value: KeyTrackingValue, result: Uint8Array): number {
    return this.#ring.get(value.keyVersion).decrypt(value.value, result, configurationAad(name));
  }

  // name's value, loading the file on the first lookup; undefined if name couldn't be a secret's
  // name, the file is missing, or it holds no value for name.
  async #value(name: string, signal: AbortSignal | undefined): Promise<KeyTrackingValue | undefined> {
    if (typeof name !== 'string') throw new TypeError('name must be a string.');
    signal?.throwIfAborted();

    // Checked first: only ASCII names are valid, so lower-casing one is ignoring ASCII case alone.
    if (!FilePerSecretCache.isValidName(name)) return undefined;

    const values = this.#values ?? await untilAborted(this.#load(), signal);
    return values?.get(name.toLowerCase());
  }

  // The values, from the load in flight or a new one; undefined if the file is missing.
  #load(): Promise<Map<string, KeyTrackingValue> | undefined> {
    this.#loading ??= this.#loadOnce().finally(() => {
      this.#loading = undefined;
    });
    return this.#loading;
  }

  // Reads, parses and authenticates the whole file, keeping its values once every one passes.
  #loadOnce(): Promise<Map<string, KeyTrackingValue> | undefined> {
    const telemetry = HkdfGuardTelemetry.cache;
    return telemetry.withSpan(SpanNames.cache.populate, async (span) => {
      if (telemetry.enableSensitiveLogging) {
        telemetry.logSensitiveOperation(span, SpanNames.cache.populate, { [AttributeNames.name]: this.filePath });
        HkdfGuardLog.sensitiveOperationLogged(this.#logger, SpanNames.cache.populate, this.filePath);
      }

      try {
        const contents = await this.#read();
        if (contents === undefined) {
          recordOperation(Results.notFound);
          return undefined;
        }

        const values = this.#parse(contents);
        for (const [name, value] of values) this.#authenticate(name, value);
        recordOperation(Results.success);
        return this.#values = values;
      } catch (error) {
        HkdfGuardLog.operationFailed(this.#logger, SpanNames.cache.populate, error);
        recordOperation(Results.error);
        throw error;
      }
    });
  }

  // The file's contents from readTrustedFile; undefined if the file or a folder above it doesn't exist.
  async #read(): Promise<Uint8Array | undefined> {
    try {
      return await readTrustedFile(this.filePath, this.#trust, this.#maxFileLength);
    } catch (error) {
      if (error instanceof KeyFileError && error.code === 'ENOENT') return undefined;
      throw error;
    }
  }

  // The secrets object's members by lower-cased name, each value parsed but not yet authenticated.
  // Every key and value is a name or ciphertext, never a secret, so each may be a string.
  #parse(contents: Uint8Array): Map<string, KeyTrackingValue> {
    if (!isUtf8(contents)) throw this.#invalid("isn't valid JSON: it isn't UTF-8");

    const values = new Map<string, KeyTrackingValue>();
    const reader = new JsonReader(contents);
    try {
      if (!reader.read()) throw this.#invalid("isn't valid JSON: it is empty");
      if (reader.token() !== JsonToken.StartObject) throw this.#invalid(`holds ${TOKEN_NAMES[reader.token()!]}, not an object of secrets`);

      // The reader throws on anything malformed or incomplete, so inside the object each token read
      // is a member's name or the object's end, and after a name, its value.
      for (;;) {
        reader.read();
        if (reader.token() === JsonToken.EndObject) break;

        const name = reader.getString();
        if (!FilePerSecretCache.isValidName(name)) throw this.#invalid(`names a secret '${name}', which isn't a secret's name`);

        reader.read();
        const encrypted = reader.token() === JsonToken.String ? reader.getString().trim() : '';
        if (encrypted.length === 0) throw this.#invalid(`holds no value for '${name}': each must be a non-empty string`);
        const key = name.toLowerCase();
        const value = this.#formatProvider.parse(encrypted);
        if (values.has(key)) throw this.#invalid(`names '${name}' more than once`);
        values.set(key, value);
      }

      // Anything after the object - a second value, stray text - throws here.
      reader.read();
    } catch (error) {
      if (error instanceof MalformedJsonError) throw this.#invalid(`isn't valid JSON: ${error.message.replace(/\.$/, '')}`);
      throw error;
    }
    return values;
  }

  #invalid(problem: string): InvalidSecretDataError {
    return new InvalidSecretDataError(`The secrets file '${this.filePath}' ${problem}.`);
  }

  // Decrypts value once into a buffer that is zeroed at once, so only values that authenticate under
  // their names - and key versions the ring holds - are ever kept.
  #authenticate(name: string, value: KeyTrackingValue): void {
    // AEAD ciphertext is always at least as long as the plaintext it encloses.
    const plaintext = new Uint8Array(value.value.length);
    try {
      this.#decryptValue(name, value, plaintext);
    } finally {
      wipe(plaintext);
    }
  }
}

function recordOperation(result: string): void {
  CacheMetrics.operations.add(1, { [AttributeNames.operationName]: SpanNames.cache.populate, [AttributeNames.result]: result });
}

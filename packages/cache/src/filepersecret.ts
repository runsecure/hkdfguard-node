import { statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
  configurationAad, InvalidArgumentError, wipe, type EncryptedFormatProvider, type KeyRing, type KeyTrackingValue, type ProtectedReadOnlyCache,
} from '@runsecure/hkdfguard-abstractions';
import { AttributeNames, CacheMetrics, HkdfGuardLog, HkdfGuardTelemetry, Results, SpanNames, type Logger } from '@runsecure/hkdfguard-diagnostics';
import { KeyFileError, KeyFileTrust, readTrustedFile } from '@runsecure/hkdfguard-securefile';

const MAX_NAME_LENGTH = 255;

// Windows' reserved device names, alone or before an extension: CreateFile opens the device, not a
// file in the folder - NUL discards a write, CON is the console, COM1 may block.
const DEVICE_NAME = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i;
const MAX_FILE_LENGTH = 64 * 1024;

const decoder = new TextDecoder();

/**
 * A ProtectedReadOnlyCache over a folder on the local filesystem holding one file per secret: the
 * file named name holds that secret's value, already encrypted under the key ring and formatted
 * (enc::v{version}::{base64}). Nothing is read up front: the first lookup of a name reads that one
 * file, authenticates its value, and caches it - still encrypted, exactly as the file holds it - so
 * every later lookup is served from memory without touching the disk. Surrounding whitespace in a
 * file, such as a trailing newline, is ignored.
 *
 * **Every file is read through readTrustedFile** (@runsecure/hkdfguard-securefile). It is refused -
 * with a KeyFileError 'EACCES', and not cached - unless it and every folder above it are owned, and
 * modifiable, only by the operating system's administrators and the principals the
 * {@link KeyFileTrust} adds, with no untrusted symbolic link on the way. Add the account that
 * deploys secrets, never the one the application runs as.
 *
 * **Every value is bound to its name.** A file's value must be encrypted with the purpose
 * configurationPurpose(name) - as a PipelineDataProtector's encrypt(value, name), or
 * ring.createProtector(configurationPurpose(name)), writes it - and a file copied under any other
 * name fails authentication with an AuthenticationFailedError when it is loaded, rather than
 * decrypting as that name's value. A file that fails is not cached, so it is read again on the next
 * lookup.
 *
 * A name is a file name: 1-{@link MAX_NAME_LENGTH} ASCII letters, digits, '-', '_' and '.', not
 * starting or ending with '.' and not a Windows device name (see {@link isValidName}), so it can
 * never reach outside the folder, or be another name's file on any platform. Any other
 * name, a missing file, a missing folder and an empty file are all reported missing - decrypt
 * resolves to 0 - so the cache can sit in a ProtectedCacheCollection beside sources with other
 * naming rules. A missing secret isn't remembered: its file is looked for again on the next lookup.
 * Names are matched exactly, and files are found as the filesystem finds them: exactly on Linux,
 * ignoring case on Windows and, by default, macOS. A file longer than {@link MAX_FILE_LENGTH} bytes
 * is refused with a KeyFileError ERR_HKDFGUARD_FILE_TOO_LARGE, reading no more than one byte past
 * that; any other failure to read it propagates, and nothing is cached. A file is read on the
 * calling thread, as readTrustedFile reads; concurrent lookups of a name not yet cached may each
 * read its file, and the first value stored is the one kept.
 *
 * A cached value is kept for the life of the instance: a file changed after its secret was loaded
 * is picked up by a new cache instance. Each value decrypts with the key version it names, so it
 * keeps decrypting after a key rotation for as long as the ring holds that version; once it doesn't,
 * decrypt fails with KeyNotFoundError.
 *
 * Telemetry: each file load is a {@link SpanNames.cache.populate} span on HkdfGuardTelemetry.cache,
 * counted in CacheMetrics.operations as "success", "not_found" or "error"; with sensitive logging
 * on, the secret's name (never a value) is logged. A failed load is logged as an error.
 */
export class FilePerSecretCache implements ProtectedReadOnlyCache {
  /** The longest name a secret's file can have. */
  static readonly MAX_NAME_LENGTH = MAX_NAME_LENGTH;

  /** The longest file, in bytes, that is read: room for a formatted secret of about 48 KB. */
  static readonly MAX_FILE_LENGTH = MAX_FILE_LENGTH;

  /** The full path of the folder the secrets' files are read from. */
  readonly folderPath: string;

  readonly #trust: KeyFileTrust;
  readonly #ring: KeyRing;
  readonly #formatProvider: EncryptedFormatProvider;
  readonly #logger: Logger | undefined;

  // Each loaded secret's value as its file held it: encrypted, bound to its name. Exact names,
  // since each spelling is bound - and authenticated - separately.
  readonly #values = new Map<string, KeyTrackingValue>();

  /**
   * @param folderPath the folder holding one file per secret, absolute or relative to the working directory
   * @param trust who besides administrators is trusted to have written the folder and its files;
   *   {@link KeyFileTrust.administratorsOnly} for no one
   * @param ring supplies the key each file's value names; owned by the caller - the cache never closes keys
   * @param formatProvider parses each file's formatted value - the same format the values were written in
   * @param logger receives a debug entry per loaded name while sensitive logging is enabled, and an
   *   error entry per failed load
   * @throws InvalidArgumentError folderPath is empty
   * @throws TypeError folderPath isn't a string, trust isn't a KeyFileTrust, or ring or formatProvider is missing
   * @throws KeyFileError 'ENOENT' folderPath doesn't name an existing folder
   */
  constructor(folderPath: string, trust: KeyFileTrust, ring: KeyRing, formatProvider: EncryptedFormatProvider, logger?: Logger) {
    if (typeof folderPath !== 'string') throw new TypeError('folderPath must be a string.');
    if (folderPath === '') throw new InvalidArgumentError('A secrets folder path is required.');
    if (!(trust instanceof KeyFileTrust)) throw new TypeError('trust must be a KeyFileTrust.');
    if (ring === undefined || ring === null) throw new TypeError('ring must not be undefined.');
    if (formatProvider === undefined || formatProvider === null) throw new TypeError('formatProvider must not be undefined.');

    this.folderPath = resolve(folderPath);
    if (statSync(this.folderPath, { throwIfNoEntry: false })?.isDirectory() !== true) {
      throw new KeyFileError('ENOENT', this.folderPath, `The secrets folder '${this.folderPath}' doesn't exist.`);
    }

    this.#trust = trust;
    this.#ring = ring;
    this.#formatProvider = formatProvider;
    this.#logger = logger;
  }

  /**
   * Whether `name` can be a secret's file name: 1-{@link MAX_NAME_LENGTH} ASCII letters, digits, '-',
   * '_' and '.', not starting with '.' (hidden, or '..'), not ending with '.' (Windows drops it, so
   * "key." would be the file "key"), and not a Windows device name - CON, PRN, AUX, NUL, COM1-COM9
   * or LPT1-LPT9, in any case, with or without an extension - which Windows opens as the device.
   */
  static isValidName(name: string | undefined | null): boolean {
    return typeof name === 'string' && name.length > 0 && name.length <= MAX_NAME_LENGTH && name[0] !== '.' && !name.endsWith('.')
      && /^[A-Za-z0-9._-]+$/.test(name) && !DEVICE_NAME.test(name);
  }

  /**
   * Decrypts `name`'s value into `result`, resolving to the bytes written, or 0 if there is no such file.
   * @throws TypeError (rejecting) name isn't a string
   * @throws AuthenticationFailedError (rejecting) the file's value wasn't encrypted for this name, or was altered
   * @throws KeyFileError (rejecting) the file's location isn't trusted, this account may not read it, or it is too long
   * @throws KeyNotFoundError (rejecting) the value's key version is no longer in the ring
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
   * An upper bound on how many bytes decrypt writes for `name`, or undefined if there is no such file.
   * @throws TypeError (rejecting) name isn't a string
   * @throws AuthenticationFailedError, KeyFileError, KeyNotFoundError (rejecting) as decrypt, when the file is loaded
   */
  async maxDecryptedLength(name: string, signal?: AbortSignal): Promise<number | undefined> {
    return (await this.#value(name, signal))?.value.length;
  }

  #decryptValue(name: string, value: KeyTrackingValue, result: Uint8Array): number {
    return this.#ring.get(value.keyVersion).decrypt(value.value, result, configurationAad(name));
  }

  // The cached value for name, loading it from its file on a miss; undefined if name can't be a
  // file name or there is no value. Concurrent misses may each load the file; the first stored is kept.
  async #value(name: string, signal: AbortSignal | undefined): Promise<KeyTrackingValue | undefined> {
    if (typeof name !== 'string') throw new TypeError('name must be a string.');
    const cached = this.#values.get(name);
    if (cached !== undefined) return cached;

    signal?.throwIfAborted();
    if (!FilePerSecretCache.isValidName(name)) return undefined;

    const telemetry = HkdfGuardTelemetry.cache;
    return telemetry.withSpan(SpanNames.cache.populate, async (span) => {
      if (telemetry.enableSensitiveLogging) {
        telemetry.logSensitiveOperation(span, SpanNames.cache.populate, { [AttributeNames.name]: name });
        HkdfGuardLog.sensitiveOperationLogged(this.#logger, SpanNames.cache.populate, name);
      }

      try {
        const encrypted = await this.#read(name, signal);
        if (encrypted === undefined) {
          recordOperation(Results.notFound);
          return undefined;
        }

        const value = this.#formatProvider.parse(encrypted);
        this.#authenticate(name, value);
        recordOperation(Results.success);
        const stored = this.#values.get(name);
        if (stored !== undefined) return stored;
        this.#values.set(name, value);
        return value;
      } catch (error) {
        HkdfGuardLog.operationFailed(this.#logger, SpanNames.cache.populate, error);
        recordOperation(Results.error);
        throw error;
      }
    });
  }

  // Decrypts value once into a buffer that is zeroed at once, so only a value that authenticates
  // under name - and a key version the ring holds - is ever cached.
  #authenticate(name: string, value: KeyTrackingValue): void {
    // AEAD ciphertext is always at least as long as the plaintext it encloses.
    const plaintext = new Uint8Array(value.value.length);
    try {
      this.#decryptValue(name, value, plaintext);
    } finally {
      wipe(plaintext);
    }
  }

  // The secret's formatted value from its trusted file, trimmed; undefined if the file or folder
  // doesn't exist, or the file is empty.
  async #read(name: string, signal: AbortSignal | undefined): Promise<string | undefined> {
    let contents: Uint8Array;
    try {
      contents = await readTrustedFile(join(this.folderPath, name), this.#trust, MAX_FILE_LENGTH, signal);
    } catch (error) {
      if (error instanceof KeyFileError && error.code === 'ENOENT') return undefined;
      throw error;
    }

    const encrypted = decoder.decode(contents).trim();
    return encrypted.length === 0 ? undefined : encrypted;
  }
}

function recordOperation(result: string): void {
  CacheMetrics.operations.add(1, { [AttributeNames.operationName]: SpanNames.cache.populate, [AttributeNames.result]: result });
}

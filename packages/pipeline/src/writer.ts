import { isUtf8 } from 'node:buffer';
import { mkdir, writeFile } from 'node:fs/promises';
import { EOL } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import type { Writable } from 'node:stream';
import {
  ClosedError, HkdfGuardError, InvalidArgumentError, wipe,
  type PipelineDataProtector, type SecretPipelineWriter as SecretPipelineWriterContract,
} from '@runsecure/hkdfguard-abstractions';
import { isWritable, JsonReader, JsonToken, MalformedJsonError, writeChunks } from '@runsecure/hkdfguard-abstractions/internal';
import { FilePerSecretCache, InvalidSecretDataError } from '@runsecure/hkdfguard-cache';
import { SecretsNotFoundError } from './errors.js';
import { tarArchive } from './tar.js';

/** One secret name a {@link SecretPipelineWriter} pulls: what to read, and the file it is written as. */
export interface SecretRequest {
  /** The name as it was given, key and all. */
  readonly secretName: string;
  /** The key to read; undefined for the secret's whole value. */
  readonly key: string | undefined;
  /** The file it is written as, and the name its value is bound to. */
  readonly fileName: string;
}

const KEY_SEPARATOR = '#';
const FILE_NAME_SEPARATOR = '__';

// rw-r--r--: what each file in a tar archive is unpacked as.
const SECRET_FILE_MODE = 0o644;

const encoder = new TextEncoder();

/**
 * The shared plumbing of a {@link SecretPipelineWriterContract SecretPipelineWriter} over one secret
 * store - the Node port of .NET's HkdfGuard.Pipeline.SecretPipelineWriter: the store's writer supplies
 * only {@link readSecret}, which reads one secret and hands its values to {@link protect},
 * {@link protectSecret} or {@link protectKeys}. Everything else - naming, grouping, encrypting,
 * keeping and writing - as one file per secret, one JSON file of them all, or either to a stream
 * as a tar archive or the JSON - is here. No key ring is involved: the protector's key is the only one.
 *
 * A secret name is the store's name for a secret, optionally followed by {@link KEY_SEPARATOR} and a
 * key it holds: "prod/app#password" is the password key of the secret prod/app. A name without one
 * reads the store's default key, if it has one, or else the secret's whole value. The secrets named
 * are grouped by the store's name, so each is read once however many of its keys are listed.
 *
 * A secret's file name is its name with every '/' and '#' replaced by {@link FILE_NAME_SEPARATOR}
 * (see {@link getFileName}): "prod/app#password" is written as prod__app__password. A name whose
 * file name FilePerSecretCache couldn't read ({@link FilePerSecretCache.isValidName}) is refused, as
 * are two names whose file names differ only in case - Windows and macOS find files ignoring case.
 * Each value is encrypted bound to its file name - `protector.encrypt(value, fileName)` - which is
 * the name FilePerSecretCache decrypts it under, so a renamed file fails authentication.
 *
 * A secret's plaintext never becomes a string: {@link protect} takes it as UTF-8 bytes, in a buffer
 * the store's writer zeroes, checks they are UTF-8 without decoding them (a value that isn't is
 * refused: the protector encrypts text), and hands them to the protector, which encrypts a copy it
 * zeroes. The protector is the caller's and is never closed, so its key can be handed to the wrap
 * process once the files are written.
 *
 * One pull at a time: a pull started while another runs is refused. {@link close} releases the
 * store's connection; a pull after it is refused, though what was kept can still be written.
 */
export abstract class SecretPipelineWriter implements SecretPipelineWriterContract {
  /** Separates a secret's name from the key it reads: "prod/app#password". */
  static readonly KEY_SEPARATOR = KEY_SEPARATOR;

  /** Replaces each '/' and '#' of a secret name in its file name. */
  static readonly FILE_NAME_SEPARATOR = FILE_NAME_SEPARATOR;

  readonly #protector: PipelineDataProtector;

  // The secrets to pull, by the store's name: each is read once, for its whole value and its keys.
  readonly #requests = new Map<string, SecretRequest[]>();

  // Each secret's encrypted, formatted value, by file name. File names that differ only in case are
  // refused when the writer is created, so matching them exactly is matching them as a filesystem
  // that ignores case does.
  readonly #protectedSecrets = new Map<string, string>();
  #pulled = false;
  #pulling = false;
  #closed = false;

  /**
   * @param protector encrypts every value read. Owned by the caller: the writer never closes it.
   * @param secretNames the secrets to pull, each a name with the key to read after '#' if any.
   *   Copied: a later change to the array isn't seen.
   * @param isValidSecretName whether the store can hold a secret by a name, before any '#'
   * @param defaultKey the key a name without one reads, for a store whose secrets are all sets of
   *   keys (HashiCorp Vault's KV); undefined when such a name reads the secret's whole value
   * @throws TypeError protector, secretNames or isValidSecretName is missing, or secretNames isn't an array
   * @throws InvalidArgumentError secretNames is empty, or holds something that isn't a string, a name
   *   the store can't hold (with a key), one whose file name isn't one FilePerSecretCache can read,
   *   or two with the same file name, in any case; or defaultKey is empty or holds '#'
   */
  protected constructor(
    protector: PipelineDataProtector, secretNames: readonly string[], isValidSecretName: (name: string) => boolean, defaultKey?: string,
  ) {
    if (protector === undefined || protector === null) throw new TypeError('protector must not be undefined.');
    if (!Array.isArray(secretNames)) throw new TypeError('secretNames must be an array of secret names.');
    if (typeof isValidSecretName !== 'function') throw new TypeError('isValidSecretName must be a function.');
    if (defaultKey !== undefined && (typeof defaultKey !== 'string' || defaultKey.length === 0 || defaultKey.includes(KEY_SEPARATOR))) {
      throw new InvalidArgumentError(`The default key '${String(defaultKey)}' isn't a key.`);
    }

    this.#protector = protector;
    this.#addRequests(secretNames, isValidSecretName, defaultKey);
  }

  /** Every secret pulled, by file name: its value encrypted and formatted, as its file will hold it. */
  get protectedSecrets(): ReadonlyMap<string, string> {
    return this.#protectedSecrets;
  }

  /**
   * The file a secret name is written as: the name with every '/' and '#' replaced by
   * {@link FILE_NAME_SEPARATOR} - "prod/app#password" is prod__app__password - and the name its value
   * is bound to, so the one to look it up by in FilePerSecretCache.
   * @throws TypeError secretName isn't a string
   */
  static getFileName(secretName: string): string {
    if (typeof secretName !== 'string') throw new TypeError('secretName must be a string.');
    return secretName.replaceAll('/', FILE_NAME_SEPARATOR).replaceAll(KEY_SEPARATOR, FILE_NAME_SEPARATOR);
  }

  /**
   * Reads every secret named in the constructor from the store and encrypts each value, keeping it
   * in {@link protectedSecrets} - replacing whatever an earlier pull kept. All of them are read
   * before any missing one is reported.
   * @param signal cancels the reads: passed to the store's client
   * @throws SecretsNotFoundError (rejecting) a secret doesn't exist, or has no such key, or its value
   *   there is empty or isn't a value; every other secret is kept
   * @throws HkdfGuardError (rejecting; ERR_HKDFGUARD_INVALID_STATE) another pull is running
   * @throws ClosedError (rejecting) the writer has been closed
   *
   * Any other failure {@link readSecret} rejects with propagates, and nothing is kept.
   */
  async pullSecrets(signal?: AbortSignal): Promise<void> {
    if (this.#closed) throw new ClosedError('This secret pipeline writer has been closed.');
    if (this.#pulling) throw new HkdfGuardError('ERR_HKDFGUARD_INVALID_STATE', 'A pull is already running: wait for it to finish.');
    this.#protectedSecrets.clear();
    this.#pulled = false;
    this.#pulling = true;
    try {
      const pulled = new Map<string, string>();
      for (const [name, requests] of this.#requests) {
        signal?.throwIfAborted();
        const values = new Map<string, string>();
        await this.readSecret(name, requests, values, signal);
        for (const request of requests) {
          const value = values.get(request.fileName);
          if (value !== undefined) pulled.set(request.fileName, value);
        }
      }

      for (const [fileName, value] of pulled) this.#protectedSecrets.set(fileName, value);
      this.#pulled = true;

      const missing = [...this.#requests.values()].flat().filter((r) => !pulled.has(r.fileName)).map((r) => r.secretName);
      if (missing.length > 0) throw new SecretsNotFoundError(missing);
    } finally {
      this.#pulling = false;
    }
  }

  /**
   * Writes every secret in {@link protectedSecrets} as a file in `folderPath`, creating the folder if
   * it doesn't exist: the file named for it, holding its encrypted, formatted value as UTF-8 (no
   * BOM). A file already there by that name is replaced; any other file is left as it is.
   *
   * Only encrypted values are written, but FilePerSecretCache refuses a folder or file anyone but
   * administrators and the principals it trusts can modify: write them where the deployment can set
   * that, or set it once they're written.
   * @param folderPath the folder to write to, absolute or relative to the working directory
   * @throws TypeError (rejecting) folderPath isn't a string
   * @throws InvalidArgumentError (rejecting) folderPath is empty
   * @throws HkdfGuardError (rejecting; ERR_HKDFGUARD_INVALID_STATE) no pull has completed
   */
  async writeProtectedSecretFiles(folderPath: string): Promise<void> {
    if (typeof folderPath !== 'string') throw new TypeError('folderPath must be a string.');
    if (folderPath.length === 0) throw new InvalidArgumentError('folderPath must not be empty.');
    this.#requirePulled();

    const folder = resolve(folderPath);
    await mkdir(folder, { recursive: true });
    for (const [fileName, value] of this.#protectedSecrets) await writeFile(join(folder, fileName), value, 'utf8');
  }

  /**
   * Writes every secret in {@link protectedSecrets} to one JSON file at `filePath`, creating its
   * folder if it doesn't exist: a single object with a member per secret, its file name mapped to
   * its encrypted, formatted value, in file-name order (ordinal), indented by two spaces with the
   * platform's line ending and none after the closing brace, as UTF-8 without a BOM - byte for byte
   * what .NET's WriteJsonSecrets writes on the same platform. A file already there is replaced.
   * Each value is bound to its member's name - decrypt(value, name) - as it is to its file name in
   * {@link writeProtectedSecretFiles}; JsonSecretsFileReadOnlyCache
   * (@runsecure/hkdfguard-cache-jsonsecretsfile) reads it.
   * @param filePath the file to write, absolute or relative to the working directory
   * @throws TypeError (rejecting) filePath isn't a string
   * @throws InvalidArgumentError (rejecting) filePath is empty
   * @throws HkdfGuardError (rejecting; ERR_HKDFGUARD_INVALID_STATE) no pull has completed
   */
  async writeJsonSecrets(filePath: string): Promise<void> {
    if (typeof filePath !== 'string') throw new TypeError('filePath must be a string.');
    if (filePath.length === 0) throw new InvalidArgumentError('filePath must not be empty.');
    this.#requirePulled();

    const path = resolve(filePath);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, this.#jsonSecrets());
  }

  /**
   * Writes every secret in {@link protectedSecrets} to `destination` as a tar archive of the files
   * {@link writeProtectedSecretFiles} would write - for a remote tar to unpack, e.g. the stdin of
   * `ssh -T host sudo -n tar -x --no-same-owner -f - -C folder`. The archive is PAX, which GNU tar
   * and bsdtar (macOS, and Windows' tar.exe) both read: one regular file per secret, in file-name
   * order (ordinal), mode 0644 - the values are encrypted, and only who may write them matters to
   * FilePerSecretCache; with --no-same-owner they belong to whoever unpacks them - modified now.
   * Each file is handed to the stream once it has accepted the one before, so a slow reader holds
   * back the writes rather than the archive piling up in memory. Resolves once the stream has
   * accepted the end of the archive; `destination` is left open: end it afterwards.
   * @param destination where to write the archive: a process's standard input
   * @param signal cancels the write; the destination then holds part of an archive - destroy it
   * @throws TypeError (rejecting) destination isn't a Writable
   * @throws HkdfGuardError (rejecting; ERR_HKDFGUARD_INVALID_STATE) no pull has completed, or
   *   destination has already ended or been destroyed
   *
   * A failed write rejects with the stream's error.
   */
  async writeProtectedSecretFilesTo(destination: Writable, signal?: AbortSignal): Promise<void> {
    if (!isWritable(destination)) throw new TypeError('destination must be a Writable stream.');
    this.#requirePulled();

    const mtime = Math.floor(Date.now() / 1000);
    const files = this.#sortedSecrets().map(([name, value]) => ({ name, data: encoder.encode(value), mode: SECRET_FILE_MODE, mtime }));
    await writeChunks(destination, tarArchive(files), signal);
  }

  /**
   * Writes every secret in {@link protectedSecrets} to `destination` as the JSON object
   * {@link writeJsonSecrets} would write, byte for byte - for a remote command to store, e.g. the
   * stdin of `ssh -T host sudo -n tee /etc/app/secrets.json`. Resolves once the stream has accepted
   * it; `destination` is left open: end it afterwards.
   * @param destination where to write the JSON: a process's standard input
   * @param signal cancels the write
   * @throws TypeError (rejecting) destination isn't a Writable
   * @throws HkdfGuardError (rejecting; ERR_HKDFGUARD_INVALID_STATE) no pull has completed, or
   *   destination has already ended or been destroyed
   *
   * A failed write rejects with the stream's error.
   */
  async writeJsonSecretsTo(destination: Writable, signal?: AbortSignal): Promise<void> {
    if (!isWritable(destination)) throw new TypeError('destination must be a Writable stream.');
    this.#requirePulled();

    await writeChunks(destination, [this.#jsonSecrets()], signal);
  }

  // The secrets object as .NET's Utf8JsonWriter writes it - indented by two spaces, the platform's
  // line ending (Environment.NewLine), relaxed escaping - in UTF-8. The values are formatted
  // ciphertext and the names [A-Za-z0-9._-], so neither needs escaping; JSON.stringify escapes
  // anything else a format provider might write as valid JSON.
  #jsonSecrets(): Uint8Array {
    const secrets = this.#sortedSecrets();
    if (secrets.length === 0) return encoder.encode('{}');
    const members = secrets.map(([name, value]) => `  ${JSON.stringify(name)}: ${JSON.stringify(value)}`);
    return encoder.encode(`{${EOL}${members.join(`,${EOL}`)}${EOL}}`);
  }

  // Every secret kept, in ordinal file-name order.
  #sortedSecrets(): [string, string][] {
    return [...this.#protectedSecrets].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  }

  #requirePulled(): void {
    if (!this.#pulled) throw new HkdfGuardError('ERR_HKDFGUARD_INVALID_STATE', 'No secrets have been pulled: call pullSecrets first.');
  }

  /** Releases the writer's connection to the store ({@link closeStore}). Safe to call more than once. */
  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    await this.closeStore();
  }

  /** Releases the store's connection, once, when the writer is closed. Nothing by default. */
  protected closeStore(): Promise<void> | void {}

  /**
   * Reads the one secret named `name` and encrypts the value each of `requests` asks for into
   * `values`, by its file name - with {@link protect}, {@link protectSecret} or {@link protectKeys} -
   * or resolves without doing so if it doesn't exist. Any other failure should reject. A request left
   * out of values is reported missing.
   * @param name the store's name for the secret, before any '#'
   * @param requests what to read from it: its whole value, a key, or both
   * @param values receives each value encrypted, by file name
   * @param signal cancels the read
   */
  protected abstract readSecret(name: string, requests: readonly SecretRequest[], values: Map<string, string>, signal?: AbortSignal): Promise<void>;

  /**
   * Encrypts a secret's whole value into `values` for each of `requests` without a key, and, when it
   * is a JSON object, the value of each requested key it holds (see {@link protectKeys}), by file
   * name. An empty secret holds nothing. `secret` is the caller's to zero.
   * @throws InvalidSecretDataError the secret isn't UTF-8 text, or is a JSON object holding a key more than once
   */
  protected protectSecret(secret: Uint8Array, requests: readonly SecretRequest[], values: Map<string, string>): void {
    if (secret.length === 0) return;

    for (const request of requests) {
      if (request.key === undefined) values.set(request.fileName, this.protect(secret, request.fileName));
    }

    if (requests.some((r) => r.key !== undefined)) this.protectKeys(secret, requests, values);
  }

  /**
   * Encrypts `plaintext` - UTF-8 bytes - bound to `fileName`, once it is known to be UTF-8; it is
   * checked byte by byte, never decoded into a string. The protector encrypts a copy it zeroes;
   * `plaintext` is the caller's to zero.
   * @returns the encrypted, formatted value
   * @throws InvalidSecretDataError plaintext isn't UTF-8 text, which the protector can't encrypt as it is
   */
  protected protect(plaintext: Uint8Array, fileName: string): string {
    // Decoding would replace every invalid sequence, so a binary value would be written altered.
    if (!isUtf8(plaintext)) throw new InvalidSecretDataError("The secret isn't UTF-8 text: the pipeline protector encrypts text.");
    return this.#protector.encrypt(plaintext, fileName);
  }

  /**
   * When `json` is exactly one JSON object, encrypts the value of each key of `requests` it holds into
   * `values`, as {@link protectKeysAt} does; anything else - plain text that merely starts like JSON
   * included - holds no keys.
   * @throws InvalidSecretDataError the object holds a key more than once
   */
  protected protectKeys(json: Uint8Array, requests: readonly SecretRequest[], values: Map<string, string>): void {
    if (!isObject(json)) return;

    const reader = new JsonReader(json);
    reader.read();
    this.protectKeysAt(reader, requests, values);
  }

  /**
   * Encrypts the value of each key of `requests` that the object `reader` is at the start of holds
   * into `values`, by file name, leaving `reader` at its end: a string as its text, a number, true or
   * false as its JSON text. A null, object, array or empty value is left out. Every value is
   * unescaped into a buffer of its own, and zeroed once encrypted.
   * @throws InvalidSecretDataError the object holds a key more than once
   * @throws MalformedJsonError the JSON is malformed, for the caller to report
   */
  protected protectKeysAt(reader: JsonReader, requests: readonly SecretRequest[], values: Map<string, string>): void {
    const seen = new Set<string>();
    while (SecretPipelineWriter.nextProperty(reader)) {
      const key = reader.getString();
      // Not named: a key is part of a secret name, which is never logged.
      if (seen.has(key)) throw new InvalidSecretDataError('The secret holds a key more than once.');
      seen.add(key);

      const request = find(reader, requests);
      reader.read();
      const token = reader.token();
      if (request !== undefined && (token === JsonToken.String || token === JsonToken.Number || token === JsonToken.True || token === JsonToken.False)) {
        const value = this.protectValue(reader, request.fileName);
        if (value !== undefined) values.set(request.fileName, value);
      } else {
        reader.skip();
      }
    }
  }

  /**
   * Reads the first token of a whole JSON document and says whether it starts an object; an empty or
   * all-whitespace document has none.
   * @throws MalformedJsonError the document doesn't start with a JSON token
   */
  protected static startsObject(reader: JsonReader): boolean {
    return reader.read() && reader.token() === JsonToken.StartObject;
  }

  /**
   * Moves `reader` to the next token and says whether it is a property name - false at the end of
   * the object `reader` is in. Inside an object the reader can't run out of data without throwing
   * MalformedJsonError, so there is nothing else to check.
   */
  protected static nextProperty(reader: JsonReader): boolean {
    reader.read();
    return reader.token() === JsonToken.PropertyName;
  }

  /**
   * Unescapes the string `reader` is at into a buffer of its own (a number, true or false is copied
   * as its JSON text) and encrypts it bound to `fileName`, zeroing it.
   * @returns the encrypted, formatted value; undefined if it is empty
   * @throws InvalidSecretDataError the value isn't UTF-8 text
   */
  protected protectValue(reader: JsonReader, fileName: string): string | undefined {
    // Unescaped, a string is never longer than it is escaped.
    const bytes = new Uint8Array(reader.valueLength);
    try {
      const length = reader.token() === JsonToken.String ? reader.copyString(bytes) : reader.copyRaw(bytes);
      return length === 0 ? undefined : this.protect(bytes.subarray(0, length), fileName);
    } finally {
      wipe(bytes);
    }
  }

  #addRequests(secretNames: readonly string[], isValidSecretName: (name: string) => boolean, defaultKey: string | undefined): void {
    if (secretNames.length === 0) throw new InvalidArgumentError('No secrets are named.');

    const fileNames = new Set<string>();
    for (const secretName of secretNames) {
      if (typeof secretName !== 'string') throw new InvalidArgumentError('A secret name is undefined, or isn\'t a string.');

      const separator = secretName.indexOf(KEY_SEPARATOR);
      const name = separator < 0 ? secretName : secretName.slice(0, separator);
      const key = separator < 0 ? defaultKey : secretName.slice(separator + 1);
      const fileName = SecretPipelineWriter.getFileName(secretName);
      if (name.length === 0 || !isValidSecretName(name) || key === '') {
        throw new InvalidArgumentError(`'${secretName}' isn't a secret name this store can hold, with a key after '${KEY_SEPARATOR}' if any.`);
      }
      if (!FilePerSecretCache.isValidName(fileName)) {
        throw new InvalidArgumentError(`'${secretName}' can't be written as a file: its file name '${fileName}' must be `
          + `1-${FilePerSecretCache.MAX_NAME_LENGTH} ASCII letters, digits, '-', '_' and '.', not starting with '.'.`);
      }
      // ASCII only, as FilePerSecretCache.isValidName just said, so lower-casing it is ignoring case.
      const folded = fileName.toLowerCase();
      if (fileNames.has(folded)) throw new InvalidArgumentError(`'${secretName}' would be written as '${fileName}', as another secret named is.`);
      fileNames.add(folded);

      let requests = this.#requests.get(name);
      if (requests === undefined) this.#requests.set(name, requests = []);
      requests.push(Object.freeze({ secretName, key, fileName }));
    }
  }
}

// One JSON object and nothing after it but whitespace.
function isObject(json: Uint8Array): boolean {
  const reader = new JsonReader(json);
  try {
    if (!reader.read() || reader.token() !== JsonToken.StartObject) return false;
    reader.skip();
    return !reader.read();
  } catch (error) {
    if (error instanceof MalformedJsonError) return false;
    throw error;
  }
}

// The request for the key reader is at the name of, if any.
function find(reader: JsonReader, requests: readonly SecretRequest[]): SecretRequest | undefined {
  for (const request of requests) {
    if (request.key !== undefined && reader.valueTextEquals(request.key)) return request;
  }
  return undefined;
}

import {
  CACHE_AAD_PREFIX, ClosedError, HkdfGuardError, InvalidArgumentError, isWellFormed, KeyNotFoundError, NoCurrentKeyError, wipe,
  type DataEncryptionKey, type DataProtector, type EncryptedFormatProvider, type KeyRing as KeyRingContract,
} from '@runsecure/hkdfguard-abstractions';
import { AttributeNames, HkdfGuardLog, HkdfGuardTelemetry, recordException, SpanNames, type Logger } from '@runsecure/hkdfguard-diagnostics';
import { DefaultFormatProvider } from './format.js';

/** An add for a version that is already registered. */
export class DuplicateVersionError extends HkdfGuardError {
  constructor(message: string) {
    super('ERR_HKDFGUARD_DUPLICATE_VERSION', message);
  }
}

const INT32_MIN = -(2 ** 31);
const INT32_MAX = 2 ** 31 - 1;
const encoder = new TextEncoder();

/** Anything a ring owns that can be closed - a DataEncryptionKey closes its provider. */
interface Closable {
  close(): unknown;
}

function isClosable(value: unknown): value is Closable {
  return typeof (value as Closable | undefined)?.close === 'function';
}

/**
 * Tracks data encryption keys by version. The highest registered version is the current one,
 * automatically - there is no separate call to designate it, so it can never fall out of sync with
 * what is registered. Versions are 32-bit integers, the range every port shares.
 *
 * The ring owns every key added to it: close() closes each one that can be closed.
 *
 * A ring built with ephemeral keys also rotates its encryption key on a schedule: every interval it
 * creates a fresh ephemeral key and adds it at currentVersion + 1, so every later encrypt uses it. A
 * superseded ephemeral key stays registered for the retention, so values encrypted under it still
 * decrypt that long; then a later rotation closes and removes it. Key-file keys are never retired.
 * A rotation supersedes whatever is current, so buildKeyRing refuses a rotating ring whose highest
 * version is a key file.
 */
export class KeyRing implements KeyRingContract {
  readonly #keys = new Map<number, DataEncryptionKey>();
  #current: number | undefined;
  #closed = false;
  /** @internal The scheduled rotation, when this ring rotates. */
  rotation: Rotation | undefined;

  /** @param formatProvider Formats what this ring's protectors produce; a DefaultFormatProvider when omitted. */
  constructor(readonly formatProvider: EncryptedFormatProvider = new DefaultFormatProvider()) {}

  /** The version new values are encrypted under - the highest registered. @throws NoCurrentKeyError */
  get currentVersion(): number {
    if (this.#current === undefined) throw new NoCurrentKeyError();
    return this.#current;
  }

  /** How often this ring adds a fresh ephemeral key, in milliseconds; undefined when it doesn't rotate. */
  get ephemeralKeyRotationIntervalMs(): number | undefined {
    return this.rotation?.intervalMs;
  }

  /**
   * Registers `key` for `version`; a version higher than every one registered becomes current. On
   * success the ring owns `key`; on failure ownership stays with the caller.
   *
   * @throws DuplicateVersionError, InvalidArgumentError (not a 32-bit integer), ClosedError
   */
  add(version: number, key: DataEncryptionKey): void {
    const telemetry = HkdfGuardTelemetry.dataProtection;
    telemetry.withSpan(SpanNames.dataProtection.keyRingAdd, (span) => {
      if (this.#closed) throw new ClosedError('This key ring has been closed.');
      if (!Number.isInteger(version) || version < INT32_MIN || version > INT32_MAX) {
        throw new InvalidArgumentError(`Key version ${version} is not a 32-bit integer.`, 'ERR_HKDFGUARD_VERSION_OUT_OF_RANGE');
      }
      if (this.#keys.has(version)) throw new DuplicateVersionError(`A key for version ${version} is already registered.`);
      this.#keys.set(version, key);
      const becameCurrent = this.#current === undefined || version > this.#current;
      if (becameCurrent) this.#current = version;
      telemetry.logSensitiveOperation(span, SpanNames.dataProtection.keyRingAdd, {
        [AttributeNames.keyVersion]: version, [AttributeNames.keyRingBecameCurrent]: becameCurrent,
      });
    });
  }

  /** The key registered for `version`. @throws KeyNotFoundError - never added, or retired. */
  get(version: number): DataEncryptionKey {
    const key = this.#keys.get(version);
    if (key !== undefined) return key;
    return HkdfGuardTelemetry.dataProtection.withSpan(SpanNames.dataProtection.keyRingGet, () => {
      throw new KeyNotFoundError(`No key is registered for version ${version}.`);
    });
  }

  /** The key registered for `version`, or undefined - the hot path, where a miss costs neither an error nor telemetry. */
  tryGet(version: number): DataEncryptionKey | undefined {
    return this.#keys.get(version);
  }

  /** The current version with its key. @throws NoCurrentKeyError */
  getCurrent(): { version: number; key: DataEncryptionKey } {
    if (this.#current === undefined) {
      return HkdfGuardTelemetry.dataProtection.withSpan(SpanNames.dataProtection.keyRingGetCurrent, () => {
        throw new NoCurrentKeyError();
      });
    }
    return { version: this.#current, key: this.get(this.#current) };
  }

  /**
   * A protector bound to this ring, using `name` (as UTF-8) as the AAD of every value it protects.
   * encrypt resolves the current version on every call, so it follows rotation; decrypt uses
   * whichever version the value names. configurationPurpose(key) names the protector encrypted
   * configuration reads a key with, which is how pipeline-protected values decrypt.
   *
   * @throws InvalidArgumentError the name is empty, not valid UTF-16, or starts with CACHE_AAD_PREFIX
   * (whose AADs belong to protected caches).
   */
  createProtector(name: string): DataProtector {
    if (name.length === 0) throw new InvalidArgumentError('A protector name is required - an empty purpose binds nothing.', 'ERR_HKDFGUARD_INVALID_PROTECTOR_NAME');
    if (!isWellFormed(name)) throw new InvalidArgumentError('The protector name is not valid UTF-16.', 'ERR_HKDFGUARD_INVALID_PROTECTOR_NAME');
    if (name.startsWith(CACHE_AAD_PREFIX)) {
      throw new InvalidArgumentError(`Protector names starting with '${CACHE_AAD_PREFIX}' are reserved for protected caches.`, 'ERR_HKDFGUARD_INVALID_PROTECTOR_NAME');
    }
    return new Protector(name, encoder.encode(name), this);
  }

  /**
   * Stops any rotation - awaiting one in flight - then closes every registered key. Keys stay
   * registered, so a later operation fails with the key's own ClosedError; a later add fails too.
   * Safe to call more than once.
   */
  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    await this.rotation?.stop();
    const failures: unknown[] = [];
    for (const key of this.#keys.values()) {
      if (isClosable(key)) {
        try {
          await key.close();
        } catch (error) {
          failures.push(error);
        }
      }
    }
    if (failures.length > 0) throw new AggregateError(failures, 'Closing some keys failed.');
  }

  /** @internal Retirement: removes `version` and closes its key, reporting whether one was removed. */
  async remove(version: number): Promise<boolean> {
    if (this.#closed) return false;
    const key = this.#keys.get(version);
    if (key === undefined) return false;
    this.#keys.delete(version);
    if (isClosable(key)) await key.close();
    return true;
  }
}

/** A key ring's scheduled ephemeral-key rotation. @internal */
export class Rotation {
  readonly ephemeral: Set<number>;
  /** Version -> when a rotation first saw it superseded (performance.now(): monotonic). */
  readonly supersededAt = new Map<number, number>();
  #timer: NodeJS.Timeout | undefined;
  #inFlight: Promise<boolean> | undefined;
  readonly #shutdown = new AbortController();

  constructor(
    private readonly ring: KeyRing,
    readonly intervalMs: number,
    readonly retentionMs: number,
    ephemeralVersions: readonly number[],
    private readonly createKey: (signal: AbortSignal) => Promise<DataEncryptionKey>,
    private readonly logger: Logger | undefined,
    manual = false,
  ) {
    this.ephemeral = new Set(ephemeralVersions);
    if (!manual) {
      this.#timer = setInterval(() => void this.rotate().catch(() => undefined), intervalMs).unref();
    }
  }

  /**
   * One rotation: create a fresh key and add it at currentVersion + 1, then retire every ephemeral
   * key whose retention has run out. A failure is recorded and logged, the current key stays in use,
   * and the next interval tries again. Resolves to whether a new key became current.
   */
  rotate(): Promise<boolean> {
    this.#inFlight ??= this.#rotateOnce().finally(() => { this.#inFlight = undefined; });
    return this.#inFlight;
  }

  async #rotateOnce(): Promise<boolean> {
    const span = HkdfGuardTelemetry.dataProtection.tracer.startSpan(SpanNames.dataProtection.keyRingRotateEphemeral);
    try {
      let current = 0;
      try {
        current = this.ring.currentVersion;
        if (current === INT32_MAX) {
          throw new InvalidArgumentError(`Version ${current} is current, so there is no higher version to rotate to; the current key stays in use.`, 'ERR_HKDFGUARD_VERSION_OUT_OF_RANGE');
        }
      } catch (error) {
        recordException(span, error);
        HkdfGuardLog.ephemeralKeyRotationFailed(this.logger, current, error);
        return false;
      }

      const next = current + 1;
      let key: DataEncryptionKey | undefined;
      try {
        key = await this.createKey(this.#shutdown.signal);
        this.ring.add(next, key);
      } catch (error) {
        // Not added, so not owned by the ring: release its revealed key here.
        if (isClosable(key)) await Promise.resolve(key.close()).catch(() => undefined);
        if (this.#shutdown.signal.aborted) return false;
        recordException(span, error);
        HkdfGuardLog.ephemeralKeyRotationFailed(this.logger, current, error);
        return false;
      }

      this.ephemeral.add(next);
      span.setAttribute(AttributeNames.keyVersion, next);
      HkdfGuardLog.ephemeralKeyRotated(this.logger, next);
      await this.retire(performance.now());
      return true;
    } finally {
      span.end();
    }
  }

  /**
   * Removes and closes every ephemeral key that stopped being current at least the retention ago. A
   * key is first seen as superseded by the rotation after the one that replaced it, so it is kept for
   * at least the retention. Key-file versions are never touched. `now` is a performance.now() reading.
   */
  async retire(now: number): Promise<void> {
    if (this.retentionMs <= 0) return;
    const current = this.ring.currentVersion;
    for (const version of this.ephemeral) {
      if (version !== current && !this.supersededAt.has(version)) this.supersededAt.set(version, now);
    }
    for (const [version, since] of [...this.supersededAt]) {
      if (version === current || now - since < this.retentionMs) continue;
      this.supersededAt.delete(version);
      this.ephemeral.delete(version);
      try {
        if (await this.ring.remove(version)) HkdfGuardLog.ephemeralKeyRetired(this.logger, version);
      } catch (error) {
        // Already out of the ring; a failure to release it must not stop the rotation.
        HkdfGuardLog.ephemeralKeyRetirementFailed(this.logger, version, error);
      }
    }
  }

  /** Stops the timer, cancelling and awaiting a rotation in flight. */
  async stop(): Promise<void> {
    clearInterval(this.#timer);
    this.#shutdown.abort();
    await this.#inFlight?.catch(() => undefined);
  }
}

/** The ring's DataProtector. Only createProtector makes one, so every instance is bound to a real ring. */
class Protector implements DataProtector {
  constructor(
    private readonly name: string,
    private readonly aad: Uint8Array,
    private readonly ring: KeyRing,
  ) {}

  /** Encrypts `plaintext` (a string as UTF-8) under the current key and formats the result. The caller's plaintext is not zeroed. */
  encrypt(plaintext: Uint8Array | string): string {
    const telemetry = HkdfGuardTelemetry.dataProtection;
    return telemetry.withSpan(SpanNames.dataProtection.protectorEncrypt, (span) => {
      telemetry.logSensitiveOperation(span, SpanNames.dataProtection.protectorEncrypt, {
        [AttributeNames.name]: this.name, [AttributeNames.plaintextLength]: plaintext.length,
      });
      const { version, key } = this.ring.getCurrent();
      // The key zeroes what it encrypts; the caller's plaintext is theirs to keep.
      const scratch = typeof plaintext === 'string' ? encoder.encode(plaintext) : Uint8Array.from(plaintext);
      try {
        return this.ring.formatProvider.format({ keyVersion: version, value: key.encrypt(scratch, this.aad) });
      } finally {
        wipe(scratch);
      }
    });
  }

  /** Decrypts `encrypted`, under whichever version it names, into `result`. Size `result` with maxDecryptedLength. */
  decrypt(encrypted: string, result: Uint8Array): number {
    const telemetry = HkdfGuardTelemetry.dataProtection;
    return telemetry.withSpan(SpanNames.dataProtection.protectorDecrypt, (span) => {
      telemetry.logSensitiveOperation(span, SpanNames.dataProtection.protectorDecrypt, {
        [AttributeNames.name]: this.name, [AttributeNames.encryptedLength]: encrypted.length,
      });
      const value = this.ring.formatProvider.parse(encrypted);
      return this.ring.get(value.keyVersion).decrypt(value.value, result, this.aad);
    });
  }

  maxDecryptedLength(encrypted: string): number {
    return this.ring.formatProvider.maxDecryptedLength(encrypted);
  }
}

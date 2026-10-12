import {
  AlreadyExistsError, cacheMatchKey, type KeyRing, type KeyTrackingValue, type ProtectedCache as ProtectedCacheContract,
  type ProtectedReadOnlyCache,
} from '@runsecure/hkdfguard-abstractions';
import { AttributeNames, CacheMetrics, HkdfGuardLog, HkdfGuardTelemetry, Results, SpanNames, type Logger } from '@runsecure/hkdfguard-diagnostics';
import { Store, type CacheSource } from './store.js';

/** Options for a {@link ProtectedCache}. */
export interface ProtectedCacheOptions {
  /** Receives each failed operation, and - while sensitive logging is enabled - each successful one. */
  logger?: Logger;
  /** Consulted when a name asked for isn't stored yet. */
  source?: CacheSource;
}

/**
 * The read/write protected cache: values are encrypted under the key ring's current key when
 * stored and bound to their names; names match ignoring ASCII case only. Nothing here holds
 * plaintext beyond a single call. The key ring is the caller's: the cache never closes keys.
 */
export class ProtectedCache implements ProtectedCacheContract {
  readonly #store: Store;
  readonly #logger: Logger | undefined;

  constructor(ring: KeyRing, options: ProtectedCacheOptions = {}) {
    this.#store = new Store(ring, options.source);
    this.#logger = options.logger;
  }

  /**
   * Encrypts `plaintext` and stores it under `name`; `plaintext` is zeroed whatever happens.
   * @throws AlreadyExistsError a value is already stored under `name`, in any ASCII case.
   * @throws EmptyValueError, InvalidCacheNameError
   */
  add(name: string, plaintext: Uint8Array): void {
    this.#write(SpanNames.cache.add, name, plaintext, (key, entry) => {
      if (this.#store.entries.has(key)) {
        throw new AlreadyExistsError(`An item with the name '${name}' has already been added.`);
      }
      this.#store.entries.set(key, entry);
    });
  }

  /** Encrypts `plaintext` and stores it under `name`, replacing any value there; `plaintext` is zeroed. */
  addOrUpdate(name: string, plaintext: Uint8Array): void {
    this.#write(SpanNames.cache.addOrUpdate, name, plaintext, (key, entry) => {
      this.#store.entries.set(key, entry);
    });
  }

  #write(operation: string, name: string, plaintext: Uint8Array, put: (key: string, entry: KeyTrackingValue) => void): void {
    const telemetry = HkdfGuardTelemetry.cache;
    let result: string = Results.success;
    try {
      telemetry.withSpan(operation, (span) => {
        if (telemetry.enableSensitiveLogging) {
          telemetry.logSensitiveOperation(span, operation, { [AttributeNames.name]: name, [AttributeNames.plaintextLength]: plaintext.length });
          HkdfGuardLog.sensitiveOperationLogged(this.#logger, operation, name);
        }
        put(cacheMatchKey(name), this.#store.encrypt(name, plaintext));
      });
    } catch (error) {
      result = Results.error;
      HkdfGuardLog.operationFailed(this.#logger, operation, error);
      throw error;
    } finally {
      CacheMetrics.operations.add(1, { [AttributeNames.operationName]: operation, [AttributeNames.result]: result });
    }
  }

  /** Decrypts the value stored under `name` into `result`, resolving to the bytes written, or 0 if none is stored. */
  decrypt(name: string, result: Uint8Array, signal?: AbortSignal): Promise<number> {
    return this.#store.decrypt(name, result, signal);
  }

  /** An upper bound on how many bytes decrypt writes for `name`, or undefined if nothing is stored. */
  maxDecryptedLength(name: string, signal?: AbortSignal): Promise<number | undefined> {
    return this.#store.maxDecryptedLength(name, signal);
  }

  /** @internal The entries, for tests that tamper with them. */
  get entriesForTesting(): Map<string, KeyTrackingValue> {
    return this.#store.entries;
  }
}

/**
 * A read-only protected cache filled from its {@link CacheSource}: each name is fetched the first
 * time it is asked for, encrypted, and served from the cache after that. The building block for
 * caches backed by an external secret store - the backend implements CacheSource, and encryption,
 * name binding and telemetry stay here.
 */
export class ReadOnlyProtectedCache implements ProtectedReadOnlyCache {
  readonly #store: Store;

  constructor(ring: KeyRing, source: CacheSource) {
    this.#store = new Store(ring, source);
  }

  decrypt(name: string, result: Uint8Array, signal?: AbortSignal): Promise<number> {
    return this.#store.decrypt(name, result, signal);
  }

  maxDecryptedLength(name: string, signal?: AbortSignal): Promise<number | undefined> {
    return this.#store.maxDecryptedLength(name, signal);
  }
}

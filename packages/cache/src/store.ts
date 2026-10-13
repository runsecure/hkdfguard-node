import {
  cacheAad, cacheMatchKey, HkdfGuardError, wipe, type KeyRing, type KeyTrackingValue,
} from '@runsecure/hkdfguard-abstractions';
import { AttributeNames, HkdfGuardTelemetry, SpanNames } from '@runsecure/hkdfguard-diagnostics';

/** An attempt to cache an empty value: decrypt reports a missing name as 0 bytes, so it would be indistinguishable from none. */
export class EmptyValueError extends HkdfGuardError {
  constructor() {
    super('ERR_HKDFGUARD_EMPTY_VALUE', 'An empty value cannot be cached: decrypt reports a missing name as 0 bytes.');
  }
}

/**
 * Supplies values a cache doesn't hold yet - a client for a remote secret store, say. On a miss the
 * cache calls fetch, encrypts what it returns under the requested name, stores it, and zeroes the
 * returned plaintext. A backend (HashiCorp Vault, Azure Key Vault, ...) implements only this.
 */
export interface CacheSource {
  /** The plaintext value for `name`, or undefined when the source has none. The cache takes ownership of the bytes and zeroes them. */
  fetch(name: string, signal?: AbortSignal): Promise<Uint8Array | undefined>;
}

/**
 * The plumbing every cache here shares: a key ring to encrypt and decrypt through, the encrypted
 * entries keyed by name, and an optional source consulted on a miss.
 *
 * Entries are keyed by the name's ASCII-upper-cased form - exactly the rule cacheAad applies - so
 * every spelling that reaches an entry also authenticates against it. Each is encrypted under the
 * ring's current key and records that version, so the cache follows rotation.
 *
 * An entry expires with its key: once the ring has retired the version it was encrypted under, the
 * entry is dropped and the name is a miss - fetched again from the source, if there is one, under
 * the current key. A version the ring never had (one above the current version) is not expired but
 * reported as KeyNotFoundError, since retirement only ever removes superseded versions.
 */
export class Store {
  readonly entries = new Map<string, KeyTrackingValue>();

  constructor(
    private readonly ring: KeyRing,
    private readonly source?: CacheSource,
  ) {}

  /** Encrypts `plaintext` bound to `name` under the current key; `plaintext` is zeroed whatever happens. */
  encrypt(name: string, plaintext: Uint8Array): KeyTrackingValue {
    try {
      if (plaintext.length === 0) throw new EmptyValueError();
      const aad = cacheAad(name);
      // Resolved on every call, so a value stored after a rotation uses the new key.
      const { version, key } = this.ring.getCurrent();
      return { keyVersion: version, value: key.encrypt(plaintext, aad) };
    } finally {
      wipe(plaintext); // normally the key's job; this covers a failure before it got that far
    }
  }

  /** The entry for `name`, fetching it from the source on a miss; undefined when neither has it. */
  async lookup(name: string, signal?: AbortSignal): Promise<KeyTrackingValue | undefined> {
    const key = cacheMatchKey(name);
    const cached = this.cached(key);
    if (cached !== undefined || this.source === undefined) return cached;

    signal?.throwIfAborted();
    const plaintext = await this.source.fetch(name, signal);
    if (plaintext === undefined) return undefined;
    const fresh = this.encrypt(name, plaintext);
    // Another caller may have stored this name while the fetch was in flight; theirs wins, so every
    // reader sees one value.
    const existing = this.cached(key);
    if (existing !== undefined) return existing;
    this.entries.set(key, fresh);
    return fresh;
  }

  /**
   * Decrypts `name`'s value into `result`, returning 0 if none is stored. The ciphertext is
   * authenticated against `name`'s AAD, so a value stored under another name fails with
   * AuthenticationFailedError.
   */
  decrypt(name: string, result: Uint8Array, signal?: AbortSignal): Promise<number> {
    const telemetry = HkdfGuardTelemetry.root;
    return telemetry.withSpan(SpanNames.cache.decrypt, async (span) => {
      telemetry.logSensitiveOperation(span, SpanNames.cache.decrypt, { [AttributeNames.name]: name });
      // A retirement can land while a fetch is awaited, so the entry's key is resolved after the
      // last await; an entry that expired in between is looked up once more (a fresh one is under
      // the current key, which is never retired).
      for (let attempt = 0; ; attempt++) {
        const entry = await this.lookup(name, signal);
        if (entry === undefined) return 0;
        if (attempt === 0 && this.#expire(cacheMatchKey(name), entry)) continue;
        return this.ring.get(entry.keyVersion).decrypt(entry.value, result, cacheAad(name));
      }
    });
  }

  /** The entry stored under match key `key`, or undefined - dropping it first if its key has been retired. */
  cached(key: string): KeyTrackingValue | undefined {
    const entry = this.entries.get(key);
    return entry === undefined || this.#expire(key, entry) ? undefined : entry;
  }

  /** Drops `entry` from `key` if the ring has retired its version, reporting whether it did. */
  #expire(key: string, entry: KeyTrackingValue): boolean {
    if (this.ring.tryGet(entry.keyVersion) !== undefined) return false;
    let current: number;
    try {
      current = this.ring.currentVersion;
    } catch {
      return false; // no key at all: let decrypt report it
    }
    if (entry.keyVersion >= current) return false; // never retired, so never registered: let decrypt report it
    if (this.entries.get(key) === entry) this.entries.delete(key);
    return true;
  }

  /** The stored ciphertext's length - an upper bound on the plaintext - or undefined when nothing is stored. */
  async maxDecryptedLength(name: string, signal?: AbortSignal): Promise<number | undefined> {
    return (await this.lookup(name, signal))?.value.length;
  }
}

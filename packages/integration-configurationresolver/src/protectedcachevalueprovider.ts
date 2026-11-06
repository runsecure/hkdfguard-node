import { wipe, type ProtectedReadOnlyCache } from '@runsecure/hkdfguard-abstractions';
import { StringValuesNotAllowedError } from './errors.js';
import type { KeyReader } from './reader.js';
import { ValueProviderBase, ValueStatus, type BytesResult, type ValueResult } from './valueproviders.js';

/** The settings of a {@link ProtectedCacheValueProvider} - .NET's init properties. */
export interface ProtectedCacheValueProviderOptions {
  /**
   * Whether tryGetValue may return a value as a string, which can't be zeroed. False by default, when
   * it rejects with StringValuesNotAllowedError instead.
   */
  allowStringValues?: boolean;
}

/**
 * A value provider over a {@link ProtectedReadOnlyCache}, so the items in a template -
 * "Password=${db-password}" - resolve from HkdfGuard's protected caches: ProtectedCache,
 * FilePerSecretCache, ProtectedCacheCollection, or a remote secret store's cache (HashiCorp Vault,
 * AWS Secrets Manager, Azure Key Vault, Google Secret Manager). A template's key is the cache's name
 * as it is, so a remote cache's "app-config#api-key" form works unchanged. The port of .NET's
 * ProtectedCacheValueProvider.
 *
 * Each value is decrypted straight into the resolver's destination when the cache's upper bound on
 * its length fits there, and otherwise into a buffer of its own that is zeroed once the value has
 * been copied out. It is never a string: {@link tryGetValue}, the one ValueProvider member that
 * returns one, rejects unless allowStringValues is set. The resolver itself never calls it.
 *
 * Every lookup is asynchronous, so a remote cache fetching a value it hasn't cached yet never blocks.
 * {@link prefetch} fetches every key a reader has read ahead of resolving, such as at startup.
 */
export class ProtectedCacheValueProvider extends ValueProviderBase {
  readonly #cache: ProtectedReadOnlyCache;

  /** Whether tryGetValue may return a value as a string. */
  readonly allowStringValues: boolean;

  /** @throws TypeError cache is undefined or null */
  constructor(cache: ProtectedReadOnlyCache, options: ProtectedCacheValueProviderOptions = {}) {
    super();
    if (cache === undefined || cache === null) throw new TypeError('cache must not be undefined.');
    this.#cache = cache;
    this.allowStringValues = options.allowStringValues ?? false;
  }

  /** The cache values are read from. */
  get cache(): ProtectedReadOnlyCache {
    return this.#cache;
  }

  /**
   * Fetches every key the reader has read, so a later resolve finds each in the cache. A key the cache
   * doesn't have is skipped; resolve reports it.
   * @param reader the reader the resolver was given, after it has read the template
   * @param signal cancels waiting for a fetch
   * @throws TypeError (rejecting) reader is undefined or null
   */
  async prefetch(reader: KeyReader, signal?: AbortSignal): Promise<void> {
    if (reader === undefined || reader === null) throw new TypeError('reader must not be undefined.');
    return this.prefetchKeys(reader.keys(), signal);
  }

  /**
   * Fetches each of `keys`, one at a time, so a later resolve finds each in the cache. A key the cache
   * doesn't have is skipped; resolve reports it.
   * @param keys the keys to fetch; a key listed twice is fetched once
   * @param signal cancels waiting for a fetch
   * @throws TypeError (rejecting) keys is undefined, null or a single string
   */
  async prefetchKeys(keys: Iterable<string>, signal?: AbortSignal): Promise<void> {
    if (keys === undefined || keys === null) throw new TypeError('keys must not be undefined.');
    if (typeof keys === 'string') throw new TypeError('keys must be several keys, not one string.');
    for (const key of new Set(keys)) {
      signal?.throwIfAborted();
      await this.#cache.maxDecryptedLength(key, signal);
    }
  }

  async tryGetBytes(key: string, destination: Uint8Array, signal?: AbortSignal): Promise<BytesResult> {
    if (typeof key !== 'string') throw new TypeError('key must be a string.');

    const maxLength = await this.#cache.maxDecryptedLength(key, signal);
    if (maxLength === undefined) return { status: ValueStatus.notFound, written: 0 };

    if (maxLength <= destination.length) {
      const written = await this.#cache.decrypt(key, destination, signal);
      // A cache reports a name it no longer holds as 0 bytes - a remote value that expired with its
      // key in between, say - and never holds an empty value.
      return written === 0 ? { status: ValueStatus.notFound, written: 0 } : { status: ValueStatus.found, written };
    }

    // The bound is above the room left, but the value itself may still fit.
    const plaintext = new Uint8Array(maxLength);
    try {
      const length = await this.#cache.decrypt(key, plaintext, signal);
      if (length === 0) return { status: ValueStatus.notFound, written: 0 };
      if (length > destination.length) return { status: ValueStatus.destinationTooSmall, written: 0 };

      destination.set(plaintext.subarray(0, length));
      return { status: ValueStatus.found, written: length };
    } finally {
      wipe(plaintext);
    }
  }

  /** @throws StringValuesNotAllowedError (rejecting) allowStringValues isn't set */
  override async tryGetValue(key: string, signal?: AbortSignal): Promise<ValueResult> {
    if (!this.allowStringValues) throw new StringValuesNotAllowedError();
    return super.tryGetValue(key, signal);
  }

  protected tryGetByteCount(key: string, signal?: AbortSignal): Promise<number | undefined> {
    return this.#cache.maxDecryptedLength(key, signal);
  }
}

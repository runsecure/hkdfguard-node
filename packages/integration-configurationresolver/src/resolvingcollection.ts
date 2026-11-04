import {
  cacheAad, InvalidArgumentError, wipe, type KeyRing, type KeyTrackingValue, type ProtectedReadOnlyCache,
} from '@runsecure/hkdfguard-abstractions';
import { AttributeNames, HkdfGuardTelemetry, SpanNames } from '@runsecure/hkdfguard-diagnostics';
import { DestinationTooSmallError, ResolvedValueTooLongError } from './errors.js';
import { ProtectedCacheValueProvider } from './protectedcachevalueprovider.js';
import { ConfigurationItemReader } from './reader.js';
import { ConfigurationItemResolver } from './resolver.js';
import { DefaultToken, type ConfigurationItemTokenBase } from './tokens.js';
import type { ValueProvider } from './valueproviders.js';

/** The settings of a {@link ResolvingProtectedCacheCollection} - .NET's init properties. */
export interface ResolvingProtectedCacheCollectionOptions {
  /** The token that marks an item; {@link DefaultToken} - `${`, `}` and the escape `$` - by default. */
  token?: ConfigurationItemTokenBase;

  /**
   * The most UTF-8 bytes a resolved value may hold; {@link ResolvingProtectedCacheCollection.DEFAULT_MAX_RESOLVED_LENGTH}
   * by default. A template that resolves to more rejects with ResolvedValueTooLongError on lookup.
   */
  maxResolvedLength?: number;
}

/** Where a name's value was found outside the resolved store. */
const Location = {
  /** No source holds the name, or its template resolved to nothing. */
  missing: 0,
  /** A source holds the name, and its value has no items: that source answers. */
  source: 1,
  /**
   * The name's template was resolved: look in the resolved store again. If an invalidate or clear kept
   * the result out of it, the lookup resolves it again.
   */
  resolved: 2,
} as const;
type Location = (typeof Location)[keyof typeof Location];

/**
 * ProtectedCacheCollection with templates: aggregates {@link ProtectedReadOnlyCache} sources, checked
 * in the order they were added, and resolves a value holding configuration items -
 * "Host=db;Password=${db-password}" - on its first lookup, from those same sources (then any value
 * providers added with {@link addValueProvider}). The resolved value is encrypted under the ring's
 * current key, bound to its name as every protected cache's entries are, and cached, so later lookups
 * only decrypt it. A value without items is answered by its source, unchanged. The port of .NET's
 * ResolvingProtectedCacheCollection.
 *
 * **Templates are trusted.** A template's items may name any value in any source, so every source
 * must be as trusted as the secrets it can reach: a template comes from whichever source holds its
 * name, and nothing marks one source as templates only. Items are resolved one level deep: an item
 * whose value is itself a template inserts that template's text unresolved. A value that is a template
 * but names a value no source or provider has rejects with ConfigurationKeyError on lookup, rather than
 * reporting the name missing. One that resolves to nothing is reported missing, as an empty value
 * can't be cached.
 *
 * **Resolved values are kept until invalidated.** When a value a template uses changes - a
 * ProtectedCache.addOrUpdate, a rotated remote secret - call {@link invalidate} for the template's
 * name, or {@link clear}; the next lookup resolves it again. A resolution already under way when
 * either is called doesn't cache its result. Which source holds a value without items is remembered
 * too, and forgotten the same way. Add every source and provider before the first lookup. A resolved
 * value expires with its key, as every protected cache's entries do: once the ring retires the
 * version it was encrypted under, the next lookup resolves it again under the current key.
 *
 * A source that throws fails the lookup, as in ProtectedCacheCollection, and the same advice holds:
 * add local sources before remote ones. Every lookup - of the name, and of each value its template
 * names - goes through the sources' asynchronous members, so a remote source never blocks.
 */
export class ResolvingProtectedCacheCollection implements ProtectedReadOnlyCache {
  /** The default maxResolvedLength: 1 MiB. */
  static readonly DEFAULT_MAX_RESOLVED_LENGTH = 1 << 20;

  readonly #sources: ProtectedReadOnlyCache[] = [];
  readonly #valueProviders: ValueProvider[] = [];
  readonly #resolved: ResolvedStore;
  readonly #plain = new Map<string, ProtectedReadOnlyCache>();
  #generation = 0;

  /** The token that marks an item. */
  readonly token: ConfigurationItemTokenBase;

  /** The most UTF-8 bytes a resolved value may hold. */
  readonly maxResolvedLength: number;

  /**
   * @param keyRing encrypts each resolved value under its current key, and decrypts it under the
   *   version it recorded; owned by the caller
   * @throws TypeError keyRing is undefined or null
   * @throws InvalidArgumentError maxResolvedLength isn't an integer of at least 1
   */
  constructor(keyRing: KeyRing, options: ResolvingProtectedCacheCollectionOptions = {}) {
    if (keyRing === undefined || keyRing === null) throw new TypeError('keyRing must not be undefined.');
    const maxResolvedLength = options.maxResolvedLength ?? ResolvingProtectedCacheCollection.DEFAULT_MAX_RESOLVED_LENGTH;
    if (!Number.isSafeInteger(maxResolvedLength) || maxResolvedLength < 1) {
      throw new InvalidArgumentError(`maxResolvedLength must be an integer of at least 1, not ${String(maxResolvedLength)}.`);
    }
    this.#resolved = new ResolvedStore(keyRing);
    this.token = options.token ?? new DefaultToken();
    this.maxResolvedLength = maxResolvedLength;
  }

  /**
   * Registers `source` as an additional lookup source, checked after every source already added - for
   * names and for the items in templates alike.
   * @returns this same collection, for chaining
   * @throws TypeError source is undefined or null
   */
  add(source: ProtectedReadOnlyCache): this {
    if (source === undefined || source === null) throw new TypeError('source must not be undefined.');
    this.#sources.push(source);
    return this;
  }

  /**
   * Registers a value provider for the items in templates only, asked after every source and every
   * provider already added. Its values are never answered by name on their own. A provider that holds
   * its values as strings is no place for secrets.
   * @returns this same collection, for chaining
   * @throws TypeError valueProvider is undefined or null
   */
  addValueProvider(valueProvider: ValueProvider): this {
    if (valueProvider === undefined || valueProvider === null) throw new TypeError('valueProvider must not be undefined.');
    this.#valueProviders.push(valueProvider);
    return this;
  }

  /**
   * Forgets `name`'s resolved value, or which source holds it, so the next lookup reads it again.
   * @returns true if anything was remembered for `name`
   * @throws TypeError name isn't a string
   */
  invalidate(name: string): boolean {
    const key = storeKey(name);
    this.#generation++;
    const resolved = this.#resolved.remove(key);
    return this.#plain.delete(name) || resolved;
  }

  /** Forgets every resolved value, and every source a value was found in. */
  clear(): void {
    this.#generation++;
    this.#resolved.clear();
    this.#plain.clear();
  }

  /**
   * Decrypts `name`'s value into `result` - its template resolved, if it is one - resolving to the
   * bytes written, or 0 if nothing holds it.
   * @throws ConfigurationKeyError (rejecting) name's value is a template naming a value nothing has
   * @throws ResolvedValueTooLongError (rejecting) name's value resolves to more than maxResolvedLength bytes
   * @throws TypeError (rejecting) name isn't a string
   */
  async decrypt(name: string, result: Uint8Array, signal?: AbortSignal): Promise<number> {
    const key = storeKey(name);
    const telemetry = HkdfGuardTelemetry.cache;
    return telemetry.withSpan(SpanNames.cache.decrypt, async (span) => {
      telemetry.logSensitiveOperation(span, SpanNames.cache.decrypt, { [AttributeNames.name]: name });
      for (;;) {
        const written = this.#resolved.decrypt(key, result);
        if (written > 0) return written;

        const { location, source } = await this.#locate(name, signal);
        if (location !== Location.resolved) return source === undefined ? 0 : source.decrypt(name, result, signal);
      }
    });
  }

  /**
   * An upper bound on how many bytes decrypt writes for `name` - resolving its template first, if it
   * is one - or undefined if nothing holds it.
   * @throws ConfigurationKeyError (rejecting) name's value is a template naming a value nothing has
   * @throws ResolvedValueTooLongError (rejecting) name's value resolves to more than maxResolvedLength bytes
   * @throws TypeError (rejecting) name isn't a string
   */
  async maxDecryptedLength(name: string, signal?: AbortSignal): Promise<number | undefined> {
    const key = storeKey(name);
    for (;;) {
      const maxLength = this.#resolved.maxDecryptedLength(key);
      if (maxLength !== undefined) return maxLength;

      const { location, source } = await this.#locate(name, signal);
      if (location !== Location.resolved) return source === undefined ? undefined : source.maxDecryptedLength(name, signal);
    }
  }

  /**
   * Finds `name`'s value outside the resolved store, resolving and caching it on the way when it is a
   * template.
   */
  async #locate(name: string, signal: AbortSignal | undefined): Promise<{ location: Location; source?: ProtectedReadOnlyCache }> {
    const plain = this.#plain.get(name);
    if (plain !== undefined) return { location: Location.source, source: plain };

    const generation = this.#generation;
    const sources = [...this.#sources];
    const valueProviders = [...this.#valueProviders];
    const { source, maxLength } = await findSource(sources, name, signal);
    if (source === undefined) return { location: Location.missing };

    const value = new Uint8Array(maxLength);
    try {
      const length = await source.decrypt(name, value, signal);
      const template = value.subarray(0, length);
      const reader = new ConfigurationItemReader(this.token);
      if (reader.readKeys(template).length === 0) {
        if (generation === this.#generation) this.#plain.set(name, source);
        return { location: Location.source, source };
      }

      let bound = length;
      for (const key of reader.keys()) bound += (await findSource(sources, key, signal)).maxLength;

      return { location: await this.#resolve(name, template, reader, bound, generation, sources, valueProviders) };
    } finally {
      wipe(value);
    }
  }

  /**
   * Resolves `template` and caches the result under `name` - unless invalidate or clear was called
   * since `generation` was read, when the result is dropped for the lookup to resolve again.
   */
  async #resolve(
    name: string,
    template: Uint8Array,
    reader: ConfigurationItemReader,
    bound: number,
    generation: number,
    sources: readonly ProtectedReadOnlyCache[],
    valueProviders: readonly ValueProvider[],
  ): Promise<Location> {
    const resolver = new ConfigurationItemResolver(this.token, reader, [
      ...sources.map((source) => new ProtectedCacheValueProvider(source)),
      ...valueProviders,
    ]);

    // The sources' bounds cover their values; a value provider's can't be known up front, so a value
    // from one may need a larger buffer.
    let capacity = Math.min(Math.max(bound, 1), this.maxResolvedLength);
    for (;;) {
      const resolved = new Uint8Array(capacity);
      try {
        let written: number;
        try {
          written = await resolver.resolve(template, resolved);
        } catch (error) {
          if (!(error instanceof DestinationTooSmallError)) throw error;
          if (capacity >= this.maxResolvedLength) throw new ResolvedValueTooLongError(this.maxResolvedLength, { cause: error });
          capacity = Math.min(2 * capacity, this.maxResolvedLength);
          continue;
        }

        if (written === 0) return Location.missing;
        if (generation === this.#generation) this.#resolved.set(storeKey(name), resolved.subarray(0, written));
        return Location.resolved;
      } finally {
        wipe(resolved);
      }
    }
  }
}

/** The first of `sources` holding `name`, as ProtectedCacheCollection finds it, with its bound; maxLength is 0 when none does. */
async function findSource(
  sources: readonly ProtectedReadOnlyCache[],
  name: string,
  signal: AbortSignal | undefined,
): Promise<{ source?: ProtectedReadOnlyCache; maxLength: number }> {
  for (const source of sources) {
    const maxLength = await source.maxDecryptedLength(name, signal);
    if (maxLength !== undefined) return { source, maxLength };
  }
  return { maxLength: 0 };
}

/**
 * `name`'s key in the resolved store. The store's AAD matches names ignoring ASCII case, as every
 * protected cache's does; this collection matches them exactly, as its sources may. So each name is
 * stored under a spelling with no upper-case ASCII - '!' becomes "!!", and an upper-case letter '!'
 * and its lower-case form - whose AAD no other name shares. Exported from this module for the
 * package's own tests, never from the package index.
 * @throws TypeError name isn't a string
 */
export function storeKey(name: string): string {
  if (typeof name !== 'string') throw new TypeError('name must be a string.');
  return /[!A-Z]/.test(name) ? name.replace(/[!A-Z]/g, (c) => (c === '!' ? '!!' : `!${c.toLowerCase()}`)) : name;
}

/**
 * The resolved values, encrypted and bound to their (store-key) names - what .NET's ProtectedCacheBase
 * does for it, as the cache package's Store does it: each entry is encrypted under the ring's current
 * key and records that version, and expires once the ring retires that version.
 */
class ResolvedStore {
  readonly #entries = new Map<string, KeyTrackingValue>();

  constructor(private readonly ring: KeyRing) {}

  /** Encrypts `plaintext` under `key`, replacing any value there; `plaintext` is zeroed whatever happens. */
  set(key: string, plaintext: Uint8Array): void {
    try {
      const aad = cacheAad(key);
      const { version, key: dek } = this.ring.getCurrent();
      this.#entries.set(key, { keyVersion: version, value: dek.encrypt(plaintext, aad) });
    } finally {
      wipe(plaintext);
    }
  }

  remove(key: string): boolean {
    return this.#entries.delete(key);
  }

  clear(): void {
    this.#entries.clear();
  }

  /** Decrypts `key`'s value into `result`, returning 0 if none is stored. */
  decrypt(key: string, result: Uint8Array): number {
    const entry = this.#cached(key);
    return entry === undefined ? 0 : this.ring.get(entry.keyVersion).decrypt(entry.value, result, cacheAad(key));
  }

  /** The stored ciphertext's length - an upper bound on the plaintext - or undefined when nothing is stored. */
  maxDecryptedLength(key: string): number | undefined {
    return this.#cached(key)?.value.length;
  }

  /** The entry stored under `key`, or undefined - dropping it first if its key has been retired. */
  #cached(key: string): KeyTrackingValue | undefined {
    const entry = this.#entries.get(key);
    if (entry === undefined || this.ring.tryGet(entry.keyVersion) !== undefined) return entry;
    let current: number;
    try {
      current = this.ring.currentVersion;
    } catch {
      return entry; // no key at all: let decrypt report it
    }
    if (entry.keyVersion >= current) return entry; // never retired, so never registered: let decrypt report it
    this.#entries.delete(key);
    return undefined;
  }
}

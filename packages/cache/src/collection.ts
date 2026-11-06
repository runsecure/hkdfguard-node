import type { ProtectedReadOnlyCache } from '@runsecure/hkdfguard-abstractions';
import { AttributeNames, HkdfGuardTelemetry, SpanNames } from '@runsecure/hkdfguard-diagnostics';

/**
 * Several read-only caches behind one lookup: decrypt and maxDecryptedLength ask each source in the
 * order it was added and return the first match. It never stores a value of its own - add registers
 * a source - so writing stays with whichever sources support it (a ProtectedCache can be one).
 *
 * A source that throws fails the lookup, even when a later source holds the name: a source that
 * couldn't answer can't say whether it holds the name, and answering from a later source could
 * return a value an earlier one overrides. Order sources so that cannot cost availability: add local
 * sources (ProtectedCache, FilePerSecretCache) before remote ones (a RemoteSecretCache such as the
 * Key Vault or Secrets Manager caches). A remote cache doesn't remember a name its store lacks, so a
 * remote source added first makes a network call for every local-only name on every lookup - enough
 * to be throttled, and then to fail every lookup.
 */
export class ProtectedCacheCollection implements ProtectedReadOnlyCache {
  readonly #sources: ProtectedReadOnlyCache[];

  constructor(...sources: ProtectedReadOnlyCache[]) {
    this.#sources = [...sources];
  }

  /** Registers `source`, checked after every source already added; returns this collection for chaining. */
  add(source: ProtectedReadOnlyCache): this {
    this.#sources.push(source);
    return this;
  }

  /** The registered sources, in order. */
  get sources(): readonly ProtectedReadOnlyCache[] {
    return this.#sources;
  }

  /** Decrypts `name`'s value from the first source that has it, or resolves to 0. A source's error stops the search. */
  decrypt(name: string, result: Uint8Array, signal?: AbortSignal): Promise<number> {
    const telemetry = HkdfGuardTelemetry.cache;
    return telemetry.withSpan(SpanNames.cache.decrypt, async (span) => {
      telemetry.logSensitiveOperation(span, SpanNames.cache.decrypt, { [AttributeNames.name]: name });
      for (const source of [...this.#sources]) {
        const written = await source.decrypt(name, result, signal);
        if (written > 0) return written;
      }
      return 0;
    });
  }

  /** The bound from the first source that has `name`, or undefined. */
  async maxDecryptedLength(name: string, signal?: AbortSignal): Promise<number | undefined> {
    for (const source of [...this.#sources]) {
      const length = await source.maxDecryptedLength(name, signal);
      if (length !== undefined) return length;
    }
    return undefined;
  }
}

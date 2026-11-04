// What the cache integration tests share: a real key ring, a source over plain text that counts what
// it is asked, a remote cache over a record, and a provider of settings. Never published.
import type { ProtectedReadOnlyCache } from '@runsecure/hkdfguard-abstractions';
import { ProtectedCache, RemoteSecretCache, SecretNameMatching, type SecretValueSink } from '@runsecure/hkdfguard-cache';
import { KeyRing } from '@runsecure/hkdfguard-dek';
import { RecordingKey } from '@runsecure/hkdfguard-test-support';
import { ValueProviderBase, ValueStatus, type BytesResult } from './index.js';

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
export const text = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

/** A ring holding one real AES-256-GCM key as version 1, its current version. */
export function newRing(): KeyRing {
  const ring = new KeyRing();
  ring.add(1, new RecordingKey());
  return ring;
}

/** A ProtectedCache holding `values`. */
export function newCache(ring: KeyRing, values: Record<string, string> = {}): ProtectedCache {
  const cache = new ProtectedCache(ring);
  for (const [name, value] of Object.entries(values)) cache.add(name, utf8(value));
  return cache;
}

/** Sizes a buffer with maxDecryptedLength, as a caller would, and decrypts `name`. */
export async function decryptText(cache: ProtectedReadOnlyCache, name: string): Promise<string> {
  const maxLength = await cache.maxDecryptedLength(name);
  if (maxLength === undefined) throw new Error(`${name} is missing`);
  const result = new Uint8Array(maxLength);
  return text(result.subarray(0, await cache.decrypt(name, result)));
}

/**
 * A ProtectedReadOnlyCache over plain strings, names matched exactly, that counts every lookup by name
 * and can run a callback the first time it decrypts a name. A real cache never holds plaintext like this.
 */
export class PlainSource implements ProtectedReadOnlyCache {
  readonly values: Map<string, string>;
  readonly decrypts = new Map<string, number>();
  readonly lengthLookups = new Map<string, number>();
  onFirstDecrypt: { name: string; run: () => unknown } | undefined;

  constructor(values: Record<string, string> = {}) {
    this.values = new Map(Object.entries(values));
  }

  set(name: string, value: string): void {
    this.values.set(name, value);
  }

  decryptCount(name: string): number {
    return this.decrypts.get(name) ?? 0;
  }

  lengthLookupCount(name: string): number {
    return this.lengthLookups.get(name) ?? 0;
  }

  async decrypt(name: string, result: Uint8Array): Promise<number> {
    this.decrypts.set(name, this.decryptCount(name) + 1);
    const hook = this.onFirstDecrypt;
    if (hook !== undefined && hook.name === name) {
      this.onFirstDecrypt = undefined;
      await hook.run();
    }

    const value = this.values.get(name);
    if (value === undefined) return 0;
    const encoded = utf8(value);
    if (encoded.length > result.length) throw new RangeError('The result is too small.');
    result.set(encoded);
    return encoded.length;
  }

  async maxDecryptedLength(name: string): Promise<number | undefined> {
    this.lengthLookups.set(name, this.lengthLookupCount(name) + 1);
    const value = this.values.get(name);
    return value === undefined ? undefined : utf8(value).length;
  }
}

/**
 * A RemoteSecretCache over a record, matching names exactly, that records each fetch. A value holding
 * a JSON object is handed over with its keys too.
 */
export class FakeRemoteSecretCache extends RemoteSecretCache {
  readonly fetches: string[] = [];

  constructor(ring: KeyRing, readonly secrets: Record<string, string> = {}) {
    super(ring, SecretNameMatching.exact);
  }

  protected isValidName(name: string): boolean {
    return name.length > 0;
  }

  protected async fetch(name: string, sink: SecretValueSink, signal?: AbortSignal): Promise<void> {
    this.fetches.push(name);
    await Promise.resolve();
    signal?.throwIfAborted();
    const secret = this.secrets[name];
    if (secret !== undefined) sink.setBytesWithJsonKeys(utf8(secret));
  }
}

/** A value provider over plain strings, as an application's provider of settings that aren't secret would be. */
export class SettingsProvider extends ValueProviderBase {
  constructor(private readonly values: Record<string, string>) {
    super();
  }

  async tryGetBytes(key: string, destination: Uint8Array): Promise<BytesResult> {
    const value = this.values[key];
    if (value === undefined) return { status: ValueStatus.notFound, written: 0 };
    const encoded = utf8(value);
    if (encoded.length > destination.length) return { status: ValueStatus.destinationTooSmall, written: 0 };
    destination.set(encoded);
    return { status: ValueStatus.found, written: encoded.length };
  }

  protected async tryGetByteCount(key: string): Promise<number | undefined> {
    const value = this.values[key];
    return value === undefined ? undefined : utf8(value).length;
  }
}

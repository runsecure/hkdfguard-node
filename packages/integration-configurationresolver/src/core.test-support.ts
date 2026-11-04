// What the resolver core's tests share: the port of the Python suite's
// configurationresolver_core_test_support.py (itself the port of .NET's TestDoubles.cs -
// CustomToken, ReadingResolver, SpyValueProvider - and TemplateFile.CreateResolver), plus a
// ValueProviderBase over a map that stands in for .NET's DictionaryValueProvider.
//
// Non-ASCII test text is built with String.fromCodePoint so that the files hold only ASCII.
import { strict as assert } from 'node:assert';
import { isZero } from '@runsecure/hkdfguard-abstractions';
import { ConfigurationKeyError, type ConfigurationKeyErrorCode } from './errors.js';
import { ConfigurationItemReader } from './reader.js';
import { ConfigurationItemResolver, type ConfigurationResolver } from './resolver.js';
import { ConfigurationItemTokenBase } from './tokens.js';
import { ValueProviderBase, ValueStatus, type BytesResult, type ValueProvider, type ValueResult } from './valueproviders.js';

// --- Characters -------------------------------------------------------------------------------

export const E_ACUTE = String.fromCodePoint(0x00e9);
export const U_DIAERESIS = String.fromCodePoint(0x00fc);
export const I_DIAERESIS = String.fromCodePoint(0x00ef);
export const O_DIAERESIS = String.fromCodePoint(0x00f6);
export const CHECK_MARK = String.fromCodePoint(0x2713);
export const LEFT_GUILLEMET = String.fromCodePoint(0x00ab);
export const RIGHT_GUILLEMET = String.fromCodePoint(0x00bb);
export const REPLACEMENT = String.fromCodePoint(0xfffd);

/** "cafe" with an acute e: 4 characters, 5 UTF-8 bytes. */
export const CAFE = 'caf' + E_ACUTE;

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { ignoreBOM: true });

/** `s` as UTF-8. */
export const utf8 = (s: string): Uint8Array => encoder.encode(s);

/** `bytes` decoded as UTF-8, ill-formed sequences replaced. */
export const fromUtf8 = (bytes: Uint8Array): string => decoder.decode(bytes);

// --- Doubles ----------------------------------------------------------------------------------

/** A token with custom start, end, and escape sequences. */
export class CustomToken extends ConfigurationItemTokenBase {
  constructor(startSequence: string, endSequence: string, escapeSequence?: string) {
    super(startSequence, endSequence, escapeSequence);
  }
}

/** Writes `value` to the start of `destination`, as .NET's Encoding.UTF8.TryGetBytes does. */
export function writeValue(value: Uint8Array, destination: Uint8Array): BytesResult {
  if (value.length > destination.length) return { status: ValueStatus.destinationTooSmall, written: 0 };
  destination.set(value, 0);
  return { status: ValueStatus.found, written: value.length };
}

/** A {@link ValueProviderBase} over a map: what the tests use where .NET's use DictionaryValueProvider. */
export class DictValueProvider extends ValueProviderBase {
  readonly #values: Map<string, string>;

  constructor(values: Record<string, string>) {
    super();
    this.#values = new Map(Object.entries(values));
  }

  async tryGetBytes(key: string, destination: Uint8Array): Promise<BytesResult> {
    const value = this.#values.get(key);
    if (value === undefined) return { status: ValueStatus.notFound, written: 0 };
    return writeValue(utf8(value), destination);
  }

  protected async tryGetByteCount(key: string): Promise<number | undefined> {
    const value = this.#values.get(key);
    return value === undefined ? undefined : utf8(value).length;
  }

  /** Exposes the protected sizing method, as .NET's SizingDictionaryValueProvider does. */
  findByteCount(key: string): Promise<number | undefined> {
    return this.tryGetByteCount(key);
  }
}

/** A value provider that records how the resolver calls it. */
export class SpyValueProvider implements ValueProvider {
  readonly #values: Map<string, string>;
  readonly throwOnLookup: unknown;
  readonly tryGetValueCalls: string[] = [];
  readonly tryGetBytesCalls: string[] = [];
  readonly bufferLengths: number[] = [];

  constructor(values: Record<string, string>, options: { throwOnLookup?: unknown } = {}) {
    this.#values = new Map(Object.entries(values));
    this.throwOnLookup = options.throwOnLookup;
  }

  async tryGetValue(key: string): Promise<ValueResult> {
    this.tryGetValueCalls.push(key);
    const value = this.#values.get(key);
    return value === undefined ? { status: ValueStatus.notFound, value: undefined } : { status: ValueStatus.found, value };
  }

  async tryGetBytes(key: string, destination: Uint8Array): Promise<BytesResult> {
    this.tryGetBytesCalls.push(key);
    this.bufferLengths.push(destination.length);
    if (this.throwOnLookup !== undefined) throw this.throwOnLookup;

    const value = this.#values.get(key);
    if (value === undefined) return { status: ValueStatus.notFound, written: 0 };
    return writeValue(utf8(value), destination);
  }
}

/** The settings of a {@link ReadingResolver}. */
export interface ReadingResolverOptions {
  ignoreUnresolvablePlaceholders?: boolean;
  maxResolutionDepth?: number;
  /** Texts whose keys are allowed as well as the source's, such as the keys of items inside values. */
  alsoAllowed?: Iterable<string>;
}

/** Reads the keys of each source before resolving it, so every key in the source is allowed. */
export class ReadingResolver implements ConfigurationResolver {
  readonly #reader: ConfigurationItemReader;
  readonly #alsoAllowed: readonly string[];
  readonly #resolver: ConfigurationItemResolver;

  constructor(token: ConfigurationItemTokenBase, valueProviders: ValueProvider[], options: ReadingResolverOptions = {}) {
    this.#reader = new ConfigurationItemReader(token);
    this.#alsoAllowed = [...(options.alsoAllowed ?? [])];
    this.#resolver = new ConfigurationItemResolver(token, this.#reader, valueProviders, {
      ignoreUnresolvablePlaceholders: options.ignoreUnresolvablePlaceholders ?? false,
      maxResolutionDepth: options.maxResolutionDepth ?? 1,
    });
  }

  resolve(source: string | Uint8Array, destination: Uint8Array): Promise<number> {
    const text = typeof source === 'string' ? source : fromUtf8(source);
    this.#reader.readKeysAll([text, ...this.#alsoAllowed]);
    return this.#resolver.resolve(source, destination);
  }
}

/**
 * Reads the keys of a trusted template and creates a resolver that allows only those keys: the port
 * of TemplateFile.CreateResolver.
 */
export function createTemplateResolver(token: ConfigurationItemTokenBase, provider: ValueProvider, template: string | Uint8Array): ConfigurationItemResolver {
  const reader = new ConfigurationItemReader(token);
  reader.readKeys(template);
  return new ConfigurationItemResolver(token, reader, [provider]);
}

// --- Helpers ----------------------------------------------------------------------------------

/** `source` as a string and as UTF-8 bytes: the two forms .NET's char and byte overloads take. */
export function both(source: string): (string | Uint8Array)[] {
  return [source, utf8(source)];
}

/** Resolves `source` into a new destination and decodes what was written. */
export async function resolveToString(resolver: ConfigurationResolver, source: string | Uint8Array, destinationLength = 1024): Promise<string> {
  const destination = new Uint8Array(destinationLength);
  const written = await resolver.resolve(source, destination);
  return fromUtf8(destination.subarray(0, written));
}

/** A destination of `length` bytes, each `fill`. */
export function filled(length: number, fill = '#'.charCodeAt(0)): Uint8Array {
  return new Uint8Array(length).fill(fill);
}

export function assertZeroed(destination: Uint8Array): void {
  assert.ok(isZero(destination), 'the destination is not zeroed');
}

/** The port of .NET's AssertKeyException: the key, error and index, and a message without the key. */
export function assertKeyError(error: unknown, key: string, code: ConfigurationKeyErrorCode, sourceIndex: number): void {
  assert.ok(error instanceof ConfigurationKeyError, `expected a ConfigurationKeyError, not ${String(error)}`);
  assert.equal(error.key, key);
  assert.equal(error.error, code);
  assert.equal(error.sourceIndex, sourceIndex);
  assert.equal(error.code, 'ERR_HKDFGUARD_CONFIGURATION_KEY');
  assert.equal(error.message, `The configuration item at index ${sourceIndex} could not be resolved (${code}).`);
  assert.ok(!error.message.includes(key));
}

/** The error `promise` rejects with; fails if it fulfils. */
export async function rejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  assert.fail('expected the promise to reject');
}

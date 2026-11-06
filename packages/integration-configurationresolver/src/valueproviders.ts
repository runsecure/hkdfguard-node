import { InvalidArgumentError, wipe } from '@runsecure/hkdfguard-abstractions';
import { ConfigurationKeyError, ConfigurationKeyErrorCode } from './errors.js';
import { decodeUtf8 } from './text.js';

/** The result of asking a {@link ValueProvider} for a value. Each value is its .NET name. */
export const ValueStatus = {
  /** The key was found and its value was written. */
  found: 'Found',
  /** The key was not found. Nothing was written. */
  notFound: 'NotFound',
  /** The key was found, but its value does not fit in the destination. Nothing usable was written. */
  destinationTooSmall: 'DestinationTooSmall',
} as const;

/** A {@link ValueStatus} value. */
export type ValueStatus = (typeof ValueStatus)[keyof typeof ValueStatus];

/** What {@link ValueProvider.tryGetBytes} reports: whether the value was found and fit, and how many bytes it wrote - 0 unless found. */
export interface BytesResult {
  status: ValueStatus;
  written: number;
}

/** What {@link ValueProvider.tryGetValue} reports: whether the value was found, and the value - undefined unless found. */
export interface ValueResult {
  status: ValueStatus;
  value: string | undefined;
}

/**
 * Provides configuration values by key - the port of IValueProvider. Values are UTF-8 bytes, so
 * .NET's TryGetChar is {@link tryGetBytes} here, and lookups are asynchronous, as every HkdfGuard
 * cache's are; `signal` cancels.
 */
export interface ValueProvider {
  /**
   * The value for `key` as a string. A string can't be zeroed once created: prefer
   * {@link tryGetBytes} for secrets.
   */
  tryGetValue(key: string, signal?: AbortSignal): Promise<ValueResult>;

  /** Writes the UTF-8 value for `key` to the start of `destination`. */
  tryGetBytes(key: string, destination: Uint8Array, signal?: AbortSignal): Promise<BytesResult>;
}

/** How many times a value is re-read when it grows between being sized and being read. */
const MAX_READ_ATTEMPTS = 3;

/**
 * Base class for value providers whose values are bytes, such as files or decrypted data - the port
 * of ValueProviderBase.
 *
 * Subclasses implement {@link tryGetBytes} and {@link tryGetByteCount}. {@link tryGetValue} is built
 * on them: the value's bytes are read into a buffer sized by tryGetByteCount, decoded, and the buffer
 * is zeroed. A value that keeps outgrowing its size, read after read, rejects with a
 * {@link ConfigurationKeyError} whose error is 'ValueUnstable'.
 */
export abstract class ValueProviderBase implements ValueProvider {
  abstract tryGetBytes(key: string, destination: Uint8Array, signal?: AbortSignal): Promise<BytesResult>;

  /**
   * The number of UTF-8 bytes needed to hold the value for `key` - the buffer size
   * {@link tryGetBytes} needs - or undefined if the key was not found.
   */
  protected abstract tryGetByteCount(key: string, signal?: AbortSignal): Promise<number | undefined>;

  /** @throws ConfigurationKeyError (rejecting) the value kept changing size while it was read */
  async tryGetValue(key: string, signal?: AbortSignal): Promise<ValueResult> {
    for (let attempt = 0; attempt < MAX_READ_ATTEMPTS; attempt++) {
      const byteCount = await this.tryGetByteCount(key, signal);
      if (byteCount === undefined) return { status: ValueStatus.notFound, value: undefined };

      const buffer = new Uint8Array(byteCount);
      try {
        const { status, written } = await this.tryGetBytes(key, buffer, signal);
        if (status === ValueStatus.found) return { status, value: decodeUtf8(buffer.subarray(0, written)) };
        if (status !== ValueStatus.destinationTooSmall) return { status, value: undefined };
      } finally {
        wipe(buffer);
      }
    }

    throw new ConfigurationKeyError(key, ConfigurationKeyErrorCode.valueUnstable);
  }
}

/**
 * Provides configuration values from several value providers, in priority order - the port of
 * CompositeValueProvider.
 *
 * Each lookup asks the providers in the order given, and the first provider that has the key supplies
 * the value; the providers after it are not asked. A provider that has the key but whose value does
 * not fit in the destination ends the lookup with 'DestinationTooSmall', rather than falling through
 * to a lower-priority value. An error a provider throws, such as a {@link ConfigurationKeyError}, is
 * not caught. Put the provider you trust most first.
 */
export class CompositeValueProvider implements ValueProvider {
  readonly #providers: readonly ValueProvider[];

  /**
   * @param providers the providers to ask, highest priority first
   * @throws InvalidArgumentError providers is empty
   * @throws TypeError a provider is undefined or null
   */
  constructor(...providers: ValueProvider[]) {
    if (providers.length === 0) throw new InvalidArgumentError('At least one value provider is required.');
    if (providers.some((provider) => provider === undefined || provider === null)) {
      throw new TypeError('The value providers must not contain undefined or null.');
    }
    this.#providers = Object.freeze([...providers]);
  }

  /** The providers, highest priority first. */
  get providers(): readonly ValueProvider[] {
    return this.#providers;
  }

  async tryGetValue(key: string, signal?: AbortSignal): Promise<ValueResult> {
    for (const provider of this.#providers) {
      const result = await provider.tryGetValue(key, signal);
      if (result.status === ValueStatus.found) return { status: ValueStatus.found, value: result.value };
    }
    return { status: ValueStatus.notFound, value: undefined };
  }

  async tryGetBytes(key: string, destination: Uint8Array, signal?: AbortSignal): Promise<BytesResult> {
    for (const provider of this.#providers) {
      const result = await provider.tryGetBytes(key, destination, signal);
      if (result.status !== ValueStatus.notFound) return { status: result.status, written: result.written };
    }
    return { status: ValueStatus.notFound, written: 0 };
  }
}

import { InvalidArgumentError, wipe } from '@runsecure/hkdfguard-abstractions';
import { ConfigurationKeyError, ConfigurationKeyErrorCode, DestinationTooSmallError } from './errors.js';
import type { KeyReader } from './reader.js';
import { endsWith, indexOf, itemKey, utf8Of, utf8Sequence } from './text.js';
import type { ConfigurationItemTokenBase } from './tokens.js';
import { CompositeValueProvider, ValueStatus, type ValueProvider } from './valueproviders.js';

/**
 * Resolves text by replacing its configuration items, such as `${Name}`, with their values - the
 * port of IConfigurationResolver.
 */
export interface ConfigurationResolver {
  /**
   * Copies `source` - a string, or UTF-8 bytes - to `destination` as UTF-8, replacing each
   * configuration item with its UTF-8 value. `destination` must not overlap `source`.
   * @returns the number of bytes written to `destination`
   * @throws DestinationTooSmallError (rejecting) destination is too small for the resolved text
   * @throws ConfigurationKeyError (rejecting) an item's key is not allowed, has no value, or its value
   *   kept changing while it was read
   */
  resolve(source: string | Uint8Array, destination: Uint8Array, signal?: AbortSignal): Promise<number>;
}

/** The settings of a {@link ConfigurationItemResolver} - .NET's init properties. */
export interface ConfigurationItemResolverOptions {
  /**
   * Copy an allowed key that no value provider has to the destination unchanged, start and end
   * sequences included, instead of throwing a ConfigurationKeyError whose error is 'NotFound'. A key
   * that is not allowed still throws with 'NotAllowed', and an error a value provider throws, such as
   * 'ValueUnstable', still propagates. False by default.
   */
  ignoreUnresolvablePlaceholders?: boolean;

  /**
   * The number of levels of items resolved; 1 by default. At 1, values are inserted exactly as they
   * are, even if they contain items. At 2, the items in each value are resolved too, and their values
   * are inserted as they are; each further level resolves one more level of values. Items in values
   * follow the same rules as items in the source: their keys must be allowed by the reader, and escape
   * sequences in values are applied. Values at the last level are inserted unchanged, escape sequences
   * included. A key whose value leads back to itself throws with 'Cycle'. An error in a value reports
   * the position of the item in the source that led to it. A value that is resolved is held in a
   * buffer that is zeroed afterwards, and is never read as a string.
   */
  maxResolutionDepth?: number;
}

/**
 * Resolves text by replacing the configuration items a token delimits with values from one or more
 * {@link ValueProvider}s, for only the keys a reader read - the port of ConfigurationItemResolver.
 *
 * Keys are trimmed of surrounding whitespace, as {@link ConfigurationItemReader} trims them. Only keys
 * the reader's keys() returns are looked up, so read the keys from a trusted template first; any other
 * key throws without a provider being asked for it. With several value providers, each key is looked
 * up in the order the providers were given, and the first that has the key supplies the value, as
 * with {@link CompositeValueProvider}. A key that is not allowed throws a {@link ConfigurationKeyError},
 * whose message does not contain the key. A key that no provider has throws the same way, unless
 * ignoreUnresolvablePlaceholders is set.
 *
 * The reader's keys are read on each resolve, so the most recent read applies. Empty items such as
 * `${}` and a start sequence with no matching end sequence are copied unchanged, and a start sequence
 * preceded by the token's escape sequence is copied without the escape sequence. By default values
 * are inserted as they are; set maxResolutionDepth to also resolve the items inside values.
 *
 * Values are written by the provider directly into the destination and are never read as strings. If
 * resolving fails, the whole destination is zeroed, so no partially resolved values are left behind.
 */
export class ConfigurationItemResolver implements ConfigurationResolver {
  readonly #reader: KeyReader;
  readonly #valueProvider: ValueProvider;
  readonly #delimiters: Delimiters;

  /** Whether an allowed key that no value provider has is copied unchanged instead of throwing. */
  readonly ignoreUnresolvablePlaceholders: boolean;

  /** The number of levels of configuration items that are resolved; 1 by default. */
  readonly maxResolutionDepth: number;

  /**
   * @param token the start, end, and escape sequences of a configuration item
   * @param reader the reader whose keys are the only keys that may be resolved
   * @param valueProviders the providers of each key's value, highest priority first
   * @throws TypeError token, reader or valueProviders is undefined or null, or a provider is
   * @throws InvalidArgumentError valueProviders is empty, or maxResolutionDepth isn't an integer of at least 1
   */
  constructor(token: ConfigurationItemTokenBase, reader: KeyReader, valueProviders: Iterable<ValueProvider>, options: ConfigurationItemResolverOptions = {}) {
    if (token === undefined || token === null) throw new TypeError('token must not be undefined.');
    if (reader === undefined || reader === null) throw new TypeError('reader must not be undefined.');
    if (valueProviders === undefined || valueProviders === null) throw new TypeError('valueProviders must not be undefined.');
    const maxResolutionDepth = options.maxResolutionDepth ?? 1;
    validateMaxResolutionDepth(maxResolutionDepth);
    const composite = new CompositeValueProvider(...valueProviders);

    this.#reader = reader;
    this.#valueProvider = composite.providers.length === 1 ? composite.providers[0]! : composite;
    this.#delimiters = {
      start: utf8Sequence(token.startSequence),
      end: utf8Sequence(token.endSequence),
      escape: utf8Sequence(token.escapeSequence),
    };
    this.ignoreUnresolvablePlaceholders = options.ignoreUnresolvablePlaceholders ?? false;
    this.maxResolutionDepth = maxResolutionDepth;
  }

  async resolve(source: string | Uint8Array, destination: Uint8Array, signal?: AbortSignal): Promise<number> {
    if (source === undefined || source === null) throw new TypeError('source must not be undefined.');
    if (!(destination instanceof Uint8Array)) throw new TypeError('destination must be a Uint8Array.');
    const { bytes, owned } = utf8Of(source, 'source');
    const run = new Resolution(
      { ...this.#delimiters, valueProvider: this.#valueProvider, ignoreUnresolvablePlaceholders: this.ignoreUnresolvablePlaceholders, maxResolutionDepth: this.maxResolutionDepth },
      destination,
      new Set(this.#reader.keys()),
      signal,
    );
    try {
      await run.write(bytes, 1, undefined);
      return run.written;
    } catch (error) {
      wipe(destination);
      throw error;
    } finally {
      if (owned) wipe(bytes);
    }
  }
}

/** @throws InvalidArgumentError depth isn't an integer of at least 1 */
export function validateMaxResolutionDepth(depth: number): void {
  if (!Number.isInteger(depth) || depth < 1) {
    throw new InvalidArgumentError(`maxResolutionDepth must be an integer of at least 1, not ${String(depth)}.`);
  }
}

/** The token's sequences as UTF-8 bytes; escape is empty when the token has none. */
interface Delimiters {
  readonly start: Uint8Array;
  readonly end: Uint8Array;
  readonly escape: Uint8Array;
}

/** What a resolve call needs of its resolver. */
interface Settings extends Delimiters {
  readonly valueProvider: ValueProvider;
  readonly ignoreUnresolvablePlaceholders: boolean;
  readonly maxResolutionDepth: number;
}

/**
 * One resolve call's state: the destination, how much of it is written, the allowed keys, and the
 * keys whose values are being resolved, outermost first.
 */
class Resolution {
  written = 0;
  readonly #resolving: string[] = [];

  constructor(
    private readonly resolver: Settings,
    private readonly destination: Uint8Array,
    private readonly allowedKeys: ReadonlySet<string>,
    private readonly signal: AbortSignal | undefined,
  ) {}

  /**
   * Copies `text` to the destination, replacing each configuration item with its value. `depth` is 1
   * for the source, 2 for a value in it, and so on; `itemIndex` is the index of the item in the
   * source that led to this text, or undefined for the source itself.
   */
  async write(text: Uint8Array, depth: number, itemIndex: number | undefined): Promise<void> {
    const { start, end, escape } = this.resolver;
    let position = 0;
    for (;;) {
      const startIndex = indexOf(text, start, position);
      if (startIndex < 0) {
        this.#copy(text.subarray(position));
        return;
      }

      const keyStart = startIndex + start.length;
      let consumed: number;
      if (escape.length > 0 && endsWith(text, escape, position, startIndex)) {
        this.#copy(text.subarray(position, startIndex - escape.length));
        this.#copy(start);
        consumed = keyStart;
      } else {
        const endIndex = indexOf(text, end, keyStart);
        if (endIndex < 0) {
          this.#copy(text.subarray(position));
          return;
        }

        consumed = endIndex + end.length;
        const key = itemKey(text, keyStart, endIndex);
        if (key.length === 0) {
          this.#copy(text.subarray(position, consumed));
        } else {
          this.#copy(text.subarray(position, startIndex));
          const sourceIndex = itemIndex ?? startIndex;
          if (!(await this.#tryWriteValue(key, sourceIndex, depth))) {
            this.#copy(text.subarray(startIndex, consumed));
          }
        }
      }

      position = consumed;
    }
  }

  /**
   * Writes `key`'s value to the destination, resolving the items in it if the depth allows.
   * @returns false when no provider has the key and unresolvable placeholders are ignored, so the item
   *   is to be copied unchanged
   */
  async #tryWriteValue(key: string, sourceIndex: number, depth: number): Promise<boolean> {
    if (!this.allowedKeys.has(key)) throw new ConfigurationKeyError(key, ConfigurationKeyErrorCode.notAllowed, sourceIndex);
    if (this.#resolving.includes(key)) throw new ConfigurationKeyError(key, ConfigurationKeyErrorCode.cycle, sourceIndex);

    this.signal?.throwIfAborted();
    const room = this.destination.subarray(this.written);
    let status: ValueStatus;
    let length: number;
    try {
      ({ status, written: length } = await this.resolver.valueProvider.tryGetBytes(key, room, this.signal));
    } catch (error) {
      if (error instanceof ConfigurationKeyError && error.sourceIndex === undefined) {
        throw new ConfigurationKeyError(error.key, error.error, sourceIndex, { cause: error });
      }
      throw error;
    }

    if (status === ValueStatus.notFound && this.resolver.ignoreUnresolvablePlaceholders) return false;
    if (status === ValueStatus.destinationTooSmall) throw new DestinationTooSmallError();
    if (status !== ValueStatus.found) throw new ConfigurationKeyError(key, ConfigurationKeyErrorCode.notFound, sourceIndex);
    if (!Number.isInteger(length) || length < 0 || length > room.length) {
      throw new RangeError(`A value provider reported writing ${String(length)} bytes into ${room.length}.`);
    }

    if (depth >= this.resolver.maxResolutionDepth || indexOf(room.subarray(0, length), this.resolver.start, 0) < 0) {
      this.written += length;
      return true;
    }

    // Move the value to a copy, zero it in the destination, and write it back resolved.
    const copy = room.slice(0, length);
    try {
      wipe(room.subarray(0, length));
      this.#resolving.push(key);
      await this.write(copy, depth + 1, sourceIndex);
      this.#resolving.pop();
      return true;
    } finally {
      wipe(copy);
    }
  }

  #copy(text: Uint8Array): void {
    if (text.length > this.destination.length - this.written) throw new DestinationTooSmallError();
    this.destination.set(text, this.written);
    this.written += text.length;
  }
}

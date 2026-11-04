import type { ProtectedReadOnlyCache } from '@runsecure/hkdfguard-abstractions';
import { InvalidOperationError } from './errors.js';
import { ProtectedCacheValueProvider } from './protectedcachevalueprovider.js';
import type { KeyReader } from './reader.js';
import { ConfigurationItemResolver, validateMaxResolutionDepth } from './resolver.js';
import { DefaultToken, type ConfigurationItemTokenBase } from './tokens.js';
import type { ValueProvider } from './valueproviders.js';

/**
 * Builds a {@link ConfigurationItemResolver} from a token, a reader, and one or more value providers
 * - the port of ConfigurationResolverBuilder, with .NET's AddProtectedCache extension method as a
 * method of its own.
 *
 * The token defaults to {@link DefaultToken}. A reader and at least one value provider are required.
 * The reader is not created for you, because only you can read the keys of your trusted template into
 * it; create it with the same token. Each {@link build} returns a new resolver that shares the reader
 * and the value providers:
 *
 * ```ts
 * const token = new DefaultToken();
 * const reader = new ConfigurationItemReader(token);
 * reader.readKeys(template);
 *
 * const resolver = new ConfigurationResolverBuilder()
 *   .withToken(token)
 *   .withReader(reader)
 *   .addProtectedCache(secrets)
 *   .build();
 * ```
 */
export class ConfigurationResolverBuilder {
  readonly #valueProviders: ValueProvider[] = [];
  #token: ConfigurationItemTokenBase = new DefaultToken();
  #reader: KeyReader | undefined;
  #ignoreUnresolvablePlaceholders = false;
  #maxResolutionDepth = 1;

  /**
   * Sets the token that defines the start, end, and escape sequences of a configuration item. Use the
   * same token as the reader.
   * @throws TypeError token is undefined or null
   */
  withToken(token: ConfigurationItemTokenBase): this {
    if (token === undefined || token === null) throw new TypeError('token must not be undefined.');
    this.#token = token;
    return this;
  }

  /**
   * Sets the reader whose keys are the only keys the resolver may resolve.
   * @throws TypeError reader is undefined or null
   */
  withReader(reader: KeyReader): this {
    if (reader === undefined || reader === null) throw new TypeError('reader must not be undefined.');
    this.#reader = reader;
    return this;
  }

  /**
   * Adds a value provider, after any added already. Providers added earlier have higher priority.
   * @throws TypeError valueProvider is undefined or null
   */
  addValueProvider(valueProvider: ValueProvider): this {
    if (valueProvider === undefined || valueProvider === null) throw new TypeError('valueProvider must not be undefined.');
    this.#valueProviders.push(valueProvider);
    return this;
  }

  /**
   * Adds a {@link ProtectedCacheValueProvider} over `cache`, after any value provider added already.
   * @throws TypeError cache is undefined or null
   */
  addProtectedCache(cache: ProtectedReadOnlyCache): this {
    return this.addValueProvider(new ProtectedCacheValueProvider(cache));
  }

  /** Sets whether an allowed key that no value provider has is copied unchanged instead of throwing. */
  ignoreUnresolvablePlaceholders(ignore = true): this {
    this.#ignoreUnresolvablePlaceholders = ignore;
    return this;
  }

  /**
   * Sets the number of levels of configuration items that are resolved; 1 inserts values as they are.
   * @throws InvalidArgumentError maxResolutionDepth isn't an integer of at least 1
   */
  withMaxResolutionDepth(maxResolutionDepth: number): this {
    validateMaxResolutionDepth(maxResolutionDepth);
    this.#maxResolutionDepth = maxResolutionDepth;
    return this;
  }

  /**
   * A new resolver from the builder's settings.
   * @throws InvalidOperationError no reader has been set, or no value provider has been added
   */
  build(): ConfigurationItemResolver {
    if (this.#reader === undefined) throw new InvalidOperationError('A reader is required. Call withReader before build.');
    if (this.#valueProviders.length === 0) {
      throw new InvalidOperationError('At least one value provider is required. Call addValueProvider before build.');
    }
    return new ConfigurationItemResolver(this.#token, this.#reader, [...this.#valueProviders], {
      ignoreUnresolvablePlaceholders: this.#ignoreUnresolvablePlaceholders,
      maxResolutionDepth: this.#maxResolutionDepth,
    });
  }
}

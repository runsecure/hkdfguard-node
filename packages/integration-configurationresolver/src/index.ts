/**
 * Resolves configuration templates - "Host=db;Password=${db-password}" - from HkdfGuard's protected
 * caches: the Node port of .NET's HkdfGuard.Integration.ConfigurationResolver, together with the parts
 * of ConfigurationResolver it needs, in this one package.
 *
 *  - ProtectedCacheValueProvider: a value provider over any ProtectedReadOnlyCache, so a resolver's
 *    items resolve from a ProtectedCache, a FilePerSecretCache, a collection or a remote secret
 *    store's cache. Each value is decrypted straight into the resolver's destination, or into a buffer
 *    that is zeroed, and is never a string.
 *  - ResolvingProtectedCacheCollection: a ProtectedCacheCollection that resolves the templates its
 *    sources hold on their first lookup, from those same sources, and caches each result encrypted
 *    under the key ring.
 *  - ConfigurationResolverBuilder.addProtectedCache: .NET's AddProtectedCache extension method.
 *  - From ConfigurationResolver: the token (ConfigurationItemTokenBase, DefaultToken), the reader
 *    (ConfigurationItemReader), the resolver (ConfigurationItemResolver, ConfigurationResolverBuilder),
 *    the value-provider contract (ValueProvider, ValueProviderBase, CompositeValueProvider, ValueStatus)
 *    and ConfigurationKeyError.
 *
 * Values are UTF-8 bytes - Node has no mutable string to resolve into - and every lookup is
 * asynchronous, as every HkdfGuard cache's is.
 */
export {
  ConfigurationKeyError, ConfigurationKeyErrorCode, DestinationTooSmallError, InvalidOperationError, ResolvedValueTooLongError,
  StringValuesNotAllowedError,
} from './errors.js';
export { ConfigurationItemTokenBase, DefaultToken } from './tokens.js';
export { ConfigurationItemReader, type KeyReader } from './reader.js';
export {
  CompositeValueProvider, ValueProviderBase, ValueStatus, type BytesResult, type ValueProvider, type ValueResult,
} from './valueproviders.js';
export { ConfigurationItemResolver, type ConfigurationItemResolverOptions, type ConfigurationResolver } from './resolver.js';
export { ConfigurationResolverBuilder } from './builder.js';
export { ProtectedCacheValueProvider, type ProtectedCacheValueProviderOptions } from './protectedcachevalueprovider.js';
export { ResolvingProtectedCacheCollection, type ResolvingProtectedCacheCollectionOptions } from './resolvingcollection.js';

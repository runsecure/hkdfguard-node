/**
 * HkdfGuard's protected caches - the Node port of the .NET HkdfGuard.Cache library and the
 * ProtectedCacheBase from HkdfGuard.Abstractions:
 *
 *  - ProtectedCache: read/write; values are added by the application.
 *  - ReadOnlyProtectedCache: filled on demand from a CacheSource, such as a secret store. A backend
 *    supplies only the source; encryption, name binding and telemetry stay here.
 *  - ProtectedCacheCollection: several read-only caches behind one lookup, checked in order.
 *
 * Every value is encrypted under its key ring's current key when stored, and records that key's
 * version, so a cache follows key rotation while earlier values stay readable. Every value is bound
 * to its name (see cacheAad); names match ignoring ASCII case only. Only ciphertext is retained.
 */
export { EmptyValueError, type CacheSource } from './store.js';
export { ProtectedCache, ReadOnlyProtectedCache, type ProtectedCacheOptions } from './cache.js';
export { ProtectedCacheCollection } from './collection.js';

/**
 * HkdfGuard's protected caches - the Node port of the .NET HkdfGuard.Cache library and the
 * ProtectedCacheBase from HkdfGuard.Abstractions:
 *
 *  - ProtectedCache: read/write; values are added by the application.
 *  - ReadOnlyProtectedCache: filled on demand from a CacheSource, such as a secret store. A backend
 *    supplies only the source; encryption, name binding and telemetry stay here.
 *  - ProtectedCacheCollection: several read-only caches behind one lookup, checked in order.
 *  - FilePerSecretCache: read-only, over a local folder of one already-encrypted file per secret,
 *    each read through @runsecure/hkdfguard-securefile's readTrustedFile on its first lookup,
 *    authenticated under its file name (configurationPurpose(name)) and cached still encrypted, as
 *    the file holds it. Names that can't be a file name inside the folder are reported missing.
 *  - RemoteSecretCache: the base of the caches over a remote secret store (the AWS Secrets Manager,
 *    Azure Key Vault, Google Secret Manager and HashiCorp Vault packages). A subclass supplies
 *    isValidName and fetch - one read of one secret by name - and hands what it read to the
 *    SecretValueSink it is given: the whole value, keys ("app-config#api-key"), or a JSON object's
 *    members as keys. One fetch per uncached secret, shared by concurrent lookups; names are matched
 *    as the store matches them (SecretNameMatching). Each fetch is a hkdfguard.cache.populate span.
 *  - SecretJsonBody: takes a secret out of a JSON HTTP response body (bytes or a stream of chunks)
 *    into the sink before an SDK can turn it into a string, returning the body redacted for the SDK
 *    to parse; captureKeys hands every member of a nested object over as a key. ErrorResponseBody
 *    reads the messages out of an error body with the same strict JSON reader, and
 *    InvalidSecretDataError reports a body or secret that can't be trusted, never quoting it.
 *
 * Every value is encrypted under its key ring's current key when stored, and records that key's
 * version, so a cache follows key rotation while earlier values stay readable. A value expires with
 * its key: once the ring retires that version, the name is a miss - a pull-through cache fetches it
 * again under the current key, and a read/write cache accepts a new add. Every value is bound to its
 * name (see cacheAad); names match ignoring ASCII case only. Only ciphertext is retained, and every
 * buffer of the library's that held plaintext is zeroed on every path.
 *
 * FilePerSecretCache is the exception to the paragraph above: its values were encrypted where they
 * were written, so it keeps each exactly as its file holds it, under the key version it names, for
 * the life of the cache. Each is bound by configurationPurpose(name), as pipeline-protected values
 * are, and names are matched exactly.
 */
export { EmptyValueError, type CacheSource } from './store.js';
export { ProtectedCache, ReadOnlyProtectedCache, type ProtectedCacheOptions } from './cache.js';
export { ProtectedCacheCollection } from './collection.js';
export { FilePerSecretCache } from './filepersecret.js';
export { RemoteSecretCache, SecretNameMatching, SecretValueSink } from './remote.js';
export { SecretJsonBody, type SecretJsonCaptureOptions } from './secretjson.js';
export { ErrorResponseBody } from './errorbody.js';
export { InvalidSecretDataError } from './errors.js';
export type { ResponseBody } from './body.js';

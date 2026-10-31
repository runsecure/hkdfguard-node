/**
 * A protected read-only cache over Google Cloud Secret Manager - the Node port of the .NET
 * HkdfGuard.Cache.GoogleSecretManager library. Each secret is read on its first lookup with
 * AccessSecretVersion, through a SecretManagerServiceClient (@google-cloud/secret-manager) the
 * application creates and owns, taken out of the response before the client can make it a message,
 * encrypted under the key ring's current key and cached only as ciphertext. A payload holding a JSON
 * object is also cached member by member, as "secret-id#key".
 *
 * ```ts
 * import { SecretManagerServiceClient } from '@google-cloud/secret-manager';
 * import { GoogleSecretManagerSecretCache } from '@runsecure/hkdfguard-cache-googlesecretmanager';
 *
 * const client = new SecretManagerServiceClient();  // the application's: Application Default Credentials
 * const cache = new GoogleSecretManagerSecretCache(client, 'my-project', ring);
 * const password = new Uint8Array((await cache.maxDecryptedLength('Db-Login#password')) ?? 0);
 * const length = await cache.decrypt('Db-Login#password', password);
 * ```
 */
export {
  GoogleSecretManagerSecretCache, type GoogleSecretManagerSecretCacheCreateOptions, type GoogleSecretManagerSecretCacheOptions,
  type SecretManagerClientOptions,
} from './cache.js';
export { InvalidSecretDataError } from '@runsecure/hkdfguard-cache';

/**
 * A protected read-only cache over one JSON file holding every secret - the Node port of the .NET
 * HkdfGuard.Cache.JsonSecretsFile library. The file is what a provisioning pipeline's
 * SecretPipelineWriter.writeJsonSecrets (@runsecure/hkdfguard-pipeline) writes, or writeJsonSecretsTo
 * streams to a remote command: a single object mapping each secret's name to its already-encrypted
 * value, each bound to its name (configurationPurpose(name)).
 *
 *  - JsonSecretsFileReadOnlyCache: the cache. The whole file is read through
 *    @runsecure/hkdfguard-securefile's readTrustedFile on the first lookup, every value authenticated
 *    under its name - any failure refuses the whole file, which is read again next time - and the
 *    values kept still encrypted. Names match ignoring ASCII case, and follow FilePerSecretCache's
 *    name rule; any other name is reported missing, as is every name while the file is missing.
 *  - JsonSecretsFileCacheOptions: the longest file read (1 MiB by default) and a logger.
 *  - InvalidSecretDataError (from @runsecure/hkdfguard-cache): the file isn't exactly the secrets
 *    object - not UTF-8 JSON, not an object, a name that isn't a secret's name or appears twice in
 *    any case, a value that isn't a non-empty string.
 *
 * ```ts
 * const deployers = new KeyFileTrust({ unixUserIds: [1001] }); // the account that deploys secrets
 * const secrets = new JsonSecretsFileReadOnlyCache('/etc/myapp/secrets.json', deployers, ring, new DefaultFormatProvider());
 * const result = new Uint8Array((await secrets.maxDecryptedLength('prod__app__password')) ?? 0);
 * const written = await secrets.decrypt('prod__app__password', result); // 0 if the file holds no such secret
 * ```
 */
export { JsonSecretsFileReadOnlyCache, type JsonSecretsFileCacheOptions } from './cache.js';
export { InvalidSecretDataError } from '@runsecure/hkdfguard-cache';

/**
 * A protected read-only cache over AWS Secrets Manager - the Node port of the .NET
 * HkdfGuard.Cache.AwsSecretsManager library. Each secret is read with GetSecretValue on its first
 * lookup, through a SecretsManagerClient (@aws-sdk/client-secrets-manager, the AWS SDK for
 * JavaScript v3) the application creates, configures and owns; taken out of the response body by a
 * middleware on that one command before the SDK can make it a string; encrypted under the key ring's
 * current key; and cached only as ciphertext. A key/value secret is cached whole and by key
 * ("prod/app#password") from the one call. Secrets are never listed.
 *
 * ```ts
 * import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
 * import { AwsSecretsManagerSecretCache } from '@runsecure/hkdfguard-cache-awssecretsmanager';
 *
 * const secretsManager = new SecretsManagerClient({});  // the application's: credentials, region, retries
 * const cache = new AwsSecretsManagerSecretCache(secretsManager, ring);
 * const password = new Uint8Array(256);
 * const length = await cache.decrypt('prod/app#password', password);  // 0 if there is none
 * ```
 */
export { AwsSecretsManagerSecretCache, type GetSecretValueClient } from './cache.js';

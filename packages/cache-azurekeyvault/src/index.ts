/**
 * A protected read-only cache over the secrets in one Azure Key Vault - the Node port of the .NET
 * HkdfGuard.Cache.AzureKeyVault library. Each secret is read on its first lookup with Get Secret
 * (the identity needs only `get` on secrets, never `list`), encrypted under the key ring's current
 * key and cached only as ciphertext; a secret holding a JSON object is cached by key too
 * ("Db-Login#password"). The cache builds its own SecretClient (@azure/keyvault-secrets) with a
 * pipeline policy that takes the value out of the response body before the SDK can turn it into a
 * string, and hands the SDK the body with the value blanked.
 *
 * ```ts
 * import { DefaultAzureCredential } from '@azure/identity';
 * import { AzureKeyVaultSecretCache } from '@runsecure/hkdfguard-cache-azurekeyvault';
 *
 * const secrets = new AzureKeyVaultSecretCache('https://myvault.vault.azure.net/', new DefaultAzureCredential(), keyRing);
 * const length = await secrets.maxDecryptedLength('Db-Login#password');
 * ```
 */
export { AzureKeyVaultSecretCache, type AzureKeyVaultSecretCacheOptions, type KeyVaultCredential } from './cache.js';

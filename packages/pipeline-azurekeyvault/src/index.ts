/**
 * A secret pipeline writer over the secrets in one Azure Key Vault - the Node port of the .NET
 * HkdfGuard.Pipeline.AzureKeyVault library: pulls a fixed list of secrets with Get Secret (the
 * identity needs only `get` on secrets, never `list`), through a SecretClient
 * (@azure/keyvault-secrets) of its own whose pipeline policy takes each value out of the response
 * body before the SDK can turn it into a string; encrypts every value at once with a
 * PipelineDataProtector bound to its file name; and writes one file per secret - the folder layout
 * FilePerSecretCache reads. A secret holding a JSON object is read by key too ("Db-Login#password").
 * No key ring is involved.
 *
 * ```ts
 * import { DefaultAzureCredential } from '@azure/identity';
 * import { AesGcmPipelineDataProtector } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
 * import { DefaultFormatProvider } from '@runsecure/hkdfguard-dek';
 * import { AzureKeyVaultSecretPipelineWriter } from '@runsecure/hkdfguard-pipeline-azurekeyvault';
 *
 * const protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), 3);
 * const writer = new AzureKeyVaultSecretPipelineWriter('https://myvault.vault.azure.net/', new DefaultAzureCredential(), protector,
 *   ['Db-Login#username', 'Db-Login#password', 'Api-Key']);
 * try {
 *   await writer.pullSecrets();
 *   await writer.writeProtectedSecretFiles('/etc/hkdfguard/secrets/myapp');
 *   // Then hand protector.keyBase64() to the wrap tool on standard input, and register the key at version 3.
 * } finally {
 *   await writer.close();
 * }
 * ```
 */
export { AzureKeyVaultSecretPipelineWriter, type AzureKeyVaultSecretPipelineWriterOptions, type KeyVaultCredential } from './writer.js';
export { InvalidSecretDataError, SecretsNotFoundError } from '@runsecure/hkdfguard-pipeline';

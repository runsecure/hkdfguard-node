/**
 * A KeyWrapper over two Azure Key Vault keys - the Node port of the .NET
 * HkdfGuard.KeyWrapping.AzureKeyVault library. Each DEK is wrapped under an RSA key (RSA-OAEP-256)
 * and the result signed by a separate EC P-256 key (ES256); unwrap verifies the signature before it
 * unwraps anything, so only a principal allowed to sign can make a key file the application accepts.
 * Calls go through the Azure SDK for JavaScript (@azure/keyvault-keys), authorized by the
 * application's Azure credential. Key files are read only from where no untrusted account could
 * have written or replaced them (@runsecure/hkdfguard-securefile), and are byte for byte those of
 * the .NET, Java and Python wrappers.
 *
 * ```ts
 * import { DefaultAzureCredential } from '@azure/identity';
 * import { AzureKeyVaultKeyWrapper } from '@runsecure/hkdfguard-keywrapping-azurekeyvault';
 *
 * const wrapper = new AzureKeyVaultKeyWrapper('https://myvault.vault.azure.net/keys/myapp-wrap',
 *   'https://myvault.vault.azure.net/keys/myapp-sign', new DefaultAzureCredential(), { context: 'com.example.myapp' });
 * ```
 */
export {
  AzureKeyVaultKeyWrapper, GENERATED_KEY_LENGTH, MAX_PLAINTEXT_LENGTH, type AzureKeyVaultKeyWrapperOptions, type KeyVaultCredential,
} from './wrapper.js';
export { AzureKeyVaultError } from './errors.js';
export { KeyFileError, KeyFileTrust, type KeyFileTrustOptions } from '@runsecure/hkdfguard-securefile';

/**
 * A secret pipeline writer over HashiCorp Vault's KV secrets engine - the Node port of the .NET
 * HkdfGuard.Pipeline.HashiCorpVault library: pulls a fixed list of secrets through Node's own
 * http/https client, parses each straight from the response stream before it can become a string,
 * encrypts every value at once with a PipelineDataProtector bound to its file name, and writes one
 * file per secret - the folder layout FilePerSecretCache reads. No key ring is involved.
 *
 *  - HashiCorpVaultSecretPipelineWriter: the writer. A name is a secret's path and the key to read,
 *    "myapp/db#password"; "myapp/db" reads the default key ("value"). KV version 2 (the default) or
 *    1, any mount, an Enterprise namespace.
 *  - HashiCorpVaultPipelineOptions: the KV version and default key, and - shared with every HkdfGuard
 *    Vault integration (VaultConnectionOptions) - the mount, namespace, timeout, retries and the
 *    https agent or the TLS (VaultTlsOptions, PEM only: a PKCS#12 password needs a key ring).
 *  - VaultTokenSource / StaticVaultTokenSource: supply the token, in plaintext copied into a buffer
 *    zeroed after each read - a pipeline has no key ring to protect it with.
 *  - VaultRequestError: Vault refused a read (403, a 404 naming an error, 503 sealed...), with its
 *    status and errors, never the token.
 *
 * ```ts
 * import { AesGcmPipelineDataProtector } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
 * import { DefaultFormatProvider } from '@runsecure/hkdfguard-dek';
 * import { HashiCorpVaultSecretPipelineWriter, StaticVaultTokenSource } from '@runsecure/hkdfguard-pipeline-hashicorpvault';
 *
 * const protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), 3);
 * const token = new StaticVaultTokenSource(process.env.VAULT_TOKEN!);
 * const writer = new HashiCorpVaultSecretPipelineWriter('https://vault.example.com:8200', token, protector,
 *   ['myapp/db#username', 'myapp/db#password', 'myapp/api']);
 * try {
 *   await writer.pullSecrets();
 *   await writer.writeProtectedSecretFiles('/etc/hkdfguard/secrets/myapp');
 *   // Then hand protector.keyBase64() to the wrap tool on standard input, and register the key at version 3.
 * } finally {
 *   await writer.close();
 *   token.close();
 * }
 * ```
 */
export { HashiCorpVaultSecretPipelineWriter } from './writer.js';
export { VaultKvVersion, type HashiCorpVaultPipelineOptions } from './options.js';
// What a writer is created with, and fails with, from the package every HkdfGuard Vault integration shares.
export {
  StaticVaultTokenSource, VaultRequestError, VaultTlsOptions, type VaultConnectionOptions, type VaultTokenSource,
} from '@runsecure/hkdfguard-integration-hashicorpvault';
export { InvalidSecretDataError, SecretsNotFoundError } from '@runsecure/hkdfguard-pipeline';

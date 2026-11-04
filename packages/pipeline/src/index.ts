/**
 * The shared base of HkdfGuard's secret pipeline writers - the Node port of the .NET
 * HkdfGuard.Pipeline library. A provisioning pipeline pulls a fixed list of secrets from a secret
 * store, encrypts each at once with a PipelineDataProtector (@runsecure/hkdfguard-abstractions)
 * bound to its file name, keeps only the ciphertext, and writes one file per secret - the folder
 * layout FilePerSecretCache (@runsecure/hkdfguard-cache) reads at runtime. No key ring is involved:
 * the protector's key is the only one, handed to the native platform's wrap process once the files
 * are written.
 *
 *  - SecretPipelineWriter: the base every store's writer extends - names ("name" or "name#key"),
 *    grouping so each secret is read once, file names ('/' and '#' become "__"), encrypting, keeping
 *    and writing. A store's writer supplies only readSecret. Implemented by
 *    @runsecure/hkdfguard-pipeline-hashicorpvault, -awssecretsmanager, -azurekeyvault and
 *    -googlesecretmanager, which never depend on the runtime caches.
 *  - PinnedBody: reads a response body that holds a secret into a buffer of the library's own.
 *  - SecretsNotFoundError: a pull found no value for some secrets - every one is named, and the rest
 *    are kept. InvalidSecretDataError (from the cache package): a secret, or a response holding one,
 *    can't be trusted as it was read - not UTF-8 text, not the store's JSON, or a key held twice.
 *
 * ```ts
 * const writer = new HashiCorpVaultSecretPipelineWriter(address, tokenSource, protector, ['myapp/db#password', 'myapp/api']);
 * try {
 *   await writer.pullSecrets();
 *   await writer.writeProtectedSecretFiles('/etc/hkdfguard/secrets/myapp');
 * } finally {
 *   await writer.close();
 * }
 * // Then hand protector.keyBase64() to the wrap tool on standard input, and register the key at its version.
 * ```
 */
export { SecretPipelineWriter, type SecretRequest } from './writer.js';
export { PinnedBody } from './body.js';
export { SecretsNotFoundError } from './errors.js';
export { InvalidSecretDataError } from '@runsecure/hkdfguard-cache';

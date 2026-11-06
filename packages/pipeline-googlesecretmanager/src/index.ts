/**
 * A secret pipeline writer over Google Cloud Secret Manager - the Node port of the .NET
 * HkdfGuard.Pipeline.GoogleSecretManager library: pulls a fixed list of secrets with
 * AccessSecretVersion (their latest versions), through a SecretManagerServiceClient
 * (@google-cloud/secret-manager) - the caller's, or one of its own from create() - taking each
 * payload out of the response before the client can make it a message; checks it against its CRC32C
 * and the secret it names; encrypts every value at once with a PipelineDataProtector bound to its
 * file name; and writes one file per secret - the folder layout FilePerSecretCache reads. A payload
 * holding a JSON object is read by key too ("db-login#password"). No key ring is involved.
 *
 * ```ts
 * import { AesGcmPipelineDataProtector } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
 * import { DefaultFormatProvider } from '@runsecure/hkdfguard-dek';
 * import { GoogleSecretManagerSecretPipelineWriter } from '@runsecure/hkdfguard-pipeline-googlesecretmanager';
 *
 * const protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), 3);
 * const writer = GoogleSecretManagerSecretPipelineWriter.create('my-project', protector,
 *   ['db-login#username', 'db-login#password', 'api-key']);  // Application Default Credentials
 * try {
 *   await writer.pullSecrets();
 *   await writer.writeProtectedSecretFiles('/etc/hkdfguard/secrets/myapp');
 *   // Then hand protector.keyBase64() to the wrap tool on standard input, and register the key at version 3.
 * } finally {
 *   await writer.close();
 * }
 * ```
 */
export {
  GoogleSecretManagerSecretPipelineWriter, type GoogleSecretManagerSecretPipelineWriterCreateOptions,
  type GoogleSecretManagerSecretPipelineWriterOptions, type SecretManagerClientOptions,
} from './writer.js';
export { InvalidSecretDataError, SecretsNotFoundError } from '@runsecure/hkdfguard-pipeline';

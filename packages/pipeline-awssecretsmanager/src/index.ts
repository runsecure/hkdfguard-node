/**
 * A secret pipeline writer over AWS Secrets Manager - the Node port of the .NET
 * HkdfGuard.Pipeline.AwsSecretsManager library: pulls a fixed list of secrets with GetSecretValue,
 * through a SecretsManagerClient (@aws-sdk/client-secrets-manager, the AWS SDK for JavaScript v3) -
 * the caller's, or one of its own from create(); takes each out of the response body by a middleware
 * on that one command before the SDK can make it a string; encrypts every value at once with a
 * PipelineDataProtector bound to its file name; and writes one file per secret - the folder layout
 * FilePerSecretCache reads. A key/value secret is read whole and by key ("prod/app#password") from
 * the one call. Secrets are never listed, and no key ring is involved.
 *
 * ```ts
 * import { AesGcmPipelineDataProtector } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
 * import { DefaultFormatProvider } from '@runsecure/hkdfguard-dek';
 * import { AwsSecretsManagerSecretPipelineWriter } from '@runsecure/hkdfguard-pipeline-awssecretsmanager';
 *
 * const protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), 3);
 * const writer = AwsSecretsManagerSecretPipelineWriter.create(protector, ['prod/app#username', 'prod/app#password', 'prod/api-key']);
 * try {
 *   await writer.pullSecrets();
 *   await writer.writeProtectedSecretFiles('/etc/hkdfguard/secrets/myapp');
 *   // Then hand protector.keyBase64() to the wrap tool on standard input, and register the key at version 3.
 * } finally {
 *   await writer.close();
 * }
 * ```
 */
export { AwsSecretsManagerSecretPipelineWriter, type GetSecretValueClient } from './writer.js';
export { InvalidSecretDataError, SecretsNotFoundError } from '@runsecure/hkdfguard-pipeline';

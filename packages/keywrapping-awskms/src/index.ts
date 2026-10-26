/**
 * A KeyWrapper over one symmetric AWS KMS key - the Node port of the .NET
 * HkdfGuard.KeyWrapping.AwsKms library. DEKs are wrapped with Encrypt, revealed with Decrypt (the key
 * pinned) and generated with GenerateDataKeyWithoutPlaintext, through a KMSClient
 * (@aws-sdk/client-kms, the AWS SDK for JavaScript v3) the application creates, configures and owns.
 * Key files are read only from where no untrusted account could have written or replaced them
 * (@runsecure/hkdfguard-securefile), since anyone who may call kms:Encrypt could otherwise choose the
 * DEK new data is encrypted under.
 *
 * ```ts
 * import { KMSClient } from '@aws-sdk/client-kms';
 * import { AwsKmsKeyWrapper } from '@runsecure/hkdfguard-keywrapping-awskms';
 *
 * const kms = new KMSClient({});  // the application's: credentials, region, retries
 * const wrapper = new AwsKmsKeyWrapper(kms, 'arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab',
 *   { encryptionContext: { purpose: 'com.example.myapp' } });
 * ```
 */
export {
  AwsKmsKeyWrapper, GENERATED_KEY_LENGTH, MAX_PLAINTEXT_LENGTH, type AwsKmsKeyWrapperOptions, type KmsClient, type KmsCommand,
} from './wrapper.js';
export { AwsKmsError } from './errors.js';
export { KeyFileError, KeyFileTrust, type KeyFileTrustOptions } from '@runsecure/hkdfguard-securefile';

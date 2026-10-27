/**
 * A KeyWrapper over one symmetric Google Cloud KMS key - the Node port of the .NET
 * HkdfGuard.KeyWrapping.GoogleKms library. DEKs are wrapped with Encrypt and revealed with Decrypt
 * (the key pinned), each bound to a fixed HkdfGuard label and the application's context and
 * checksummed with CRC32C, through a KeyManagementServiceClient (@google-cloud/kms) the application
 * creates, configures and owns. Key files are read only from where no untrusted account could have
 * written or replaced them (@runsecure/hkdfguard-securefile), and are byte for byte those of the .NET,
 * Java and Python wrappers.
 *
 * ```ts
 * import { KeyManagementServiceClient } from '@google-cloud/kms';
 * import { GoogleKmsKeyWrapper } from '@runsecure/hkdfguard-keywrapping-googlekms';
 *
 * const kms = new KeyManagementServiceClient();  // the application's: Application Default Credentials
 * const wrapper = new GoogleKmsKeyWrapper(kms, 'projects/my-project/locations/us-east1/keyRings/myapp/cryptoKeys/myapp-wrap',
 *   { context: 'com.example.myapp' });
 * ```
 */
export {
  GoogleKmsKeyWrapper, GENERATED_KEY_LENGTH, MAX_CONTEXT_LENGTH, MAX_PLAINTEXT_LENGTH, type CloudKmsClient, type DecryptRequest,
  type EncryptRequest, type GoogleKmsKeyWrapperOptions,
} from './wrapper.js';
export { GoogleKmsError } from './errors.js';
export { KeyFileError, KeyFileTrust, type KeyFileTrustOptions } from '@runsecure/hkdfguard-securefile';

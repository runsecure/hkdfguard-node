import { HkdfGuardError } from '@runsecure/hkdfguard-abstractions';

/**
 * An AWS KMS call that failed - KMS refused it, or it could not be made (no credentials, KMS
 * unreachable) - or that answered with something no wrapped DEK can be, or a wrapped DEK refused
 * before KMS was called because no ciphertext this wrapper produced is that size. The message names
 * the operation, the key, and - for a refusal - KMS's error name and the HTTP status; the AWS SDK's
 * own error is the `cause`.
 *
 * The Node port of the .NET wrapper's CryptographicException (Python's CryptographicError): the
 * abstractions package has no shared error for a failed key-wrapping operation, so like the native
 * key wrapper's StatusError this is the package's own.
 */
export class AwsKmsError extends HkdfGuardError {
  constructor(
    /** "wrap", "unwrap" or "generate-and-wrap". */
    readonly operation: string,
    /** The key the wrapper was created for, as given. */
    readonly keyId: string,
    message: string,
    options?: { cause?: unknown },
  ) {
    super('ERR_HKDFGUARD_AWS_KMS', message, options);
  }
}

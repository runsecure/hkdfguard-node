import { HkdfGuardError } from '@runsecure/hkdfguard-abstractions';

/**
 * A Cloud KMS call that failed - Cloud KMS refused it, or it could not be made (a credential that
 * can't get a token, an unreachable service, retries that ran out of time) - or that answered with
 * something no wrapped DEK can be: a response corrupted in transit, or for another key. Also a
 * wrapped DEK refused before Cloud KMS was called because no ciphertext this wrapper produced is that
 * size. The message names the operation, the key, and - for a refusal - the gRPC status and Google's
 * description; the client's own error is the `cause`.
 *
 * The Node port of the .NET and Java wrappers' CryptographicException (Python's CryptographicError),
 * and the counterpart of AwsKmsError and AzureKeyVaultError: the abstractions package has no shared
 * error for a failed key-wrapping operation, so this is the package's own.
 */
export class GoogleKmsError extends HkdfGuardError {
  constructor(
    /** "wrap" (for wrap and generateAndWrap) or "unwrap". */
    readonly operation: string,
    /** The key the wrapper was created for: its resource name. */
    readonly keyName: string,
    message: string,
    options?: { cause?: unknown },
  ) {
    super('ERR_HKDFGUARD_GOOGLE_KMS', message, options);
  }
}

import { HkdfGuardError } from '@runsecure/hkdfguard-abstractions';

/**
 * An Azure Key Vault call that failed - Key Vault refused it, or it could not be made (a credential
 * that can't get a token, an unreachable vault, a key the SDK refuses to use) - or that answered with
 * something no wrapped DEK can be built from, or a wrapped DEK refused because it isn't one this
 * wrapper wrote or its signature doesn't verify. The message names the operation, the key, and - for
 * a refusal - Key Vault's error code and the HTTP status; the Azure SDK's own error is the `cause`.
 *
 * The Node port of the .NET wrapper's CryptographicException (Python's CryptographicError), and the
 * counterpart of the AWS KMS key wrapper's AwsKmsError: the abstractions package has no shared error
 * for a failed key-wrapping operation, so this is the package's own.
 */
export class AzureKeyVaultError extends HkdfGuardError {
  constructor(
    /** "wrap", "sign", "verify" or "unwrap". */
    readonly operation: string,
    /** The key the failing step was for: its identifier, with the version used once one is known. */
    readonly keyId: string,
    message: string,
    options?: { cause?: unknown },
  ) {
    super('ERR_HKDFGUARD_AZURE_KEY_VAULT', message, options);
  }
}

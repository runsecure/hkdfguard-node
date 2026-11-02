import { HkdfGuardError } from '@runsecure/hkdfguard-abstractions';

/**
 * A Vault transit call that failed - Vault refused it (403 for a token without the policy, 400 for a
 * ciphertext that doesn't authenticate, 503 while sealed...), or it could not be made (connection
 * refused, DNS, no answer within the timeout, once the retries are spent) - or that answered with
 * something no wrapped DEK can be: an answer that isn't Vault's, one that says Vault ignored a
 * parameter, or one over the size limit. Also a wrapped DEK refused before Vault was called because
 * it isn't a Vault ciphertext of a size this wrapper produces. The message names the operation, the
 * key, and - for a refusal - Vault's status and the errors it listed (`Vault answered 400
 * BadRequest: cipher: message authentication failed`), never the token; Node's network error, or the
 * DOMException named TimeoutError for an attempt that timed out, is the `cause`.
 *
 * The Node port of the .NET wrapper's CryptographicException (whose inner HttpRequestException
 * carries the status, here {@link statusCode}), and the counterpart of AwsKmsError, AzureKeyVaultError
 * and GoogleKmsError: the abstractions package has no shared error for a failed key-wrapping
 * operation, so this is the package's own.
 */
export class HashiCorpVaultTransitError extends HkdfGuardError {
  constructor(
    /** "wrap", "unwrap" or "generate-and-wrap". */
    readonly operation: string,
    /** The transit key the wrapper was created for. */
    readonly keyName: string,
    message: string,
    options?: {
      cause?: unknown;
      /** The HTTP status Vault answered with, when it answered. */
      statusCode?: number;
    },
  ) {
    super('ERR_HKDFGUARD_VAULT_TRANSIT', message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.statusCode = options?.statusCode;
  }

  /** The HTTP status Vault answered with; undefined if it didn't answer, or answered with something unusable. */
  readonly statusCode: number | undefined;
}

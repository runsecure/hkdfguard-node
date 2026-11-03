import { HkdfGuardError } from '@runsecure/hkdfguard-abstractions';

/**
 * A request to Vault that didn't succeed: Vault answered with a status the caller can't use - 403
 * for a token that is invalid or not allowed the path, a 404 naming an error (no such mount), 503
 * while Vault is sealed, a redirect - or, with no {@link statusCode}, no answer came. The counterpart
 * of Java's VaultRequestException and Python's VaultRequestError. Its message names the request and
 * Vault's status and errors, never the token; Node's network error, if any, is the `cause`.
 */
export class VaultRequestError extends HkdfGuardError {
  /**
   * @param message what was requested, and Vault's answer
   * @param options the HTTP status Vault answered with, if it answered, and the failure behind this one
   */
  constructor(message: string, options?: { statusCode?: number; cause?: unknown }) {
    super('ERR_HKDFGUARD_VAULT_REQUEST', message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.statusCode = options?.statusCode;
  }

  /** The HTTP status Vault answered with; undefined if it didn't answer. */
  readonly statusCode: number | undefined;

  /**
   * Whether another attempt may be answered differently: no answer at all, 429 (rate limited) or a
   * 5xx other than 501 (Vault answers 503 while sealed or electing a leader).
   */
  get isTransient(): boolean {
    const status = this.statusCode;
    return status === undefined || status === 429 || (status >= 500 && status !== 501);
  }
}

import { HkdfGuardError } from '@runsecure/hkdfguard-abstractions';

/**
 * Vault answered a read with a status other than success or "nothing at this path": 403 for a token
 * that is invalid or not allowed to read the path, a 404 naming an error (no such mount), 503 while
 * Vault is sealed, a redirect, and so on - the counterpart of Java's VaultRequestException, Python's
 * VaultRequestError and the HttpRequestException .NET's cache throws. Its message holds the path
 * read, the status and the errors Vault listed, never the token.
 */
export class VaultRequestError extends HkdfGuardError {
  /**
   * @param message what was read, and Vault's answer
   * @param statusCode the HTTP status Vault answered with
   */
  constructor(message: string, readonly statusCode: number) {
    super('ERR_HKDFGUARD_VAULT_REQUEST', message);
  }

  /**
   * Whether another attempt may be answered differently: 429 (rate limited) or a 5xx other than 501
   * (Vault answers 503 while sealed or electing a leader).
   */
  get isTransient(): boolean {
    return this.statusCode === 429 || (this.statusCode >= 500 && this.statusCode !== 501);
  }
}

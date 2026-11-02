import { InvalidArgumentError, wipe } from '@runsecure/hkdfguard-abstractions';

/** The longest token a {@link VaultTokenSource} may supply, in bytes (ASCII characters). */
export const MAX_TOKEN_LENGTH = 2048;

/**
 * Supplies the Vault token every transit request is made with. Getting that token - logging in with
 * AppRole, Kubernetes or a certificate, renewing it, replacing it before it expires - is the
 * source's job, not the wrapper's, so any auth method can sit behind the wrapper.
 * {@link StaticVaultTokenSource} is a token you already hold.
 *
 * The token is copied, as ASCII bytes, into a buffer the wrapper owns and zeroes once the call is
 * done, rather than returned as a string, which JavaScript can't erase. (The Vault cache's
 * VaultTokenProvider hands its token over protected by the key ring instead; a key wrapper can't,
 * since it runs before there is a key ring.)
 *
 * Asked once per wrap, unwrap or generateAndWrap - not per retry. A token that is empty, over
 * {@link MAX_TOKEN_LENGTH} or isn't printable ASCII without spaces fails the call with an
 * HkdfGuardError (ERR_HKDFGUARD_INVALID_VAULT_TOKEN), quoting nothing. The wrapper waits at most its
 * timeoutMs for the source; one that takes longer fails the call with a TimeoutError. A source's
 * failure fails the call as it is, and isn't retried: retrying a login is the source's own business.
 */
export interface VaultTokenSource {
  /**
   * Copies the token to make the next request with into `destination`, as ASCII bytes, and returns
   * how many it wrote.
   * @param destination where to write the token: {@link MAX_TOKEN_LENGTH} bytes
   * @param signal aborted once the wrapper's timeout has passed, or the call that asked is aborted:
   *   pass it on to any call the source makes
   */
  copyToken(destination: Uint8Array, signal: AbortSignal): Promise<number> | number;
}

/**
 * A token issued elsewhere - VAULT_TOKEN, say - held in a buffer of its own and zeroed on
 * {@link close}. Nothing renews or replaces it, so once it expires or is revoked every request fails
 * with 403.
 */
export class StaticVaultTokenSource implements VaultTokenSource {
  // Buffer.alloc, never the shared pool allocUnsafe draws from, so zeroing it reaches every copy this class made.
  readonly #token: Buffer;

  /**
   * @param token the token, copied. A string can't be erased: read it from the environment once,
   *   here, and keep no other reference to it - or hand over its bytes, and zero them once this returns.
   * @throws InvalidArgumentError token isn't a string or a Uint8Array, is empty, is over
   *   MAX_TOKEN_LENGTH, or isn't printable ASCII without spaces
   */
  constructor(token: string | Uint8Array) {
    if (typeof token !== 'string' && !(token instanceof Uint8Array)) throw new InvalidArgumentError('token must be a string or a Uint8Array.');
    if (!isValidToken(token) || token.length > MAX_TOKEN_LENGTH) {
      throw new InvalidArgumentError(`A Vault token is 1-${MAX_TOKEN_LENGTH} printable ASCII characters, with no spaces.`);
    }
    this.#token = Buffer.alloc(token.length);
    // Checked above - printable ASCII - so latin1 is the token exactly.
    if (typeof token === 'string') this.#token.write(token, 'latin1');
    else this.#token.set(token);
  }

  /** @throws InvalidArgumentError destination is too small for the token */
  copyToken(destination: Uint8Array): number {
    if (!(destination instanceof Uint8Array) || destination.length < this.#token.length) {
      throw new InvalidArgumentError(`The token is ${this.#token.length} characters; destination holds ${destination?.length}.`);
    }
    destination.set(this.#token);
    return this.#token.length;
  }

  /** Zeroes the token. A request made afterwards fails, its token no longer one. Safe to call more than once. */
  close(): void {
    wipe(this.#token);
  }
}

/** Whether `token` can go in a header: non-empty printable ASCII, with no spaces. */
export function isValidToken(token: string | Uint8Array): boolean {
  if (token.length === 0) return false;
  for (let i = 0; i < token.length; i++) {
    const code = typeof token === 'string' ? token.charCodeAt(i) : token[i]!;
    if (code < 0x21 || code > 0x7e) return false;
  }
  return true;
}

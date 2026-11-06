import { InvalidArgumentError, wipe, type DataProtector } from '@runsecure/hkdfguard-abstractions';

/** The longest token a {@link VaultTokenSource} may supply, in bytes (ASCII characters). */
export const MAX_TOKEN_LENGTH = 2048;

/**
 * The purpose to create the Vault client's token protector with -
 * `keyRing.createProtector(TOKEN_PURPOSE)` - so a token protected for the client can't be decrypted
 * as anything else, nor anything else as it. (The secret cache has a purpose of its own,
 * HashiCorpVaultSecretCache.TOKEN_PURPOSE.)
 */
export const TOKEN_PURPOSE = 'HkdfGuard.Integration.HashiCorpVault.Token';

/**
 * Supplies the Vault token every request of an integration that runs before there is a key ring -
 * the transit key wrapper - is made with. Getting that token - logging in with AppRole, Kubernetes or
 * a certificate, renewing it, replacing it before it expires - is the source's job, not the
 * integration's, so any auth method can sit behind it. {@link StaticVaultTokenSource} is a token you
 * already hold.
 *
 * The token is copied, as ASCII bytes, into a buffer the integration owns and zeroes once the call is
 * done, rather than returned as a string, which JavaScript can't erase. ({@link VaultTokenProvider}
 * hands its token over protected by the key ring instead, for an integration that has one.)
 *
 * Asked once per call - not per retry. A token that is empty, over {@link MAX_TOKEN_LENGTH} or isn't
 * printable ASCII without spaces fails the call with an HkdfGuardError
 * (ERR_HKDFGUARD_INVALID_VAULT_TOKEN), quoting nothing. The integration waits at most its timeoutMs
 * for the source; one that takes longer fails the call with a TimeoutError. A source's failure fails
 * the call as it is, and isn't retried: retrying a login is the source's own business.
 */
export interface VaultTokenSource {
  /**
   * Copies the token to make the next request with into `destination`, as ASCII bytes, and returns
   * how many it wrote.
   * @param destination where to write the token: {@link MAX_TOKEN_LENGTH} bytes
   * @param signal aborted once the integration's timeout has passed, or the call that asked is
   *   aborted: pass it on to any call the source makes
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

/**
 * Supplies the Vault token every request of an integration with a key ring - the Vault client, the
 * secret cache - is made with, protected: as that integration's token protector encrypted it
 * (`tokenProtector.encrypt(token)`), never the token itself. Getting that token - logging in with
 * AppRole, Kubernetes or a certificate, renewing it, replacing it before it expires - is the
 * provider's job, so any auth method can sit behind it. {@link StaticVaultToken} is a token you
 * already hold.
 *
 * Asked once per call - for the cache, once per fetch; the integration never keeps the token, and
 * decrypts it only to put it in that call's requests. A token that isn't protected so fails the
 * call. The integration waits at most its timeoutMs for the provider; one that takes longer fails the
 * call with a TimeoutError. A provider's failure fails the call as it is, and isn't retried: retrying
 * a login is the provider's own business.
 */
export interface VaultTokenProvider {
  /**
   * The token to make the next request with, protected by the integration's token protector.
   * @param signal aborted once the integration's timeout has passed, or the call that asked is
   *   aborted: pass it on to any call the provider makes
   */
  getToken(signal: AbortSignal): Promise<string> | string;
}

/**
 * A token issued elsewhere - VAULT_TOKEN, say - held only in protected form. Nothing renews or
 * replaces it, so once it expires or is revoked every request fails with 403.
 */
export class StaticVaultToken implements VaultTokenProvider {
  readonly #protectedToken: string;

  /**
   * @param protectedToken the token as the integration's token protector protected it
   *   (`tokenProtector.encrypt(token)`), never the token itself; see {@link protect}
   * @throws TypeError protectedToken isn't a string
   * @throws InvalidArgumentError protectedToken is empty or whitespace
   */
  constructor(protectedToken: string) {
    if (typeof protectedToken !== 'string') throw new TypeError('protectedToken must be a string.');
    if (protectedToken.trim() === '') throw new InvalidArgumentError('The protected token must not be empty or whitespace.');
    this.#protectedToken = protectedToken;
  }

  /**
   * Protects `token` with `tokenProtector` - the protector the integration is given - and holds only
   * the result. A string can't be erased: read the token from the environment once, here, and keep
   * no other reference to it - or hand over its bytes, and zero them once this returns.
   * @throws TypeError tokenProtector or token is missing
   * @throws InvalidArgumentError token is empty, or isn't printable ASCII without spaces
   */
  static protect(tokenProtector: DataProtector, token: string | Uint8Array): StaticVaultToken {
    if (tokenProtector === undefined || tokenProtector === null) throw new TypeError('tokenProtector must not be undefined.');
    if (typeof token !== 'string' && !(token instanceof Uint8Array)) throw new TypeError('token must be a string or a Uint8Array.');
    if (!isValidToken(token)) throw new InvalidArgumentError('A Vault token is printable ASCII, with no spaces.');
    return new StaticVaultToken(tokenProtector.encrypt(token));
  }

  getToken(): Promise<string> {
    return Promise.resolve(this.#protectedToken);
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

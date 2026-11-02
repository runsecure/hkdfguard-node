import { InvalidArgumentError, type DataProtector } from '@runsecure/hkdfguard-abstractions';

/**
 * Supplies the Vault token every read is made with, protected: as the cache's token protector
 * encrypted it (`tokenProtector.encrypt(token)`), never the token itself. Getting that token -
 * logging in with AppRole, Kubernetes or a certificate, renewing it, replacing it before it expires -
 * is the provider's job, not the cache's, so any auth method can sit behind the cache.
 * {@link StaticVaultToken} is a token you already hold.
 *
 * Asked once per fetch; the cache never keeps the token, and decrypts it only to put it in that
 * fetch's requests. A token that isn't protected so fails the fetch. The cache waits at most its
 * timeoutMs for the provider; one that takes longer fails the fetch with a TimeoutError. A
 * provider's failure fails the fetch as it is, and isn't retried: retrying a login is the provider's
 * own business.
 */
export interface VaultTokenProvider {
  /**
   * The token to make the next read with, protected by the cache's token protector.
   * @param signal aborted once the cache's timeout has passed, or the lookup that started the fetch
   *   is aborted: pass it on to any call the provider makes
   */
  getToken(signal: AbortSignal): Promise<string> | string;
}

/**
 * A token issued elsewhere - VAULT_TOKEN, say - held only in protected form. Nothing renews or
 * replaces it, so once it expires or is revoked every fetch fails with 403.
 */
export class StaticVaultToken implements VaultTokenProvider {
  readonly #protectedToken: string;

  /**
   * @param protectedToken the token as the cache's token protector protected it
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
   * Protects `token` with `tokenProtector` - the protector the cache is given - and holds only the
   * result. A string can't be erased: read the token from the environment once, here, and keep no
   * other reference to it - or hand over its bytes, and zero them once this returns.
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

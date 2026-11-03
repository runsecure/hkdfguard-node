import type { VaultConnectionOptions } from '@runsecure/hkdfguard-integration-hashicorpvault';
import type { KeyFileTrust } from '@runsecure/hkdfguard-securefile';

/**
 * The context a HashiCorpVaultTransitKeyWrapper binds, who may have written its key files, which
 * transit secrets engine it calls, and how it connects - the mount (default "transit", or e.g.
 * "transit/team-a"), namespace, timeout, retries, agent and TLS every HkdfGuard Vault integration
 * shares (VaultConnectionOptions). Every transit call the wrapper makes is safe to repeat, so each
 * is retried as those options say. Every member is optional; the values are checked by the
 * wrapper's constructor.
 */
export interface HashiCorpVaultTransitKeyWrapperOptions extends VaultConnectionOptions {
  /**
   * Bound into every wrapped DEK as Vault's associated_data, and required again to reveal it;
   * omitted or empty binds none. Use one value per application, so a key file made for one can't be
   * used by another that shares the key. Not secret, and must not hold one: at most
   * {@link MAX_CONTEXT_LENGTH} bytes in UTF-8.
   */
  readonly context?: string;

  /**
   * Who besides the operating system's administrators may have written a key file
   * HashiCorpVaultTransitKeyWrapper.readKeyFile reads; omitted trusts administrators only
   * (KeyFileTrust.administratorsOnly).
   */
  readonly keyFileTrust?: KeyFileTrust;
}

/** The longest context, in UTF-8 bytes. */
export const MAX_CONTEXT_LENGTH = 1024;

import type { Logger } from '@runsecure/hkdfguard-diagnostics';
import type { VaultConnectionOptions } from '@runsecure/hkdfguard-integration-hashicorpvault';

/** The version of a KV secrets engine, which decides its read path and response shape. */
export const VaultKvVersion = {
  /** KV version 1: one unversioned value per path, read at {mount}/{path}. */
  v1: 1,
  /** KV version 2: versioned secrets, read at {mount}/data/{path}; the latest version is read. */
  v2: 2,
} as const;

/** A {@link VaultKvVersion} value. */
export type VaultKvVersion = (typeof VaultKvVersion)[keyof typeof VaultKvVersion];

/**
 * Which KV secrets engine a HashiCorpVaultSecretCache reads, and how it connects - the mount (default
 * "secret", or e.g. "kv/team-a"), namespace, timeout, retries, agent and TLS every HkdfGuard Vault
 * integration shares (VaultConnectionOptions). A read that keeps failing transiently is retried as
 * those options say; a 404 naming an error isn't retried. Every member is optional; the values are
 * checked by the cache's constructor.
 */
export interface HashiCorpVaultSecretCacheOptions extends VaultConnectionOptions {
  /** The engine's version. Default {@link VaultKvVersion.v2}. */
  readonly kvVersion?: VaultKvVersion;

  /**
   * The key read from a secret looked up without one: "myapp/db" reads this key of the secret at
   * myapp/db, while "myapp/db#password" reads its password key. Default "value".
   */
  readonly defaultKey?: string;

  /** Receives a debug entry per fetched name while sensitive logging is enabled, and an error entry per failed fetch. */
  readonly logger?: Logger;
}

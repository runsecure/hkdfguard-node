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
 * Which KV secrets engine a HashiCorpVaultSecretPipelineWriter reads, and how it connects - the mount
 * (default "secret", or e.g. "kv/team-a"), namespace, timeout, retries, agent and TLS every HkdfGuard
 * Vault integration shares (VaultConnectionOptions; the limits are
 * @runsecure/hkdfguard-integration-hashicorpvault's MIN_RETRY_COUNT, MAX_RETRY_COUNT,
 * MAX_RETRY_DELAY_MS and MAX_TIMEOUT_MS). A read that keeps failing transiently is retried as those
 * options say; a 404 naming an error isn't retried. Every member is optional; the values are checked
 * by the writer's constructor.
 *
 * For mutual TLS give `tls` a PEM certificate and key: a password-protected PKCS#12 key store's
 * password is protected by a key ring, which a pipeline doesn't have yet.
 */
export interface HashiCorpVaultPipelineOptions extends VaultConnectionOptions {
  /** The engine's version. Default {@link VaultKvVersion.v2}. */
  readonly kvVersion?: VaultKvVersion;

  /**
   * The key read from a secret named without one: "myapp/db" reads this key of the secret at
   * myapp/db, while "myapp/db#password" reads its password key. Default "value".
   */
  readonly defaultKey?: string;
}

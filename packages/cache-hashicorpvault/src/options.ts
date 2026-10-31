import type { Agent } from 'node:http';
import type { Logger } from '@runsecure/hkdfguard-diagnostics';

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
 * Which KV secrets engine a HashiCorpVaultSecretCache reads, and how it connects. Every member is
 * optional; the values are checked by the cache's constructor.
 */
export interface HashiCorpVaultSecretCacheOptions {
  /** Where the KV secrets engine is mounted, e.g. "secret" (the default) or "kv/team-a". */
  mountPath?: string;

  /** The engine's version. Default {@link VaultKvVersion.v2}. */
  kvVersion?: VaultKvVersion;

  /**
   * The key read from a secret looked up without one: "myapp/db" reads this key of the secret at
   * myapp/db, while "myapp/db#password" reads its password key. Default "value".
   */
  defaultKey?: string;

  /**
   * The Vault Enterprise namespace every read is made in, e.g. "team-a/prod"; undefined (the
   * default) for the root namespace. Sent as X-Vault-Namespace, as VAULT_NAMESPACE is.
   */
  namespace?: string;

  /**
   * How long one attempt may take, in milliseconds: getting the token, or one request and Vault's
   * whole response. Default 30 seconds; at most {@link HashiCorpVaultSecretCacheOptions.MAX_TIMEOUT_MS}.
   * A fetch that keeps failing transiently makes up to {@link retryCount} + 1 attempts, with the
   * waits between them.
   */
  timeoutMs?: number;

  /**
   * How many times a request that failed transiently is retried: one that got no answer (connection
   * refused or reset, DNS), lost its connection mid-response, timed out, or was answered 429 or a 5xx
   * other than 501 (Vault answers 503 while sealed or electing a leader). Anything else - 403, a 404
   * naming an error, a token provider's failure, the caller's abort - isn't retried.
   * {@link HashiCorpVaultSecretCacheOptions.MIN_RETRY_COUNT}-{@link HashiCorpVaultSecretCacheOptions.MAX_RETRY_COUNT};
   * default 3.
   */
  retryCount?: number;

  /**
   * The wait before the first retry, in milliseconds, doubling before each retry after it, up to
   * {@link HashiCorpVaultSecretCacheOptions.MAX_RETRY_DELAY_MS}. Every wait also adds a random 0-100
   * ms, so many clients reconnecting at once - after a network outage, say - don't all retry
   * together. Zero to MAX_RETRY_DELAY_MS; default 200.
   */
  retryDelayMs?: number;

  /**
   * The agent every https request is sent through, e.g. `new https.Agent({ ca: readFileSync('vault-ca.pem') })`
   * trusting a private CA, or one presenting a client certificate (cert and key). Not destroyed by
   * the cache. Undefined (the default) for the cache's own keep-alive agent, which verifies Vault's
   * certificate and host name against Node's trust store (plus NODE_EXTRA_CA_CERTS). Unused for an
   * http address. Node never follows a redirect, whatever the agent; one that is a proxy sends the
   * token through it.
   */
  agent?: Agent;

  /** Receives a debug entry per fetched name while sensitive logging is enabled, and an error entry per failed fetch. */
  logger?: Logger;
}

/** The limits of {@link HashiCorpVaultSecretCacheOptions}. */
export const HashiCorpVaultSecretCacheOptions = {
  /** The fewest retries {@link HashiCorpVaultSecretCacheOptions.retryCount} allows. */
  MIN_RETRY_COUNT: 3,
  /** The most retries {@link HashiCorpVaultSecretCacheOptions.retryCount} allows. */
  MAX_RETRY_COUNT: 10,
  /** The longest wait between retries, in milliseconds, before the random 0-100 ms each adds. */
  MAX_RETRY_DELAY_MS: 10_000,
  /** The longest {@link HashiCorpVaultSecretCacheOptions.timeoutMs}: the longest delay a Node timer keeps. */
  MAX_TIMEOUT_MS: 2_147_483_647,
} as const;

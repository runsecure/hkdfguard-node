import type { Agent } from 'node:http';
import type { KeyFileTrust } from '@runsecure/hkdfguard-securefile';

/**
 * The context a HashiCorpVaultTransitKeyWrapper binds, who may have written its key files, which
 * transit secrets engine it calls, and how it connects. Every member is optional; the values are
 * checked by the wrapper's constructor.
 */
export interface HashiCorpVaultTransitKeyWrapperOptions {
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

  /** Where the transit secrets engine is mounted, e.g. "transit" (the default) or "transit/team-a". */
  readonly mountPath?: string;

  /**
   * The Vault Enterprise namespace every request is made in, e.g. "team-a/prod"; undefined (the
   * default) for the root namespace. Sent as X-Vault-Namespace, as VAULT_NAMESPACE is.
   */
  readonly namespace?: string;

  /**
   * How long one attempt may take, in milliseconds: getting the token, or one request and Vault's
   * whole response. Default 30 seconds; at most {@link HashiCorpVaultTransitKeyWrapperOptions.MAX_TIMEOUT_MS}.
   * A call that keeps failing transiently makes up to {@link retryCount} + 1 attempts, with the waits
   * between them.
   */
  readonly timeoutMs?: number;

  /**
   * How many times a request that failed transiently is retried: one that got no answer (connection
   * refused or reset, DNS), lost its connection mid-response, timed out, or was answered 429 or a 5xx
   * other than 501 (Vault answers 503 while sealed or electing a leader). Anything else - 400 for a
   * ciphertext that doesn't authenticate, 403, a token source's failure, the caller's abort - isn't
   * retried. Every transit call this wrapper makes is safe to repeat.
   * {@link HashiCorpVaultTransitKeyWrapperOptions.MIN_RETRY_COUNT}-{@link HashiCorpVaultTransitKeyWrapperOptions.MAX_RETRY_COUNT};
   * default 3.
   */
  readonly retryCount?: number;

  /**
   * The wait before the first retry, in milliseconds, doubling before each retry after it, up to
   * {@link HashiCorpVaultTransitKeyWrapperOptions.MAX_RETRY_DELAY_MS}. Every wait also adds a random
   * 0-100 ms, so many clients reconnecting at once don't all retry together. Zero to
   * MAX_RETRY_DELAY_MS; default 200.
   */
  readonly retryDelayMs?: number;

  /**
   * The agent every https request is sent through, e.g. `new https.Agent({ ca: readFileSync('vault-ca.pem') })`
   * trusting a private CA, or one presenting a client certificate (cert and key). Not destroyed by
   * the wrapper. Undefined (the default) for the wrapper's own keep-alive agent, which verifies
   * Vault's certificate and host name against Node's trust store (plus NODE_EXTRA_CA_CERTS). Unused
   * for an http address. Node never follows a redirect, whatever the agent - so, unlike .NET's
   * HttpMessageHandler, there is no AllowRedirects to set; an agent that is a proxy sends the token
   * and the DEKs through it.
   */
  readonly agent?: Agent;
}

/** The limits of {@link HashiCorpVaultTransitKeyWrapperOptions}. */
export const HashiCorpVaultTransitKeyWrapperOptions = {
  /** The fewest retries {@link HashiCorpVaultTransitKeyWrapperOptions.retryCount} allows. */
  MIN_RETRY_COUNT: 3,
  /** The most retries {@link HashiCorpVaultTransitKeyWrapperOptions.retryCount} allows. */
  MAX_RETRY_COUNT: 10,
  /** The longest wait between retries, in milliseconds, before the random 0-100 ms each adds. */
  MAX_RETRY_DELAY_MS: 10_000,
  /** The longest {@link HashiCorpVaultTransitKeyWrapperOptions.timeoutMs}: the longest delay a Node timer keeps. */
  MAX_TIMEOUT_MS: 2_147_483_647,
} as const;

/** The longest context, in UTF-8 bytes. */
export const MAX_CONTEXT_LENGTH = 1024;

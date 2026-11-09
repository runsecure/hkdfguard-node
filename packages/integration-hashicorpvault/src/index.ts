/**
 * HkdfGuard's integration with HashiCorp Vault - the Node port of the .NET, Java and Python
 * HkdfGuard.Integration.HashiCorpVault libraries: VaultClient, a port of vault-client-go - generic
 * reads and writes, and typed methods generated from Vault's OpenAPI spec - with tokens held only
 * protected by the key ring; and what every HkdfGuard Vault integration (the transit key wrapper,
 * the KV secret cache) shares, through Node's own http and https clients with no third-party
 * dependency:
 *
 *  - VaultTlsOptions: the CA certificates trusted and the client certificate presented - PEM, or
 *    password-protected PKCS#12 key stores whose passwords are protected by the key ring.
 *  - VaultTokenSource / StaticVaultTokenSource: a token copied into a buffer the integration zeroes,
 *    for one that runs before there is a key ring; VaultTokenProvider / StaticVaultToken: a token
 *    protected by the key ring.
 *  - VaultRequestError: Vault refused a request, with its status, never the token.
 *  - VaultConnectionOptions: the mount, namespace, timeout, retries, agent and TLS the transit key
 *    wrapper's and the KV secret cache's options share, checked by checkConnectionOptions.
 *  - The address, path and token checks, the retry limits and backoff, and the shared runner,
 *    request builder and response reading the integrations are built on (VaultConnector,
 *    withRetries, sendAttempt, readBody, readVaultErrors...).
 */
export {
  describeAnswer, MAX_ERROR_BODY_LENGTH, readBody, readVaultErrors, SecureBuffer, vaultRefusal,
} from './body.js';
export {
  apiBase, checkConnectionOptions, checkConnectionSettings, checkTlsOptions, DEFAULT_RETRY_DELAY_MS, DEFAULT_TIMEOUT_MS, isValidPath, isValidSegment,
  MAX_RETRY_COUNT, MAX_RETRY_DELAY_MS, MAX_TIMEOUT_MS, MIN_RETRY_COUNT, NAMESPACE_HEADER, REQUEST_HEADER, retryDelay, TOKEN_HEADER, type VaultApiBase,
  type VaultConnectionOptions, type VaultConnectionSettings,
} from './connection.js';
export { VaultRequestError } from './errors.js';
export {
  checkProtectedToken, chunksOf, copyTokenWithin, createVaultAgent, decryptToken, getTokenWithin, httpsAgentFor, invalidTokenError, isTransient,
  markTransient, putProtectedToken, putToken, runWithin, sendAttempt, vaultHeaders, VaultConnector, withRetries,
} from './http.js';
export { UNVERIFIED_WARNING_CODE, VaultTlsOptions, type VaultTlsAgentOptions } from './tls.js';
/** Who besides administrators may have written the TLS files ({@link VaultTlsOptions.fileTrust}), and the error a refused file is read with. */
export { KeyFileError, KeyFileTrust, type KeyFileTrustOptions } from '@runsecure/hkdfguard-securefile';
export {
  isValidToken, MAX_TOKEN_LENGTH, StaticVaultToken, StaticVaultTokenSource, TOKEN_PURPOSE, type VaultTokenProvider, type VaultTokenSource,
} from './token.js';
export * from './client-index.js';

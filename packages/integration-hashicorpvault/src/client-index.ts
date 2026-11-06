// The Vault client: VaultClient, its options, responses and errors, and the API generated from
// Vault's OpenAPI spec with its models. Re-exported by the package index.
export { VaultJsonError, VaultRedirectError, VaultResponseError } from './client-errors.js';
export {
  VaultClientOptions, VaultRequest, type VaultRequestCallback, type VaultRequestOptions, type VaultResponseCallback,
} from './client-options.js';
export { VaultClient } from './client.js';
export { formatGoDuration, parseGoDuration } from './duration.js';
export { AuthApi, SecretsApi, SystemApi, VaultApis } from './generated/index.js';
export * from './generated/schema.js';
export { JsonKind, JsonValue, JsonWriter, type VaultModel } from './json.js';
export { compareReplicationStates, ReplicationForwardingMode, VaultReplication, VaultReplicationState } from './replication.js';
export {
  VaultMfaRequirement, VaultRawResponse, type VaultMfaConstraint, type VaultMfaMethod, type VaultResponse, type VaultResponseAuth,
  type VaultResponseWrapInfo,
} from './response.js';
export { defaultRetryPolicy, linearJitterBackoff, VaultRateLimiter, VaultRetryOptions, type Backoff, type RetryPolicy } from './retry.js';

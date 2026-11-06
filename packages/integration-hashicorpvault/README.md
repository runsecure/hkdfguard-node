# @runsecure/hkdfguard-integration-hashicorpvault

HkdfGuard's integration with HashiCorp Vault - the Node port of the .NET, Java and Python
`HkdfGuard.Integration.HashiCorpVault` libraries - through Node's own `node:http` and `node:https`,
with no third-party dependency. It holds `VaultClient`, and what every HkdfGuard Vault integration
shares: `@runsecure/hkdfguard-keywrapping-hashicorpvault` and `@runsecure/hkdfguard-cache-hashicorpvault`
are built on it, and re-export what their callers use.

## Vault client

`VaultClient` is a port of HashiCorp's [vault-client-go](https://github.com/hashicorp/vault-client-go)
and the Node counterpart of the .NET, Java and Python HkdfGuard clients:

- **Generic requests**: `read`, `readRaw`, `write`, `writeFromBytes`, `writeFromStream`, `list`,
  `delete` and `unwrap` reach any path.
- **Typed requests**, generated from Vault's OpenAPI spec (`openapi.json`) for the operations
  `generator.json` names - logins and tokens, KV v1 and v2, cubbyhole, transit, and a few system
  endpoints: `vault.auth`, `vault.secrets` and `vault.system`, 103 methods and 77 models.
- **Tokens held only protected** by the key ring (`keyRing.createProtector(VaultClient.TOKEN_PURPOSE)`).
  A token Vault returns - a login's, a wrapping token - is protected straight from the response's
  bytes and never becomes a string.
- **Namespaces, MFA, response wrapping, read-your-writes replication states, retries
  (go-retryablehttp's), rate limiting, one opt-in redirect, request and response callbacks**, and
  `VaultClientOptions.fromEnvironment()` for the `VAULT_*` variables.

Every method returns a promise, and takes a `signal` in its options. See
[docs/how-to/use-hashicorp-vault-client.md](../../docs/how-to/use-hashicorp-vault-client.md).

```ts
import { VaultClient, VaultClientOptions } from '@runsecure/hkdfguard-integration-hashicorpvault';

const vault = new VaultClient(keyRing.createProtector(VaultClient.TOKEN_PURPOSE),
  VaultClientOptions.fromEnvironment(keyRing.createProtector(VaultClient.TOKEN_PURPOSE)));
const secret = await vault.secrets.kvV2Read('myapp/config', { mountPath: 'secret' });
console.log(secret?.data?.data?.region?.asString());
vault.close();
```

The typed API is regenerated with `node scripts/generate-vault-client.mjs` (from hkdfguard-node)
after changing `generator.json`, or after pulling a newer `openapi.json` from Vault yourself
(`vault read sys/internal/specs/openapi`); the spec isn't fetched.

## What the integrations share

- **`VaultTlsOptions`**: the CA certificates Vault's must chain to, and the client certificate
  presented for the cert auth method or a Vault requiring mutual TLS - PEM files or PEM in memory, or
  password-protected PKCS#12 key stores whose passwords are protected by a key ring
  (`VaultTlsOptions.protectPassword(keyRing.createProtector(VaultTlsOptions.PASSWORD_PURPOSE), password)`).
  Also `serverName` (`VAULT_TLS_SERVER_NAME`) and `insecureSkipVerify` (`VAULT_SKIP_VERIFY`, for
  development only). Read once, into one TLS secure context every connection shares; refused
  together with an `agent` of your own.
- **Tokens**: `VaultTokenSource` and `StaticVaultTokenSource` copy the token into a buffer the
  integration zeroes, for one that runs before there is a key ring (the transit key wrapper);
  `VaultTokenProvider` and `StaticVaultToken` hand it over protected by the key ring.
- **`VaultRequestError`** (`ERR_HKDFGUARD_VAULT_REQUEST`): a request Vault refused, or that got no
  answer, with its status, never the token; `isTransient` for 429, a 5xx other than 501, or no answer.
- **`VaultConnectionOptions`**: the mount, namespace, timeout, retries, agent and TLS the transit
  key wrapper's and the KV secret cache's options extend, checked by one `checkConnectionOptions`,
  with one set of limits (`MIN_RETRY_COUNT`, `MAX_RETRY_COUNT`, `MAX_RETRY_DELAY_MS`,
  `MAX_TIMEOUT_MS`) and defaults (`DEFAULT_TIMEOUT_MS`, `DEFAULT_RETRY_DELAY_MS`).
- **The address, path and token checks** (`apiBase`, which `VaultClient` uses too), and the runner the
  integrations make their requests with: `VaultConnector` (the agent, from the caller, built from
  `VaultTlsOptions` or its own: `httpsAgentFor`, which `VaultClient` uses too), `vaultHeaders`,
  `putToken` and `putProtectedToken`, `sendAttempt` (one request and its whole response within the
  timeout, abandoned on abort), `withRetries` and `runWithin`.
- **Reading Vault's answers**, for the wrapper, the cache and `VaultClient` alike: `readBody` (the
  whole body, at most a limit, into a `SecureBuffer` that is zeroed, each chunk zeroed once copied),
  `readVaultErrors` (the errors a refusal lists) and `vaultRefusal` (the `VaultRequestError` the
  wrapper and the cache report: `Vault answered 403 Forbidden: permission denied`).

```ts
import { VaultTlsOptions } from '@runsecure/hkdfguard-integration-hashicorpvault';

const protector = keyRing.createProtector(VaultTlsOptions.PASSWORD_PURPOSE);
const tls: VaultTlsOptions = {
  trustStoreFile: 'vault-trust.p12',
  trustStorePassword: VaultTlsOptions.protectPassword(protector, process.env.TRUST_STORE_PASSWORD!),
  clientKeyStoreFile: 'myapp.p12',
  clientKeyStorePassword: VaultTlsOptions.protectPassword(protector, process.env.KEY_STORE_PASSWORD!),
  clientKeyStoreAlias: 'myapp', // only if the store holds several keys; matched ignoring case
  passwordProtector: protector,
};
```

### Key stores

Node's own `pfx` option takes a store's password only as a string, which JavaScript can't erase,
and presents only the first key a store holds, so stores are read by this package's own PKCS#12
reader, over `node:crypto`, with the password decrypted into a buffer only while the store is read.
It reads what OpenSSL 3 and keytool (Java 11.0.12 or later) write - PBES2 (PBKDF2 with AES-CBC) or
PKCS#12's triple-DES encryption, under an HMAC - including a Java trust store of certificates only.
It refuses legacy RC2 and RC4 (`openssl pkcs12 -legacy`, older Java), JKS and JCEKS, and PBMAC1,
each with how to re-export the store. The client key reaches OpenSSL as PEM from a buffer zeroed once
the secure context holds it.

The test fixtures - throwaway keys and stores trusted nowhere else - are made by
`test-fixtures/generate.sh`.

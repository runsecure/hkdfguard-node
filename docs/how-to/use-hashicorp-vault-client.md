# Call Vault's API with the HashiCorp Vault client

This page uses `VaultClient`, from `@runsecure/hkdfguard-integration-hashicorpvault`, to call
HashiCorp Vault's HTTP API from Node.js. It covers logging in, managing tokens, the KV and cubbyhole
secrets engines and the transit engine. Generic methods reach anything else Vault exposes.

`VaultClient` is a port of HashiCorp's
[vault-client-go](https://github.com/hashicorp/vault-client-go). It's generated from the same
OpenAPI spec, but only for the endpoints HkdfGuard needs. It's the Node counterpart of .NET's
`HkdfGuard.Integration.HashiCorpVault`, Java's and Python's `hkdfguard-integration-hashicorpvault`.
Like the rest of HkdfGuard, it holds Vault tokens only in protected form.

To read secrets into memory your application uses, prefer `HashiCorpVaultSecretCache`
(`@runsecure/hkdfguard-cache-hashicorpvault`). It reads each secret straight into a buffer of its
own and keeps it encrypted. `VaultClient` returns response data as ordinary strings and
`JsonValue`s, like any other API client.

## 1. Install the package

```bash
npm install @runsecure/hkdfguard-integration-hashicorpvault
```

It needs Node.js 22 or later, and has no third-party dependency: requests go through `node:http`
and `node:https`.

## 2. Create a client

A client needs a token protector: a protector on your application's key ring, created for
`VaultClient.TOKEN_PURPOSE`. Every token the client holds is encrypted with it.

```ts
import { VaultClient } from '@runsecure/hkdfguard-integration-hashicorpvault';

// keyRing is your application's KeyRing.
const tokenProtector = keyRing.createProtector(VaultClient.TOKEN_PURPOSE);
const vault = new VaultClient(tokenProtector, { address: 'https://vault.example.com:8200' });
```

Or read the options from the `VAULT_*` environment variables vault-client-go reads - `VAULT_ADDR`,
`VAULT_TOKEN` (protected with the protector you pass), `VAULT_NAMESPACE`, `VAULT_CLIENT_TIMEOUT`,
`VAULT_CACERT` and the other TLS variables, `VAULT_RATE_LIMIT`, the retry variables:

```ts
const vault = new VaultClient(tokenProtector, VaultClientOptions.fromEnvironment(tokenProtector));
```

The address must be https, except on loopback (a local agent or dev server), unless you set
`allowUnencryptedHttp`. Close the client when you're done: `vault.close()` releases its connections.

### TLS

`tls` takes `VaultTlsOptions`: PEM CA certificates and client certificate, or password-protected
PKCS#12 stores whose passwords are protected by the key ring - see the package README. Or pass an
`https.Agent` of your own as `agent`; the two can't be combined.

## 3. Log in, and use the token

A login's token is protected as the response is read; hand it to `setToken`:

```ts
vault.clearToken();
const login = await vault.auth.appRoleLogin({ roleId, secretId });
vault.setToken(login!.auth!.clientToken!);
```

A token you already hold is protected by `setToken(string)` or `protectToken(string)`. Pass a
`VaultTokenProvider` to `setToken` to log in, renew and replace tokens however you like; it's asked
once per request. A request can make itself with another token: `{ token: provider }` in its options.

## 4. Read and write secrets

```ts
await vault.secrets.kvV2Write('myapp/db', { data: { password: Buffer.from(password) } }, { mountPath: 'secret' });
const read = await vault.secrets.kvV2Read('myapp/db', { mountPath: 'secret' });
const version = read?.data?.metadata?.version?.asNumber();
```

A `Uint8Array` in a request body is written as a UTF-8 string without becoming one. The generic
methods reach any path, with or without its `/v1/`:

```ts
const health = await vault.read('sys/health');
await vault.write('cubbyhole/note', { text: 'hello' });
const keys = await vault.list('secret/metadata/myapp');
```

`readRaw` returns the response as it is - its status, headers and body stream - unparsed and not
bound by the request timeout.

## 5. Transit

```ts
const encrypted = await vault.secrets.transitEncrypt('myapp-key', { plaintext: Buffer.from(data).toString('base64') });
const ciphertext = encrypted?.data?.ciphertext?.asString();
```

To wrap HkdfGuard's data encryption keys with transit, use `HashiCorpVaultTransitKeyWrapper`
(`@runsecure/hkdfguard-keywrapping-hashicorpvault`) instead.

## 6. Per-request settings

Every method takes `VaultRequestOptions` last: `token`, `namespace`, `mfaCredentials`,
`responseWrappingTtlMs`, `customHeaders`, `requestCallbacks` and `responseCallbacks`, `mountPath`
for a generated method, `queryParameters`, `replicationForwardingMode`, and `signal` to abort the
request. The client's own settings - `setNamespace`, `setMfaCredentials`, `setResponseWrapping`,
`setCustomHeaders`, the callbacks - apply to every request started afterwards; `copy()` gives a
client whose settings change independently.

## 7. Response wrapping

```ts
const wrapped = await vault.secrets.kvV2Read('myapp/db', { responseWrappingTtlMs: 300_000 });
const unwrapped = await vault.unwrap(wrapped!.wrapInfo!.token!, KvV2ReadResponse.read);
```

## 8. Errors, retries and timeouts

- `VaultResponseError`: Vault refused the request - its `statusCode`, the `errors` it listed.
  `VaultClient.isErrorStatus(error, 404)` finds it among an error's causes.
- `VaultRedirectError`: a redirect the client wouldn't follow. Redirects are off unless
  `followRedirects` is set, since they'd carry the token wherever they point.
- `VaultJsonError`: the answer isn't the JSON expected.
- Node's network error when Vault can't be reached, a DOMException named `TimeoutError` past
  `requestTimeoutMs` (60 seconds by default, its token, retries and redirect included), and the
  signal's reason when the request is aborted.

Failures are retried as vault-client-go retries them: no answer (unless Vault's certificate was
refused), 412, 429 and 5xx other than 501, twice by default, waiting 1-1.5 seconds times the attempt.
Change that with `retry` (`retryMax`, `retryWaitMinMs`, `retryWaitMaxMs`, `checkRetry`, `backoff`),
and limit the request rate with `rateLimiter: new VaultRateLimiter(rate, burst)`.

## 9. Regenerate the typed API

The typed methods and models in `src/generated/` are generated from the package's `openapi.json`,
for the operations its `generator.json` names. After changing `generator.json`, or after pulling a
newer spec from the Vault version you target (`vault read -format=json sys/internal/specs/openapi`),
regenerate from hkdfguard-node:

```bash
node scripts/generate-vault-client.mjs
```

It rewrites only the files that change, and the package's tests fail if the generated code is stale.

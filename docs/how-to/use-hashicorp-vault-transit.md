# Wrap keys with HashiCorp Vault transit

This page sets up a key in a HashiCorp Vault transit secrets engine as HkdfGuard's KEK and uses it
from Node.js with `HashiCorpVaultTransitKeyWrapper`, in place of the native TPM, Secure Enclave or
Platform Crypto Provider KEK.

Use it when your applications already authenticate to Vault, or run somewhere a cloud KMS isn't
available, and you want key access controlled by Vault policy and recorded in Vault's audit log
rather than tied to one machine's TPM.

To run the transit integration tests against a Vault dev server, see
[Run the HashiCorp Vault transit integration tests](run-hashicorp-vault-transit-integration-tests.md).

## How it compares

| | Native (`NativeKeyWrapperV1`) | Vault transit (`HashiCorpVaultTransitKeyWrapper`) |
|---|---|---|
| KEK | A P-256 key in the TPM, Secure Enclave or Platform Crypto Provider | An `aes256-gcm96` transit key |
| Identified by | A service name | Vault's address and the key's name |
| Who may wrap and unwrap | Local accounts and groups the native library allows | Tokens whose policy grants `update` on the key's `encrypt`, `decrypt` and `datakey/wrapped` paths |
| Each call | Local | A request to Vault's HTTP API, recorded in Vault's audit log |
| Key file reads | Through the native library, which refuses files another account could have replaced | The same rules, checked by `@runsecure/hkdfguard-securefile`; who else is trusted is set with `KeyFileTrust` |
| Install | The native package | No SDK: the wrapper talks to Vault's HTTP API through Node's own `node:http` and `node:https` |

`HashiCorpVaultTransitKeyWrapper`:

- **Pins the key.** Every request names the key, and a ciphertext carries only its key version, so a
  key file wrapped under another transit key fails to authenticate rather than being revealed.
- **Binds your context** into every wrapped DEK as Vault's `associated_data` (AAD).
- **Never makes a DEK a string.** HashiCorp ships no Node SDK, and the community client parses
  Vault's answers into JavaScript strings, which can't be erased. The wrapper encodes a DEK straight
  into a request body of its own, reads Vault's answer into a buffer of its own, and zeroes both.

Wrapped DEKs aren't interchangeable between wrapper types: a key file wrapped by one can't be
unwrapped by another. A transit-wrapped DEK is Vault's ciphertext as it returns it, `vault:v1:...`,
about 89 bytes of ASCII - byte for byte what the .NET `HashiCorpVaultTransitKeyWrapper` and the Go,
Java and Python wrappers write, so each reads the others', given the same key and context.

## 1. Create the transit key

As a Vault operator, enable the engine (once) and create the key:

```bash
vault secrets enable transit
vault write -f transit/keys/myapp-kek type=aes256-gcm96
```

| Setting | Choose | Why |
|---|---|---|
| `type` | `aes256-gcm96` (the default), `aes128-gcm96` or `chacha20-poly1305` | The wrapper needs an AEAD key for its context (associated data) |
| `derived` | `false` (the default) | A derived key needs a `context` on every request, which the wrapper doesn't send. Worse, a key that *isn't* derived silently ignores one, so the wrapper binds its context as `associated_data` instead |
| `exportable` | `false` (the default) | Nothing here needs the key material out of Vault |
| `deletion_allowed` | `false` (the default) | Deleting the key makes every DEK wrapped under it unreadable, for good |

Rotate it with `vault write -f transit/keys/myapp-kek/rotate`. New DEKs are wrapped under the latest
version; existing key files keep revealing as long as their version is at or above the key's
`min_decryption_version`, so don't raise that until every key file is rewrapped.

## 2. Grant each role only what it calls

Give `update`, and never `create`, on exactly the paths each role uses. `transit/encrypt/{name}`
creates a key that doesn't exist yet when the token has `create`, so with it a mistyped key name
would quietly wrap DEKs under a brand-new key.

A release pipeline that creates key files:

```hcl
path "transit/encrypt/myapp-kek"         { capabilities = ["update"] }
path "transit/datakey/wrapped/myapp-kek" { capabilities = ["update"] }
```

The application, which only reads existing key files:

```hcl
path "transit/decrypt/myapp-kek" { capabilities = ["update"] }
```

Add `transit/encrypt/myapp-kek` (and `transit/datakey/wrapped/myapp-kek`) to the application only
if it generates ephemeral keys at startup.

```bash
vault policy write myapp-kek-pipeline pipeline.hcl
vault policy write myapp-kek-app app.hcl
```

Then bind each policy to the auth method its role logs in with (AppRole, Kubernetes, a certificate,
a cloud IAM role).

> **Security:** anyone whose policy allows `encrypt` on the key can make a key file the application
> accepts, holding a DEK of their choosing. Keep `encrypt` with the pipeline.

## 3. Give the process a token

Every request is made with a token from a `VaultTokenSource`. Logging in, renewing and replacing the
token is the source's job, so any auth method can sit behind the wrapper. The source copies the
token, as ASCII bytes, into a buffer the wrapper owns and zeroes once the call is done, rather than
handing it over as a string.

`StaticVaultTokenSource` holds a token you already have, such as one a Vault Agent wrote to a sink
file. Nothing renews it, so once it expires every request fails with 403:

```ts
import { StaticVaultTokenSource } from '@runsecure/hkdfguard-keywrapping-hashicorpvault';

const token = new StaticVaultTokenSource(process.env.VAULT_TOKEN!);
```

A string can't be erased: read the token from the environment once, there, and keep no other
reference to it - or hand over its bytes and zero them once the constructor returns.
`token.close()` zeroes the source's copy.

For a long-running service, prefer a Vault Agent on loopback with `use_auto_auth_token`, which
renews the token itself, or implement `VaultTokenSource` over your auth method:

```ts
import type { VaultTokenSource } from '@runsecure/hkdfguard-keywrapping-hashicorpvault';

const source: VaultTokenSource = {
  async copyToken(destination, signal) {
    // Write the token's ASCII bytes into destination (MAX_TOKEN_LENGTH bytes); return how many.
  },
};
```

The wrapper asks once per call, not per retry, and waits at most its timeout; a source's failure
fails the call as it is.

> **Note:** this is not the cache's `VaultTokenProvider`. That one hands over a token protected by
> the key ring; a key wrapper runs before there is a key ring, so it can't.

## 4. Create the wrapper

Install the packages:

```sh
npm install @runsecure/hkdfguard-keywrapping-hashicorpvault @runsecure/hkdfguard-cryptoprovider-aesgcm256 @runsecure/hkdfguard-dek
```

> **TODO (maintainer):** confirm the install command once the packages are published.

The package has no third-party dependency. It brings `@runsecure/hkdfguard-securefile`, which on
Windows compiles a small C add-on when it is installed - so installing on Windows needs Python 3 and
Visual Studio Build Tools, as `@runsecure/hkdfguard-keywrapping-native-v1` does. Nothing is compiled
on Linux or macOS.

```ts
import { HashiCorpVaultTransitKeyWrapper } from '@runsecure/hkdfguard-keywrapping-hashicorpvault';

const wrapper = new HashiCorpVaultTransitKeyWrapper('https://vault.example.com:8200', 'myapp-kek', token,
  { context: 'com.example.myapp' });
```

- **The address must be https**, except on a loopback address (a local Vault Agent or dev server):
  every request carries a token, and wrap and unwrap carry plaintext DEKs. A path is kept as a
  prefix, for Vault behind a reverse proxy. Node never follows a redirect, which would carry the
  token elsewhere; a redirect is reported as an error.
- **The context** is bound into every wrapped DEK as Vault's `associated_data` and must be given
  again, exactly, to reveal it. Use the same value on every wrapper that handles one application's
  key files. It isn't a secret and must not hold one.
- **With a context, `generateAndWrap` generates the DEK in your process** and wraps it with
  `encrypt`, because `datakey/wrapped` ignores `associated_data`. Without one, Vault generates it
  and returns it wrapped only, so the plaintext DEK never leaves Vault on that call. Choose a context
  for the binding, or none for generation in Vault.
- **Old Vaults are refused, not trusted.** If Vault answers that it ignored a parameter, as one
  too old for `associated_data` does, the call fails rather than return a DEK bound to no context.
- **A signal abandons the call.** Every method takes an `AbortSignal`; an abort destroys the
  request in flight, or stops the wait for the token or a retry, and rejects with the signal's
  reason. No retry follows.
- **Close the wrapper** with `wrapper.close()` to release its connections, but only once nothing
  uses it, including a key ring's background refresh. It doesn't close the token source or an agent
  you supply.

The options set a mount other than `transit`, a Vault Enterprise namespace, the per-attempt timeout
(`timeoutMs`, 30 seconds), and retries: a request that gets no answer, loses its connection, times
out, or is answered 429 or a 5xx other than 501 is retried 3 times by default (`retryCount`, 3-10),
waiting 200 ms (`retryDelayMs`) and doubling, up to 10 seconds, plus up to 100 ms of jitter. To
trust a private CA, or present a client certificate (Vault's cert auth method, or a Vault requiring
mutual TLS), give `tls`, a `VaultTlsOptions` - the same settings the .NET, Java and Python wrappers
and Vault's own `VAULT_CACERT`, `VAULT_CLIENT_CERT`, `VAULT_CLIENT_KEY` and `VAULT_TLS_SERVER_NAME`
take:

```ts
const wrapper = new HashiCorpVaultTransitKeyWrapper('https://vault.example.com:8200', 'myapp-kek', token, {
  context: 'com.example.myapp',
  mountPath: 'transit/team-a',
  namespace: 'team-a/prod',
  tls: {
    serverCertificateFile: '/etc/myapp/vault-ca.pem',
    clientCertificateFile: '/etc/myapp/myapp.pem',
    clientCertificateKeyFile: '/etc/myapp/myapp-key.pem',
    // fileTrust: new KeyFileTrust({ ... }) - the account that deploys these files, besides administrators
  },
});
```

Each file is read through `readTrustedFile` (`@runsecure/hkdfguard-securefile`) and refused unless
it, and every folder above it, is owned by an administrator or a principal in `fileTrust`
(administrators only by default) and writable by no one else: whoever could replace the CA file
could point the wrapper at a server of their own, and be handed every DEK it wraps.

### Certificates in a password-protected key store

The CA certificates and the client key can come from PKCS#12 stores instead: a trust store in place
of the PEM CA certificates, a client key store in place of the PEM certificate and key. A store's
password is never held in the clear. Protect it once with a protector on a key ring, and give the
options the result and that protector:

```ts
import { VaultTlsOptions } from '@runsecure/hkdfguard-keywrapping-hashicorpvault';

const protector = keyRing.createProtector(VaultTlsOptions.PASSWORD_PURPOSE);
const password = VaultTlsOptions.protectPassword(protector, process.env.MYAPP_KEYSTORE_PASSWORD!);

const tls: VaultTlsOptions = {
  trustStoreFile: 'vault-trust.p12', trustStorePassword: password,
  clientKeyStoreFile: 'myapp.p12', clientKeyStorePassword: password,
  clientKeyStoreAlias: 'myapp', // only if the store holds several keys
  passwordProtector: protector,
};
```

Store `password` - the protected form - in your configuration, not the password. The stores are read
once, when the wrapper is created, into one TLS secure context every connection shares: each
password is decrypted into a buffer only while its store is read, and zeroed at once. A password
that `protector` didn't protect is refused without being quoted. The alias is matched ignoring case,
as Java's PKCS#12 key store does.

Some things to know:

- The key ring that protects the password can't be the one this wrapper unwraps keys for, since that
  ring isn't built until the wrapper exists. Use an earlier ring - for example one whose wrapper is
  the native platform's - or pass PEM files, protected by file permissions, instead.
- Only PKCS#12 is read. A JKS or JCEKS store is refused; convert one with
  `keytool -importkeystore -srckeystore myapp.jks -destkeystore myapp.p12 -deststoretype PKCS12`.
- Node's own `pfx` option takes the password only as a string, which JavaScript can't erase, and
  presents only the first key a store holds. So the stores are read by HkdfGuard's own PKCS#12
  reader instead, which takes the password as bytes. It reads what OpenSSL 3 and keytool (Java
  11.0.12 or later) write - PBKDF2 with AES-CBC, or PKCS#12's triple-DES encryption, under an HMAC -
  and refuses the legacy RC2 and RC4 that `openssl pkcs12 -legacy` and older Java write: re-export
  such a store with a current `openssl pkcs12 -export` or keytool. It also refuses a store without
  its integrity MAC (`-nomac`), which nothing would tie to its password, and a client key that
  isn't encrypted (`-keypbe NONE`).
- The client key reaches OpenSSL as PEM from a buffer zeroed once the secure context holds it. What
  OpenSSL keeps of it, it keeps in its own memory.

Without `tls`, Node's trust store (plus `NODE_EXTRA_CA_CERTS`) verifies the certificate and host
name. An `https.Agent` of your own (`new Agent({ ca: readFileSync('vault-ca.pem'), keepAlive: true })`,
say) can be given as `agent` instead of `tls`, but not with it; one that is a proxy sends the token
and the DEKs through it.

Use it as any other key wrapper, with ephemeral keys or key files, as in
[Wrap keys with AWS KMS](use-aws-kms.md#5-build-a-key-ring-with-an-ephemeral-key). An ephemeral key
needs `encrypt` (or `datakey/wrapped`) to be made, which step 2 keeps from the application. Use key
files instead, or give an application that only ever uses ephemeral keys a key of its own.

## 5. Create and use key files

The release pipeline creates key files with the wrapper itself, logged in as the pipeline role from
step 2:

```ts
import { writeFileSync } from 'node:fs';
import { MAX_WRAPPED_KEY_BYTES } from '@runsecure/hkdfguard-abstractions';

const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
const length = await wrapper.generateAndWrap(wrapped);
writeFileSync('C:\\HkdfGuardKeys\\myapp\\v1.key', wrapped.subarray(0, length));
wrapper.close();
token.close();
```

To wrap a key the pipeline already holds, such as an `AesGcmPipelineDataProtector`'s, call `wrap`
with it and zero your copy afterwards, as [Wrap keys with AWS KMS](use-aws-kms.md#6-create-a-key-file)
shows. `wrap` accepts 1-256 bytes.

Key files are read only from where no untrusted account could have written or replaced them,
exactly as for AWS KMS: see [Where key files can live](use-aws-kms.md#where-key-files-can-live), and
pass a `KeyFileTrust` as the wrapper's `keyFileTrust` option if the pipeline writes key files as an
account of its own. Then use the key file as in [Use the key file](use-aws-kms.md#7-use-the-key-file).
`buildKeyRing` calls `decrypt` once per key, so the application fails to start if Vault can't be
reached or refuses the key.

## Choosing a refresh interval

Every key in a ring re-reveals itself once per `keyRefreshInterval`: one `decrypt` request to Vault.
At 300 seconds that is 8,640 requests per key per process every 30 days, each one in the audit log.
See [Choosing a refresh interval](use-aws-kms.md#choosing-a-refresh-interval) for the trade-off.

## Limitations

- **Copies the wrapper can't zero.** The wrapper zeroes every buffer of its own that held a DEK -
  the request body `encrypt` is sent, the response `decrypt` answers with (each chunk Node hands it
  too, once copied), the value read out of it and the DEK decoded from that - and the buffer the
  token is copied into. But Node takes a header value only as a string, so each request leaves the
  token in two strings (the header's value and the request head Node builds from it) until the
  garbage collector reuses their memory; and the socket's and, over TLS, OpenSSL's buffers are below
  the wrapper's reach. `hardenProcess()` from `@runsecure/hkdfguard-keywrapping-native-v1` keeps a
  debugger or crash dump away from such copies.
- **A token source that writes late.** If a source finishes writing after the wrapper's timeout has
  passed, the wrapper has already zeroed and dropped the buffer it gave it; what the source wrote
  there afterwards isn't zeroed. Honour the signal the source is given.
- The key-file limitations are those of [Wrap keys with AWS KMS](use-aws-kms.md#limitations).

## If something goes wrong

Every Vault failure rejects with a `HashiCorpVaultTransitError` (`code`
`ERR_HKDFGUARD_VAULT_TRANSIT`) whose message gives Vault's status and errors, never the token; its
`statusCode` is Vault's HTTP status when Vault answered, and Node's network error, or a
`DOMException` named `TimeoutError`, is its `cause` when it didn't. A failed unwrap zeroes the
caller's buffer. An aborted signal rejects with its reason, unchanged. A token source's own failure
propagates as it is; a source slower than the timeout rejects with a `TimeoutError`. Argument errors
- an address, key name or option that isn't one - throw `InvalidArgumentError`. Reading a key file
fails before Vault is called, as described for [AWS KMS](use-aws-kms.md#if-something-goes-wrong).

| The message says | Cause | Fix |
|---|---|---|
| `403 Forbidden` ... `permission denied` | The token's policy doesn't grant `update` on this path, or the token is invalid or expired | Step 2's paths; renew or replace the token |
| `400 BadRequest` ... `encryption key not found` | No key by that name in this mount (or namespace) | Check the key name, `mountPath` and `namespace` |
| `400 BadRequest` ... `cipher: message authentication failed` | The key file was altered, wrapped under another key, or with a different context | Restore the file; use the key and context it was created with |
| `400 BadRequest` ... `missing 'context' for key derivation` | The key is derived | Create a key with `derived=false` and rewrap |
| `400 BadRequest` ... `disallowed by policy (too old)` | The file's key version is below `min_decryption_version` | Lower it, or rewrap the file under the current version |
| `ignored a parameter` | This Vault doesn't support `associated_data` | Upgrade Vault (the integration tests run against 1.19) |
| `503 ServiceUnavailable` | Vault is sealed, or electing a leader, beyond the retries | Unseal Vault; check its HA status |
| `307 TemporaryRedirect` | A proxy or load balancer redirects, which the wrapper never follows | Point the address at Vault itself, or the active node's listener |
| `no answer within` | No answer within `timeoutMs`, on every attempt | Check the address and network path |
| `ECONNREFUSED`, `ENOTFOUND` | Nothing listens at the address, or the name doesn't resolve | Check the address |
| `SELF_SIGNED_CERT_IN_CHAIN`, `UNABLE_TO_VERIFY_LEAF_SIGNATURE` | Vault's certificate isn't trusted | Give `tls` its CA (`serverCertificateFile` or `trustStoreFile`) |
| `ERR_TLS_CERT_ALTNAME_INVALID` | Vault's certificate isn't issued to the address's host | Use the name it is issued to, or set `tls.serverName` |
| `password is wrong, or the store was altered` | The key store's password isn't the one protected, or the file changed | Protect the store's password again |
| `legacy RC2`, `JKS or JCEKS` | A key store Node can't read | Re-export it as PKCS#12 with AES, as the message says |
| `must be https` (`InvalidArgumentError`) | An http address that isn't loopback | Use https, or a local Vault Agent on loopback |
| `ERR_HKDFGUARD_INVALID_VAULT_TOKEN` | The token source supplied no token, or one with spaces or non-ASCII characters | Check what the source reads |

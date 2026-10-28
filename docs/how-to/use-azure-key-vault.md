# Wrap keys with Azure Key Vault

This page sets up two Azure Key Vault keys as HkdfGuard's KEK and uses them from Node.js with
`AzureKeyVaultKeyWrapper`, in place of the native TPM, Secure Enclave or Platform Crypto Provider
KEK.

To run the Azure Key Vault integration tests against keys of your own, see
[Run the Azure Key Vault integration tests](run-azure-key-vault-integration-tests.md).

## Why two keys

A Key Vault (Standard or Premium) offers RSA and EC keys. Only RSA keys can wrap; EC keys can only
sign and verify. RSA-OAEP wrapping needs nothing but the public key, which isn't secret, so on its
own anyone could produce a wrapped DEK holding a key *they* chose, and your application would encrypt
new data under it.

So `AzureKeyVaultKeyWrapper` uses:

- an **RSA key** (2048 or 3072 bits) to wrap and unwrap each DEK, with RSA-OAEP-256;
- a separate **EC P-256 key** to sign each wrapped DEK, with ES256.

Signing happens inside Key Vault and needs the `sign` permission. Unwrap checks the signature
before it unwraps anything. So a key file the application accepts proves it was made by a principal
allowed to sign: give that permission to the pipeline that creates key files, never to the
application.

| | AWS KMS | Azure Key Vault |
|---|---|---|
| Keys | One symmetric key | An RSA key to wrap, an EC P-256 key to sign |
| Who can create a key file the app accepts | Principals allowed `kms:Encrypt` | Principals allowed `sign` on the EC key |
| Context binding | Encryption context (AAD) | A context string bound into the signature |
| New DEKs | Generated inside KMS | Generated in the process, then wrapped |
| Client | The application's `KMSClient` | Created by the wrapper from the application's credential |

Wrapped DEKs aren't interchangeable between wrappers: a key file belongs to the kind of wrapper that
made it. Between languages they are: a key file made by the .NET `AzureKeyVaultKeyWrapper`, the Java
`AzureKeyVaultKeyWrapperImpl`, the Python `AzureKeyVaultKeyWrapper` or the Go
`azurekeyvault.KeyWrapper` is read by this one, and the other way round, given the same two keys and
context.

## 1. Create the keys

Create a vault, or use an existing one, with **purge protection** turned on. Deleting a key makes
every DEK wrapped under it, and all data encrypted under those DEKs, permanently unrecoverable;
purge protection keeps a deleted key recoverable for its retention period.

Create the two keys, each allowed only the operations it needs:

```bash
az keyvault key create --vault-name myvault --name myapp-wrap --kty RSA --size 3072 --ops wrapKey unwrapKey
az keyvault key create --vault-name myvault --name myapp-sign --kty EC --curve P-256 --ops sign verify
```

In the portal: **Keys**, **Generate/Import**, then for the first choose **RSA** and 2048 or 3072
bits, and for the second **EC** and **P-256**. After creating each, open its version and clear every
permitted operation except the two above.

Use 2048 or 3072 bits for the RSA key. A 4096-bit key's wrapped DEK is too large for a key file
(`MAX_WRAPPED_KEY_BYTES`, 512 bytes), and wrapping under one is refused.

Copy each key's **key identifier** without the version, for example
`https://myvault.vault.azure.net/keys/myapp-wrap`.

## 2. Grant each identity only what it calls

With Azure RBAC, assign roles on each **key**, not the vault:

| Identity | On the RSA key | On the EC key |
|---|---|---|
| Release pipeline that creates key files | Key Vault Crypto Service Encryption User | Key Vault Crypto User |
| Application | Key Vault Crypto Service Encryption User | HkdfGuard Key Verifier (below) |

Every role here includes reading the key (`get`). The wrapper reads each key's current version
before it wraps or signs under it, and the Azure SDK reads a key version before it first uses it
(to check it is enabled and allowed the operation).

The Azure SDK for JavaScript verifies in the vault, so the application needs `verify` on the EC key.
No built-in role allows `verify` without also allowing `sign`, so that role is a custom one. Create
it once per subscription, from `verifier.json`:

```json
{
  "Name": "HkdfGuard Key Verifier",
  "Description": "Read a Key Vault key and verify signatures with it.",
  "Actions": [],
  "DataActions": ["Microsoft.KeyVault/vaults/keys/read", "Microsoft.KeyVault/vaults/keys/verify/action"],
  "AssignableScopes": ["/subscriptions/<subscription-id>"]
}
```

```bash
az role definition create --role-definition @verifier.json

vaultId=$(az keyvault show -n myvault --query id -o tsv)
az role assignment create --assignee <app-principal-id> --role "Key Vault Crypto Service Encryption User" \
  --scope "$vaultId/keys/myapp-wrap"
az role assignment create --assignee <app-principal-id> --role "HkdfGuard Key Verifier" \
  --scope "$vaultId/keys/myapp-sign"
```

With vault access policies instead, which apply to the whole vault: the pipeline gets **Get**,
**Wrap Key** and **Sign**; the application **Get**, **Unwrap Key** and **Verify**.

> **Security:** never give the application `sign` on the EC key (Key Vault Crypto User, Crypto
> Officer, or the Sign access policy). With it, anyone controlling the application, and able to
> replace a key file, could choose its DEK.

If an identity can't have **Get**, each key identifier you give the wrapper must name a version
(`.../keys/myapp-wrap/<version>`): without `get` the wrapper can't learn which version is current,
and a key file must record the version that made it. Unwrapping needs no `get`, since every key file
names its versions.

## 3. Give the process a credential

Every call is authorized by an Azure `TokenCredential`. Deployed, use a **managed identity**
(`new ManagedIdentityCredential()`, or `new DefaultAzureCredential()`, which finds it, both from
`@azure/identity`); on a developer machine, `DefaultAzureCredential` uses your `az login`. Don't give
a deployed process a client secret.

## 4. Create the wrapper

Install the packages, and `@azure/identity` for the credential:

```sh
npm install @runsecure/hkdfguard-keywrapping-azurekeyvault @runsecure/hkdfguard-cryptoprovider-aesgcm256 @runsecure/hkdfguard-dek @azure/identity
```

> **TODO (maintainer):** confirm the install command once the packages are published.

`@runsecure/hkdfguard-keywrapping-azurekeyvault` brings `@runsecure/hkdfguard-securefile`, which on
Windows compiles a small C add-on when it is installed - so installing on Windows needs Python 3 and
Visual Studio Build Tools, as `@runsecure/hkdfguard-keywrapping-native-v1` does. Nothing is compiled
on Linux or macOS.

```ts
import { DefaultAzureCredential } from '@azure/identity';
import { AzureKeyVaultKeyWrapper } from '@runsecure/hkdfguard-keywrapping-azurekeyvault';

const wrapper = new AzureKeyVaultKeyWrapper('https://myvault.vault.azure.net/keys/myapp-wrap',
  'https://myvault.vault.azure.net/keys/myapp-sign', new DefaultAzureCredential(), { context: 'com.example.myapp' });
```

- **Give key identifiers without a version.** Every key file records the versions it was made with,
  so both keys can be rotated in Key Vault with no change here. Keep an old version enabled for as
  long as key files made with it are in use. The wrapper reads each key's current version the first
  time it wraps, and keeps using that version for as long as it lives: restart the process (or create
  a new wrapper) to wrap new key files under a rotated key.
- **The context** is bound into every key file's signature and must be given again, exactly, to
  reveal it. Use one value per application, so a key file made for one can't be used by another
  that shares the keys. It isn't secret.
- **Client options.** `clientOptions` are passed to every Key Vault client the wrapper creates:
  `retryOptions`, `proxyOptions`, `serviceVersion`, `userAgentOptions`, an `httpClient`, for example
  `clientOptions: { retryOptions: { maxRetries: 2 } }`. Every wrapper call also takes an
  `AbortSignal`, which aborts the request.
- **Nothing to close.** The wrapper creates one client per key version it uses and keeps it, so a
  key ring's refresh doesn't read the keys again; the clients hold nothing that needs releasing.

## 5. Build a key ring with an ephemeral key

An ephemeral key is generated at startup and never written anywhere. Key Vault has no "generate data
key", so the wrapper generates it in the process and wraps it:

```ts
import { AesGcmCryptoProviderFactory } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { buildKeyRing } from '@runsecure/hkdfguard-dek';

const ring = await buildKeyRing({
  serviceName: 'com.example.myapp',
  keyWrapper: wrapper,
  cryptoProviderFactory: new AesGcmCryptoProviderFactory(),
  keyRefreshInterval: 300,
  ephemeralKeys: [1],
});
const protector = ring.createProtector('customer-notes');
const encrypted = protector.encrypt('The launch code is 0000');
// ...
await ring.close();
```

An ephemeral key needs `sign` to be made, which step 2 keeps from the application. Use key files
instead, or give an identity that only ever uses ephemeral keys its own pair of keys. Everything
encrypted under an ephemeral key is lost when the process exits.

## 6. Create a key file

The release pipeline creates key files with the wrapper itself, running as the pipeline identity
from step 2:

```ts
import { writeFileSync } from 'node:fs';
import { MAX_WRAPPED_KEY_BYTES } from '@runsecure/hkdfguard-abstractions';

const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
const length = await wrapper.generateAndWrap(wrapped);
writeFileSync('C:\\HkdfGuardKeys\\myapp\\v1.key', wrapped.subarray(0, length));
```

To wrap the key of an `AesGcmPipelineDataProtector`, use `wrap` as in
[Wrap keys with AWS KMS](use-aws-kms.md#6-create-a-key-file). An RSA-2048 key's key file is 359
bytes, an RSA-3072 key's 487.

Key files are read only from where no untrusted account could have written or replaced them,
exactly as for AWS KMS: see [Where key files can live](use-aws-kms.md#where-key-files-can-live), and
pass a `KeyFileTrust` as the wrapper's `keyFileTrust` option if the pipeline writes key files as an
account of its own. Then use the key file as in [Use the key file](use-aws-kms.md#7-use-the-key-file).

## Choosing a refresh interval

Every key in a ring re-reveals itself once per `keyRefreshInterval`: a verify and an unwrap, both
Key Vault calls. See [Choosing a refresh interval](use-aws-kms.md#choosing-a-refresh-interval) for
the trade-off, and [Key Vault pricing](https://azure.microsoft.com/pricing/details/key-vault/) for
what each operation costs: RSA 3072 and EC keys are billed at a higher rate than RSA 2048.

## Limitations

- **Every operation is a Key Vault call.** The Azure SDK for JavaScript has no local RSA-OAEP-256
  or ES256, so wrapping and verifying go to the vault too, unlike the .NET, Java and Python ports,
  which do both with the public key in the process.
- **Copies the wrapper can't zero.** The wrapper zeroes its own copy of a key it wraps, and the
  buffer the SDK decodes an unwrapped key into once it is copied into your `result`. But the SDK
  sends and receives that key as base64 text in a JSON body: JavaScript strings, which can't be
  zeroed and live until garbage-collected. `hardenProcess()` from
  `@runsecure/hkdfguard-keywrapping-native-v1` keeps a debugger or crash dump away from them.
- The key-file limitations are those of
  [Wrap keys with AWS KMS](use-aws-kms.md#limitations).

## If something goes wrong

Every Key Vault failure rejects with an `AzureKeyVaultError` (`code`
`ERR_HKDFGUARD_AZURE_KEY_VAULT`); for a refusal the message names Key Vault's error code and the
HTTP status, and the SDK's `RestError` is its `cause`. A failed unwrap zeroes the caller's buffer.
An aborted signal rejects with the SDK's (or Node's) `AbortError`, unchanged. Argument errors - a
key identifier that isn't one, included - throw `InvalidArgumentError`. Reading a key file fails as
described for [AWS KMS](use-aws-kms.md#if-something-goes-wrong).

| The message says | Cause | Fix |
|---|---|---|
| `Forbidden (HTTP 403)` or `ForbiddenByRbac` | The identity lacks the operation on that key | Step 2 |
| `KeyNotFound (HTTP 404)` | The identifier is wrong, or the key version a key file names was purged | Check the identifier; restore the version |
| `couldn't read its current version` | The identity can't `get` the key, and its identifier names no version | Step 2: grant `get`, or name a version |
| `signature doesn't verify` | The key file was altered, made under another context, or not signed by a principal allowed to sign | Restore it; use the same context |
| `not a wrapped DEK written by AzureKeyVaultKeyWrapper` | The file isn't one of this wrapper's key files | Check the path and wrapper |
| `Use a 2048- or 3072-bit RSA key` | The wrapping key is 4096 bits | Create a smaller RSA key |
| `The signing key must be an EC P-256 key` | The signing key is another curve | Create an EC P-256 key |
| `Operation ... is not supported on key` | The key's permitted operations don't include this one, or the two identifiers are swapped | Step 1's `--ops`; check both identifiers |
| `reported key ... instead` | Key Vault answered for a different key | Check both identifiers |
| `isn't a Key Vault key identifier` (`InvalidArgumentError`) | An identifier isn't `https://{vault}/keys/{name}`, with an optional version | Copy the key identifier again |
| `ECONNREFUSED`, `ENOTFOUND`, `ETIMEDOUT` | The vault can't be reached: no network route, a proxy, or a wrong vault name | Check the network path to the vault |
| `DefaultAzureCredential failed to retrieve a token` | No credential could get a token | Step 3 |

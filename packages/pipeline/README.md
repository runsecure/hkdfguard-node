# @runsecure/hkdfguard-pipeline

The shared base of HkdfGuard's secret pipeline writers - the Node port of .NET's
`HkdfGuard.Pipeline`. A provisioning pipeline that runs before a durable KEK exists pulls a fixed
list of secrets from a secret store, encrypts each at once with a `PipelineDataProtector` bound to
its file name, keeps only the ciphertext, and writes one file per secret - the folder layout
`FilePerSecretCache` (`@runsecure/hkdfguard-cache`) reads at runtime. No key ring is involved.

- `SecretPipelineWriter`: the base every store's writer extends. It takes the secret names - `name`,
  or `name#key` for a member of a secret holding a JSON object - groups them so each secret is read
  once, names each file (`/` and `#` become `__`: `prod/app#password` is `prod__app__password`),
  refuses names `FilePerSecretCache` couldn't read or that differ only in case, encrypts every value
  bound to its file name, and writes the files (UTF-8, no BOM, replacing only its own) - or one
  JSON file of them all (`writeJsonSecrets`, the file `JsonSecretsFileReadOnlyCache` reads), or
  either to a `Writable` such as an `ssh` child's stdin: `writeProtectedSecretFilesTo` (a PAX tar
  archive of the files, mode 0644, for `tar -x --no-same-owner -f -`) and `writeJsonSecretsTo`. A
  store's writer supplies only `readSecret`, handing values to `protect`, `protectSecret` or
  `protectKeys`.
- `PinnedBody`: reads a response body that holds a secret into a buffer of the library's own, each
  chunk zeroed once copied.
- `SecretsNotFoundError` (`ERR_HKDFGUARD_SECRETS_NOT_FOUND`): a pull found no value for some
  secrets - every one is named, and the rest are kept. `InvalidSecretDataError`: a value that isn't
  UTF-8 text, a response that isn't the store's JSON, or a JSON object holding a key twice.

Values never become JavaScript strings: each is kept as UTF-8 bytes, checked byte by byte to be
UTF-8 (never decoded), handed to the protector and zeroed.

| Store | Writer's package |
|---|---|
| HashiCorp Vault (KV 1 or 2) | `@runsecure/hkdfguard-pipeline-hashicorpvault` |
| AWS Secrets Manager | `@runsecure/hkdfguard-pipeline-awssecretsmanager` |
| Azure Key Vault | `@runsecure/hkdfguard-pipeline-azurekeyvault` |
| Google Cloud Secret Manager | `@runsecure/hkdfguard-pipeline-googlesecretmanager` |

```ts
import type { SecretPipelineWriter } from '@runsecure/hkdfguard-abstractions';

// Any store's writer, created with the secret names and a PipelineDataProtector.
export async function provision(writer: SecretPipelineWriter, folder: string): Promise<void> {
  try {
    await writer.pullSecrets(); // rejects with SecretsNotFoundError if any is missing; the rest are kept
    await writer.writeProtectedSecretFiles(folder); // one file per secret, for FilePerSecretCache
    // or: await writer.writeJsonSecrets(`${folder}/secrets.json`); // one JSON file, for JsonSecretsFileReadOnlyCache
  } finally {
    await writer.close();
  }
}
```

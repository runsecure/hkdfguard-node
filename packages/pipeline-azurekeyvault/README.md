# @runsecure/hkdfguard-pipeline-azurekeyvault

A secret pipeline writer over one Azure Key Vault - the Node port of .NET's
`HkdfGuard.Pipeline.AzureKeyVault`. `AzureKeyVaultSecretPipelineWriter` pulls a fixed list of
secrets with Get Secret (the identity needs only `get` on secrets, never `list`), encrypts every
value at once with a `PipelineDataProtector` bound to its file name, and writes one file per secret
for `FilePerSecretCache`. It is independent of the runtime cache, and of any key ring.

`Api-Key` reads a secret's whole value, `Db-Login#password` a member of a JSON object value. The
writer's own `SecretClient` has a per-retry policy that reads each response body into a buffer of the
library's own, so the value never becomes a string; `SecretClient` is handed only the secret's
identifier.

```ts
import { DefaultAzureCredential } from '@azure/identity';
import { AesGcmPipelineDataProtector } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { DefaultFormatProvider } from '@runsecure/hkdfguard-dek';
import { AzureKeyVaultSecretPipelineWriter } from '@runsecure/hkdfguard-pipeline-azurekeyvault';

const protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), 3);
const writer = new AzureKeyVaultSecretPipelineWriter('https://myvault.vault.azure.net/', new DefaultAzureCredential(), protector,
  ['Db-Login#username', 'Db-Login#password', 'Api-Key']);
try {
  await writer.pullSecrets();
  await writer.writeProtectedSecretFiles('/etc/hkdfguard/secrets/myapp'); // Db-Login__username, Db-Login__password, Api-Key
} finally {
  await writer.close();
}
// Then hand protector.keyBase64() to the wrap tool on standard input, and register the key at version 3.
```

`@azure/identity` is the application's to install. See the module documentation (`src/index.ts`)
for names, options and errors.

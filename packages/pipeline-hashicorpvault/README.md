# @runsecure/hkdfguard-pipeline-hashicorpvault

A secret pipeline writer over HashiCorp Vault's KV secrets engine - the Node port of .NET's
`HkdfGuard.Pipeline.HashiCorpVault`. `HashiCorpVaultSecretPipelineWriter` pulls a fixed list of
secrets through Node's own HTTP client, parses each straight from the response stream, encrypts
every value at once with a `PipelineDataProtector` bound to its file name, and writes one file per
secret for `FilePerSecretCache`. It is independent of the runtime cache, and of any key ring.

A name is a secret's path, with the key to read after `#`: `myapp/db#password` reads the `password`
key of the secret at `myapp/db`, and `myapp/db` reads `defaultKey` (`value`). KV version 2 (the
default) or 1, any mount, an Enterprise namespace; the timeout, retries, agent and TLS (PEM) are the
options every HkdfGuard Vault integration shares. The token comes from a `VaultTokenSource` - a
pipeline has no key ring to protect it with - copied into a buffer zeroed after each read.

```ts
import { AesGcmPipelineDataProtector } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { DefaultFormatProvider } from '@runsecure/hkdfguard-dek';
import { HashiCorpVaultSecretPipelineWriter, StaticVaultTokenSource } from '@runsecure/hkdfguard-pipeline-hashicorpvault';

const protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), 3);
const token = new StaticVaultTokenSource(process.env['VAULT_TOKEN'] ?? '');
const writer = new HashiCorpVaultSecretPipelineWriter(process.env['VAULT_ADDR'] ?? 'https://vault.example.com:8200', token, protector,
  ['myapp/db#username', 'myapp/db#password', 'myapp/api']);
try {
  await writer.pullSecrets();
  await writer.writeProtectedSecretFiles('/etc/hkdfguard/secrets/myapp'); // myapp__db__username, myapp__db__password, myapp__api
} finally {
  await writer.close();
  token.close();
}
// Then hand protector.keyBase64() to the wrap tool on standard input, and register the key at version 3.
```

A missing secret or key rejects with `SecretsNotFoundError` once every secret has been read, the
rest kept; Vault's refusals with `VaultRequestError`; a response that isn't Vault's JSON with
`InvalidSecretDataError`. See the module documentation (`src/index.ts`) for the details.

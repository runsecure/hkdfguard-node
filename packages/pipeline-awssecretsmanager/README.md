# @runsecure/hkdfguard-pipeline-awssecretsmanager

A secret pipeline writer over AWS Secrets Manager - the Node port of .NET's
`HkdfGuard.Pipeline.AwsSecretsManager`. `AwsSecretsManagerSecretPipelineWriter` pulls a fixed list
of secrets with `GetSecretValue` (the principal needs only `secretsmanager:GetSecretValue`), encrypts
every value at once with a `PipelineDataProtector` bound to its file name, and writes one file per
secret for `FilePerSecretCache`. It is independent of the runtime cache, and of any key ring.

`prod/api-key` reads the whole SecretString, `prod/app#password` a member of a key/value secret -
both from one call per secret. A SecretBinary is refused: the protector encrypts text. Each
`GetSecretValueCommand` carries a middleware of its own that reads the response body into a buffer
of the library's own and hands the SDK `{}` in its place, so the value never becomes a string.

```ts
import { AesGcmPipelineDataProtector } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { DefaultFormatProvider } from '@runsecure/hkdfguard-dek';
import { AwsSecretsManagerSecretPipelineWriter } from '@runsecure/hkdfguard-pipeline-awssecretsmanager';

const protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), 3);
// A client of its own, credentials from the SDK's default chain (IRSA or EKS Pod Identity on EKS);
// or pass a SecretsManagerClient of yours to the constructor.
const writer = AwsSecretsManagerSecretPipelineWriter.create(protector, ['prod/app#username', 'prod/app#password', 'prod/api-key'],
  { region: 'us-east-1' });
try {
  await writer.pullSecrets();
  await writer.writeProtectedSecretFiles('/etc/hkdfguard/secrets/myapp'); // prod__app__username, prod__app__password, prod__api-key
} finally {
  await writer.close();
}
// Then hand protector.keyBase64() to the wrap tool on standard input, and register the key at version 3.
```

See the module documentation (`src/index.ts`) for names, errors and who owns the client.

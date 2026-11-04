# @runsecure/hkdfguard-pipeline-googlesecretmanager

A secret pipeline writer over one Google Cloud project's Secret Manager - the Node port of .NET's
`HkdfGuard.Pipeline.GoogleSecretManager`. `GoogleSecretManagerSecretPipelineWriter` pulls a fixed
list of secrets' latest versions with AccessSecretVersion (the principal needs only
`secretmanager.versions.access`), checks each payload against its CRC32C and the secret it names,
encrypts every value at once with a `PipelineDataProtector` bound to its file name, and writes one
file per secret for `FilePerSecretCache`. It is independent of the runtime cache, and of any key ring.

`api-key` reads the whole payload, `db-login#password` a member of a JSON object payload. The call
is made on the client's gRPC stub with the writer's own response deserializer, so the payload never
becomes a protobuf message or a string; it and the message gRPC received are zeroed.

```ts
import { AesGcmPipelineDataProtector } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { DefaultFormatProvider } from '@runsecure/hkdfguard-dek';
import { GoogleSecretManagerSecretPipelineWriter } from '@runsecure/hkdfguard-pipeline-googlesecretmanager';

const protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), 3);
// A client of its own, signed in with Application Default Credentials (Workload Identity on GKE);
// or pass a SecretManagerServiceClient of yours to the constructor.
const writer = GoogleSecretManagerSecretPipelineWriter.create('my-project', protector, ['db-login#username', 'db-login#password', 'api-key']);
try {
  await writer.pullSecrets();
  await writer.writeProtectedSecretFiles('/etc/hkdfguard/secrets/myapp'); // db-login__username, db-login__password, api-key
} finally {
  await writer.close();
}
// Then hand protector.keyBase64() to the wrap tool on standard input, and register the key at version 3.
```

See the module documentation (`src/index.ts`) for names, options, retries and errors.

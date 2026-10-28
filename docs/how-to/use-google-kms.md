# Wrap keys with Google Cloud KMS

This page sets up a Google Cloud KMS key as HkdfGuard's KEK and uses it from Node.js with
`GoogleKmsKeyWrapper`, in place of the native TPM, Secure Enclave or Platform Crypto Provider KEK.

## How it compares

Cloud KMS works like AWS KMS: one symmetric key, used through `Encrypt` and `Decrypt`, which never
leaves Cloud KMS.

| | AWS KMS | Azure Key Vault | Google Cloud KMS |
|---|---|---|---|
| Keys | One symmetric key | An RSA key to wrap, an EC P-256 key to sign | One symmetric key |
| Who can create a key file the app accepts | Principals allowed `kms:Encrypt` | Principals allowed `sign` on the EC key | Principals allowed `useToEncrypt` |
| Context binding | Encryption context (AAD) | A context string bound into the signature | A context string bound as AAD |
| New DEKs | Generated inside KMS | Generated in the process, then wrapped | Generated in the process, then wrapped |

`GoogleKmsKeyWrapper`:

- **Pins the key.** `Decrypt` is always called against the key you configure, and Cloud KMS
  refuses a ciphertext made under any other key.
- **Binds a fixed HkdfGuard label and your context** into every wrapped DEK as additional
  authenticated data (AAD). A ciphertext the same key made for anything else isn't accepted as a
  DEK.
- **Checksums every request and response with CRC32C**, as Google recommends, so data corrupted
  in transit is refused.

A key file belongs to the wrapper type that made it: a Cloud KMS key file can't be read by the AWS
or Azure wrappers. It is byte for byte the .NET `GoogleKmsKeyWrapper`'s, the Java
`GoogleKmsKeyWrapperImpl`'s and the Python `GoogleKmsKeyWrapper`'s, so each reads the others', given
the same key and context.

## 1. Create the key

Enable the API, then create a key ring and a key whose purpose is **encryption**
(`ENCRYPT_DECRYPT`, algorithm `GOOGLE_SYMMETRIC_ENCRYPTION`):

```bash
gcloud services enable cloudkms.googleapis.com --project my-project

gcloud kms keyrings create myapp --location us-east1 --project my-project
gcloud kms keys create myapp-wrap --keyring myapp --location us-east1 --project my-project \
  --purpose encryption --protection-level hsm \
  --rotation-period 90d --next-rotation-time 2027-01-01T00:00:00Z
```

| Setting | Choose | Why |
|---|---|---|
| Purpose | **Symmetric encrypt/decrypt** | `GoogleKmsKeyWrapper` calls `Encrypt` and `Decrypt`, which only this purpose accepts |
| Protection level | **HSM** (or Software) | HSM keeps the key in a FIPS 140-2 Level 3 module; both work the same here |
| Rotation | Automatic, if you like | A ciphertext names the version that made it, so rotation needs nothing here |
| Location | Where the application runs | Key rings can't be moved or deleted; the name is part of every call |

In the console: **Security**, **Key Management**, **Create key ring**, then **Create key** with
**Purpose: Symmetric encrypt/decrypt**.

> **Security:** destroying a key version makes every DEK wrapped under it, and all data encrypted
> under those DEKs, permanently unrecoverable. Cloud KMS waits before destroying a version (30 days
> by default; `--destroy-scheduled-duration` sets it when the key is created), during which it can
> be restored. Keep every version that made a key file in use enabled.

Copy the key's **resource name**, for example
`projects/my-project/locations/us-east1/keyRings/myapp/cryptoKeys/myapp-wrap`:

```bash
gcloud kms keys describe myapp-wrap --keyring myapp --location us-east1 --project my-project --format "value(name)"
```

Give the key, never a key version (`.../cryptoKeyVersions/1`): the wrapper refuses one. Encrypt
uses the key's primary version, and Decrypt finds the version from the ciphertext.

## 2. Grant each identity only what it calls

Grant roles on the **key**, not the project or key ring:

| Identity | Role on the key |
|---|---|
| Release pipeline that creates key files | Cloud KMS CryptoKey Encrypter (`roles/cloudkms.cryptoKeyEncrypter`) |
| Application | Cloud KMS CryptoKey Decrypter (`roles/cloudkms.cryptoKeyDecrypter`) |

```bash
gcloud kms keys add-iam-policy-binding myapp-wrap --keyring myapp --location us-east1 --project my-project \
  --member "serviceAccount:myapp@my-project.iam.gserviceaccount.com" \
  --role roles/cloudkms.cryptoKeyDecrypter
```

> **Security:** give the application decrypt without encrypt. Symmetric encryption needs no
> secret beyond permission to use the key, so any principal allowed `useToEncrypt` can create a key
> file the application accepts, holding a DEK of its choosing. Keep encrypt with the pipeline.

## 3. Give the process a credential

The client signs in with Application Default Credentials (ADC). Deployed, use the **attached
service account** (Compute Engine, Cloud Run, GKE Workload Identity); outside Google Cloud, use
Workload Identity Federation. On a developer machine, ADC uses
`gcloud auth application-default login`. Don't give a deployed process a service account key file.

## 4. Create the wrapper

Install the packages, and `@google-cloud/kms` for the client:

```sh
npm install @runsecure/hkdfguard-keywrapping-googlekms @runsecure/hkdfguard-cryptoprovider-aesgcm256 @runsecure/hkdfguard-dek @google-cloud/kms
```

> **TODO (maintainer):** confirm the install command once the packages are published.

`@google-cloud/kms` brings `google-gax`, `google-auth-library` (ADC), `@grpc/grpc-js` and
`protobufjs`. `@runsecure/hkdfguard-keywrapping-googlekms` brings `@runsecure/hkdfguard-securefile`,
which on Windows compiles a small C add-on when it is installed - so installing on Windows needs
Python 3 and Visual Studio Build Tools, as `@runsecure/hkdfguard-keywrapping-native-v1` does. Nothing
is compiled on Linux or macOS.

```ts
import { KeyManagementServiceClient } from '@google-cloud/kms';
import { GoogleKmsKeyWrapper } from '@runsecure/hkdfguard-keywrapping-googlekms';

const kms = new KeyManagementServiceClient();  // Application Default Credentials
const wrapper = new GoogleKmsKeyWrapper(kms, 'projects/my-project/locations/us-east1/keyRings/myapp/cryptoKeys/myapp-wrap',
  { context: 'com.example.myapp' });
```

- **The context** is bound into every key file and must be given again, exactly, to reveal it.
  Use one value per application, so a key file made for one can't be used by another that shares
  the key. It isn't secret.
- **Create one client and keep it.** `KeyManagementServiceClient` holds a gRPC channel and can be
  shared between wrappers. The wrapper never closes it: `await kms.close()` once nothing uses the
  wrapper any more - after the key ring is closed, since its background refresh calls the wrapper.
- **Client settings.** Credentials, the endpoint and the transport are the client's:
  `new KeyManagementServiceClient({ credentials, apiEndpoint })`, or `{ fallback: true }` for
  HTTP/JSON instead of gRPC. By default the client retries `UNAVAILABLE` and `DEADLINE_EXCEEDED`
  for up to 60 seconds in all before the wrapper rejects.
- **Keep the client's debug logging off.** Setting `GOOGLE_SDK_NODE_LOGGING` to include this client
  makes it log every request and response in full - the keys the wrapper sends and receives
  included.
- **A signal stops the wait, not the call.** Every wrapper method takes an `AbortSignal`, but the
  client can't cancel a call. An abort rejects at once with the signal's reason; the request runs on
  until it completes or times out, and a key it reveals then is zeroed unused.

Use it as any other key wrapper, with ephemeral keys or key files, as in
[Wrap keys with AWS KMS](use-aws-kms.md#5-build-a-key-ring-with-an-ephemeral-key). An ephemeral key
needs `useToEncrypt` to be made, which step 2 keeps from the application. Use key files instead, or
give an identity that only ever uses ephemeral keys its own key.

## 5. Create and use key files

The release pipeline creates key files with the wrapper itself, running as the pipeline identity
from step 2:

```ts
import { writeFileSync } from 'node:fs';
import { MAX_WRAPPED_KEY_BYTES } from '@runsecure/hkdfguard-abstractions';

const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
const length = await wrapper.generateAndWrap(wrapped);
writeFileSync('C:\\HkdfGuardKeys\\myapp\\v1.key', wrapped.subarray(0, length));
await kms.close();
```

`generateAndWrap` generates the DEK in the pipeline's process, since Cloud KMS has no "generate data
key". To wrap the key of an `AesGcmPipelineDataProtector`, use `wrap` as in
[Wrap keys with AWS KMS](use-aws-kms.md#6-create-a-key-file). A key file is about 113 bytes.

Key files are read only from where no untrusted account could have written or replaced them,
exactly as for AWS KMS: see [Where key files can live](use-aws-kms.md#where-key-files-can-live), and
pass a `KeyFileTrust` as the wrapper's `keyFileTrust` option if the pipeline writes key files as an
account of its own. Then use the key file as in [Use the key file](use-aws-kms.md#7-use-the-key-file).

## Choosing a refresh interval

Every key in a ring re-reveals itself once per `keyRefreshInterval`: one `Decrypt` call to Cloud
KMS. See [Choosing a refresh interval](use-aws-kms.md#choosing-a-refresh-interval) for the
trade-off, and [Cloud KMS pricing](https://cloud.google.com/kms/pricing) for what each operation and
active key version costs: HSM keys cost more than software keys.

## Limitations

- **Copies the wrapper can't zero.** The wrapper zeroes its own copy of a key it wraps once the
  client is done with the request, and the buffer the client decodes a revealed key into once it is
  copied into your `result`. But the client serializes each request into a buffer of its own (a
  protobuf message over gRPC, base64 text in JSON over HTTP/JSON), which the wrapper can't reach.
  `hardenProcess()` from `@runsecure/hkdfguard-keywrapping-native-v1` keeps a debugger or crash
  dump away from such copies.
- **No credential, no process - unless initialized first.** Called with no credential, Google's
  client rejects the call and also raises an unhandled rejection of its own, which ends a Node
  process. The wrapper awaits the client's `initialize()` before every call, so the call rejects
  with the reason instead; do the same before using the client for anything else.
- The key-file limitations are those of
  [Wrap keys with AWS KMS](use-aws-kms.md#limitations).

## If something goes wrong

Every Cloud KMS failure rejects with a `GoogleKmsError` (`code` `ERR_HKDFGUARD_GOOGLE_KMS`); for a
refusal the message names the gRPC status and Google's description, and the client's error is its
`cause` (over HTTP/JSON too, where the client maps the HTTP status to a gRPC one). A failed unwrap
zeroes the caller's buffer. An aborted signal rejects with its reason, unchanged. Argument errors -
a resource name that isn't one, included - throw `InvalidArgumentError`. Reading a key file fails
as described for [AWS KMS](use-aws-kms.md#if-something-goes-wrong).

| The message says | Cause | Fix |
|---|---|---|
| `PERMISSION_DENIED` | The identity lacks the role on the key, or the API isn't enabled | Step 2; `gcloud services enable cloudkms.googleapis.com` |
| `NOT_FOUND` | The resource name is wrong | Step 1's `describe` command |
| `INVALID_ARGUMENT: Decryption failed.` | The key file was altered, made under another key or context, or by another tool | Restore it; use the same key and context |
| `FAILED_PRECONDITION` | The key version the key file names is disabled or destroyed | Re-enable or restore the version |
| `isn't a Cloud KMS key's resource name` (`InvalidArgumentError`) | The name is malformed, or names a key version | Give `projects/.../cryptoKeys/{key}` |
| `corrupted in transit` | A checksum didn't match | Retry; if it persists, check proxies between the process and Cloud KMS |
| `Could not load the default credentials` | No credential could be found | Step 3 |
| `UNAUTHENTICATED` | A credential was found but couldn't get a token | Step 3 |
| `UNAVAILABLE`, or `DEADLINE_EXCEEDED: Total timeout of API ... exceeded 60000 milliseconds` | Cloud KMS couldn't be reached, even after the client's retries | Check the network path to `cloudkms.googleapis.com` |

# hkdfguard-node
HkdfGuard KeyWrapping and Secrets Protection Library for Node JS

The Node.js port of HkdfGuard, written in TypeScript. Span, metric and attribute names, error
semantics, ciphertext layout and the `enc::v<version>::<base64>` format are identical to the .NET and
Go ports, so values written by one port are read by the others.

**Documentation:** start with [Getting started](docs/getting-started.md), which takes one Windows PC
or Apple-silicon Mac from nothing to a TPM- or Secure-Enclave-protected key file. Key setup -
installing the native package and provisioning, wrapping and retiring KEKs with the `hkdfguard`
tool - is in the [CLI reference](docs/reference/cli.md). The [docs index](docs/README.md)
lists every page.

## Packages

Each package is published separately. Implementations depend only on the abstractions, never on each
other, so the key wrapper, the cipher and the cache can each be swapped for another implementation.
(The AWS KMS, Azure Key Vault, Google Cloud KMS and HashiCorp Vault transit key wrappers, the
`cache` package's `FilePerSecretCache` and `cache-jsonsecretsfile`, use `securefile`, a helper that
implements no interface; the `pipeline-*` writers use `pipeline`, which uses `cache` only for
`FilePerSecretCache`'s file-name rule.)

| Package | Port of | What it is |
|---|---|---|
| `@runsecure/hkdfguard-diagnostics` | HkdfGuard.Diagnostics | OpenTelemetry names and helpers, sensitive-logging flags, logging (any console-shaped logger) |
| `@runsecure/hkdfguard-abstractions` | HkdfGuard.Abstractions | Interfaces (`KeyWrapper`, `CryptoProviderFactory`, `KeyRing`, `ProtectedCache`, `PipelineDataProtector`, `SecretPipelineWriter`, ...), shared rules and errors |
| `@runsecure/hkdfguard-keywrapping-native-v1` | HkdfGuard.KeyWrapping.V1 | `KeyWrapper` over the OS's native KMS library (TPM2, Secure Enclave, Platform Crypto Provider) |
| `@runsecure/hkdfguard-keywrapping-awskms` | HkdfGuard.KeyWrapping.AwsKms | `KeyWrapper` over one symmetric AWS KMS key, through the AWS SDK for JavaScript v3 (`KMSClient`) |
| `@runsecure/hkdfguard-keywrapping-azurekeyvault` | HkdfGuard.KeyWrapping.AzureKeyVault | `KeyWrapper` over an RSA wrapping key and an EC P-256 signing key in Azure Key Vault, through `@azure/keyvault-keys` |
| `@runsecure/hkdfguard-keywrapping-googlekms` | HkdfGuard.KeyWrapping.GoogleKms | `KeyWrapper` over one symmetric Google Cloud KMS key, through `@google-cloud/kms` (`KeyManagementServiceClient`) |
| `@runsecure/hkdfguard-integration-hashicorpvault` | HkdfGuard.Integration.HashiCorpVault | `VaultClient`, a vault-client-go port with tokens held only protected by the key ring; and what the Vault key wrapper and cache share - `VaultTlsOptions` (PEM, or PKCS#12 key stores whose passwords the key ring protects), the token sources, retries and address checks |
| `@runsecure/hkdfguard-keywrapping-hashicorpvault` | HkdfGuard.KeyWrapping.HashiCorpVault | `KeyWrapper` over one key in a HashiCorp Vault transit secrets engine, through Node's own HTTP client |
| `@runsecure/hkdfguard-securefile` | HkdfGuard.SecureFile | `readTrustedKeyFile`: the native library's key-file checks in TypeScript, for key wrappers with no native library to read through; `readTrustedFile` and `readTrustedFileWith`: the same location checks for any other file (secret files, certificates), with only a caller-chosen size limit, read at most one byte past it |
| `@runsecure/hkdfguard-cryptoprovider-aesgcm256` | HkdfGuard.CryptoProvider.AesGcm256 | The AES-256-GCM `CryptoProviderFactory` and `PipelineDataProtector` (whose `writeDek` writes its key to the wrap tool's stdin from a buffer zeroed once written) |
| `@runsecure/hkdfguard-dek` | HkdfGuard.DataEncryptionKey, HkdfGuard.Options | Key rings with rotation, data protectors, the stored format, `buildKeyRing`, and options read from an `appsettings.json` section |
| `@runsecure/hkdfguard-cache` | HkdfGuard.Cache | Protected caches, pull-through `CacheSource`s and collections; `FilePerSecretCache` over a trusted local folder of one already-encrypted file per secret, each read through `readTrustedFile` on its first lookup and cached still encrypted; `RemoteSecretCache`, `SecretValueSink`, `SecretJsonBody` for caches over a secret store. Depends on `securefile` |
| `@runsecure/hkdfguard-cache-jsonsecretsfile` | HkdfGuard.Cache.JsonSecretsFile | `JsonSecretsFileReadOnlyCache` over one trusted JSON file holding every secret, as a pipeline's `writeJsonSecrets` writes it: a single object mapping each secret's name to its already-encrypted value. The whole file is read through `readTrustedFile` on the first lookup, every value authenticated under its name (any failure refuses the whole file, which is read again next time), and the values kept still encrypted; names match ignoring ASCII case and follow `FilePerSecretCache`'s name rule. Depends on `cache` and `securefile` |
| `@runsecure/hkdfguard-cache-awssecretsmanager` | HkdfGuard.Cache.AwsSecretsManager | `AwsSecretsManagerSecretCache` over AWS Secrets Manager, through the application's `SecretsManagerClient` |
| `@runsecure/hkdfguard-cache-azurekeyvault` | HkdfGuard.Cache.AzureKeyVault | `AzureKeyVaultSecretCache` over Azure Key Vault secrets, through `@azure/keyvault-secrets` |
| `@runsecure/hkdfguard-cache-googlesecretmanager` | HkdfGuard.Cache.GoogleSecretManager | `GoogleSecretManagerSecretCache` over Google Cloud Secret Manager, through a `SecretManagerServiceClient` |
| `@runsecure/hkdfguard-cache-hashicorpvault` | HkdfGuard.Cache.HashiCorpVault | `HashiCorpVaultSecretCache` over HashiCorp Vault's KV secrets engine, through Node's own HTTP client |
| `@runsecure/hkdfguard-pipeline` | HkdfGuard.Pipeline | `SecretPipelineWriter`, the shared base of the secret stores' pipeline writers: a fixed list of secret names (`name` or `name#key`) and a `PipelineDataProtector`; each secret read once however many of its keys are listed, every value encrypted at once bound to its file name (`/` and `#` become `__`), only the ciphertext kept, and written as one file per secret - the layout `FilePerSecretCache` reads - or as one JSON file of them all (`writeJsonSecrets`), the file `JsonSecretsFileReadOnlyCache` reads; each also to a stream (`writeProtectedSecretFilesTo`, a PAX tar archive of the files; `writeJsonSecretsTo`, the JSON) for a remote command's stdin, such as `ssh -T host sudo -n tar -x ...`. No key ring; a value that isn't UTF-8 text is refused. `PinnedBody` reads a response body into a buffer of the library's own. Depends on `cache` (for `FilePerSecretCache`'s file-name rule), never on the runtime caches |
| `@runsecure/hkdfguard-pipeline-hashicorpvault` | HkdfGuard.Pipeline.HashiCorpVault | `HashiCorpVaultSecretPipelineWriter` over one HashiCorp Vault KV engine, version 1 or 2 (`path` or `path#key`, a name without a key reading `defaultKey`), the token from a `VaultTokenSource` in a buffer zeroed after each read, through Node's own HTTP client |
| `@runsecure/hkdfguard-pipeline-awssecretsmanager` | HkdfGuard.Pipeline.AwsSecretsManager | `AwsSecretsManagerSecretPipelineWriter` over AWS Secrets Manager (`name` for the whole SecretString, `name#key` for a member of a key/value secret), through the caller's `SecretsManagerClient` or one of its own (`create`); a middleware on each `GetSecretValueCommand` takes the body before the SDK parses it and hands the SDK `{}`; a SecretBinary is refused |
| `@runsecure/hkdfguard-pipeline-azurekeyvault` | HkdfGuard.Pipeline.AzureKeyVault | `AzureKeyVaultSecretPipelineWriter` over one Azure Key Vault (`name` or `name#key` for a member of a JSON object value), through its own `SecretClient` whose per-retry policy takes the body before the SDK parses it; any `TokenCredential` - Workload Identity on AKS |
| `@runsecure/hkdfguard-pipeline-googlesecretmanager` | HkdfGuard.Pipeline.GoogleSecretManager | `GoogleSecretManagerSecretPipelineWriter` over one Google Cloud project's Secret Manager (`id` or `id#key`), the latest version read on the client's gRPC stub with the writer's own deserializer; each payload checked against its CRC32C and the secret it names, and zeroed, as is gRPC's received message; `create` for a client of its own (Application Default Credentials - Workload Identity on GKE) |
| `@runsecure/hkdfguard-encryptedconfig` | HkdfGuard.EncryptedConfiguration | Reads pipeline-encrypted secrets from any configuration source (`envLookup`, `flattenJson`, `mapLookup`) |
| `@runsecure/hkdfguard-integration-configurationresolver` | HkdfGuard.Integration.ConfigurationResolver, with the parts of ConfigurationResolver it uses | Resolves `${name}` templates from the protected caches: `ProtectedCacheValueProvider` over any cache, and `ResolvingProtectedCacheCollection`, which resolves the templates its sources hold and caches each result encrypted |
| `@runsecure/hkdfguard-options-certificate` | HkdfGuard.Options.Certificate | `CertificateOptions` (Windows store, macOS keychain, Linux OpenSSL provider, or a password-protected PKCS#12/PEM file), its validator and `CertificateOptionsLoader`: a `LoadedCertificate` that signs and decrypts through the store - whose key is never exported - and serves TLS from a file or provider key, every file read through `readTrustedFile`. Its own N-API add-on on Windows and macOS. Depends on `securefile` |

```ts
import { NativeKeyWrapperV1 } from '@runsecure/hkdfguard-keywrapping-native-v1';
import { AesGcmCryptoProviderFactory } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { buildKeyRing } from '@runsecure/hkdfguard-dek';

const ring = await buildKeyRing({
  keyWrapper: NativeKeyWrapperV1.create('com.example.orders'), // the KEK: swap for another KeyWrapper
  cryptoProviderFactory: new AesGcmCryptoProviderFactory(),     // the cipher: swap for another factory
  keyRefreshInterval: 60,
  keyFiles: { 1: '/etc/app/key.v1' },
});
const protector = ring.createProtector('orders');
```

The same settings can come from the `HkdfGuard` section of an `appsettings.json` shared with the .NET
port, and pipeline-encrypted secrets from that file can be read back:

```ts
import { keyRingConfigFromOptions, keyRingOptionsFromJson } from '@runsecure/hkdfguard-dek';
import { EncryptedConfigurationReader, flattenJson, mapLookup } from '@runsecure/hkdfguard-encryptedconfig';

const appsettings = readFileSync('appsettings.json', 'utf8');
const ring = await buildKeyRing(keyRingConfigFromOptions(keyRingOptionsFromJson(appsettings), wrapper, factory));
const secrets = new EncryptedConfigurationReader(ring, mapLookup(flattenJson(appsettings)));
const n = await secrets.decrypt('ConnectionStrings:Admin', buffer);
```

## Encryption budget

With random 96-bit nonces, AES-GCM is safe for about 2^32 encryptions under one key (NIST
SP 800-38D). Each crypto provider counts the encryptions under its key, warns at 2^28, and
refuses to encrypt past 2^31 (`MAX_ENCRYPTIONS_PER_KEY`). Decryption is never limited.

That count is kept per process, by design. It is exact for the key an application should encrypt
with at runtime: an ephemeral key, generated at startup and held only in that process's memory, so
no other process or restart ever adds to its use. Key files are different. They carry what the
deployment pipeline encrypted and are meant to be decrypted at runtime; every process that loads a
key file, and every restart, starts a fresh count for it.

**For encrypt operations, add an ephemeral key** at a version above every key file
(`ephemeralKeys: [2]` beside `keyFiles: { 1: ... }`). New values are then encrypted under it, while the pipeline's values still decrypt
under their key files. A value encrypted under an ephemeral key can't be decrypted once the process
exits, which suits caches and other in-process data; never persist it.

If an application does encrypt values that must outlive the process under a key file, its
encryptions under that file are not counted together across instances and restarts. Bound them by
deploying a new key file at a higher version regularly. `keyFileMaxAgeDays` (365 days by default) enforces this: a
current key file stops encrypting at that age, and decryption under it never stops.

## The native add-on

`@runsecure/hkdfguard-keywrapping-native-v1` calls the native KMS library through its own small C
add-on, `native/hkdfguard_native.c`, compiled by node-gyp when the package is installed - so
installing it needs Python 3 and a C compiler (Visual Studio Build Tools on Windows). On Windows it
is linked with `/DEPENDENTLOADFLAG:0x800`, so the DLLs it imports - `wintrust`, `crypt32` and
`version` among them, none a KnownDLL - resolve from System32 only: Node loads an add-on with
`LOAD_WITH_ALTERED_SEARCH_PATH`, which would otherwise search its own folder first, letting a
planted `wintrust.dll` decide whether `HkdfGuard.dll` is trusted. The add-on only
loads and calls the library; every verification rule (path ownership, code signature on Windows and
macOS, the dynamic linker's environment, what would be and what was actually loaded) is TypeScript,
and is tested on every platform. On Linux, before loading, the process's own dynamic linker is asked
in list mode (`ld.so --list`, what `ldd` uses) where it would find every library
`libhkdfguard.so.1` pulls in; each must pass the same ownership checks, so a dependency found
somewhere writable is refused before any of its code runs. The Linux library is not
content-pinned: verify a release with Sigstore/cosign (`gh attestation verify`) when you install it,
and the loader enforces path integrity from there.
On macOS the per-user location is found from the account database (the add-on's `getpwuid_r`),
never `$HOME`, and the library must be at least version 0.9.0 - its `LC_ID_DYLIB` current version,
covered by the signature - so an older signed release can't be planted in its place. On Windows
the same 0.9.0 floor applies to `HkdfGuard.dll`'s signed version resource, and a DLL with none is
refused.

Certificate revocation: on Windows, once the signature and its pins have passed, the loader asks
WinVerifyTrust once more, now checking revocation across the signing chain and allowed to fetch
revocation data over the network. It refuses the library only when a certificate is definitely
revoked; if revocation can't be determined (offline, no data), it loads. A host whose network
silently drops traffic, rather than refusing it, may stall once, on the first load, until that
lookup times out. On macOS revocation isn't checked: the defences are the Developer ID and Team ID
pins, the admin-only system install, and the minimum library version. A compromised signing
identity is answered by a new release and a raised minimum version.

KMS calls run on libuv's thread pool, so a TPM operation never blocks the event loop.

The Windows library is `%ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll`, beside the `hkdfguard.exe`
tool; on Linux the tool is `/usr/bin/hkdfguard`. Every platform's library returns the same status
codes, number for number (`Status` in `packages/keywrapping-native-v1/src/status.ts`): a failed
call throws `StatusError`, whose message says what its status means - adding, on each platform,
what to do about it there.

**Key files are read through the native library.** `NativeKeyWrapperV1.readKeyFile`, which
`buildKeyRing` uses for every key file, reads the file with the
library's `hkdfguard_open_file`. It returns the bytes still wrapped and never touches a KEK, but
first refuses a file that is missing, unreadable, the wrong size, not a wrapped DEK, or that holds
what looks like an unwrapped key (32 raw bytes, optionally followed by one line ending (LF or
CRLF), or their hex or base64: treat that as a key exposure) - and one whose path isn't trusted: a link, junction or other reparse point, an 8.3 short
name, a network, mapped or SUBST drive, or a file or folder another account could write or replace.
A refusal throws `KeyFileRefusedError`, with `status` and an fs-style `code`: `ENOENT`, `EACCES`
(unreadable or untrusted), `ERR_HKDFGUARD_INVALID_KEY_FILE` (size or contents),
`ERR_HKDFGUARD_INVALID_ARGUMENT` (status -1: a path the library rejects as an argument) or `EIO`. Every key
wrapper must implement `readKeyFile`: there is no fallback that reads key files with Node's own file
I/O, because whoever can replace a key file chooses the key new data is encrypted under, and only
the wrapper can say which files it trusts.

### Process hardening

DEKs pass through your process's memory, so a crash dump, or another process of the same user
attaching a debugger or reading that memory, could recover them. `hardenProcess()` calls the
native library's `hkdfguard_harden_process_with_flags` to close that off, on every platform:

| Platform | What it does |
|---|---|
| Windows | Crash reports leave out the heap, and the process's and its threads' access lists are replaced so only SYSTEM can read or write its memory, inject threads or duplicate its handles. Its own account keeps only query, synchronize and terminate. |
| Linux | Core dumps off (hard limit included), and the process marked non-dumpable, which also stops ptrace and `/proc/<pid>/mem` access by the same user. |
| macOS | Core dumps off and debugger attachment denied. Whether code can be injected depends on the host executable's code signature, which the library checks but can't change. |

Neither the native library nor any machine policy does this for you: it changes process-wide
state your application owns, so it is opt-in. Call it once, early in startup - after any privilege
drop on Linux, and on Windows before the process starts threads: threads that exist at the call
are covered, later ones keep the default access. In Node that means before the first asynchronous
`fs`, `crypto`, `dns` or `zlib` call and the first KMS call (each starts libuv's thread pool), and
before any `worker_threads` worker:

```ts
import { hardenProcess } from '@runsecure/hkdfguard-keywrapping-native-v1';

hardenProcess();   // throws StatusError if it fails: don't start
```

Native debuggers, memory dumps and crash dumps stop working for the process. It is a same-user
barrier: it does not stop administrators, root, SYSTEM, `SeDebugPrivilege`, `CAP_SYS_PTRACE` or
the kernel, and it does not keep memory out of swap, the page file or hibernation files. Nor does
it cover Node's own inspector, which runs inside the process: don't run a hardened process with
`--inspect`, and on Linux and macOS start it with `--disable-sigusr1`, since otherwise any process
of the same user can open the inspector by sending it `SIGUSR1`.

`hardenProcess({ requireProtectedSignature: true })` is the strict form the native command-line
tools use: it fails unless no other process of the same user can debug or inject into this one.
An option `hardenProcess` doesn't know, or a value that isn't a boolean, throws
`InvalidArgumentError` before the native library is called.

- **Windows:** it also closes threads started later - libuv's thread pool included - and
  everything else the process creates afterwards without its own security descriptor (child
  processes, named pipes, named events), to its own account. Use it in a service that shares no
  objects with other processes by name: a `child_process` started afterwards, for example, can't
  be stopped by Task Manager, and a same-user client can't connect to a named pipe the process
  creates without a security descriptor.
- **macOS:** it fails unless the host executable is signed with the Hardened Runtime and without
  the `get-task-allow` or `DYLD_*` entitlements, so unsigned hosts such as a plain `node` can't
  use it. Without it, a weak signature is only logged.
- **Linux:** it adds nothing; the plain call already guarantees it.

**Node on Windows:** the plain call closes the threads that exist when it runs, and threads started
later keep the default access, which lets other processes of the same user read and change their
registers. Calling it before the first asynchronous call keeps libuv's thread pool covered, but
nothing in a real service stays that disciplined: any dependency's first `fs.promises` or `crypto`
call, a `worker_threads` worker, or a later KMS call starts threads that plain mode leaves open. So
**use `requireProtectedSignature: true` for a Windows service**: it closes later threads too.

## Wrapping under AWS KMS instead

`@runsecure/hkdfguard-keywrapping-awskms` puts the KEK in AWS KMS instead of the machine's TPM or
Secure Enclave: DEKs are wrapped with `Encrypt`, revealed with `Decrypt` - the key pinned, so a key
file wrapped under any other key is refused - and generated with `GenerateDataKeyWithoutPlaintext`,
so the plaintext of a new DEK never leaves KMS. Access is IAM's, every call is in CloudTrail, and
no native library is involved. The application creates, configures and owns the `KMSClient`; the
wrapper never creates or destroys one.

```ts
import { KMSClient } from '@aws-sdk/client-kms';
import { AwsKmsKeyWrapper } from '@runsecure/hkdfguard-keywrapping-awskms';

const kms = new KMSClient({});
const ring = await buildKeyRing({
  keyWrapper: new AwsKmsKeyWrapper(kms, 'arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab',
    { encryptionContext: { purpose: 'com.example.orders' } }), // logged in plaintext by CloudTrail: no secrets
  cryptoProviderFactory: new AesGcmCryptoProviderFactory(),
  keyRefreshInterval: 300,
  keyFiles: { 1: '/etc/hkdfguard/keys/orders/v1.key' },
});
```

A KMS failure rejects with `AwsKmsError` (`ERR_HKDFGUARD_AWS_KMS`), naming the operation, the key,
KMS's error name and the HTTP status, with the SDK's error as its `cause`. The wrapper zeroes its
copy of a key sent to `Encrypt` and the buffer the SDK decodes `Decrypt`'s plaintext into; the
base64 strings the SDK puts on the wire can't be zeroed.

Key files are read through `@runsecure/hkdfguard-securefile`, which applies the native library's
`hkdfguard_open_file` rules without the native library: the file and every folder above it must be
owned and writable only by administrators (SYSTEM, Administrators, TrustedInstaller; root) or a
`KeyFileTrust` principal, on a local fixed drive with no link, junction or substituted drive on its
path (Windows), or through directories and links only root or a trusted user owns (Linux, Apple
silicon macOS) - and must not look like a plaintext key. Anyone who can call `kms:Encrypt` on the
key could otherwise replace a key file and choose your DEK. On Linux and macOS the checks are Node's
own `fs` calls; on Windows they need Win32 calls (owner and DACL through the opened handle, final
path, reparse points, 8.3 names, drive type), made through the package's small C add-on
(`native/hkdfguard_securefile.c`), compiled by node-gyp at install on Windows only. It links only
`kernel32` and `advapi32`, with `/DEPENDENTLOADFLAG` restricting their resolution to System32, and
returns facts only: every rule is TypeScript, tested on every platform.

[Wrap keys with AWS KMS](docs/how-to/use-aws-kms.md) covers the key, IAM permissions, credentials,
key files, refresh intervals, limitations and troubleshooting.

## Wrapping under Azure Key Vault instead

`@runsecure/hkdfguard-keywrapping-azurekeyvault` puts the KEK in Azure Key Vault, as two keys: an RSA
key (2048 or 3072 bits) wraps each DEK with RSA-OAEP-256, and a separate EC P-256 key signs each
wrapped DEK with ES256. RSA-OAEP wrapping needs only the public key, so on its own anyone could make
a key file holding a DEK they chose; the signature needs the signing key's private half, which never
leaves Key Vault, and `unwrap` verifies it before it unwraps anything. Give `sign` to the pipeline
that creates key files, never to the application.

```ts
import { DefaultAzureCredential } from '@azure/identity';
import { AzureKeyVaultKeyWrapper } from '@runsecure/hkdfguard-keywrapping-azurekeyvault';

const ring = await buildKeyRing({
  keyWrapper: new AzureKeyVaultKeyWrapper('https://myvault.vault.azure.net/keys/orders-wrap',
    'https://myvault.vault.azure.net/keys/orders-sign',
    new DefaultAzureCredential(),             // a managed identity, deployed
    { context: 'com.example.orders' }),       // bound into every signature; not secret
  cryptoProviderFactory: new AesGcmCryptoProviderFactory(),
  keyRefreshInterval: 300,
  keyFiles: { 1: '/etc/hkdfguard/keys/orders/v1.key' },
});
```

Both keys are pinned: a key file records only the two key versions it was made with, and the vault
and key names always come from the constructor, so either key can be rotated in Key Vault while the
versions existing key files name stay enabled. Key files are byte for byte those of the .NET, Java
and Python wrappers (359 bytes under an RSA-2048 key, 487 under RSA-3072). The wrapper creates its
Key Vault clients from the application's credential, one per key version it uses. The SDK has no
local RSA-OAEP-256 or ES256, so every operation is a Key Vault call; `generateAndWrap` generates
the DEK in the process, since Key Vault has no "generate data key". A failure rejects with
`AzureKeyVaultError` (`ERR_HKDFGUARD_AZURE_KEY_VAULT`), naming the operation, the key, Key Vault's
error code and the HTTP status, with the SDK's error as its `cause`. As with AWS KMS, the wrapper
zeroes its own copies of keys, but not the base64 strings the SDK puts on the wire, and reads key
files through `@runsecure/hkdfguard-securefile`.

[Wrap keys with Azure Key Vault](docs/how-to/use-azure-key-vault.md) covers the two keys, the
permissions for each identity, credentials, key files and troubleshooting.

## Wrapping under Google Cloud KMS instead

`@runsecure/hkdfguard-keywrapping-googlekms` puts the KEK in Google Cloud KMS: one symmetric key
(purpose `ENCRYPT_DECRYPT`), used through `Encrypt` and `Decrypt` with a `KeyManagementServiceClient`
(`@google-cloud/kms`) the application creates, owns and closes.

```ts
import { KeyManagementServiceClient } from '@google-cloud/kms';
import { GoogleKmsKeyWrapper } from '@runsecure/hkdfguard-keywrapping-googlekms';

const kms = new KeyManagementServiceClient();  // Application Default Credentials
const ring = await buildKeyRing({
  keyWrapper: new GoogleKmsKeyWrapper(kms, 'projects/my-project/locations/us-east1/keyRings/orders/cryptoKeys/orders-wrap',
    { context: 'com.example.orders' }),        // bound into every wrapped DEK; not secret
  cryptoProviderFactory: new AesGcmCryptoProviderFactory(),
  keyRefreshInterval: 300,
  keyFiles: { 1: '/etc/hkdfguard/keys/orders/v1.key' },
});
```

The key is pinned: `Decrypt` always names the key given, never a version, and Cloud KMS refuses a
ciphertext made under any other key; a ciphertext names its own key version, so rotation needs
nothing here. Every wrapped DEK binds a fixed HkdfGuard label and the context as additional
authenticated data, and every request and response carries a CRC32C checksum, as Google recommends.
Symmetric encryption needs no secret beyond permission to use the key, so give the application
decrypt only and the pipeline that creates key files encrypt only; key files are read through
`@runsecure/hkdfguard-securefile`, as for AWS KMS. Key files are byte for byte those of the .NET, Java
and Python wrappers, about 113 bytes. `generateAndWrap` generates the DEK in the process, since Cloud
KMS has no "generate data key". A failure rejects with `GoogleKmsError` (`ERR_HKDFGUARD_GOOGLE_KMS`),
naming the operation, the key and the gRPC status (`INVALID_ARGUMENT: Decryption failed.`), with the
client's error as its `cause`.

The wrapper zeroes its own copies of keys, and the buffer the client decodes `Decrypt`'s plaintext
into, but not the request the client serializes. Two things about Google's client matter here:

- **Keep its debug logging off.** With `GOOGLE_SDK_NODE_LOGGING` naming it, the client logs every
  request and response - plaintext keys included.
- **It can't cancel a call.** A `signal` that aborts stops the wrapper waiting; the request runs on
  until it completes or the client's timeout passes, and a key it then reveals is zeroed unused.

The wrapper awaits the client's `initialize` before every call, so a missing credential rejects that
call. Called directly, the client would also raise an unhandled rejection, which ends the process.

[Wrap keys with Google Cloud KMS](docs/how-to/use-google-kms.md) covers the key, the IAM roles for
each identity, credentials, key files and troubleshooting.

## Wrapping under HashiCorp Vault transit instead

`@runsecure/hkdfguard-keywrapping-hashicorpvault` puts the KEK in a HashiCorp Vault transit secrets
engine: one key (`aes256-gcm96`, Vault's default), used through `encrypt` and `decrypt`, with new
DEKs made by `datakey/wrapped` so the plaintext never leaves Vault. HashiCorp ships no Node SDK, and
the community client parses Vault's answers into strings that can't be zeroed, so the wrapper talks
to Vault's HTTP API through Node's own `node:http` and `node:https`, with no third-party dependency,
as `@runsecure/hkdfguard-cache-hashicorpvault` does.

```ts
import { HashiCorpVaultTransitKeyWrapper, StaticVaultTokenSource } from '@runsecure/hkdfguard-keywrapping-hashicorpvault';

const token = new StaticVaultTokenSource(process.env.VAULT_TOKEN!); // or a VaultTokenSource over your auth method
const wrapper = new HashiCorpVaultTransitKeyWrapper('https://vault.example.com:8200', 'orders-kek', token,
  { context: 'com.example.orders' });          // bound as associated_data; not secret
const ring = await buildKeyRing({
  keyWrapper: wrapper,
  cryptoProviderFactory: new AesGcmCryptoProviderFactory(),
  keyRefreshInterval: 300,
  keyFiles: { 1: '/etc/hkdfguard/keys/orders/v1.key' },
});
// Once the ring is closed: wrapper.close(); token.close();
```

The key is pinned by its path, and Vault's key rotation is transparent: a ciphertext names its key
version, and stays readable while that version is at or above `min_decryption_version`. The context
is bound into every wrapped DEK as Vault's `associated_data`; since `datakey/wrapped` ignores it,
with a context `generateAndWrap` generates the DEK in the process and wraps it with `encrypt`. An
answer whose warnings say Vault ignored a parameter (a Vault too old for `associated_data`) is
refused, so a context is never silently dropped. A key file is Vault's ciphertext, `vault:v1:...`,
about 89 bytes of ASCII, byte for byte that of the .NET, Go, Java and Python wrappers, and is read
through `@runsecure/hkdfguard-securefile`, as for AWS KMS. The address must be https, except on
loopback; no redirect is followed; a transient failure (no answer, 429, a 5xx other than 501) is
retried with exponential backoff and jitter. A private CA, a client certificate, or both from password-protected
PKCS#12 key stores, are set as `tls` (`VaultTlsOptions`, from
`@runsecure/hkdfguard-integration-hashicorpvault`, which the wrapper and the cache share). A failure rejects with `HashiCorpVaultTransitError`
(`ERR_HKDFGUARD_VAULT_TRANSIT`), naming the operation, the key, and Vault's status and errors
(`Vault answered 400 BadRequest: cipher: message authentication failed`).

The DEK never becomes a string: it is base64-encoded straight into a request body of the wrapper's
own and read out of Vault's answer the same way, and every buffer that held it - and the buffer the
token is copied into - is zeroed. What can't be zeroed is the token in the request header (Node takes
headers only as strings) and the socket's and OpenSSL's buffers.

[Wrap keys with HashiCorp Vault transit](docs/how-to/use-hashicorp-vault-transit.md) covers the key,
the policies for each role, tokens, key files and troubleshooting.

## Reading secrets from a folder, one file per secret

`FilePerSecretCache` (package `@runsecure/hkdfguard-cache`) is a `ProtectedReadOnlyCache` over a
local folder holding one file per secret: the file named `Db-Password` holds that secret's value,
already encrypted and formatted (`enc::v3::...`). Nothing is read up front: the first lookup of a
name reads that one file, checks its value authenticates, and caches it in memory still encrypted,
exactly as the file holds it. Every later lookup is served from memory:

```ts
import { DefaultFormatProvider } from '@runsecure/hkdfguard-dek';
import { FilePerSecretCache } from '@runsecure/hkdfguard-cache';
import { KeyFileTrust } from '@runsecure/hkdfguard-securefile';

const deployers = new KeyFileTrust({ windowsPrincipals: ['S-1-5-21-...-1005'] }); // the account that deploys secrets
const secrets = new FilePerSecretCache('C:\\HkdfGuardSecrets\\myapp', deployers, ring, new DefaultFormatProvider());

const result = new Uint8Array((await secrets.maxDecryptedLength('Db-Password')) ?? 0);
const written = await secrets.decrypt('Db-Password', result); // 0 if there's no such file
```

Each file must be encrypted for its own name, with the purpose `configurationPurpose(name)` (from
`@runsecure/hkdfguard-abstractions`). That is what a `PipelineDataProtector` writes for the secret
identifier `name`, and what `ring.createProtector(configurationPurpose(name))` writes. A file copied
under another name fails with an `AuthenticationFailedError` when it is loaded, and isn't cached, so
a corrected file is read on the next lookup.

Every file is read through `readTrustedFile` (package `@runsecure/hkdfguard-securefile`), so it is
refused, with a `KeyFileError` whose `code` is `'EACCES'`, unless it and every folder above it are
owned and modifiable only by the operating system's administrators and the principals the
`KeyFileTrust` adds. Add the account that deploys secrets, never the one the application runs as:
one that can rewrite its own secrets can be made to roll one back.

A name is a file name: 1-255 ASCII letters, digits, `-`, `_` and `.`, not starting with `.`, so it
can't reach outside the folder. Any other name (for example `ConnectionStrings:Admin`), a missing
or empty file and a missing folder all resolve to 0, so the cache can sit in a
`ProtectedCacheCollection` beside other sources (before any remote one: a source that fails fails
the lookup); a missing secret isn't remembered, so a file added later is found. A file over 64 KiB
is refused with a `KeyFileError` whose `code` is `ERR_HKDFGUARD_FILE_TOO_LARGE`, read no more than
one byte past that; any other read failure rejects with the `KeyFileError` `readTrustedFile` reports.
A file is read on the calling thread, as key files are. A cached value isn't refreshed: a changed
file is picked up by a new cache instance.

### All the secrets in one JSON file

`JsonSecretsFileReadOnlyCache` (package `@runsecure/hkdfguard-cache-jsonsecretsfile`) reads the
same values from one JSON file instead - the object a pipeline's `writeJsonSecrets` writes, each
member a secret's name mapped to its encrypted value:

```ts
import { JsonSecretsFileReadOnlyCache } from '@runsecure/hkdfguard-cache-jsonsecretsfile';

const secrets = new JsonSecretsFileReadOnlyCache('/etc/myapp/secrets.json', deployers, ring, new DefaultFormatProvider());
const result = new Uint8Array((await secrets.maxDecryptedLength('Db-Password')) ?? 0);
const written = await secrets.decrypt('Db-Password', result); // 0 if the file holds no such secret
```

The whole file is read through `readTrustedFile` on the first lookup, under the same trust rules,
and every value in it is authenticated under its name before any is kept: one that fails, names a
key version the ring doesn't hold, or a file that isn't exactly that object (an
`InvalidSecretDataError`: a name that isn't a secret's name or appears twice in any case, a value
that isn't a non-empty string) refuses the whole file, which is read again on the next lookup.
Names follow `FilePerSecretCache`'s rule and match ignoring ASCII case; a missing file reports every
secret missing, and isn't remembered. A file over 1 MiB (`maxFileLength`) is refused with a
`KeyFileError` `ERR_HKDFGUARD_FILE_TOO_LARGE`. Concurrent lookups share one load.

## Caching secrets from a secret store

The four `cache-*` packages are `ProtectedReadOnlyCache`s over a secret store. Each one fetches a
secret the first time it is looked up, encrypts it under the key ring's current key, bound to its
name, and from then on holds only the ciphertext. Nothing is listed or fetched up front. A name is a
secret's name, optionally followed by `#` and a key: `app-config#api-key` is the `api-key` member of
the JSON object the secret `app-config` holds, and `app-config` is the whole value. One fetch caches
the whole value and every key, and concurrent lookups of one secret share that fetch. A missing
secret reads as 0 bytes and isn't remembered. Aborting a lookup's `signal` stops that lookup; the
fetch is aborted only when it was that lookup's own.

The response body is taken out of the SDK's response before the SDK parses it, so the secret never
becomes a JavaScript string; the SDK parses a copy with the value blanked out, and every buffer that
held it is zeroed. What can't be zeroed (the HTTP stack's own buffers, and the Vault token in a
request header) is described in each package's module documentation.

```ts
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { ProtectedCacheCollection } from '@runsecure/hkdfguard-cache';
import { AwsSecretsManagerSecretCache } from '@runsecure/hkdfguard-cache-awssecretsmanager';

const client = new SecretsManagerClient({});  // the application creates, configures and owns the client
const secrets = new AwsSecretsManagerSecretCache(client, ring);
const caches = new ProtectedCacheCollection(localCache, secrets);

const result = new Uint8Array((await caches.maxDecryptedLength('prod/app-config#api-key')) ?? 0);
const written = await caches.decrypt('prod/app-config#api-key', result);
```

| Store | Package | How the body is captured |
|---|---|---|
| AWS Secrets Manager | `@runsecure/hkdfguard-cache-awssecretsmanager` | a deserialize-step middleware on each `GetSecretValueCommand` the cache sends, never on the client |
| Azure Key Vault | `@runsecure/hkdfguard-cache-azurekeyvault` | a per-retry pipeline policy on the cache's own `SecretClient`, reading the body as a stream |
| Google Cloud Secret Manager | `@runsecure/hkdfguard-cache-googlesecretmanager` | the gRPC call made on the client's own channel with the cache's response deserializer, so no protobuf message holds the payload |
| HashiCorp Vault | `@runsecure/hkdfguard-cache-hashicorpvault` | the HTTPS response streamed straight into the parser |

Each package's module documentation (`src/index.ts`) covers its names, options and errors.

### Secret cache integration tests

Each `cache-*` package has integration tests that read a real secret. They are reported as skipped,
never passed, until the secret is named. Set the matching `..._SECRET_JSON` variable to the JSON
object the secret holds, and the tests also compare the whole value and every key with it. The
variables are the ones the .NET, Java and Python tests read, from the environment or the settings
file at the repository root. A settings file names secrets and test values only, never a credential,
and `.gitignore` excludes it.

| Store | Variables | Settings file | Signs in with |
|---|---|---|---|
| AWS Secrets Manager | `HKDFGUARD_TEST_AWS_SECRET_NAME`, `HKDFGUARD_TEST_AWS_SECRET_JSON` | `aws.test.properties` | the access keys in the environment, else `~/.aws/credentials` only |
| Azure Key Vault | `HKDFGUARD_TEST_AZURE_SECRET_ID`, `HKDFGUARD_TEST_AZURE_SECRET_JSON`, `HKDFGUARD_TEST_AZURE_SEPARATE_SECRETS` | `azure.test.properties` | `DefaultAzureCredential` |
| Google Cloud Secret Manager | `HKDFGUARD_TEST_GOOGLE_SECRET_NAME`, `HKDFGUARD_TEST_GOOGLE_SECRET_JSON` | `google.test.properties` | Application Default Credentials |
| HashiCorp Vault | `HKDFGUARD_TEST_VAULT_ADDR`, `HKDFGUARD_TEST_VAULT_SECRET_NAME`, `HKDFGUARD_TEST_VAULT_CACERT`; `HKDFGUARD_TEST_VAULT_TOKEN` and `HKDFGUARD_TEST_VAULT_SECRET_JSON` from the environment only | `vault.test.properties` | the token |

The how-to guides set up each store:
[AWS Secrets Manager](docs/how-to/run-aws-secrets-manager-cache-integration-tests.md),
[Azure Key Vault](docs/how-to/run-azure-key-vault-secret-cache-integration-tests.md),
[Google Cloud Secret Manager](docs/how-to/run-google-secret-manager-cache-integration-tests.md),
[HashiCorp Vault](docs/how-to/run-hashicorp-vault-cache-integration-tests.md). Every other secret
cache test runs against a fake store, reached through the store's own client where it has one, and
sends nothing over the network. The `pipeline-*` writers' tests run the same way, against the same fakes, and
each runs the shared `SecretPipelineWriter` contract (`secretPipelineWriterContract` in
`packages/test-support`, the port of .NET's `SecretPipelineWriterContractTests`) as well as its own.

## Writing secrets from a store as files, in a pipeline

The four `pipeline-*` packages are the end of a provisioning pipeline that runs before a durable
KEK exists. Each `SecretPipelineWriter` is given a fixed list of secret names and a
`PipelineDataProtector`; `pullSecrets()` reads each secret once - however many of its keys are
listed - and encrypts every value at once, bound to its file name, keeping only the ciphertext;
`writeProtectedSecretFiles(folder)` then writes one file per secret, the folder layout
`FilePerSecretCache` reads at runtime. No key ring is involved: the protector's key is the only one,
handed to the native wrap process once the files are written. The writers never depend on the
runtime `cache-*` packages.

A name is a secret's name, optionally followed by `#` and a key: `prod/app#password` is the
`password` member of the JSON object `prod/app` holds, written as `prod__app__password` (each `/`
and `#` becomes `__`) and bound to that file name, so it decrypts as that name in
`FilePerSecretCache` and a renamed file fails authentication. A name whose file name
`FilePerSecretCache` can't read, or two whose file names differ only in case, are refused when the
writer is created. A missing secret, key or empty value is reported once every secret has been
read, by a `SecretsNotFoundError` naming them all - the rest are kept, and can still be written; any
other failure keeps nothing. A value that isn't UTF-8 text is refused with `InvalidSecretDataError`:
the protector encrypts text. As in the caches, each response body is taken before the SDK parses
it, so no value becomes a JavaScript string, and every buffer that held one is zeroed.
`writeProtectedSecretFiles` and `writeJsonSecrets` write each file whole to a temporary name in its
folder and rename it into place, mode 0644 in a 0755 folder (never wider, whatever the umask), so a
reader never sees a partial file and a symbolic link planted at a secret's path is replaced rather
than written through; a folder that is itself a symbolic link is refused.

```ts
import { AesGcmPipelineDataProtector } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { DefaultFormatProvider } from '@runsecure/hkdfguard-dek';
import { AwsSecretsManagerSecretPipelineWriter } from '@runsecure/hkdfguard-pipeline-awssecretsmanager';

const protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), 3);
const writer = AwsSecretsManagerSecretPipelineWriter.create(protector, ['prod/app#username', 'prod/app#password', 'prod/api-key']);
try {
  await writer.pullSecrets();
  await writer.writeProtectedSecretFiles('/etc/hkdfguard/secrets/myapp'); // prod__app__username, prod__app__password, prod__api-key
} finally {
  await writer.close();
}
// Then hand the key to the wrap tool on standard input - protector.writeDek(wrap.stdin), then
// wrap.stdin.end() - register the key at version 3, and close the protector.
```

The same secrets can go to another host without touching the local disk: each writer streams them
to a `Writable`, such as the stdin of an `ssh` child process. `writeProtectedSecretFilesTo` writes a
PAX tar archive of the files `writeProtectedSecretFiles` would write (one regular file per secret,
mode 0644, readable by GNU tar and bsdtar) for `ssh -T host sudo -n tar -x --no-same-owner -f - -C
/etc/hkdfguard/secrets/myapp`; `writeJsonSecretsTo` writes the JSON `writeJsonSecrets` would, for
`ssh -T host sudo -n tee /etc/myapp/secrets.json`. `writeJsonSecrets(file)` writes that JSON - one
object, each file name mapped to its encrypted value, in ordinal order, indented, UTF-8 without a
BOM, byte for byte what the .NET writer writes on the same platform - for
`JsonSecretsFileReadOnlyCache` to read. Each resolves once the stream has accepted the last byte,
writing the next piece only once the stream has accepted the one before, and leaves the stream
open: end it, so the remote command sees the end of its input. The protector's
`writeDek(stdin)` writes its key the same way, as the wrap tool's `--dek-stdin` reads it, from a
buffer zeroed once the write calls back - so use a stream that is done with the bytes by then, as a
child process's stdin is, never one that hands the buffer on, such as a `PassThrough`.

```ts
import { spawn } from 'node:child_process';
import { once } from 'node:events';

const tar = spawn('ssh', ['-T', 'deploy@app1', 'sudo', '-n', 'tar', '-x', '--no-same-owner', '-f', '-', '-C', '/etc/hkdfguard/secrets/myapp'],
  { stdio: ['pipe', 'inherit', 'inherit'] });
await writer.writeProtectedSecretFilesTo(tar.stdin);
tar.stdin.end();
const [code] = await once(tar, 'exit');
if (code !== 0) throw new Error(`tar on app1 failed with ${code}`);
```

| Store | Package | Writer |
|---|---|---|
| AWS Secrets Manager | `@runsecure/hkdfguard-pipeline-awssecretsmanager` | `AwsSecretsManagerSecretPipelineWriter`: the caller's `SecretsManagerClient`, or `create(protector, names, config)` for one of its own |
| Azure Key Vault | `@runsecure/hkdfguard-pipeline-azurekeyvault` | `AzureKeyVaultSecretPipelineWriter(vaultUrl, credential, protector, names)` |
| Google Cloud Secret Manager | `@runsecure/hkdfguard-pipeline-googlesecretmanager` | `GoogleSecretManagerSecretPipelineWriter`: the caller's `SecretManagerServiceClient`, or `create(projectId, protector, names)` for one of its own |
| HashiCorp Vault | `@runsecure/hkdfguard-pipeline-hashicorpvault` | `HashiCorpVaultSecretPipelineWriter(address, tokenSource, protector, names, options)`, a name without a key reading `defaultKey` (`value`) |

Only encrypted values are written, but `FilePerSecretCache` refuses a folder or file anyone but the
administrators and the principals its `KeyFileTrust` adds can modify: write them where the
deployment can set that, or set it once they're written. Each package's module documentation
(`src/index.ts`) covers its names, options and errors.

## Resolving configuration templates from the caches

`@runsecure/hkdfguard-integration-configurationresolver` fills the `${name}` items in a template - a
connection string, a configuration file - with values from any protected cache. It is the port of
.NET's `HkdfGuard.Integration.ConfigurationResolver`, and holds the parts of ConfigurationResolver it
needs too, so it depends only on the abstractions and diagnostics packages. Each value is decrypted
straight into the destination, or into a buffer that is zeroed, and never becomes a string.

```ts
import { ConfigurationItemReader, ConfigurationResolverBuilder, DefaultToken } from '@runsecure/hkdfguard-integration-configurationresolver';

const template = 'Host=db.internal;Password=${prod/app-config#password}';
const token = new DefaultToken();
const reader = new ConfigurationItemReader(token);
reader.readKeys(template); // only the keys read from the trusted template are looked up

const resolver = new ConfigurationResolverBuilder().withToken(token).withReader(reader).addProtectedCache(caches).build();
const connectionString = new Uint8Array(1024);
const length = await resolver.resolve(template, connectionString);
```

`ResolvingProtectedCacheCollection` is a `ProtectedCacheCollection` that resolves the templates its
sources hold, on their first lookup, and caches each result encrypted under the key ring, so anything
that reads a cache reads resolved templates. See
[Resolve configuration templates](docs/how-to/resolve-configuration-templates.md).

## Opening a certificate from a store, a provider or a file

`@runsecure/hkdfguard-options-certificate` opens the certificate a `Certificate` configuration section
names - the .NET port's keys, read by `certificateOptionsFromJson` - from the Windows certificate
store, a macOS keychain, an OpenSSL 3 provider on Linux (tpm2-openssl, pkcs11-provider) or a
password-protected PKCS#12 or PEM file whose password comes from a protected cache. A store's key
stays in CNG or the keychain: `sign` and `decrypt` call the store through the package's own add-on,
and TLS from it is refused, as Node's OpenSSL can't reach it. A file's key is decrypted by the
package's own PKCS#12/PBES2 reader and held sealed; a provider's key is the provider's object in
Node's OpenSSL, which loads the provider from `--openssl-config`. Every certificate and key file is
read through `readTrustedFile` (`securefile`): one that anyone but administrators and the loader's
`KeyFileTrust` (`fileTrust`, administrators only by default) could have written or replaced - or a
folder above it, or a link on the way - is refused, since whoever can replace a key file chooses
the key the application serves TLS with, or signs as.

```ts
import { createServer } from 'node:https';
import { CertificateOptionsLoader, certificateOptionsFromJson } from '@runsecure/hkdfguard-options-certificate';

const certificate = await new CertificateOptionsLoader({ passwords: caches }).load(certificateOptionsFromJson(appsettings));
const server = createServer(handler);
certificate.configureServer(server); // a File or Linux source; a store's key signs and decrypts only
```

See [Open a certificate from a store, a provider or a file](docs/how-to/use-certificate-options.md).

## Development

Node.js 22 or later (see `.nvmrc`), with Python 3 and a C compiler for the add-on.

```sh
npm install   # also compiles the native add-on
npm test      # builds every package, then runs each package's tests (node:test)
```

## Testing

Every package has tests beside its source (`src/*.test.ts`). `scripts/check.sh` runs what CI runs -
a clean `npm ci` (compiling the add-on), a forced build that type-checks every platform's loader,
each package's tests, `npm audit` of the runtime dependencies, and a dry-run `npm pack` of every
published package to check it ships no tests or sources - from any host:

```sh
scripts/check.sh                                 # everything
scripts/check.sh packages/keywrapping-native-v1  # one package's tests
npx -y -p node@22 -c scripts/check.sh            # with an older node on PATH
```

The AWS KMS key wrapper's tests use an in-process fake KMS that really encrypts (AES-GCM, binding the
key and encryption context), a real `KMSClient` whose HTTP handler answers in-process, and a real
refused connection; its integration tests against a real KMS key are reported as skipped unless
`HKDFGUARD_TEST_AWS_KMS_KEY_ID` names one - see
[Run the AWS KMS integration tests](docs/how-to/run-aws-kms-integration-tests.md). The Azure Key
Vault key wrapper's tests run the real Azure SDK against an in-process fake vault that answers its
HTTP requests - really wrapping with RSA-OAEP-256 and signing ES256 digests - and its integration
tests against real keys are reported as skipped unless `HKDFGUARD_TEST_AZURE_WRAP_KEY_ID` and
`HKDFGUARD_TEST_AZURE_SIGN_KEY_ID` name them, in the environment or a git-ignored
`azure.test.properties` at the repository root - see
[Run the Azure Key Vault integration tests](docs/how-to/run-azure-key-vault-integration-tests.md). The
Google Cloud KMS key wrapper's tests run a real `KeyManagementServiceClient` against a fake Cloud KMS,
a gRPC server on the loopback address that really encrypts (AES-GCM, binding the key, its version
and the additional authenticated data) and checks the request's checksums; its integration tests
against a real key are reported as skipped unless `HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME` names one, in
the environment or a git-ignored `google.test.properties` at the repository root - see
[Run the Google Cloud KMS integration tests](docs/how-to/run-google-kms-integration-tests.md). The
HashiCorp Vault transit key wrapper's tests serve a fake transit engine from `node:http` on 127.0.0.1,
called through the wrapper's real http client, that really encrypts (AES-GCM per key version, the
context as AAD); its integration tests against a real Vault are reported as skipped unless
`HKDFGUARD_TEST_VAULT_TRANSIT_KEY` names a transit key, in the environment or a git-ignored
`vault.test.properties` at the repository root - see
[Run the HashiCorp Vault transit integration tests](docs/how-to/run-hashicorp-vault-transit-integration-tests.md). The
securefile package's rules are tested against simulated filesystems and security descriptors on every
platform, and against real files on Windows, Linux and macOS (each platform's suite skipped on the
others); on Linux the real-file tests use `keyFileDirectory`'s private folder, so run them as a
non-root user to cover the refusals root would pass.

The certificate options' tests run against certificates they make and other tools' PKCS#12 and PKCS#8
files, with TLS handshakes over a local server; their suites against real key storage are opt-in -
`HKDFGUARD_TEST_WINDOWS_CERT_STORE=1` (throwaway CNG certificates in CurrentUser\My, removed
afterwards), `HKDFGUARD_TEST_MACOS_KEYCHAIN=1`, and `HKDFGUARD_TEST_OPENSSL_PROVIDER` with a provider
key - see [Open a certificate from a store, a provider or a file](docs/how-to/use-certificate-options.md).

The native key wrapper's tests make real calls against a provisioned service. They are reported as
skipped, never passed, unless the test service exists: on Windows and macOS the tests find it by
themselves (through the library's `hkdfguard_kek_exists` export, and the provisioning tool's
`status` command, respectively); on Linux, and for any other service, set `HKDFGUARD_TEST_SERVICE`.
`HKDFGUARD_TEST_SERVICE_OTHER` names a second provisioned service for the cross-service isolation
tests. To provision a test host, run from `packages/keywrapping-native-v1`:

- Linux: `sudo scripts/provision-linux-test-key.sh` (the TPM-backed test KEK and policy; `--remove` undoes it)
- macOS: `scripts/provision-macos-test-key.sh` as the account that runs the tests (`--remove` retires the KEK)
- Windows: `./scripts/provision-windows-test-key.ps1` from an elevated PowerShell (`-Remove` retires
  the KEK; a provisioning run also retires the legacy `com.hkdfguard.native.windows.test`, after
  asking - `-KeepLegacyKey` keeps it)

Each checks the installed tool (`hkdfguard.exe`, `/usr/bin/hkdfguard`, or the macOS install directory's
`hkdfguard`) against the same pins the loader applies before
running it, and prints the `npm test` command to run next. Every platform's script provisions the
same default test service, `com.hkdfguard.integration.test.221` (`DEFAULT_TEST_SERVICE` in the
tests) - the KEKs every port's copy provisions, so one host serves all the ports' tests.

**Linux key files:** the Linux native library refuses a key file if any directory up its chain is
writable by its group or others, sticky or not - so never one under `/tmp`, `/var/tmp` or
`/dev/shm`. The tests that write key files it reads (and the `hkdfguard wrap` test) put them in a
private (0700) folder from `keyFileDirectory` in `packages/test-support`: under `$XDG_RUNTIME_DIR`
when that passes the same check, else under `~/.cache/hkdfguard-tests`, every directory up the chain
owned by root or the test user and writable by neither group nor others - and removed after each
test. Without such a directory those tests are skipped, saying why.

The tests against the real system and the installed native library are in three platform suites
in `packages/keywrapping-native-v1/src`, each skipped as a whole on the other platforms and each
case skipped with its reason when what it needs is missing - never passed:

| Suite | Runs | Needs, beyond its platform |
|---|---|---|
| Linux: `linux.test.ts` (loader against the real filesystem and dynamic linker; the library's contract: exact statuses, its own service-name and length checks, tampering, capacities, concurrency, the `hkdfguard` deployment path) | Linux | Path, `/proc` and libc checks: nothing. Installed-library checks: the `libhkdfguard1` package. Contract tests: the package and `HKDFGUARD_TEST_SERVICE`; some also `HKDFGUARD_TEST_SERVICE_OTHER`, `tpm.require_pinned_names = true` in `/etc/hkdfguard/policy.toml`, or `/usr/bin/hkdfguard` |
| macOS: the `macOS loader` suite in `native.test.ts` (location and signature checks, the provisioning tool refused as a library, probes, the default test service found only when provisioned) | macOS | The library and `hkdfguard` installed (system or per-user); the rest need nothing |
| Windows: `windows.test.ts` (loader: fixed path, planted file, junction, unsigned, tampered, not a PE image, the installed signer and mapped module, `hkdfguard.exe` refused as not a DLL, `hkdfguard_kek_exists`) and the key-file suite in `native.test.ts` | Windows | `%ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll` (and `hkdfguard.exe`) installed; reading back a real key file also the test service |

What every platform shares - loading once, round trips, direct binding calls, too-small buffers,
corrupt payloads, another service's payload - is the `installed native library` suite in
`native.test.ts`; the gating all of them use is in `src/installed.test-support.ts`.

`packages/integration` holds the end-to-end tests over the real native KEK - a pipeline encrypting
configuration, the native KEK wrapping its key, an application reading it back, and runtime keys
generated through the KEK - the port of the .NET `NativeEndToEndTests`. It is a private workspace,
never published, so the published packages never depend on each other; it runs against the same
test service and is skipped the same way.

**macOS:** in the native library's legacy keychain mode the KEK's access list names the binary
that created it, so the first native call from each `node` executable is answered with a keychain
dialog in a logged-in session - click "Always Allow" - and with status -18 where there is no UI.
The first call under each service is made in a short-lived child process (the same `node`
executable, so "Always Allow" there answers for the tests too) that is killed after 60 seconds, and
the tests then fail with a message saying so rather than hang.

`hardenProcess()` hardens the whole test process, so its tests against the real library
(`src/hardening.test.ts`: Windows and Linux) run only with `HKDFGUARD_TEST_PROCESS_HARDENING=1`.
`node --test` runs each test file in its own process, so the rest of the suite is never hardened.
On Windows the check that the process's own account can no longer open it for reading is made by a
second process of that account - Windows PowerShell, calling `OpenProcess` by the test process's
pid - so the shipped add-on carries no test-only export:

```sh
cd packages/keywrapping-native-v1
HKDFGUARD_TEST_PROCESS_HARDENING=1 node --test-name-pattern="closes the process" dist/hardening.test.js
HKDFGUARD_TEST_PROCESS_HARDENING=1 node --test-name-pattern="requireProtectedSignature" dist/hardening.test.js
```

## Continuous integration and releases

The **CI** workflow (`.github/workflows/ci.yml`) runs on every push to `main` or `develop`, every
pull request, and on demand. It calls the reusable `build.yml`, which runs `scripts/check.sh` on
Ubuntu, macOS (Apple silicon) and Windows - so the native add-on is compiled by each platform's own
C toolchain. GitHub's runners have no HkdfGuard native library, so the native round trips are
reported as skipped there; a self-hosted runner with a provisioned test service runs them too. No
secrets, no write permissions.

Every package is released together, at one version, by one tag:

```sh
node scripts/set-version.mjs 0.2.0 && npm install   # every package, and every pin between them
git commit -am "Release 0.2.0"
git tag v0.2.0 && git push origin main v0.2.0
```

The **Release** workflow (`release.yml`) then:

1. **version**: checks the tag (`scripts/release-tag.sh`), refusing it unless every package and
   every reference between them is already at that version.
2. **build**: the same `build.yml` CI runs, on every OS.
3. **pack**: packs every published package once, from the tagged commit, and attests the
   tarballs' build provenance (`gh attestation verify <file> --repo runsecure/hkdfguard-node`).
4. **publish-npm**: publishes exactly those tarballs to npm with **provenance** - a
   Sigstore-signed statement of the repository, workflow and commit each was built from, which
   `npm audit signatures` verifies - through npm **trusted publishing**, so no long-lived npm token
   is stored. It runs in the `release` environment, and only once the repository variable
   `HKDFGUARD_PUBLISH_NPM` is `true`. A pre-release suffix (`v1.0.0-rc.1`) goes to the `next`
   dist-tag.
5. **github-release**: creates the GitHub Release with the tarballs and their SHA-256s. Versions
   `0.x`, and any with a pre-release suffix, are published as GitHub pre-releases.

npm has no author signing like Authenticode; provenance, the registry's own signature and the
GitHub attestation are how a package's origin is proved. Nothing shipped is a binary - the add-ons
are compiled on each consumer's machine - so there is nothing to Authenticode-sign or notarize; the
header of `release.yml` says where that would go if prebuilt add-on binaries are ever shipped, and
lists the one-time npm and GitHub setup publishing depends on. Third-party actions are pinned to
full commit SHAs.

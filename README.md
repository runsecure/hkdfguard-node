# hkdfguard-node
HkdfGuard KeyWrapping and Secrets Protection Library for Node JS

The Node.js port of HkdfGuard, written in TypeScript. Span, metric and attribute names, error
semantics, ciphertext layout and the `enc::v<version>::<base64>` format are identical to the .NET and
Go ports, so values written by one port are read by the others.

**Documentation:** start with [Getting started](docs/getting-started.md), which takes one Windows PC
or Apple-silicon Mac from nothing to a TPM- or Secure-Enclave-protected key file. Key setup -
installing the native package and provisioning, wrapping and retiring KEKs with the `hkdfguard`
tool (`hkdfguard-v1-initialize` on macOS) - is in the [CLI reference](docs/reference/cli.md). The [docs index](docs/README.md)
lists every page.

## Packages

Each package is published separately. Implementations depend only on the abstractions, never on each
other, so the key wrapper, the cipher and the cache can each be swapped for another implementation.

| Package | Port of | What it is |
|---|---|---|
| `@runsecure/hkdfguard-diagnostics` | HkdfGuard.Diagnostics | OpenTelemetry names and helpers, sensitive-logging flags, logging (any console-shaped logger) |
| `@runsecure/hkdfguard-abstractions` | HkdfGuard.Abstractions | Interfaces (`KeyWrapper`, `CryptoProviderFactory`, `KeyRing`, `ProtectedCache`, ...), shared rules and errors |
| `@runsecure/hkdfguard-keywrapping-native-v1` | HkdfGuard.KeyWrapping.V1 | `KeyWrapper` over the OS's native KMS library (TPM2, Secure Enclave, Platform Crypto Provider) |
| `@runsecure/hkdfguard-cryptoprovider-aesgcm256` | HkdfGuard.CryptoProvider.AesGcm256 | The AES-256-GCM `CryptoProviderFactory` and `PipelineDataProtector` |
| `@runsecure/hkdfguard-dek` | HkdfGuard.DataEncryptionKey, HkdfGuard.Options | Key rings with rotation, data protectors, the stored format, `buildKeyRing`, and options read from an `appsettings.json` section |
| `@runsecure/hkdfguard-cache` | HkdfGuard.Cache | Protected caches, pull-through `CacheSource`s (for Vault, Key Vault, ...) and collections |
| `@runsecure/hkdfguard-encryptedconfig` | HkdfGuard.EncryptedConfiguration | Reads pipeline-encrypted secrets from any configuration source (`envLookup`, `flattenJson`, `mapLookup`) |

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

## The native add-on

`@runsecure/hkdfguard-keywrapping-native-v1` calls the native KMS library through its own small C
add-on, `native/hkdfguard_native.c`, compiled by node-gyp when the package is installed - so
installing it needs Python 3 and a C compiler (Visual Studio Build Tools on Windows). The add-on only
loads and calls the library; every verification rule (path ownership, code signature or pinned
SHA-256, the dynamic linker's environment, what was actually loaded) is TypeScript, and is tested on
every platform. KMS calls run on libuv's thread pool, so a TPM operation never blocks the event loop.

The Windows library is `%ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll`, beside the `hkdfguard.exe`
tool; on Linux the tool is `/usr/bin/hkdfguard`. Every platform's library returns the same status
codes, number for number (`Status` in `packages/keywrapping-native-v1/src/status.ts`): a failed
call throws `StatusError`, whose message says what its status means - adding, on each platform,
what to do about it there.

**Key files are read through the native library.** `NativeKeyWrapperV1.readKeyFile`, which
`buildKeyRing` uses for every key file whenever the key wrapper has one, reads the file with the
library's `hkdfguard_open_file`. It returns the bytes still wrapped and never touches a KEK, but
first refuses a file that is missing, unreadable, the wrong size, not a wrapped DEK, or that holds
what looks like an unwrapped key (32 raw bytes, or their hex or base64: treat that as a key
exposure) - and one whose path isn't trusted: a link, junction or other reparse point, an 8.3 short
name, a network, mapped or SUBST drive, or a file or folder another account could write or replace.
A refusal throws `KeyFileRefusedError`, with `status` and an fs-style `code`: `ENOENT`, `EACCES`
(unreadable or untrusted), `ERR_HKDFGUARD_INVALID_KEY_FILE` (size or contents) or `EIO`. A key
wrapper without `readKeyFile` has its key files read by `readKeyFile` in
`@runsecure/hkdfguard-dek`, with Node's own file I/O.

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

The native key wrapper's tests make real calls against a provisioned service. They are reported as
skipped, never passed, unless the test service exists: on Windows and macOS the tests find it by
themselves (through the library's `hkdfguard_kek_exists` export, and the provisioning tool's
`status` command, respectively); on Linux, and for any other service, set `HKDFGUARD_TEST_SERVICE`.
`HKDFGUARD_TEST_SERVICE_OTHER` names a second provisioned service for the cross-service isolation
tests. To provision a test host, run from `packages/keywrapping-native-v1`:

- Linux: `sudo scripts/provision-linux-test-key.sh` (TPM-backed test KEKs and policy; `--remove` undoes it)
- macOS: `scripts/provision-macos-test-key.sh` as the account that runs the tests (`--remove` retires the KEK)
- Windows: `./scripts/provision-windows-test-key.ps1` from an elevated PowerShell

Each checks the installed tool (`hkdfguard.exe`, `/usr/bin/hkdfguard`, or `hkdfguard-v1-initialize`
on macOS) against the same pins the loader applies before
running it, and prints the `npm test` command to run next. They provision the same KEKs as the .NET
and Go ports' copies, so one host serves all three ports' tests.

`packages/integration` holds the end-to-end tests over the real native KEK - a pipeline encrypting
configuration, the native KEK wrapping its key, an application reading it back, and runtime keys
generated through the KEK - the port of the .NET `NativeEndToEndTests`. It is a private workspace,
never published, so the published packages never depend on each other; it runs against the same
test service and is skipped the same way.

**macOS:** in the native library's legacy keychain mode the KEK's access list names the binary
that created it, so the first native call from each `node` executable is answered with a keychain
dialog in a logged-in session - click "Always Allow" - and with status -18 where there is no UI.
The tests fail with a message saying so after 60 seconds rather than hang.

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
GitHub attestation are how a package's origin is proved. Nothing shipped is a binary - the add-on
is compiled on each consumer's machine - so there is nothing to Authenticode-sign or notarize; the
header of `release.yml` says where that would go if prebuilt add-on binaries are ever shipped, and
lists the one-time npm and GitHub setup publishing depends on. Third-party actions are pinned to
full commit SHAs.

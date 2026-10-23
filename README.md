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
installing it needs Python 3 and a C compiler (Visual Studio Build Tools on Windows). The add-on only
loads and calls the library; every verification rule (path ownership, code signature on Windows and
macOS, the dynamic linker's environment, what was actually loaded) is TypeScript, and is tested on
every platform. The Linux library is not content-pinned: verify a release with Sigstore/cosign
(`gh attestation verify`) when you install it, and the loader enforces path integrity from there.
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
what looks like an unwrapped key (32 raw bytes, or their hex or base64: treat that as a key
exposure) - and one whose path isn't trusted: a link, junction or other reparse point, an 8.3 short
name, a network, mapped or SUBST drive, or a file or folder another account could write or replace.
A refusal throws `KeyFileRefusedError`, with `status` and an fs-style `code`: `ENOENT`, `EACCES`
(unreadable or untrusted), `ERR_HKDFGUARD_INVALID_KEY_FILE` (size or contents) or `EIO`. Every key
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
GitHub attestation are how a package's origin is proved. Nothing shipped is a binary - the add-on
is compiled on each consumer's machine - so there is nothing to Authenticode-sign or notarize; the
header of `release.yml` says where that would go if prebuilt add-on binaries are ever shipped, and
lists the one-time npm and GitHub setup publishing depends on. Third-party actions are pinned to
full commit SHAs.

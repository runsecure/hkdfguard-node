# `hkdfguard-v1-initialize` reference

`hkdfguard-v1-initialize` is installed with each platform's native HkdfGuard package. It does the
jobs the Node library deliberately can't:

- **`provision`** creates a service's KEK. Wrapping and unwrapping never create one.
- **`wrap`** turns a DEK into a key file.
- On macOS, **`status`** reports a KEK and **`retire`** deletes one.

The Windows section was taken from the tool's own `--help` output and checked against its
behavior; the macOS section from the installed tool's `--help` output and observed behavior. The
Linux section is partial.

The same tools serve the .NET and Go ports: a key file written by `wrap` is read by any of the
libraries, and a service provisioned once serves them all.

- [Windows](#windows)
- [macOS](#macos)
- [Linux](#linux)

## Windows

Installed at `%ProgramFiles%\HkdfGuard\v1\hkdfguard-v1-initialize.exe`, beside `HkdfGuardV1.dll`.

```text
hkdfguard-v1-initialize provision --service-name|-sn <name>
hkdfguard-v1-initialize wrap --key-file-path|-kf <path> --service-name|-sn <name> --dek-stdin --group|-g <name> [--force|-f]
```

`--help` after a command shows that command's help. `--help` alone, or no arguments, shows the
summary above.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, or `--help` |
| 1 | The command ran and failed; the reason is on standard error |
| 2 | Usage error: unknown command, or a required option missing |

Errors are written to standard error as `error: <reason>`. A native failure names the failing
call and its meaning, for example:

```text
error: hkdfguard_create_kek failed: this KEK exists, but this account is not authorized to use it (creating a new KEK requires an elevated process; this account may lack rights)
```

### Service names

Every command takes `--service-name`. A service name is 1 to 128 characters, each an ASCII
letter, digit or `.`; it doesn't start with `.` and doesn't contain `..`. For example,
`com.example.myapp`. Use exactly the same name in the tool and in your application
(`NativeKeyWrapperV1.create`, `KeyRingConfig.serviceName`, `KeyRingOptions.ServiceName`).

> **TODO (maintainer):** `provision --service-name bad..name` currently fails with the
> "not authorized" message above instead of rejecting the name. Either fix the tool to validate
> the name first, or document what it does.

### `provision`

```text
hkdfguard-v1-initialize provision --service-name|-sn <name>
```

Makes sure the service's machine-wide KEK exists and passes verification. If it is missing,
`provision` creates it; if it exists, `provision` re-verifies its properties and access list. It
never wraps a DEK and never touches a file, so it is safe to run repeatedly, for example from
every deployment.

| Option | Short | Required | Meaning |
|---|---|---|---|
| `--service-name <name>` | `-sn` | Yes | The service whose KEK to create or verify |

**Run it elevated.** Creating a machine-wide KEK needs administrator rights.

The KEK is a non-exportable P-256 key in the Microsoft Platform Crypto Provider (the TPM), or in
the Microsoft Software Key Storage Provider when no TPM is available.

> **TODO (maintainer):** describe:
> - how the storage provider is chosen, and how `HKLM\Software\Policies\HkdfGuard\KeyStoragePolicy`
>   changes that (its value names and allowed values);
> - the access list a new KEK gets, and how `HKLM\Software\Policies\HkdfGuard\KeyUseGroups`
>   adds groups to it (format, and what counts as "over-broad");
> - whether the installer creates `HkdfGuardUsers`, and what a KEK grants it.

Failures you may see:

| Status | Meaning | What to do |
|---|---|---|
| -13 | Not authorized, for example not elevated | Run from an elevated prompt |
| -3 | The key storage provider or key couldn't be opened or created | Check the TPM is enabled, or the storage policy |
| -9 | `KeyStoragePolicy` is invalid | Fix the policy value |
| -10 | A `KeyUseGroups` entry is unresolvable, not a group, or over-broad | Fix the policy entry |
| -14 | The existing KEK's access list is missing, lacks SYSTEM or Administrators, or grants an over-broad principal | Investigate before re-provisioning: the KEK may have been tampered with |

### `wrap`

```text
hkdfguard-v1-initialize wrap --key-file-path|-kf <path> --service-name|-sn <name> --dek-stdin --group|-g <name> [--force|-f]
```

Wraps a DEK under the service's existing KEK and writes the result to a key file. It never creates
a KEK: run `provision` for the service first.

| Option | Short | Required | Meaning |
|---|---|---|---|
| `--key-file-path <path>` | `-kf` | Yes | Where to write the key file |
| `--service-name <name>` | `-sn` | Yes | The service whose KEK wraps the DEK |
| `--dek-stdin` | | Yes | Read the DEK from standard input. Currently the only way to supply it |
| `--group <name>` | `-g` | Yes | The local group allowed to read the key file: the group your application's account is in |
| `--force` | `-f` | No | See the TODO below |

**Input.** Standard input carries the DEK: exactly 32 random bytes, base64-encoded, which is 44
characters.

> **TODO (maintainer):** confirm:
> - what `--force` does (presumably: overwrite an existing key file, which `wrap` otherwise refuses);
> - the exact permissions written on the key file;
> - whether `wrap` must run elevated;
> - whether a trailing newline on standard input is accepted.

> **Security:**
> - Pass the DEK only on standard input. Never put it in a command-line argument or an
>   environment variable, where process listings, shell history, CI logs and crash dumps can
>   record it.
> - Don't build or hold the DEK in a PowerShell or Bash variable either: those strings can't be
>   cleared from memory. Write it to the tool's input from a byte buffer you zero afterwards. See
>   [Getting started, step 5](../getting-started.md#5-create-a-key-file) for a Node example using
>   `AesGcmPipelineDataProtector`.
> - Keep key files in a folder only administrators can write to. A key file is not a secret, but
>   anyone who can replace it decides which key your application encrypts new data with. The Node
>   library refuses a key file its group or other users can write.

Failures you may see:

| Status | Meaning | What to do |
|---|---|---|
| -12 | No KEK is provisioned for this service | Run `provision` first |
| -13 | The KEK exists, but this account may not use it | Run as an account in `HkdfGuardUsers` or a `KeyUseGroups` group |
| -1 | Invalid argument, for example a DEK that isn't 32 bytes | Check the standard input is 44 base64 characters |

> **TODO (maintainer):** add the error `wrap` reports for a `--group` that doesn't exist or isn't
> allowed.

### Status codes

The tool reports the native library's status codes. The full list, with meanings, is the
`windowsStatusDescriptions` table in
[`packages/keywrapping-native-v1/src/status.ts`](../../packages/keywrapping-native-v1/src/status.ts).
The Node library reports the same codes as `StatusError.status`, with the meaning in its message.

## macOS

Installed system-wide at `/Library/Application Support/HkdfGuard/v1`, or per user at
`~/.hkdfguard/v1`, beside `libhkdfguard_v1.dylib`. The KEK is a Secure Enclave key, so it needs
Apple silicon and macOS 13 or later.

```text
hkdfguard-v1-initialize provision --service-name|-sn <name>
hkdfguard-v1-initialize wrap --key-file-path|-kf <path> --service-name|-sn <name> \
                          ( --dek-stdin | --dek-file <path> ) [--fingerprint|-fp <hex>] [--force|-f]
hkdfguard-v1-initialize retire --service-name|-sn <name> ( --fingerprint|-fp <hex> | --corrupt )
hkdfguard-v1-initialize status --service-name|-sn <name>
```

`--help`, or no arguments, shows the summary above. Every command shares one usage text.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, or `--help` |
| 1 | The command ran and failed; the reason is on standard error |
| 2 | Usage error: no or unknown command, or a required option missing |

Errors are written to standard error as `error: <reason>`, for example
`error: --dek-stdin: no data on standard input`.

### Service names

As on Windows: 1 to 128 ASCII letters, digits or `.`, not starting with `.`, never containing
`..`. On macOS the native library lowercases the name before everything else, so
`Com.Example.App` and `com.example.app` are the same KEK. The Node library still rejects a name that
breaks the rule before any native call.

> **TODO (maintainer):** `status --service-name bad..name` reports `kek: absent` with exit code 0
> instead of rejecting the name. Either fix the tool to validate the name first, or document what
> it does.

### Keychain modes

The native library keeps the KEK's keychain item in one of two keychains, chosen from the calling
process's own code-signing entitlements, never from configuration:

- **legacy** (`keychain: legacy` in `status`): the process has no `keychain-access-groups`
  entitlement - a bare executable such as this tool, or a `node` process that loads the library.
  Items live in the login keychain, protected by its lock and by a per-item access list that
  names the binary that created the item. Any other binary gets an interactive prompt in a
  logged-in session ("Always Allow" adds it to the list), or status -17 where there is no UI.
- **data-protection** (`keychain: data-protection`): the process is a Team-signed app bundle with
  that entitlement. Access is decided from the signed identity: no prompts, no per-item lists.

The two keychains are disjoint: provision a service in the mode its consumers run in, or they
report -10 (no KEK). Every KEK is created usable only while the device is unlocked, and never
leaves the device: no backup or restore carries it.

### `provision`

```text
hkdfguard-v1-initialize provision --service-name|-sn <name>
```

Creates the Secure Enclave KEK for the service if it doesn't exist yet, and prints the KEK's
fingerprint (the SHA-256 of its public key, 64 hex characters) - record it. The only command that
creates keys; safe to run repeatedly. Run it as the account that will use the KEK, without `sudo`:
in legacy mode the item is created in that account's login keychain.

### `wrap`

```text
hkdfguard-v1-initialize wrap --key-file-path|-kf <path> --service-name|-sn <name> \
                          ( --dek-stdin | --dek-file <path> ) [--fingerprint|-fp <hex>] [--force|-f]
```

Wraps the pipeline's 32-byte DEK under the already-provisioned KEK and writes the wrapped payload
(156 bytes) to the key file. Never creates a KEK: fails if none exists for the service. Prints the
fingerprint of the KEK the payload was wrapped under.

| Option | Short | Required | Meaning |
|---|---|---|---|
| `--key-file-path <path>` | `-kf` | Yes | Where to write the wrapped payload |
| `--service-name <name>` | `-sn` | Yes | The service whose KEK wraps the DEK |
| `--dek-stdin` | | One of the two | Read the base64 DEK from standard input |
| `--dek-file <path>` | | One of the two | Read the base64 DEK from a file |
| `--fingerprint <hex>` | `-fp` | No | Refuse to write unless the KEK actually used has this fingerprint, as printed by `provision` |
| `--force` | `-f` | No | Securely overwrite an existing key file |

> **Security:** prefer `--dek-stdin`; a `--dek-file` leaves the key on disk until it is securely
> deleted. Pass `--fingerprint` too, so the tool refuses to write a key file under any KEK other
> than the one recorded at provisioning. The DEK is never accepted as a command-line argument.

> **TODO (maintainer):** document the permissions written on the key file.

### `retire`

```text
hkdfguard-v1-initialize retire --service-name|-sn <name> ( --fingerprint|-fp <hex> | --corrupt )
```

Deletes the KEK for the service, only if its fingerprint matches, or, with `--corrupt`, only if
the library reports the item as corrupt (-11) and the Secure Enclave is proven usable in this
session, so a healthy KEK that merely couldn't be loaded right now is never mistaken for a corrupt
one. The only command that deletes keys. **Everything wrapped under that KEK becomes permanently
unrecoverable**: migrate to a new service name first.

### `status`

```text
hkdfguard-v1-initialize status --service-name|-sn <name>
```

Read-only: never creates or deletes anything. Reports the keychain mode, whether a KEK exists for
the service, and its fingerprint:

```text
service: com.example.myapp
keychain: legacy
kek: present
fingerprint: 820eac654e8eaae4911a49cf646263dd8a035a0b645d71182501b1ca63e19a1c
```

Because the tool created the KEK, `status` never triggers the keychain prompt; it is how the Node
test suite tells whether a test service is provisioned.

### Status codes

The `macStatusDescriptions` table in
[`packages/keywrapping-native-v1/src/status.ts`](../../packages/keywrapping-native-v1/src/status.ts) lists every code. The
ones you are most likely to meet: -10 no KEK for this service (run `provision`), -16 the payload
was wrapped under a different KEK, -17 the keychain denied access (locked, or no UI session for the
prompt), -6 the payload was altered.

## Linux

The native library is published for Ubuntu 24.04 on amd64 as the `libhkdfguard1` package
(`hkdfguard-libs` on RPM distributions is planned), installed to `/usr/lib/<multiarch>/` or
`/usr/lib64/`, with `hkdfguard-v1-initialize` at `/usr/bin/hkdfguard-v1-initialize` from the
`hkdfguard` package. The KEK is a TPM 2.0 key.

What is known so far, from `packages/keywrapping-native-v1/scripts/provision-linux-test-key.sh` and
the Linux integration tests:

- The package installs no policy and no TPM derivation secret, so on a fresh host every wrap fails
  with "no KEK is provisioned" (-9) until root creates `/etc/hkdfguard/tpm.derivation-secret` (32
  random bytes, readable by the service's group) and writes `/etc/hkdfguard/policy.toml`.
- With `tpm.require_pinned_names = true` in the policy, only services whose TPM Name is listed
  under `[tpm.pinned_names]` have a KEK; `provision` prints the Name an unlisted service would get.
- `provision --service-name <name>` confirms a service; `wrap` accepts `--dek-file <path>` as well
  as `--dek-stdin`, and writes the key file with mode `0600`.
- The account running the application must be in the `tss` group to open `/dev/tpmrm0`.

> **TODO (maintainer):** paste the Linux `--help` output and fill in this section to match the
> Windows one: commands, options, exit codes, the policy file's full schema, and the status codes
> (`linuxStatusDescriptions` in `packages/keywrapping-native-v1/src/status.ts`).

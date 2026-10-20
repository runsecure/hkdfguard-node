# HkdfGuard documentation (Node.js)

Pick the page for what you're doing.

**New to HkdfGuard:** start with [Getting started](getting-started.md). It takes one machine, a
Windows PC or an Apple-silicon Mac, from nothing to encrypting and decrypting with a key the
platform protects (TPM or Secure Enclave), then to a durable key file.

**Running HkdfGuard in production** (installing, provisioning, creating key files): see the
[`hkdfguard` CLI reference](reference/cli.md).

**Porting from the .NET or Go libraries:** the same pages exist in `hkdfguard-dotnet/docs` and
`hkdfguard-go/docs`, with the same structure. Everything a value or a key file is made of - the
`enc::v<version>::<base64>` format, the AES-256-GCM ciphertext, the purpose and name binding, the
native key files - is byte-identical between the ports, so one deployment serves all three.

## Map

| Kind | Page | Status |
|---|---|---|
| Tutorial | [Getting started](getting-started.md) | Draft |
| How-to | Provision a service on each platform | Planned (the test-host scripts under `packages/keywrapping-native-v1/scripts` show each platform's steps) |
| How-to | Create key files in a deployment pipeline | Planned (see [Getting started, step 5](getting-started.md#5-create-a-key-file)) |
| How-to | Rotate keys | Planned (see [Getting started, step 6](getting-started.md#6-use-the-key-file)) |
| How-to | Load settings from an `appsettings.json` shared with the .NET port | Planned (see `keyRingOptionsFromJson` in the README) |
| How-to | Troubleshoot | Planned (see [If something goes wrong](getting-started.md#if-something-goes-wrong)) |
| Reference | [`hkdfguard` CLI](reference/cli.md) | Draft (Windows and macOS; Linux partial) |
| Reference | Native status codes | Planned (the tables in `packages/keywrapping-native-v1/src/status.ts` for now) |
| Reference | `KeyRingOptions` / configuration schema | Planned (the doc comments in `packages/dek/src/options.ts` for now) |
| Reference | API | Planned (generated from the TSDoc comments; each package ships `.d.ts` files) |
| Explanation | Key hierarchy: KEK, wrapped DEK, AES-GCM | Planned (see [How the pieces fit](getting-started.md#how-the-pieces-fit)) |
| Explanation | Threat model and fail-closed behavior | Planned |
| Explanation | How the native library is verified before loading | Planned (see the README's *The native add-on* and the package comment of `keywrapping-native-v1`) |

## Conventions

- Every code sample in these pages type-checks and runs against the current source on Node.js 22.
  When you change one, run it before committing.
- Facts about the `hkdfguard` tool come from its own `--help` output and observed behavior.
  Anything not yet confirmed is marked **TODO (maintainer)**; search for that string before
  publishing.
- Security rules are stated as rules, at the step where they apply, in a block that starts with
  **Security:**.

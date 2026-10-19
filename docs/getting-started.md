# Getting started

This tutorial takes one machine from nothing to encrypting and decrypting with a key protected by
the platform: the TPM on Windows, the Secure Enclave on a Mac. It then replaces that in-memory key
with a durable key file, which is what a real deployment uses.

It takes about 20 minutes. You need one of:

- Windows 10 or 11, or Windows Server 2019 or later, with administrator rights for one step, and
  Visual Studio Build Tools with the "Desktop development with C++" workload.
- macOS 13 or later on Apple silicon, with the Xcode Command Line Tools (`xcode-select --install`).

And, on either:

- Node.js 22 or later. 22.18 or later runs the TypeScript in this tutorial directly; on an earlier
  22.x add `--experimental-strip-types` to each `node` command.
- Python 3, which node-gyp uses to compile the key wrapper's native add-on when it is installed.
- The HkdfGuard native package for your platform.

Linux works the same way with its own paths and a TPM-backed KEK; see the
[CLI reference](reference/cli.md#linux) for what is published so far.

## How the pieces fit

HkdfGuard never holds your master key. There are two keys:

- The **KEK** (key-encryption key) lives in the TPM, or in the Secure Enclave on a Mac. It never
  leaves it. Each KEK is identified by a **service name**, such as `com.example.myapp`.
- A **DEK** (data encryption key) is what actually encrypts your data, with AES-256-GCM. On disk
  it exists only *wrapped*, encrypted under the KEK. Your process asks the native library to unwrap
  it at startup and holds it in memory that is zeroed when you're done.

Two separate things are installed:

| Part | Where it comes from | What it does |
|---|---|---|
| The npm packages | `@runsecure/hkdfguard-dek`, `-cryptoprovider-aesgcm256`, `-keywrapping-native-v1` and their dependencies | Everything your code calls |
| The native library and its `hkdfguard` tool (`hkdfguard-v1-initialize` on macOS) | The HkdfGuard native package: `%ProgramFiles%\HkdfGuard\v1` on Windows, `/Library/Application Support/HkdfGuard/v1` (or `~/.hkdfguard/v1`) on macOS | Hold and use the KEK |

`@runsecure/hkdfguard-keywrapping-native-v1` contains a small C add-on, compiled when the package is
installed, that does nothing but load the native library and call it. It loads the library only
from that location, and only after its TypeScript has checked the folder's ownership and
permissions and the library's code signature. It never searches `PATH`, `LD_LIBRARY_PATH`,
`DYLD_LIBRARY_PATH`, `node_modules` or your application folder.

## 1. Install the native package

**Windows:** run the HkdfGuard installer as an administrator.

> **TODO (maintainer):** give the installer's file name and where to download it, and say whether
> it creates the `HkdfGuardUsers` group.

Check that it installed:

```powershell
Get-AuthenticodeSignature "$env:ProgramFiles\HkdfGuard\v1\HkdfGuard.dll" | Select-Object Status, SignerCertificate
```

`Status` must be `Valid`.

**macOS:** install the native package system-wide, to `/Library/Application Support/HkdfGuard/v1`.
(A per-user install at `~/.hkdfguard/v1` is also loaded, but only when there is no system-wide
one.)

> **TODO (maintainer):** give the package's file name and where to download it.

Check that it installed, with the same requirement the library applies when it loads:

```sh
codesign --verify --strict \
  -R='identifier "libhkdfguard_v1" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "MFW3T8R8J3"' \
  "/Library/Application Support/HkdfGuard/v1/libhkdfguard_v1.dylib" && echo OK
```

## 2. Provision a KEK for your service

Choose a service name. It is 1 to 128 ASCII letters, digits or dots, doesn't start with a dot,
and never contains `..`. Reverse-DNS style works well: `com.example.myapp`. Hyphens are not
allowed.

**Windows:** open PowerShell **as administrator** and run:

```powershell
& "$env:ProgramFiles\HkdfGuard\v1\hkdfguard.exe" provision --service-name com.example.myapp
```

This creates the KEK in the TPM. Running it again is safe: if the KEK already exists, the command
only checks that its properties and access list are still correct.

Then let the account your application runs as use the KEK by adding it to the `HkdfGuardUsers`
group:

```powershell
Add-LocalGroupMember -Group HkdfGuardUsers -Member "$env:USERDOMAIN\$env:USERNAME"
```

Sign out and back in, so your session picks up the new group.

> **Security:** add only the accounts that run your application. Any member of the group can use
> every KEK the group is allowed to use.

**macOS:** run, as the account your application will run as (not with `sudo`):

```sh
"/Library/Application Support/HkdfGuard/v1/hkdfguard-v1-initialize" provision --service-name com.example.myapp
```

This creates the KEK in the Secure Enclave and prints its **fingerprint**: record it, `wrap` and
`retire` can be told to insist on it. Running it again is safe. The KEK's keychain item is created
in that account's login keychain, so provision as the account that will use it.

> **Security:** in this mode the keychain item's access list names the binary that created it, the
> tool. The binary that uses the KEK from your application is `node` itself, so the first time a
> given `node` executable uses the KEK in a logged-in session - including after every Node.js
> upgrade, or with each version a version manager such as nvm installs - macOS asks whether to
> allow it; choose **Always Allow**. In a session with no UI (ssh, a launch daemon outside a login
> session), the library reports status -18 instead. Run unattended consumers as a LaunchAgent
> inside a logged-in session, with a fixed `node`.

## 3. Encrypt and decrypt with an in-memory key

Create a project and add the packages:

```sh
mkdir hkdfguarddemo && cd hkdfguarddemo
npm init -y && npm pkg set type=module
npm install @runsecure/hkdfguard-abstractions @runsecure/hkdfguard-dek \
  @runsecure/hkdfguard-cryptoprovider-aesgcm256 @runsecure/hkdfguard-keywrapping-native-v1
```

The last package compiles its add-on as it installs; an error from node-gyp here means Python 3 or
the C compiler from the list above is missing.

> **TODO (maintainer):** confirm these package names resolve once they are published. Until then,
> install them from a checkout of `hkdfguard-node` after `npm install` there, by path
> (`npm install ../hkdfguard-node/packages/dek ...`, one path per package).

Write `main.ts`:

```ts
import { wipe } from '@runsecure/hkdfguard-abstractions';
import { AesGcmCryptoProviderFactory } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { buildKeyRing } from '@runsecure/hkdfguard-dek';
import { NativeKeyWrapperV1 } from '@runsecure/hkdfguard-keywrapping-native-v1';

const ring = await buildKeyRing({
  keyWrapper: NativeKeyWrapperV1.create('com.example.myapp'),
  cryptoProviderFactory: new AesGcmCryptoProviderFactory(),
  keyRefreshInterval: 60,
  ephemeralKeys: [1],
});
try {
  const protector = ring.createProtector('customer-notes');
  const encrypted = protector.encrypt(new TextEncoder().encode('The launch code is 0000'));
  console.log(encrypted);

  const buffer = new Uint8Array(protector.maxDecryptedLength(encrypted));
  try {
    const n = protector.decrypt(encrypted, buffer);
    console.log(new TextDecoder().decode(buffer.subarray(0, n)));
  } finally {
    wipe(buffer);
  }
} finally {
  await ring.close();
}
```

Run it with `node main.ts`. You should see something like:

```text
enc::v1::35zt4fIdLUCinFy3S6/8N1yf53CaMBiU+eRmC2PyVVIJV+LwFzm7Q3xf2sU/JmatNCgp
The launch code is 0000
```

What happened:

- `buildKeyRing` asked the native library to generate a fresh DEK and wrap it under your KEK. It
  then unwrapped it into memory that is zeroed when the ring is closed. The plaintext DEK was never
  on disk.
- `enc::v1::...` is the stored form: `v1` is the key version, and the rest is the AES-GCM
  ciphertext in base64. It is the same format the .NET and Go libraries write and read.
- `'customer-notes'` is the protector's **purpose**. It is bound into every value, so a value
  encrypted by one protector never decrypts under a protector with another name.
- `keyRefreshInterval: 60` makes the library re-check the KEK every 60 seconds. If the KEK stops
  being available (it was deleted, or your account lost access), encryption and decryption stop
  after three failed checks, about three minutes, until access returns. That is the default
  `refreshFailurePolicy`; `RefreshFailurePolicy.failOpen()` keeps the last good key instead.
- KMS calls run on libuv's thread pool, so a slow TPM never blocks the event loop.
- Plaintext travels as a `Uint8Array`, so it can be zeroed: `wipe` clears the buffer when you are
  done. `encrypt` also accepts a `string` for convenience, but a JavaScript string can't be
  cleared from memory, so prefer bytes for anything secret.

**The catch:** an ephemeral key exists only in this process. Run the program again and the first
value can't be decrypted, because that key is gone. That's right for short-lived data such as
session tokens. Data you store needs a key file.

## 4. Understand key files

A **key file** holds one wrapped DEK. It is useless without the KEK, so it is not a secret in the
usual sense, but its permissions still matter. Anyone who can replace it controls the key your
application encrypts new data with. So `NativeKeyWrapperV1` reads every key file through the native
library, which checks it before returning a byte: it refuses a file another account could write or
replace (the file or a folder above it), one reached through a symbolic link, junction or other
reparse point, an 8.3 short name or a network, mapped or SUBST drive, one that isn't a regular file
or is the wrong size, and one that holds what looks like an *unwrapped* key - 32 raw bytes, or their
hex or base64. Treat that last one as a key exposure. The file comes back still wrapped; reading it
never touches the KEK.

You create a key file once per release, or per key rotation, with `hkdfguard wrap`
(`hkdfguard-v1-initialize wrap` on macOS).
The tool reads the DEK on standard input, wraps it under the service's KEK, and writes the file
with restricted permissions. On Windows its `--group` option names the local group whose members
can read the file.

> **TODO (maintainer):** describe the exact permissions `wrap` puts on the key file on each
> platform, and whether `wrap` must run elevated on Windows.

Where does the DEK come from? In a deployment pipeline, use `AesGcmPipelineDataProtector`. It
generates a key in memory and can encrypt your configuration secrets under it (read back at
runtime by `@runsecure/hkdfguard-encryptedconfig`). At the end of the pipeline you pass that same
key to `wrap`. This tutorial skips the configuration secrets and only creates the file.

## 5. Create a key file

Add `keyfile.ts`. It generates a DEK, passes it to `wrap` on standard input, and zeroes every copy
it controls:

```ts
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { AesGcmPipelineDataProtector } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { DefaultFormatProvider } from '@runsecure/hkdfguard-dek';

/**
 * Generates a DEK, passes it to the hkdfguard tool's wrap on standard input, and zeroes every copy
 * it controls. group is the local group allowed to read the key file (Windows requires it; omit it
 * elsewhere).
 */
export async function createKeyFile(toolPath: string, serviceName: string, keyFilePath: string, group?: string): Promise<void> {
  // The pipeline protector generates the DEK in memory; close() zeroes it and its base64 form.
  const protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), 1);
  try {
    const args = ['wrap', '--service-name', serviceName, '--key-file-path', keyFilePath, '--dek-stdin'];
    if (group !== undefined) args.push('--group', group);
    const tool = spawn(toolPath, args, { stdio: ['pipe', 'inherit', 'inherit'] });
    const exited = once(tool, 'close');
    // A tool that exits before reading its input breaks the pipe; its exit code says why.
    let writeError: Error | undefined;
    tool.stdin.on('error', (error) => { writeError = error; });

    // The key crosses to the tool as bytes from the protector's own buffer, never through a string.
    tool.stdin.end(protector.keyBase64());
    const [code] = await exited;
    if (code !== 0) throw new Error(`hkdfguard wrap exited with code ${code}`);
    if (writeError !== undefined) throw writeError;
  } finally {
    protector.close();
  }
}
```

Call it once. On Windows:

```ts
import { join } from 'node:path';
import { createKeyFile } from './keyfile.ts';

await createKeyFile(
  join(process.env.ProgramFiles!, 'HkdfGuard', 'v1', 'hkdfguard.exe'),
  'com.example.myapp',
  'C:\\ProgramData\\MyApp\\keys\\v1.key',
  'HkdfGuardUsers');
```

On macOS:

```ts
import { createKeyFile } from './keyfile.ts';

await createKeyFile(
  '/Library/Application Support/HkdfGuard/v1/hkdfguard-v1-initialize',
  'com.example.myapp',
  '/Library/Application Support/MyApp/keys/v1.key');
```

> **Security:** pass the DEK on standard input, as above. Never pass it as a command-line argument
> or an environment variable: process listings, shell history, CI logs and crash dumps record
> those. Don't build it in a PowerShell or Bash variable either, and never decode `keyBase64()`
> into a JavaScript `string` (`TextDecoder`, `Buffer.toString`, a template literal). Those can't be
> cleared from memory.

## 6. Use the key file

Replace `ephemeralKeys` with `keyFiles`:

```ts
const ring = await buildKeyRing({
  keyWrapper: NativeKeyWrapperV1.create('com.example.myapp'),
  cryptoProviderFactory: new AesGcmCryptoProviderFactory(),
  keyRefreshInterval: 60,
  keyFiles: { 1: keyFilePath },
});
```

Now values survive a restart: encrypt, run the program again, and decrypt the earlier value.

The number you give `keyFiles` is the version that appears as `v1` in every value. When you
rotate, add a `v2.key` as `keyFiles: { 1: v1Path, 2: v2Path }`. New values use the highest
version, and older values still decrypt as long as their key file stays registered.

Rotate at least yearly. AES-GCM is only safe for a limited number of encryptions under one key,
and a key file outlives the process that counts them. So a key file stops encrypting 365 days
after it was last written (`keyFileMaxAgeDays`, or `KeyFileMaxAgeDays` in `appsettings.json`, sets
anywhere from 1 to 3650). A warning is logged at 90% of that age. After it, encrypting throws
`EncryptionLimitReachedError`, and values under that key file still decrypt. The age is the file's
modification time, so copy key files with their timestamps kept (`cp -p`, `rsync -t`). A plain
copy resets the clock.

The same settings can come from a file shared with the .NET port: `keyRingOptionsFromJson` reads the
`HkdfGuard` section of an `appsettings.json`, with the same field names (`ServiceName`,
`KeyRefreshInterval`, `KeyFiles`, `EphemeralKeys`, ...), and `keyRingConfigFromOptions` validates
it and turns it into the configuration above.

## If something goes wrong

Every error is an `HkdfGuardError` with a stable `code`; test with `instanceof` or on `code`. A
failed native call is a `StatusError` whose `status` is the native code and whose message includes
its meaning. The codes are the same on every platform (`Status` in
`@runsecure/hkdfguard-keywrapping-native-v1`). A key file the native library refused is a
`KeyFileRefusedError`, whose message names the file, the status and its meaning.

| You see | Cause | Fix |
|---|---|---|
| `NotInstalledError` (`ERR_HKDFGUARD_NATIVE_NOT_INSTALLED`) | The native package isn't installed at its fixed location | Step 1 |
| `UntrustedError` (`ERR_HKDFGUARD_NATIVE_UNTRUSTED`) | The installed library, or a folder above it, failed verification: wrong signature, writable by non-administrators, or (macOS) a `DYLD_LIBRARY_PATH` entry shadows it | Reinstall the native package; don't change that folder's permissions; clear the linker variables |
| `UnsupportedPlatformError` (`ERR_HKDFGUARD_NATIVE_UNSUPPORTED_PLATFORM`) | An Intel Mac or an x64 `node` under Rosetta, an unsupported OS, or the add-on was never compiled | Use an arm64 `node` on Apple silicon; install Python 3 and a C compiler, then `npm rebuild @runsecure/hkdfguard-keywrapping-native-v1` |
| `StatusError` `-17` | No KEK is provisioned for this service name | Step 2, with the same service name |
| `StatusError` `-18` (Windows) | The KEK exists, but this account may not use it | Add the account to `HkdfGuardUsers`, then sign out and in |
| `StatusError` `-18` (macOS) | The keychain would not answer: locked, no UI session for the access prompt, or the prompt was declined | Run from a logged-in session and choose Always Allow |
| `StatusError` `-16` | The key file was wrapped under a different service's KEK | Use the service name the file was created with |
| `StatusError` `-10`, `-11` or `-12` | The key file was altered | Restore it from your deployment artifacts |
| `KeyFileRefusedError` `-32` (`ENOENT`) or `-33` (`EACCES`) | The key file, or a folder in its path, doesn't exist; or this account may not read it | Check the path, and the `--group` it was wrapped for |
| `KeyFileRefusedError` `-39` (`EACCES`) | The key file's path isn't trusted: another account could write or replace the file or a folder above it, or it is reached through a link, junction, short name or network drive | Keep key files in a folder only administrators (or root) and the application's account can write, by a real local path |
| `KeyFileRefusedError` `-37` (`ERR_HKDFGUARD_INVALID_KEY_FILE`) | The file holds what looks like an **unwrapped** key | Treat the key as exposed: delete the file, rotate, and wrap a new key file |
| `KeyFileRefusedError` `-35`, `-36` or `-38` (`ERR_HKDFGUARD_INVALID_KEY_FILE`) | The file is the wrong size, or isn't a wrapped key | Recreate it with `wrap` |
| `InvalidServiceNameError` | The name breaks the rule in step 2 | Use letters, digits and dots only |
| `InvalidKeyFileError` (`ERR_HKDFGUARD_INVALID_KEY_FILE`), from a key wrapper that doesn't read key files itself | The key file is empty, too large, or not a regular file. Or someone other than the application could replace it: the file is writable by its group or others, it or a folder above it is owned by a user other than root or the application's own, or a folder above it is writable by its group or others without the sticky bit | Fix the permissions (`0600` or `0640` on the file, owned by root or the application's account, in folders only those can write), or recreate it with `wrap` |
| `KeyAccessSuspendedError` | The KEK stopped answering for three refreshes in a row | Restore access to the KEK; operations resume on the next successful refresh |
| `EncryptionLimitReachedError` (`ERR_HKDFGUARD_ENCRYPTION_LIMIT_REACHED`) naming a key file | The current key file is older than `keyFileMaxAgeDays` (365 by default) | Wrap a new key file and register it at a higher version (step 6); old values keep decrypting |

## Next steps

- [`hkdfguard` CLI reference](reference/cli.md): every command and option.
- The README's package table and examples for `@runsecure/hkdfguard-cache` and
  `@runsecure/hkdfguard-encryptedconfig`, until their how-to pages are written.

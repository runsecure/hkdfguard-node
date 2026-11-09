# @runsecure/hkdfguard-options-certificate

Plain-data, validated options naming one X.509 certificate - in the Windows certificate store, a
macOS keychain, an OpenSSL 3 provider on Linux (a TPM, a PKCS#11 token) or a password-protected file -
and the loader that opens it without ever exporting a key the operating system holds. The Node port
of .NET's `HkdfGuard.Options.Certificate`, alongside the Java, Go and Python ports.

```sh
npm install @runsecure/hkdfguard-options-certificate
```

Requires Node.js 22 or later. On Windows and macOS the install compiles this package's own N-API
add-on (`native/hkdfguard_certificate.c`) with node-gyp, which needs Python 3 and a C compiler
(Visual Studio Build Tools; the Xcode command line tools). The add-on is what reaches the Windows
store (crypt32 and CNG, loaded from System32 only) and the keychains (the Security framework). On
Linux nothing is built: files and provider keys go through `node:crypto` and `node:tls`.

## Options

`CertificateOptions` names exactly one source. Its fields are .NET's in camelCase, and the same
`appsettings.json` section binds through `certificateOptionsFromJson(document, 'Certificate')` or
`certificateOptionsFromObject(section)` (keys match ignoring case; enums by name, ignoring case, or by
.NET's number; booleans also as `"true"`/`"false"`; **an unknown key is an error**):

```json
"Certificate": { "Windows": { "StoreLocation": "LocalMachine", "StoreName": "My", "Subject": "CN=api.example.com" } }
"Certificate": { "MacOS": { "StoreLocation": "LocalMachine", "Subject": "CN=api.example.com" } }
"Certificate": { "Linux": { "Provider": "pkcs11", "KeyUri": "pkcs11:token=tls;object=api;type=private", "CertificateFile": "/etc/myapp/tls.crt" } }
"Certificate": { "Linux": { "Provider": "tpm2", "KeyUri": "/etc/myapp/tls-key.pem", "CertificateFile": "/etc/myapp/tls.crt" } }
"Certificate": { "File": { "Path": "/etc/myapp/tls.pfx", "PasswordSecretName": "tls-pfx-password" } }
"Certificate": { "File": { "Path": "/etc/myapp/tls.crt", "Format": "Pem", "KeyPath": "/etc/myapp/tls.key", "PasswordSecretName": "tls-key-password" } }
```

`requirePrivateKey` defaults to true; set it false for a certificate only to be trusted. A file's
password never appears in configuration: `passwordSecretName` names a secret in a
`ProtectedReadOnlyCache` (a `FilePerSecretCache`, a remote secret cache), which the loader decrypts
into a buffer and zeroes as soon as the key is read. An unprotected key file is refused unless
`allowUnprotectedPrivateKey` is set, for development.

A store certificate is found by its subject distinguished name, compared whole and decoded, ignoring
case - `"CN=api"` never matches `"CN=api.example.com"`. Of the certificates with that subject, the one
valid now (and with its private key, when one is required) that expires last is chosen, so a renewal
under the same subject is picked up with no configuration change. Matching by subject trusts whoever
can write the store: use one only administrators can, such as LocalMachine's My.

```ts
import { constants } from 'node:crypto';
import { createServer } from 'node:https';
import { CertificateOptionsLoader, certificateOptionsFromJson } from '@runsecure/hkdfguard-options-certificate';

const options = certificateOptionsFromJson(appsettingsJson, 'Certificate');
// passwords: a ProtectedReadOnlyCache; omit if no file has one. fileTrust: a KeyFileTrust naming who
// besides administrators may have written the certificate and key files; administrators only if omitted.
const loader = new CertificateOptionsLoader({ passwords });
const certificate = await loader.load(options, 'tls');
try {
  const server = createServer(handler);
  certificate.configureServer(server, { minVersion: 'TLSv1.3' }); // File and Linux sources
  server.listen(443);

  const signature = await certificate.sign('sha256', data, { padding: constants.RSA_PKCS1_PSS_PADDING }); // any source
} finally {
  await certificate.close(); // once nothing will sign with it; contexts already made keep working
}
```

`CertificateOptionsValidator` (and `validateCertificateOptions(options)`) reports every failure at
once; the loader validates first and rejects with `InvalidCertificateOptionsError`, listing them.

## What each source gives

| Source | Key stays in | `sign` / `decrypt` | `configureServer` / `createSecureContext` |
|---|---|---|---|
| Windows store | CNG (or the TPM through the Platform Crypto Provider): acquired with `CryptAcquireCertificatePrivateKey`, CNG only and silently | `NCryptSignHash` (RSA PKCS #1 v1.5 and PSS, ECDSA) and `NCryptDecrypt` (PKCS #1 v1.5, OAEP), on libuv's thread pool | Throw `NativeProviderRequiredError` |
| macOS keychain (My only) | The keychain: the identity's `SecKeyRef` | `SecKeyCreateSignature`, `SecKeyCreateDecryptedData`, on the thread pool | Throw `NativeProviderRequiredError` |
| Linux OpenSSL provider | The provider (TPM, token): the provider's own key object in Node's OpenSSL | Yes, through `node:crypto` (OAEP only for decryption, below) | Yes: `node:tls` decodes the key through the provider |
| File (PKCS#12, PEM + encrypted PKCS#8) | Process memory, sealed (AES-256-GCM under a random key), wiped on `close()` | Yes, through `node:crypto` | Yes |

Without its private key (`requirePrivateKey` false), any source's certificate gives a
`createSecureContext()` that trusts it - and its chain - alone (`ca`), in place of the system's roots.

`LoadedCertificate` has `certificate` (a `node:crypto` `X509Certificate`), `chain` (the other
certificates a PKCS#12 or PEM file held, in file order), `subject`, `notBefore`, `notAfter`,
`publicKey`, `hasPrivateKey` and `keyLocation`, and:

- `sign(hash, data, options?)` - `hash` is `'sha1' | 'sha224' | 'sha256' | 'sha384' | 'sha512'`
  (SHA-224 not with CNG). The options are `crypto.sign`'s: `padding` (`RSA_PKCS1_PADDING`, the
  default, or `RSA_PKCS1_PSS_PADDING`), `saltLength` (bytes, `RSA_PSS_SALTLEN_DIGEST` or
  `RSA_PSS_SALTLEN_MAX_SIGN`, the default) with MGF1 over the same hash, and for ECDSA `dsaEncoding`
  (`'der'`, the default, or `'ieee-p1363'`).
- `decrypt(ciphertext, options?)` - RSA only; `crypto.privateDecrypt`'s options: `padding`
  (`RSA_PKCS1_OAEP_PADDING`, the default, or `RSA_PKCS1_PADDING`), `oaepHash` (default `'sha1'`) and
  `oaepLabel`. A new buffer to zero once used. `RSA_PKCS1_PADDING` is refused for a store or provider
  key: neither can answer bad padding with implicit rejection, so whoever submits ciphertexts could
  recover a plaintext (Bleichenbacher's attack). A file key does it as Node does, with implicit rejection.
- `configureServer(server, options?)` - makes a `tls.Server` (an `https` or `http2` secure server too)
  present the certificate and chain, through `server.setSecureContext`. Node's servers ignore a
  `secureContext` option, so this is how a server gets it.
- `createSecureContext(options?)` - a `SecureContext` for `tls.connect` (a client certificate), a
  `TLSSocket`, or what an `SNICallback` gives.
- `close()` - waits for operations in flight, releases store handles and wipes what it holds; every
  later use throws `ClosedError`. A TLS context keeps its own copy of the key in OpenSSL and outlives it.

Every operation that reaches a store or a file is asynchronous.

### Files

The PKCS#12 and PBES2 decryption is HkdfGuard's own, as in the Go and Python ports, and shared with
the Vault client's key stores (it lives in `abstractions`): PBES2 (PBKDF2
with HMAC-SHA-1/224/256/384/512, AES-128/192/256-CBC or 3DES-CBC), PKCS#12's own 3DES, HMAC-SHA-1/2
integrity MACs, BER as well as DER. Legacy RC2 and RC4 files (`openssl pkcs12 -legacy`) are refused
with a hint to re-export with AES, as are PBMAC1 and public-key-protected files, and legacy
OpenSSL-encrypted PEM keys (`Proc-Type`); key derivations are capped at 1,000,000 iterations each and
4,000,000 per file. Node's own `pfx` option isn't used: it takes the password only as a string, reads
whichever key it finds first, and reads what OpenSSL's legacy provider would.

A file read with a password must carry its integrity MAC, and every private key in it must be
encrypted; either failing is an `InvalidCertificateFileError`. RFC 7292 makes the MAC optional, but
it is the only thing that ties the file to its password: without one, a file of anyone's plaintext
key and certificate would read under any password. OpenSSL, keytool and Windows always write one
unless told not to (`-nomac`); a plaintext key (`-keypbe NONE`) is refused as a plaintext PEM key is
when a password is named. A file read without a password, under `AllowUnprotectedPrivateKey`, needs
neither, and its key is reported as an unprotected key file.

Every file - a PKCS#12, a PEM certificate or key, a Linux provider's certificate and key file - is
read through `readTrustedFile` (`@runsecure/hkdfguard-securefile`): it is refused, with a
`KeyFileError` of code `EACCES` saying what isn't trusted, unless it and every folder above it are
owned by an administrator (root; SYSTEM, Administrators or TrustedInstaller) or a principal in the
loader's `fileTrust` (`KeyFileTrust.administratorsOnly` by default) and writable by no one else,
with no untrusted symbolic link on the way - whoever can replace a key file chooses the key the
application serves TLS with, or signs as. Name the account your deployment writes the files as,
never the one the application runs as, outside a developer machine. Files are read whole into
buffers sized once (libuv reads straight into them); the password arrives from the cache into a
buffer, never a string, and is zeroed when the load ends. PBKDF2 is
`pbkdf2Sync`, PKCS#12's key derivation and MAC `createHash`/`createHmac`, and every derived key,
intermediate digest and decrypted buffer is a `Buffer` zeroed once used. The decrypted PKCS#8 is
sealed at once under a random AES-256-GCM key, and each use unseals it into a buffer wiped straight
after.

What can't be wiped from JavaScript: the copies `node:crypto` makes inside OpenSSL - the PBKDF2
password, cipher and HMAC key schedules, and the key parsed for each `sign`/`decrypt` - which OpenSSL
cleanses as it frees them (a `Cipher`, `Hash` or `KeyObject` when V8 collects it); and the PEM key a
TLS context is made from, which `node:tls` copies into a memory BIO it frees without zeroing (our
buffer is wiped as soon as the context exists). The context itself holds the key in OpenSSL until it
is collected.

### Windows store and macOS keychain

The store is opened read-only (Windows: `CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG`; a
store that doesn't exist reads as empty, as .NET's does). The chosen key is never exported, nor asked
to be exportable, whatever its export policy: every signature and decryption is the store's call,
made on libuv's thread pool on the add-on's own copy of the digest or ciphertext. A decryption's
plaintext is copied into a new `Buffer` and the native copy zeroed. Handles are released by
`close()` once no operation is in flight (each operation holds its key alive), and by a finalizer if
a `LoadedCertificate` is dropped unclosed. On Windows a key only a legacy CryptoAPI provider holds, or
one that would show a dialog, is refused (`NoPrivateKeyError`/`UnsupportedCertificateError`). On
macOS the login keychain is the effective user's, from the account database, never `$HOME`.

### Linux OpenSSL providers

`node:crypto` and `node:tls` read a PEM key through OpenSSL 3's decoders, which include every loaded
provider's: a `TSS2 PRIVATE KEY` through tpm2-openssl's, a `PKCS#11 PROVIDER URI` through
pkcs11-provider's. The key they give is the provider's own object, so every signature, decryption and
TLS handshake signature is the TPM's or the token's. `KeyUri` is a `pkcs11:` URI - handed to
pkcs11-provider in memory as a URI PEM - or the absolute path of a key file the provider decodes, such
as the one `openssl genpkey -provider tpm2 ...` writes. A persistent TPM handle (`handle:0x81000001`)
has no such file and is refused by the validator; so is a plain or encrypted PKCS#8 key file, which
OpenSSL would read into the process. The key is opened once at load time and checked to be the
certificate's.

Node has no API to load a provider at run time: it loads them from an OpenSSL configuration file at
startup. Start Node with `--openssl-config=/etc/myapp/openssl.cnf` (it reads the `nodejs_conf`
section) or with `--openssl-shared-config` and `OPENSSL_CONF` (the `openssl_conf` section):

```ini
nodejs_conf = hkdfguard_init
[hkdfguard_init]
providers = provider_sect
[provider_sect]
default = default_sect
tpm2 = tpm2_sect
[default_sect]
activate = 1
[tpm2_sect]
module = /usr/lib/x86_64-linux-gnu/ossl-modules/tpm2.so
activate = 1
```

Without it no decoder takes the key, and the load rejects with `OpenSslProviderUnavailableError`. Both
a distribution's Node (Ubuntu's `nodejs`, linked to the system's libcrypto) and the official
nodejs.org binaries (OpenSSL built in) load tpm2-openssl and pkcs11-provider this way; both were
tested. The provider's own settings - `TPM2OPENSSL_TCTI`, the PKCS#11 module, a token PIN (prefer
`pin-source=file:...` in the URI, or the provider's configuration, to `pin-value`) - come from its
environment or the configuration file. `privateKeyEngine`/`privateKeyIdentifier` (OpenSSL engines)
aren't used: engines are deprecated in OpenSSL 3, and no PKCS#11 engine is needed when the provider is.

Things seen with the providers, which are theirs, not this package's:

- Node decrypts RSA PKCS #1 v1.5 only with implicit rejection (CVE-2023-46809), which a provider key
  can't do, so `decrypt` with `RSA_PKCS1_PADDING` throws `UnsupportedCertificateError` for one; OAEP
  works with a TPM key. SoftHSM's OAEP fails inside OpenSSL itself (`openssl pkeyutl -decrypt` too).
- SoftHSM, through pkcs11-provider, crashes the process as it exits unless the provider's section has
  `pkcs11-module-quirks = no-deinit` (the `openssl` command crashes the same way).
- Each `KeyObject` and TLS context holds a TPM object until V8 collects it; a TPM reached without a
  resource manager (swtpm over TCP) holds only a few at once. Use the kernel's `/dev/tpmrm0` (the
  default TCTI) and reuse one context rather than make one per connection.
- `dsaEncoding: 'ieee-p1363'` is produced by this package from the DER signature: Node's own
  conversion crashes the process (SIGSEGV) with a pkcs11-provider EC key.

## Errors

Every error has a stable `code`. `InvalidCertificateOptionsError` (`ERR_HKDFGUARD_INVALID_CERTIFICATE_OPTIONS`,
with `failures`); `CertificateNotFoundError` (`ERR_HKDFGUARD_CERTIFICATE_NOT_FOUND`);
`CertificateNotValidNowError` (`ERR_HKDFGUARD_CERTIFICATE_NOT_VALID_NOW`); `NoPrivateKeyError`
(`ERR_HKDFGUARD_CERTIFICATE_NO_PRIVATE_KEY`); `NoPasswordSourceError`
(`ERR_HKDFGUARD_CERTIFICATE_NO_PASSWORD_SOURCE`); `PasswordNotFoundError` (a `KeyNotFoundError`,
`ERR_HKDFGUARD_KEY_NOT_FOUND`); `InvalidCertificateFileError` (`ERR_HKDFGUARD_INVALID_CERTIFICATE_FILE`);
`WrongPasswordError` (`ERR_HKDFGUARD_CERTIFICATE_WRONG_PASSWORD`); `UnsupportedCertificateError`
(`ERR_HKDFGUARD_UNSUPPORTED_CERTIFICATE`) and its `NativeProviderRequiredError`
(`ERR_HKDFGUARD_CERTIFICATE_NATIVE_PROVIDER_REQUIRED`) and `OpenSslProviderUnavailableError`
(`ERR_HKDFGUARD_OPENSSL_PROVIDER_UNAVAILABLE`); `CertificateStoreError` (`ERR_HKDFGUARD_CERTIFICATE_STORE`,
with the store call's `status`). Bad configuration from `certificateOptionsFromJson` is an
`InvalidArgumentError` (`ERR_HKDFGUARD_INVALID_OPTIONS_JSON`); a use after `close()` is `ClosedError`
(`ERR_HKDFGUARD_CLOSED`); a file that can't be read rejects with `securefile`'s `KeyFileError`, whose
`code` follows Node's (`ENOENT` for a missing file; `EACCES` for one this account may not read, or
whose location isn't trusted - the message says what).

## Differences from .NET

- **Store keys and TLS.** .NET's `X509Certificate2` from a store goes straight into `SslStream`.
  Node's TLS is OpenSSL, which takes a key only as PEM or through a provider loaded into it; a store's
  key is never exported to make one, and Node's OpenSSL has no provider for CNG or the keychain, so
  `configureServer` and `createSecureContext` throw `NativeProviderRequiredError` for a Windows or
  macOS store key. `sign` and `decrypt` call the store directly.
- **Linux providers.** .NET opens `KeyUri` through `SafeEvpPKeyHandle.OpenKeyFromProvider` (an
  `OSSL_STORE` URI). Node has no `OSSL_STORE` API: `KeyUri` is a `pkcs11:` URI or a key-file path,
  decoded through the provider's decoder, and a TPM `handle:` is refused. The provider must be loaded
  by Node's OpenSSL configuration at startup; `Provider` names it in messages, and whichever loaded
  provider decodes the key holds it. `decrypt` with PKCS #1 v1.5 is refused for a provider key.
- **macOS stores.** Only My - the login keychain for CurrentUser, the System keychain for
  LocalMachine - is read, as in the Go and Python ports; the validator refuses any other store name on
  macOS (.NET also maps Root and others to trust settings, which would hand back roots macOS no
  longer trusts if read without them).
- **What a load returns.** A `LoadedCertificate`, not an `X509Certificate2`: the certificate as a
  `node:crypto` `X509Certificate`, the rest of a PKCS#12 or PEM file's certificates as `chain` (.NET
  drops them), and the key's operations as methods with `crypto.sign`'s and `crypto.privateDecrypt`'s
  options. A file's key is held sealed in memory, where .NET imports it as a non-exportable,
  non-persisted key. There is no prehashed signing: `sign` hashes the data itself.
- **Servers.** A TLS server is given the certificate with `configureServer(server)` -
  `tls.Server.setSecureContext` - because Node's `createServer` ignores a `secureContext` option.
- **Asynchronous only.** `load` returns a promise (with an optional `AbortSignal` for the password
  read); there is no synchronous `Load`. `sign`, `decrypt` and `close` are asynchronous too, the
  store's calls running on libuv's thread pool.
- **Legacy files.** RC2/RC4 PKCS#12 files, PBMAC1 and public-key-protected PKCS#12 contents, and
  legacy OpenSSL-encrypted PEM keys (`Proc-Type`) are refused; .NET on Windows reads RC2/RC4.
  Iteration counts are capped (1,000,000 per derivation, 4,000,000 per file).
- **Subject matching.** Compared attribute by attribute, decoded, each multi-valued RDN's attributes
  as a set (as the Java and Python ports do) rather than .NET's comparison of the rendered strings;
  case is ignored character by character, as `OrdinalIgnoreCase` does. A store certificate this
  package can't parse is skipped.
- **Store keys' algorithms.** SHA-1, SHA-256, SHA-384 and SHA-512 with CNG (SHA-224 too on macOS);
  PSS and OAEP with MGF1 over the same hash; on macOS a PSS salt of the hash's length only and OAEP
  with no label. A Windows key CNG can't open silently - a third-party CSP without a KSP, or one that
  would show a dialog - is refused.
- **Paths.** Absolute by the host's rules, as .NET's `Path.IsPathFullyQualified` judges them.
- **Configuration and errors.** `certificateOptionsFromJson`/`certificateOptionsFromObject` refuse
  unknown keys (.NET's binder ignores them) and fields are camelCase. Failures are typed errors with
  stable codes (above) where .NET throws `OptionsValidationException`, `InvalidOperationException`,
  `CryptographicException` and `KeyNotFoundException`. The validator also refuses, where the source
  is otherwise usable, a macOS store other than My and a Linux `KeyUri` that is neither a `pkcs11:`
  URI nor an absolute path.

## Tests

The unit tests run everywhere, against certificates they make and the Go and Python ports' fixtures
(OpenSSL- and .NET-written PKCS#12 and PKCS#8 files, in `testdata`), with TLS handshakes over a local
`node:tls` server. Three opt-in suites touch real key storage:

- `HKDFGUARD_TEST_WINDOWS_CERT_STORE=1`: makes throwaway non-exportable RSA and ECDSA certificates in
  CurrentUser\My with `New-SelfSignedCertificate`, signs and decrypts through CNG, verifies with
  `node:crypto` against the public key, and removes them with their keys, however the test ends.
- `HKDFGUARD_TEST_MACOS_KEYCHAIN=1`: imports throwaway RSA and ECDSA identities into the login
  keychain and deletes them. **Not yet run on a Mac**; the keychain code is untested.
- `HKDFGUARD_TEST_OPENSSL_PROVIDER=<provider>` with `HKDFGUARD_TEST_OPENSSL_PROVIDER_KEY_URI` and
  `HKDFGUARD_TEST_OPENSSL_PROVIDER_CERTIFICATE` (and `HKDFGUARD_TEST_OPENSSL_PROVIDER_OAEP=0` for a
  token that can't OAEP-decrypt): TLS handshakes, signatures and decryption through a real provider
  key, under a Node started with `--openssl-config`. See
  [Open a certificate from a store, a provider or a file](https://github.com/runsecure/hkdfguard-node/blob/main/docs/how-to/use-certificate-options.md).

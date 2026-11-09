# Open a certificate from a store, a provider or a file

This page opens one certificate - and its private key - from where configuration says it is, with
`@runsecure/hkdfguard-options-certificate`: the Windows certificate store, a macOS keychain, a TPM or
PKCS#11 token on Linux through an OpenSSL 3 provider, or a password-protected PKCS#12 or PEM file.
The package is the Node port of .NET's `HkdfGuard.Options.Certificate`, and reads the same
`Certificate` configuration section. Its README describes the whole API.

## 1. Install

```sh
npm install @runsecure/hkdfguard-options-certificate
```

On Windows and macOS this compiles the package's add-on with node-gyp, which needs Python 3 and a C
compiler (Visual Studio Build Tools, or the Xcode command line tools). On Linux nothing is compiled.

## 2. Load the certificate

```ts
import { readFileSync } from 'node:fs';
import { createServer } from 'node:https';
import { CertificateOptionsLoader, certificateOptionsFromJson } from '@runsecure/hkdfguard-options-certificate';

const options = certificateOptionsFromJson(readFileSync('appsettings.json', 'utf8'), 'Certificate');
// passwords: the ProtectedReadOnlyCache a file's password is in - a FilePerSecretCache, say.
// fileTrust: who besides administrators may have written the certificate and key files (a KeyFileTrust);
// administrators only when left out.
const certificate = await new CertificateOptionsLoader({ passwords }).load(options, 'tls');

const server = createServer((request, response) => response.end('hello'));
certificate.configureServer(server, { minVersion: 'TLSv1.3' }); // a File or Linux source
server.listen(8443);
```

`load` validates the options first, and rejects with `InvalidCertificateOptionsError` listing every
problem. A store's certificate is found by its subject, and the one valid now that expires last is
taken, so a renewal under the same subject needs no configuration change.

Give a server the certificate with `configureServer`: Node's `tls.createServer`, `https.createServer`
and `http2.createSecureServer` ignore a `secureContext` option. `createSecureContext()` is for
`tls.connect` (a client certificate) and an `SNICallback`. Call `configureServer` again after loading
a renewed certificate; connections already open keep theirs.

> **Security:** Matching by subject trusts whoever can add a certificate to the store to choose it.
> Keep the certificate in a store only administrators can write, such as LocalMachine's My, or the
> System keychain.

## 3. Choose the source

### Windows certificate store

Put the certificate in LocalMachine\My with a CNG key, non-exportable:

```powershell
Import-PfxCertificate -FilePath api.pfx -CertStoreLocation Cert:\LocalMachine\My -Password $pw
# or, for a test:
New-SelfSignedCertificate -Subject 'CN=api.example.com' -CertStoreLocation Cert:\LocalMachine\My `
  -KeyExportPolicy NonExportable -Provider 'Microsoft Software Key Storage Provider'
```

Grant the service's account read access to the key (certlm.msc, *Manage Private Keys*), and configure:

```json
"Certificate": { "Windows": { "StoreLocation": "LocalMachine", "StoreName": "My", "Subject": "CN=api.example.com" } }
```

`certificate.sign(...)` and `certificate.decrypt(...)` call CNG (`NCryptSignHash`, `NCryptDecrypt`).
`decrypt` uses OAEP: RSA PKCS #1 v1.5 decryption with a store key is refused, as CNG would answer bad
padding with an error of its own - the oracle Bleichenbacher's attack needs.
`configureServer` and `createSecureContext` throw `NativeProviderRequiredError`: Node's TLS is
OpenSSL, which can't reach a CNG key, and the key is never exported to give it one. Use a File or
Linux source where Node itself must serve TLS.

> **Security:** The key is acquired silently, through CNG only. A key only a legacy CryptoAPI provider
> holds, or one that would show a dialog, is refused: re-import it into a CNG key storage provider.

### macOS keychain

Import the identity into the System keychain (LocalMachine) or the login keychain (CurrentUser), and
use `"MacOS"` in place of `"Windows"`; only the My store is read:

```json
"Certificate": { "MacOS": { "StoreLocation": "LocalMachine", "Subject": "CN=api.example.com" } }
```

As on Windows, `sign` and `decrypt` call the keychain and TLS from its key is refused. The keychain
is never allowed to show a dialog: a key whose access list doesn't include the application fails
with `NoPrivateKeyError` rather than waiting for someone to click. Add the application to the key's
access list (Keychain Access, Access Control). **TODO (maintainer):** these steps and the keychain
code have not yet been run on a Mac.

### Linux: a key in a PKCS#11 token (pkcs11-provider)

Node loads OpenSSL providers only from an OpenSSL configuration file at startup. Both Ubuntu's
`nodejs` (linked to the system's OpenSSL) and the official nodejs.org binaries (OpenSSL built in) load
pkcs11-provider and tpm2-openssl this way. With SoftHSM standing in for the token (Ubuntu):

```sh
sudo apt-get install pkcs11-provider softhsm2 opensc
mkdir tokens && printf 'directories.tokendir = %s/tokens\n' "$PWD" > softhsm2.conf
export SOFTHSM2_CONF=$PWD/softhsm2.conf
softhsm2-util --init-token --free --label hkdfguard --pin 1234 --so-pin 5678
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 --keypairgen --key-type EC:prime256v1 --label tls --id 01
URI='pkcs11:token=hkdfguard;object=tls;type=private?pin-value=1234'   # or pin-source=file:/path/to/pin
openssl req -provider pkcs11 -provider default -new -x509 -key "$URI" -subj /CN=api.example.com -days 30 -out tls.crt
```

(`openssl` may crash as it exits with SoftHSM; the certificate is written first.) Write the
configuration Node starts with - `openssl version -m` prints the modules directory:

```ini
# openssl-node.cnf
nodejs_conf = hkdfguard_init
[hkdfguard_init]
providers = provider_sect
[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect
[default_sect]
activate = 1
[pkcs11_sect]
module = /usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so
pkcs11-module-path = /usr/lib/softhsm/libsofthsm2.so
pkcs11-module-quirks = no-deinit
activate = 1
```

```json
"Certificate": { "Linux": { "Provider": "pkcs11", "KeyUri": "pkcs11:token=hkdfguard;object=tls;type=private?pin-value=1234", "CertificateFile": "/path/tls.crt" } }
```

```sh
node --openssl-config=$PWD/openssl-node.cnf app.js
# or: OPENSSL_CONF=$PWD/openssl-node.cnf node --openssl-shared-config app.js   (with an openssl_conf section)
```

`pkcs11-module-quirks = no-deinit` stops SoftHSM crashing the process as it exits. Without the
configuration, `load` rejects with `OpenSslProviderUnavailableError`.

> **Security:** A `pin-value` in the URI is in your configuration and the process's memory. Prefer
> `pin-source=file:/path/to/pin` (a file only the service can read) or the token's own login setup.

### Linux: a key in the TPM (tpm2-openssl)

Create the key in the TPM; `openssl genpkey` writes a `TSS2 PRIVATE KEY` file, a key blob only that
TPM can load - not the key itself:

```sh
sudo apt-get install tpm2-openssl
openssl genpkey -provider tpm2 -provider default -algorithm EC -pkeyopt group:P-256 -out tls-key.pem
openssl req -provider tpm2 -provider default -new -key tls-key.pem -subj /CN=api.example.com -out tls.csr
# have your CA issue tls.crt from tls.csr (a self-signed one: openssl req -x509 ... -key tls-key.pem)
```

Configure the provider as for pkcs11, with a `tpm2 = tpm2_sect` line and
`[tpm2_sect] module = .../ossl-modules/tpm2.so` and `activate = 1`, and:

```json
"Certificate": { "Linux": { "Provider": "tpm2", "KeyUri": "/etc/myapp/tls-key.pem", "CertificateFile": "/etc/myapp/tls.crt" } }
```

`KeyUri` is the key file's path. A persistent handle (`handle:0x81000001`) is refused: Node reads a
key only from PEM, through the provider's decoder, and has no `OSSL_STORE` API to open a handle. A
`CertificateFile` holding the leaf and its CA chain is presented whole.

Each key object and TLS context holds a TPM object until V8 collects it. The kernel's resource
manager, `/dev/tpmrm0` - tpm2-openssl's default - swaps them as needed; a TPM reached without one
(swtpm over TCP, `TPM2OPENSSL_TCTI=swtpm:...`) holds only two of these keys at once. Configure each
server once rather than per connection.

### A file

```json
"Certificate": { "File": { "Path": "/etc/myapp/tls.pfx", "PasswordSecretName": "tls-pfx-password" } }
"Certificate": { "File": { "Path": "/etc/myapp/tls.crt", "Format": "Pem", "KeyPath": "/etc/myapp/tls.key", "PasswordSecretName": "tls-key-password" } }
```

The password is a secret in the `ProtectedReadOnlyCache` given to the loader - a file in a
`FilePerSecretCache` folder named `tls-pfx-password`, say. A PEM key must be encrypted PKCS#8
(`openssl pkcs8 -topk8 -v2 aes-256-cbc`). A legacy RC2 or RC4 PKCS#12 (`openssl pkcs12 -legacy`, old
Windows exports) is refused: re-export it with `openssl pkcs12 -export` from OpenSSL 3, without
`-legacy`. With a password named, a PKCS#12 must carry its integrity MAC (not `-nomac`) and its key
must be encrypted (not `-keypbe NONE`): otherwise nothing ties the file to the password, and a
planted file of anyone's key would load under it.

> **Security:** The password is read into a buffer and zeroed as soon as the key is read; it never
> becomes a string. The key is held sealed in memory and wiped by `close()`. What can't be wiped from
> JavaScript - the copies OpenSSL makes, and the PEM a TLS context is made from - is listed in the
> package README. `AllowUnprotectedPrivateKey` accepts a key file with no password; set it only for
> development.
>
> Every certificate and key file - `Path`, `KeyPath`, a Linux source's `CertificateFile` and key
> file - is read through `readTrustedFile` (`@runsecure/hkdfguard-securefile`), and refused unless
> it, and every folder above it, is owned by an administrator (root; SYSTEM, Administrators or
> TrustedInstaller) or a principal in the loader's `fileTrust`, and writable by no one else, with no
> untrusted symbolic link on the way: whoever can replace a key file chooses the key the
> application serves TLS with. Give `fileTrust` a `KeyFileTrust` naming the account your deployment
> writes the files as - never the account the application runs as, outside a developer machine.
> A refusal rejects with `KeyFileError`, code `EACCES`, saying what isn't trusted.

## 4. Run the opt-in tests

The package's unit tests run everywhere (`npm test --workspace packages/options-certificate`). The
suites against real key storage need asking for.

Windows - makes throwaway non-exportable RSA and ECDSA certificates in CurrentUser\My and removes them
with their keys, however the tests end:

```powershell
cd packages/options-certificate
$env:HKDFGUARD_TEST_WINDOWS_CERT_STORE = "1"
node --test dist/windows.test.js
Get-ChildItem Cert:\CurrentUser\My | Where-Object Subject -like '*hkdfguard-node-test*'   # nothing is left
```

macOS - imports throwaway identities into the login keychain and deletes them:

```sh
HKDFGUARD_TEST_MACOS_KEYCHAIN=1 node --test dist/macos.test.js
```

Linux - a TLS handshake, signatures and decryption through a real provider key, with the
configuration above (`HKDFGUARD_TEST_OPENSSL_PROVIDER_OAEP=0` for SoftHSM, whose OAEP decryption
fails in OpenSSL itself):

```sh
HKDFGUARD_TEST_OPENSSL_PROVIDER=pkcs11 HKDFGUARD_TEST_OPENSSL_PROVIDER_KEY_URI="$URI" \
HKDFGUARD_TEST_OPENSSL_PROVIDER_CERTIFICATE=$PWD/tls.crt HKDFGUARD_TEST_OPENSSL_PROVIDER_OAEP=0 \
  node --openssl-config=$PWD/openssl-node.cnf dist/provider.test.js
```

For tpm2, set `HKDFGUARD_TEST_OPENSSL_PROVIDER=tpm2` and the key file's path as the key URI.

## Differences from .NET

- A store's key can't serve TLS from Node (`NativeProviderRequiredError`); .NET gives it to `SslStream`.
- A Linux `KeyUri` is a `pkcs11:` URI or a key file's path, not an `OSSL_STORE` URI; a TPM `handle:`
  is refused, and the provider is loaded by Node's OpenSSL configuration, not by the loader.
- Servers take the certificate through `configureServer`; `load` is asynchronous only.
- Only the My store is read on macOS; legacy RC2/RC4 PKCS#12 files are refused; unknown configuration
  keys are errors.

The package README's *Differences from .NET* has the full list.

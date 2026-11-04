// OpenSSL 3 provider keys on Linux, through Node's own OpenSSL.
//
// node:crypto's createPrivateKey and node:tls's createSecureContext read a PEM key through OpenSSL 3's
// decoders, which include every loaded provider's: a `TSS2 PRIVATE KEY` through tpm2-openssl's, a
// `PKCS#11 PROVIDER URI` through pkcs11-provider's. The key they give is the provider's own object, so
// every signature and decryption - and every TLS handshake signature - is the TPM's or the token's,
// and the key never enters the process.
//
// Node has no API to load a provider at run time: it loads them from an OpenSSL configuration file
// at startup - `node --openssl-config=/etc/myapp/openssl.cnf` (its `nodejs_conf` section), or
// `--openssl-shared-config` with OPENSSL_CONF (the `openssl_conf` section). Both a distribution's
// Node (linked to the system's libcrypto) and the official nodejs.org binaries (with OpenSSL built in)
// load tpm2-openssl and pkcs11-provider this way. Without it, no decoder takes the key, and the load
// is refused with OpenSslProviderUnavailableError. Never exported from the package index.
import { createPrivateKey, type KeyObject } from 'node:crypto';
import * as der from './der.js';
import { InvalidCertificateFileError, OpenSslProviderUnavailableError, UnsupportedCertificateError } from './errors.js';
import { encodePem, pemBlocks } from './pem.js';

export const PKCS11_URI_LABEL = 'PKCS#11 PROVIDER URI';
const PKCS11_URI_DESCRIPTION = 'PKCS#11 Provider URI v1.0';
const KEY_LABELS = new Set(['PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'ENCRYPTED PRIVATE KEY']);

/**
 * A `pkcs11:` URI as pkcs11-provider's decoder takes it from a key file: a `PKCS#11 PROVIDER URI` PEM,
 * SEQUENCE { desc VisibleString, uri UTF8String }. The URI names the key; it holds no secret unless it
 * carries a `pin-value`, which belongs in the provider's configuration (or `pin-source=file:`).
 */
export function pkcs11UriPem(uri: string): Buffer {
  const body = der.encode(der.SEQUENCE, der.encode(der.VISIBLE_STRING, Buffer.from(PKCS11_URI_DESCRIPTION, 'latin1')),
    der.encode(der.UTF8_STRING, Buffer.from(uri, 'utf8')));
  return encodePem(PKCS11_URI_LABEL, body);
}

/**
 * Checks `pem` - a provider key file's contents - holds no key OpenSSL's own decoders would read into
 * the process: a Linux source names a key a provider holds, never a plain or encrypted PKCS#8 file.
 * @throws InvalidCertificateFileError it holds such a key, or no PEM block at all
 */
export function checkProviderKeyFile(pem: Buffer, path: string): void {
  const blocks = pemBlocks(pem, (problem) => new InvalidCertificateFileError(`'${path}': ${problem}`));
  if (blocks.length === 0) throw new InvalidCertificateFileError(`'${path}' holds no PEM key for a provider to decode.`);
  for (const block of blocks) {
    if (KEY_LABELS.has(block.label)) {
      throw new InvalidCertificateFileError(`'${path}' holds a ${block.label}, a key OpenSSL would read into the process: a Linux source's KeyUri `
        + 'names a key an OpenSSL provider holds (a TSS2 PRIVATE KEY, or a pkcs11: URI). Use a File source for a key file.');
    }
  }
}

/**
 * The provider's key object for `pem`, decoded by whichever loaded provider takes it.
 * @throws OpenSslProviderUnavailableError no loaded provider decodes it
 * @throws UnsupportedCertificateError the provider decoded it but couldn't give the key
 */
export function openProviderKey(provider: string, pem: Buffer): KeyObject {
  try {
    return createPrivateKey({ key: pem });
  } catch (error) {
    const code = (error as { code?: string }).code;
    const message = (error as Error).message;
    if (code === 'ERR_OSSL_UNSUPPORTED' || /DECODER routines::unsupported/.test(message)) {
      throw new OpenSslProviderUnavailableError(
        `No OpenSSL provider loaded into this Node decoded the key (${message}): either the '${provider}' provider isn't loaded, or it is `
        + "and couldn't open the key - a TPM or token it can't reach (its TCTI, module, token or PIN), or a key file that isn't one. Node "
        + `loads providers only from an OpenSSL configuration file at startup: start it with --openssl-config=<file> whose nodejs_conf section `
        + `activates the '${provider}' provider (and default), or with --openssl-shared-config and OPENSSL_CONF naming such a file. This `
        + `Node's OpenSSL is ${process.versions.openssl}${process.config.variables.node_shared_openssl ? ", the system's shared library" : ', built in'}.`,
        { cause: error });
    }
    throw new UnsupportedCertificateError(
      `The OpenSSL provider '${provider}' didn't give the key (${message}): check the key is there, that the provider is configured to reach `
      + 'it (its module, token, PIN or TCTI), and that it is the certificate\'s.', { cause: error });
  }
}

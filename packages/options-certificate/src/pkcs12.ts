// PKCS#12 files and encrypted PKCS#8 keys, read by the reader HkdfGuard's packages share
// (@runsecure/hkdfguard-abstractions/internal's `pkcs12`, which says what it reads and refuses), its
// refusals turned into this package's errors. Written there rather than given to Node's tls `pfx`
// option, which takes the password only as a string, reads the first key it finds, and can't say
// which certificate is the key's. Never exported from the package index.
import { wipe } from '@runsecure/hkdfguard-abstractions';
import { pkcs12 } from '@runsecure/hkdfguard-abstractions/internal';
import { InvalidCertificateFileError, UnsupportedCertificateError, WrongPasswordError } from './errors.js';

/** The largest PKCS#12 or key file read, in bytes: far beyond any certificate, chain or key. */
export const MAX_FILE_LENGTH = 4 * 1024 * 1024;

/** What a PKCS#12 file holds: its certificates' DER, in file order, and its private keys, each a PKCS#8 PrivateKeyInfo in a buffer {@link wipe} zeroes. */
export class Pkcs12Contents {
  readonly certificates: Buffer[] = [];
  readonly keys: Buffer[] = [];

  wipe(): void {
    for (const key of this.keys) wipe(key);
    this.keys.length = 0;
  }
}

/**
 * Reads a PKCS#12 file with a UTF-8 password - undefined for a file without one, which is tried as
 * both the empty password and no password, as tools write either.
 *
 * With a password, the file must carry its integrity MAC, and every private key in it must be
 * encrypted. RFC 7292 makes the MAC optional, but it is the only thing that ties the file to the
 * password: without one, a file holding a plaintext key and certificate - anyone's - reads under any
 * password at all. OpenSSL, keytool and Windows always write one unless told not to (-nomac). A
 * plaintext key is refused for the same reason as in a PEM key file: the password was named to
 * protect it, and it doesn't. Without a password - a file read under AllowUnprotectedPrivateKey -
 * neither is required: nothing is claimed to protect it.
 * @throws WrongPasswordError the file's MAC doesn't verify, or its contents don't decrypt
 * @throws InvalidCertificateFileError it isn't a PKCS#12 file; or, with a password, it has no MAC or
 *   holds a key that isn't encrypted
 * @throws UnsupportedCertificateError legacy RC2/RC4, PBMAC1, or public-key (enveloped or signed) contents
 */
export function decodePkcs12(data: Buffer, password: Uint8Array | undefined): Pkcs12Contents {
  const hasPassword = password !== undefined && password.length > 0;
  let read: pkcs12.Pkcs12Contents;
  try {
    read = pkcs12.readPkcs12(data, password, { requireIntegrity: hasPassword });
  } catch (error) {
    throw certificateError(error, 'The PKCS#12 file');
  }
  const contents = new Pkcs12Contents();
  for (const certificate of read.certificates) contents.certificates.push(certificate.der);
  for (const key of read.keys) contents.keys.push(key.der); // moved, not copied: contents.wipe() zeroes them
  return contents;
}

/**
 * Decrypts an EncryptedPrivateKeyInfo - an encrypted PKCS#8 PEM key's contents - with a UTF-8
 * password: its PrivateKeyInfo, in a new buffer the caller wipes.
 * @throws WrongPasswordError the password doesn't decrypt it to a key
 * @throws InvalidCertificateFileError it is malformed
 * @throws UnsupportedCertificateError it is encrypted with an algorithm this doesn't read
 */
export function decryptPkcs8(encrypted: Buffer, password: Uint8Array | undefined): Buffer {
  try {
    return pkcs12.decryptPrivateKeyInfo(encrypted, password);
  } catch (error) {
    throw certificateError(error, 'The encrypted private key');
  }
}

// The shared reader's refusal as this package's error, its message under `subject`.
function certificateError(error: unknown, subject: string): unknown {
  if (!(error instanceof pkcs12.Pkcs12Error)) return error;
  switch (error.kind) {
    case 'wrongPassword':
      return new WrongPasswordError(`${subject} ${error.message}`);
    case 'unsupported':
      return new UnsupportedCertificateError(`${subject} ${error.message}`);
    case 'unencryptedKey':
      return new InvalidCertificateFileError(`${subject} holds a private key that isn't encrypted, but File.PasswordSecretName names a password `
        + 'for it; export it with the key encrypted (not -keypbe NONE), or leave PasswordSecretName unset and set AllowUnprotectedPrivateKey.');
    case 'noMac':
    case 'malformed':
      return new InvalidCertificateFileError(`${subject} ${error.message}`);
  }
}

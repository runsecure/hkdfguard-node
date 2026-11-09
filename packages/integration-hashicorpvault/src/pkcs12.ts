// Password-protected PKCS#12 key stores (RFC 7292), read by the reader HkdfGuard's packages share
// (@runsecure/hkdfguard-abstractions/internal's `pkcs12`, which says what it reads and refuses):
// Node's TLS reads a PKCS#12 only as a whole client identity - the first key it finds, with a string
// passphrase - so it can neither pick a key by alias nor read a trust store of certificates only.
// Reads what OpenSSL 3 and Java's keytool write - PBES2 (PBKDF2, AES-CBC) or PKCS#12's own
// triple-DES PBE, under an HMAC - and refuses RC2 and RC4, which OpenSSL 3 left to its legacy
// provider. The HMAC is required, though RFC 7292 makes it optional: it is the only thing that ties
// a store to its password, and without it a trust store of anyone's CA in plain contents reads under
// any password. A private key must be encrypted, as the password was set to protect it. Never
// exported from the package index.
import { InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';
import { pkcs12 } from '@runsecure/hkdfguard-abstractions/internal';

/** The largest key store read, in bytes: a store of a key and its chain is a few KB. */
export const MAX_KEY_STORE_LENGTH = 1024 * 1024;

/** A private key in a key store: its PKCS#8 DER, which the caller zeroes, and its attributes. */
export interface Pkcs12Key {
  readonly friendlyName: string | undefined;
  readonly localKeyId: Buffer | undefined;
  readonly pkcs8: Buffer;
}

/** An X.509 certificate in a key store: its DER, and its attributes. */
export interface Pkcs12Certificate {
  readonly friendlyName: string | undefined;
  readonly localKeyId: Buffer | undefined;
  readonly der: Buffer;
}

/** What a key store holds. */
export interface Pkcs12Contents {
  readonly keys: Pkcs12Key[];
  readonly certificates: Pkcs12Certificate[];
}

/**
 * The keys (if `readKeys`) and certificates in the PKCS#12 store `store`, its integrity checked and
 * its contents decrypted under `password` - the password's UTF-8 bytes, which the caller zeroes.
 * Every buffer this makes from the password is zeroed before it returns.
 * @param what names the store in errors, e.g. "client key store 'client.p12'"
 * @throws InvalidArgumentError the store isn't a PKCS#12 store this can read, has no integrity MAC,
 *   holds a key (when `readKeys`) that isn't encrypted, or the password is wrong
 */
export function readPkcs12(store: Uint8Array, password: Uint8Array, readKeys: boolean, what: string): Pkcs12Contents {
  if (store.length > MAX_KEY_STORE_LENGTH) throw new InvalidArgumentError(`The ${what} is over ${MAX_KEY_STORE_LENGTH} bytes; a key store is far smaller.`);
  let read: pkcs12.Pkcs12Contents;
  try {
    read = pkcs12.readPkcs12(store, password, { requireIntegrity: true, readKeys, noun: 'store' });
  } catch (error) {
    if (error instanceof pkcs12.Pkcs12Error) throw new InvalidArgumentError(`The ${what} ${error.message}`);
    throw error;
  }
  return {
    // Moved, not copied: the caller zeroes each key.
    keys: read.keys.map((key) => ({ friendlyName: key.friendlyName, localKeyId: key.localKeyId, pkcs8: key.der })),
    certificates: read.certificates.map((certificate) => ({ ...certificate })),
  };
}

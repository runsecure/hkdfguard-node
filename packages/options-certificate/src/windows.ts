// The Windows certificate store, through the add-on: crypt32 opens a system store read-only and only
// if it exists and enumerates its certificates, and a chosen one's private key is acquired through CNG
// alone - CryptAcquireCertificatePrivateKey with CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG and
// CRYPT_ACQUIRE_SILENT_FLAG - as an NCrypt key handle every signature (NCryptSignHash) and decryption
// (NCryptDecrypt) goes through, on libuv's thread pool. The key is never exported. A key only a legacy
// CryptoAPI provider holds, or one that would need a dialog to open, is refused.
import { CertificateStoreError, NoPrivateKeyError, UnsupportedCertificateError } from './errors.js';
import { p1363ToDer, type HashAlgorithm } from './keys.js';
import { certificateAddon, isHandle, type CertificateAddon, type NativeHandle, type NativeStatusError } from './native.js';
import { StoreLocation, StoreName } from './options.js';
import type { StoreCertificate, StoreKey } from './store.js';

const CNG_HASHES: Partial<Record<HashAlgorithm, number>> = { sha1: 1, sha256: 256, sha384: 384, sha512: 512 };

/** The system store a StoreName opens: its own name, but CertificateAuthority, which is "CA". */
export function windowsStoreName(name: StoreName): string {
  return name === StoreName.certificateAuthority ? 'CA' : name;
}

/** Every certificate in the system store `name` at `location`, read-only. A store that doesn't exist, or can't be opened, reads as empty, as .NET's does. */
export function readWindowsStore(location: StoreLocation, name: StoreName): StoreCertificate[] {
  const addon = certificateAddon();
  let entries: ReturnType<NonNullable<CertificateAddon['windowsReadStore']>>;
  try {
    entries = addon.windowsReadStore!(location === StoreLocation.currentUser ? 1 : 2, windowsStoreName(name));
  } catch (error) {
    throw new CertificateStoreError(`Reading the ${location} ${name} certificate store failed: ${(error as Error).message}`,
      (error as NativeStatusError).status ?? -1, { cause: error });
  }
  return (entries ?? []).map((entry) => new WindowsCertificate(addon, entry.der, entry.hasPrivateKey, entry.handle));
}

class WindowsCertificate implements StoreCertificate {
  #handle: NativeHandle | undefined;

  constructor(private readonly addon: CertificateAddon, readonly der: Buffer, readonly hasPrivateKey: boolean, handle: NativeHandle) {
    this.#handle = handle;
  }

  openPrivateKey(): StoreKey {
    if (this.#handle === undefined) throw new UnsupportedCertificateError('The certificate has been closed.');
    const result = this.addon.windowsOpenKey!(this.#handle);
    if (isHandle(result)) return new NCryptKey(this.addon, result);
    if (result.error === 'not-cng') throw new UnsupportedCertificateError("Its private key isn't a CNG key: re-import it into a CNG key storage provider.");
    throw new NoPrivateKeyError(`Its private key can't be opened through CNG, silently (error 0x${(result.status >>> 0).toString(16).toUpperCase().padStart(8, '0')}): `
      + 'a key only a legacy CryptoAPI provider holds must be re-imported into a CNG key storage provider, and one that needs a dialog '
      + "can't be used by a service.");
  }

  close(): void {
    if (this.#handle !== undefined) this.addon.windowsFreeCertificate!(this.#handle);
    this.#handle = undefined;
  }
}

/** A CNG key, held by its NCrypt handle: every signature is an NCryptSignHash call and every decryption an NCryptDecrypt call. */
class NCryptKey implements StoreKey {
  #handle: NativeHandle | undefined;

  constructor(private readonly addon: CertificateAddon, handle: NativeHandle) {
    this.#handle = handle;
  }

  async signDigest(digest: Buffer, hash: HashAlgorithm, scheme: 'pkcs1' | 'pss' | 'ecdsa', saltLength: number): Promise<Buffer> {
    const handle = this.#open();
    const padding = scheme === 'ecdsa' ? 0 : scheme === 'pkcs1' ? 1 : 2;
    const signature = await call(() => this.addon.windowsSign!(handle, digest, cngHash(hash), padding, saltLength), 'sign');
    // CNG gives an ECDSA signature as r || s (IEEE P1363); X.509 and node:crypto's default take DER.
    return scheme === 'ecdsa' ? p1363ToDer(signature) : signature;
  }

  async decrypt(ciphertext: Buffer, scheme: 'pkcs1' | 'oaep', hash: HashAlgorithm, label: Buffer): Promise<Buffer> {
    const handle = this.#open();
    return call(() => this.addon.windowsDecrypt!(handle, ciphertext, scheme === 'oaep' ? 2 : 1, scheme === 'oaep' ? cngHash(hash) : 0, label), 'decrypt');
  }

  close(): void {
    if (this.#handle !== undefined) this.addon.releaseKey(this.#handle);
    this.#handle = undefined;
  }

  #open(): NativeHandle {
    if (this.#handle === undefined) throw new UnsupportedCertificateError('The key has been released.');
    return this.#handle;
  }
}

function cngHash(hash: HashAlgorithm): number {
  const value = CNG_HASHES[hash];
  if (value === undefined) throw new UnsupportedCertificateError(`A CNG key can't sign or decrypt with ${hash}: use SHA-1, SHA-256, SHA-384 or SHA-512.`);
  return value;
}

async function call(operation: () => Promise<Buffer>, what: string): Promise<Buffer> {
  try {
    return await operation();
  } catch (error) {
    const status = (error as NativeStatusError).status;
    if (status === undefined) throw error;
    throw new CertificateStoreError(`The Windows certificate store couldn't ${what}: ${(error as Error).message}`, status, { cause: error });
  }
}

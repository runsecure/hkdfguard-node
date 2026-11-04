// The macOS keychains, through the add-on and the Security framework: CurrentUser is the login
// keychain of the effective user (from the account database, never $HOME) and LocalMachine the System
// keychain, and the search is restricted to that one keychain. A certificate with its private key is
// an identity (kSecClassIdentity); its key stays in the keychain, and every signature is a
// SecKeyCreateSignature call and every decryption a SecKeyCreateDecryptedData call, on libuv's thread
// pool. Only My - the keychain itself - is a store here, as in the Go and Python ports.
//
// Not yet run on a Mac: HKDFGUARD_TEST_MACOS_KEYCHAIN=1 runs the keychain round trip there.
import { CertificateStoreError, NoPrivateKeyError, UnsupportedCertificateError } from './errors.js';
import { type HashAlgorithm } from './keys.js';
import { certificateAddon, isHandle, type CertificateAddon, type NativeHandle, type NativeStatusError } from './native.js';
import { StoreLocation, StoreName } from './options.js';
import type { StoreCertificate, StoreKey } from './store.js';

// The numbers native/hkdfguard_certificate.c's mac_algorithm maps to SecKeyAlgorithms.
const HASH_INDEX: Record<HashAlgorithm, number> = { sha1: 1, sha224: 2, sha256: 3, sha384: 4, sha512: 5 };
const RSA_PKCS1_SIGNATURE = 10;
const RSA_PSS_SIGNATURE = 20;
const ECDSA_SIGNATURE = 30;
const RSA_PKCS1_ENCRYPTION = 41;
const RSA_OAEP_ENCRYPTION = 50;

/** The identities and certificates of the keychain `location` names. Only My is a store on macOS; a keychain that doesn't exist reads as empty. */
export function readMacKeychain(location: StoreLocation, name: StoreName): StoreCertificate[] {
  if (name !== StoreName.my) throw new UnsupportedCertificateError(`Only the My store - the keychain itself - can be read on macOS, not ${name}.`);
  const addon = certificateAddon();
  let read: ReturnType<NonNullable<CertificateAddon['macReadKeychain']>>;
  try {
    read = addon.macReadKeychain!(location === StoreLocation.currentUser ? 1 : 2);
  } catch (error) {
    throw new CertificateStoreError(`Reading the ${location} keychain failed: ${(error as Error).message}`, (error as NativeStatusError).status ?? -1,
      { cause: error });
  }
  if (read === null) return [];
  const found: StoreCertificate[] = read.identities.map((identity) => new KeychainCertificate(addon, identity.der, identity.handle));
  for (const der of read.certificates) {
    if (!found.some((certificate) => certificate.der.equals(der))) found.push(new KeychainCertificate(addon, der, undefined));
  }
  return found;
}

class KeychainCertificate implements StoreCertificate {
  #identity: NativeHandle | undefined;
  readonly hasPrivateKey: boolean;

  constructor(private readonly addon: CertificateAddon, readonly der: Buffer, identity: NativeHandle | undefined) {
    this.#identity = identity;
    this.hasPrivateKey = identity !== undefined;
  }

  openPrivateKey(): StoreKey {
    if (this.#identity === undefined) throw new NoPrivateKeyError('The keychain holds no private key for it.');
    const result = this.addon.macOpenKey!(this.#identity);
    if (isHandle(result)) return new KeychainKey(this.addon, result);
    throw new NoPrivateKeyError(`The keychain won't give its private key: ${result.message}.`);
  }

  close(): void {
    if (this.#identity !== undefined) this.addon.macReleaseIdentity!(this.#identity);
    this.#identity = undefined;
  }
}

/** A SecKeyRef in the keychain. */
class KeychainKey implements StoreKey {
  #handle: NativeHandle | undefined;

  constructor(private readonly addon: CertificateAddon, handle: NativeHandle) {
    this.#handle = handle;
  }

  async signDigest(digest: Buffer, hash: HashAlgorithm, scheme: 'pkcs1' | 'pss' | 'ecdsa', saltLength: number): Promise<Buffer> {
    const handle = this.#open();
    if (scheme === 'pss' && saltLength !== digest.length) {
      // The Security framework's PSS salt is always the hash's length.
      throw new UnsupportedCertificateError('A keychain key signs PSS only with a salt the hash\'s length (RSA_PSS_SALTLEN_DIGEST).');
    }
    const base = scheme === 'ecdsa' ? ECDSA_SIGNATURE : scheme === 'pss' ? RSA_PSS_SIGNATURE : RSA_PKCS1_SIGNATURE;
    // An X9.62 ECDSA signature is DER already.
    return call(() => this.addon.macSign!(handle, digest, base + HASH_INDEX[hash]), 'sign');
  }

  async decrypt(ciphertext: Buffer, scheme: 'pkcs1' | 'oaep', hash: HashAlgorithm, label: Buffer): Promise<Buffer> {
    const handle = this.#open();
    if (scheme === 'oaep' && label.length > 0) throw new UnsupportedCertificateError('A keychain key decrypts OAEP only with an empty label.');
    return call(() => this.addon.macDecrypt!(handle, ciphertext, scheme === 'oaep' ? RSA_OAEP_ENCRYPTION + HASH_INDEX[hash] : RSA_PKCS1_ENCRYPTION), 'decrypt');
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

async function call(operation: () => Promise<Buffer>, what: string): Promise<Buffer> {
  try {
    return await operation();
  } catch (error) {
    const status = (error as NativeStatusError).status;
    if (status === undefined) throw error;
    if (status === -1) throw new UnsupportedCertificateError(`The keychain key can't ${what} this way: ${(error as Error).message}`, { cause: error });
    throw new CertificateStoreError(`The keychain couldn't ${what}: ${(error as Error).message}`, status, { cause: error });
  }
}

import type { HashAlgorithm } from './keys.js';
import type { StoreLocation, StoreName } from './options.js';

/**
 * A private key an operating system store holds: every operation is a call into the store, and the
 * key is never exported.
 */
export interface StoreKey {
  /**
   * Signs `digest`, the `hash` of the data: RSA with PKCS #1 v1.5 or PSS (MGF1 over `hash`,
   * `saltLength` bytes of salt), or ECDSA - whose signature is returned DER-encoded.
   */
  signDigest(digest: Buffer, hash: HashAlgorithm, scheme: 'pkcs1' | 'pss' | 'ecdsa', saltLength: number): Promise<Buffer>;
  /** Decrypts with an RSA key - PKCS #1 v1.5, or OAEP with MGF1 over `hash` and `label` - into a new buffer the caller wipes. */
  decrypt(ciphertext: Buffer, scheme: 'pkcs1' | 'oaep', hash: HashAlgorithm, label: Buffer): Promise<Buffer>;
  /** Releases the handle to the key, once no operation is in flight. */
  close(): void;
}

/** One certificate a store read gave, holding whatever handle reaches it until closed. */
export interface StoreCertificate {
  /** The certificate, DER-encoded. */
  readonly der: Buffer;
  /** Whether the store holds its private key. */
  readonly hasPrivateKey: boolean;
  /**
   * Opens the certificate's private key where the store keeps it; it is never exported.
   * @throws NoPrivateKeyError the store won't open it
   * @throws UnsupportedCertificateError it isn't a key this port can use
   */
  openPrivateKey(): StoreKey;
  /** Releases the handle to the certificate. */
  close(): void;
}

/**
 * Reads every certificate in a store, read-only; a store that doesn't exist reads as empty. The
 * loader's default reads Windows' certificate stores on Windows and the keychains on macOS; tests
 * pass their own.
 */
export type StoreReader = (location: StoreLocation, name: StoreName) => readonly StoreCertificate[] | Promise<readonly StoreCertificate[]>;

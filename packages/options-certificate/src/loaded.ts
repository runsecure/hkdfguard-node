import {
  constants, createCipheriv, createDecipheriv, createHash, createPrivateKey, privateDecrypt, randomBytes, sign, type KeyObject, type X509Certificate,
} from 'node:crypto';
import { createSecureContext, type SecureContext, type SecureContextOptions, type Server } from 'node:tls';
import { ClosedError, InvalidArgumentError, wipe } from '@runsecure/hkdfguard-abstractions';
import { NativeProviderRequiredError, NoPrivateKeyError, UnsupportedCertificateError } from './errors.js';
import {
  derToP1363, ecFieldLength, resolveDecryption, resolveSignature, type Decryption, type DecryptOptions, type HashAlgorithm, type Signature,
  type SignOptions,
} from './keys.js';
import { encodePem } from './pem.js';
import type { StoreKey } from './store.js';
import { describe, type ParsedCertificate } from './x509.js';

/** Where a certificate's private key is, and how each use of it reaches it. */
export interface KeySource {
  readonly description: string;
  /** Signs `data`; an ECDSA signature DER-encoded, whatever `signature.dsaEncoding` asks (the caller converts it). */
  sign(data: Uint8Array, signature: Signature): Promise<Buffer>;
  decrypt(ciphertext: Uint8Array, decryption: Decryption): Promise<Buffer>;
  /** The key as node:tls takes it - a PEM in a new buffer the caller wipes. */
  tlsKey(): Buffer;
  close(): void;
}

/**
 * A key a store holds: every use is a call into it, and it is never exported - so Node's TLS, which
 * takes a key only as PEM or through an OpenSSL provider, can't use it.
 */
export class StoreKeySource implements KeySource {
  constructor(private readonly key: StoreKey, readonly description: string) {}

  async sign(data: Uint8Array, signature: Signature): Promise<Buffer> {
    const digest = createHash(signature.hash).update(data).digest();
    return this.key.signDigest(digest, signature.hash, signature.scheme, signature.saltLength);
  }

  async decrypt(ciphertext: Uint8Array, decryption: Decryption): Promise<Buffer> {
    return this.key.decrypt(Buffer.from(ciphertext), decryption.scheme, decryption.hash, decryption.label);
  }

  tlsKey(): Buffer {
    throw new NativeProviderRequiredError(
      `The certificate's private key is held by ${this.description}, and Node's TLS takes a key only as PEM or through an OpenSSL provider; `
      + "the store's key is never exported to make one, and Node's OpenSSL has no provider for the store. Use sign() and decrypt(), which "
      + 'call the store, or a File or Linux source for TLS.');
  }

  close(): void {
    this.key.close();
  }
}

/**
 * A key read from a file, held sealed: its PKCS#8 encrypted with AES-256-GCM under a random key, both
 * in buffers wiped on close. Each use unseals it into a buffer wiped straight after - node:crypto
 * parses it into OpenSSL for the call, which frees (and cleanses) it when the call returns; a TLS
 * context is given it as a PEM buffer, wiped once the context is made.
 */
export class FileKeySource implements KeySource {
  readonly description: string;
  #key: Buffer;
  #iv: Buffer;
  #sealed: Buffer;
  #tag: Buffer;

  /** Seals `privateKeyInfo`; the caller still wipes it. */
  constructor(privateKeyInfo: Buffer, description = 'a key file') {
    this.description = description;
    this.#key = randomBytes(32);
    this.#iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.#key, this.#iv);
    const first = cipher.update(privateKeyInfo);
    const last = cipher.final();
    this.#sealed = Buffer.concat([first, last]); // ciphertext only
    this.#tag = cipher.getAuthTag();
  }

  #with<T>(use: (privateKeyInfo: Buffer) => T): T {
    if (this.#sealed.length === 0) throw new ClosedError('The certificate has been closed.');
    const decipher = createDecipheriv('aes-256-gcm', this.#key, this.#iv);
    decipher.setAuthTag(this.#tag);
    let first: Buffer | undefined;
    let last: Buffer | undefined;
    let plaintext: Buffer | undefined;
    try {
      first = decipher.update(this.#sealed);
      last = decipher.final();
      plaintext = Buffer.alloc(first.length + last.length);
      first.copy(plaintext, 0);
      last.copy(plaintext, first.length);
      return use(plaintext);
    } finally {
      wipe(first);
      wipe(last);
      wipe(plaintext);
    }
  }

  async sign(data: Uint8Array, signature: Signature): Promise<Buffer> {
    return this.#with((privateKeyInfo) => sign(signature.hash, data, {
      key: privateKeyInfo,
      format: 'der',
      type: 'pkcs8',
      ...signOptions(signature),
    }));
  }

  async decrypt(ciphertext: Uint8Array, decryption: Decryption): Promise<Buffer> {
    return this.#with((privateKeyInfo) => {
      try {
        // privateDecrypt's types don't take the DER key itself, as it does: parsed here as it would parse it.
        const key = createPrivateKey({ key: privateKeyInfo, format: 'der', type: 'pkcs8' });
        return privateDecrypt({ key, ...decryptOptions(decryption) }, ciphertext);
      } catch (error) {
        return decryptionRefused(error);
      }
    });
  }

  tlsKey(): Buffer {
    return this.#with((privateKeyInfo) => encodePem('PRIVATE KEY', privateKeyInfo));
  }

  close(): void {
    for (const buffer of [this.#key, this.#iv, this.#sealed, this.#tag]) wipe(buffer);
    this.#sealed = Buffer.alloc(0);
  }
}

/**
 * A key an OpenSSL provider holds - the TPM's, a token's - as the provider's own key object, through
 * which node:crypto signs and decrypts; and the PEM it was decoded from (a TSS2 key blob the TPM
 * alone can use, or a pkcs11: URI), which each TLS context decodes again.
 */
export class ProviderKeySource implements KeySource {
  readonly description: string;
  #key: KeyObject | undefined;
  #pem: Buffer;

  constructor(provider: string, key: KeyObject, pem: Buffer) {
    this.description = `the OpenSSL provider '${provider}'`;
    this.#key = key;
    this.#pem = pem;
  }

  #object(): KeyObject {
    if (this.#key === undefined) throw new ClosedError('The certificate has been closed.');
    return this.#key;
  }

  async sign(data: Uint8Array, signature: Signature): Promise<Buffer> {
    return sign(signature.hash, data, { key: this.#object(), ...signOptions(signature) });
  }

  async decrypt(ciphertext: Uint8Array, decryption: Decryption): Promise<Buffer> {
    try {
      return privateDecrypt({ key: this.#object(), ...decryptOptions(decryption) }, ciphertext);
    } catch (error) {
      return decryptionRefused(error);
    }
  }

  tlsKey(): Buffer {
    this.#object();
    return Buffer.from(this.#pem);
  }

  close(): void {
    // The key object is the provider's, freed when it is collected: it holds a handle, not the key.
    this.#key = undefined;
    wipe(this.#pem); // a URI may carry a pin-value
  }
}

// An ECDSA signature is always asked of node:crypto as DER, and made IEEE P1363 here when that is
// wanted: Node's own conversion reads the curve from a legacy EC_KEY, which a provider's key isn't -
// it crashes the process (SIGSEGV, Node 22 with pkcs11-provider).
function signOptions(signature: Signature): { padding?: number; saltLength?: number } {
  if (signature.scheme === 'ecdsa') return {};
  if (signature.scheme === 'pkcs1') return { padding: constants.RSA_PKCS1_PADDING };
  return { padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: signature.saltLength };
}

function decryptOptions(decryption: Decryption): { padding: number; oaepHash?: string; oaepLabel?: Buffer } {
  if (decryption.scheme === 'pkcs1') return { padding: constants.RSA_PKCS1_PADDING };
  return { padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: decryption.hash, oaepLabel: decryption.label };
}

// Options a caller can't give createSecureContext: the certificate's own, which it sets.
const RESERVED_TLS_OPTIONS = ['key', 'cert', 'pfx', 'passphrase', 'privateKeyEngine', 'privateKeyIdentifier'] as const;

/**
 * An opened certificate: {@link certificate}, the chain its source gave with it, and - when it came
 * with its private key - the way to that key, which stays where its source keeps it:
 *
 * - a Windows store's key in CNG and a macOS keychain's in the keychain: {@link sign} and
 *   {@link decrypt} are calls into the store, and {@link createSecureContext} refuses
 *   (NativeProviderRequiredError), since Node's TLS can't reach a store's key;
 * - an OpenSSL provider's key in the provider: sign, decrypt and createSecureContext all go through it;
 * - a key file's key sealed in memory, under a random key - both wiped by {@link close}.
 *
 * Close it to release the store's handles and wipe what is held; every use of the key after that
 * throws ClosedError, and close waits for uses in flight.
 */
export class LoadedCertificate {
  readonly #leaf: ParsedCertificate;
  readonly #chain: readonly ParsedCertificate[];
  #key: KeySource | undefined;
  readonly #releases: { close(): void }[];
  #inFlight = 0;
  #idle: (() => void)[] = [];
  #closed = false;

  /** @internal Made by CertificateOptionsLoader. */
  constructor(certificates: readonly ParsedCertificate[], key: KeySource | undefined, releases: { close(): void }[] = []) {
    this.#leaf = certificates[0]!;
    this.#chain = certificates.slice(1);
    this.#key = key;
    this.#releases = releases;
  }

  /** The certificate itself. */
  get certificate(): X509Certificate {
    return this.#leaf.x509;
  }

  /** The other certificates its source gave with it - a PKCS#12 or PEM file's after the certificate itself, in file order; none from a store. */
  get chain(): readonly X509Certificate[] {
    return this.#chain.map((certificate) => certificate.x509);
  }

  /** The certificate's subject, as .NET renders it: "CN=api.example.com, O=Contoso". */
  get subject(): string {
    return describe(this.#leaf);
  }

  /** The start of the certificate's validity period. */
  get notBefore(): Date {
    return new Date(this.#leaf.notBefore);
  }

  /** The end of the certificate's validity period. */
  get notAfter(): Date {
    return new Date(this.#leaf.notAfter);
  }

  /** The certificate's public key. */
  get publicKey(): KeyObject {
    return this.#leaf.x509.publicKey;
  }

  /** Whether it came with its private key. */
  get hasPrivateKey(): boolean {
    return this.#key !== undefined;
  }

  /** Where its private key is, as messages name it ("the Windows certificate store", "a key file", ...); undefined without one. */
  get keyLocation(): string | undefined {
    return this.#key?.description;
  }

  /** Whether {@link close} has been called. */
  get closed(): boolean {
    return this.#closed;
  }

  /**
   * Signs `data`, hashed with `algorithm`, with the private key - as crypto.sign(algorithm, data, key)
   * does: an RSA key with PKCS #1 v1.5 (the default) or PSS, an ECDSA key giving DER (the default) or
   * IEEE P1363. See {@link SignOptions}.
   * @throws NoPrivateKeyError it came without one
   * @throws UnsupportedCertificateError the key's source can't sign this way (SHA-224 with CNG, a PSS salt the keychain can't make...)
   * @throws CertificateStoreError the store's call failed
   * @throws ClosedError it has been closed
   */
  async sign(algorithm: HashAlgorithm, data: Uint8Array, options?: SignOptions): Promise<Buffer> {
    if (!(data instanceof Uint8Array)) throw new InvalidArgumentError('data must be a Uint8Array.');
    const signature = resolveSignature(algorithm, options, this.publicKey);
    return this.#use(async (key) => {
      // Every source gives an ECDSA signature DER-encoded; IEEE P1363 is made from it here.
      const result = await key.sign(data, signature);
      return signature.scheme === 'ecdsa' && signature.dsaEncoding === 'ieee-p1363' ? derToP1363(result, ecFieldLength(this.publicKey)) : result;
    });
  }

  /**
   * Decrypts `ciphertext` with the RSA private key - as crypto.privateDecrypt does, OAEP by default.
   * See {@link DecryptOptions}. A new buffer the caller wipes once used.
   * @throws NoPrivateKeyError it came without one
   * @throws UnsupportedCertificateError not an RSA key, or a source that can't decrypt this way
   * @throws CertificateStoreError the store's call failed (as a ciphertext that isn't one does)
   * @throws ClosedError it has been closed
   */
  async decrypt(ciphertext: Uint8Array, options?: DecryptOptions): Promise<Buffer> {
    if (!(ciphertext instanceof Uint8Array)) throw new InvalidArgumentError('ciphertext must be a Uint8Array.');
    const decryption = resolveDecryption(options, this.publicKey);
    return this.#use((key) => key.decrypt(ciphertext, decryption));
  }

  /**
   * A new TLS secure context, from node:tls's createSecureContext(options) - for tls.connect's or a
   * TLSSocket's `secureContext`, or what a server's SNICallback gives:
   *
   * - with the private key, presenting this certificate and its chain;
   * - without it (RequirePrivateKey false), trusting this certificate and its chain alone (`ca`), in
   *   place of the system's roots - for a client that pins its server's CA, say.
   *
   * A server's default context isn't one of these: tls.createServer, https.createServer and
   * http2.createSecureServer ignore a `secureContext` option. Give a server this certificate with
   * {@link configureServer}.
   *
   * `options` may set anything but the certificate's own key, cert, pfx and passphrase (and, without a
   * key, ca). The context holds its own copy of the key, in OpenSSL, from then on: it outlives close().
   * A provider key is decoded again for each context - reuse a context rather than make one per connection.
   * @throws NativeProviderRequiredError the key is a Windows or macOS store's
   * @throws ClosedError it has been closed
   */
  createSecureContext(options: SecureContextOptions = {}): SecureContext {
    if (this.#key === undefined) {
      const { chain } = this.#tlsOptions(options);
      if (options.ca !== undefined) throw new InvalidArgumentError("createSecureContext sets ca itself for a certificate without its key; it can't be given.");
      return createSecureContext({ ...options, ca: chain });
    }
    return this.#withTlsKey(options, (full) => createSecureContext(full));
  }

  /**
   * Makes `server` - a tls.Server, or an https or http2 secure server, which are ones - present this
   * certificate and its chain, through its setSecureContext(options): the context every connection
   * gets unless an SNICallback gives another. `options` are the rest of the context's options
   * (minVersion, ciphers, ca and requestCert's trust...), as for {@link createSecureContext}.
   *
   * The key reaches node:tls as a PEM in a buffer of this certificate's own, wiped once the context
   * is made; the server keeps that (wiped) buffer as its `key` property, and the context its own copy
   * of the key in OpenSSL, which outlives close(). Call it again - after a renewal, say - to replace
   * the context; connections already open keep theirs.
   * @throws NoPrivateKeyError it came without its private key
   * @throws NativeProviderRequiredError the key is a Windows or macOS store's
   * @throws ClosedError it has been closed
   */
  configureServer(server: Server, options: SecureContextOptions = {}): void {
    if (server === null || typeof server !== 'object' || typeof (server as { setSecureContext?: unknown }).setSecureContext !== 'function') {
      throw new InvalidArgumentError('server must be a tls.Server (or an https or http2 secure server).');
    }
    if (this.#key === undefined) {
      this.#tlsOptions(options);
      throw new NoPrivateKeyError('The certificate came without its private key: a server needs it to present the certificate.');
    }
    this.#withTlsKey(options, (full) => server.setSecureContext(full));
  }

  // The certificate and chain as PEM, once `options` are checked to leave them to this certificate.
  #tlsOptions(options: SecureContextOptions): { chain: Buffer } {
    for (const name of RESERVED_TLS_OPTIONS) {
      if (options[name] !== undefined) throw new InvalidArgumentError(`The certificate sets ${name} itself; it can't be given.`);
    }
    if (this.#closed) throw new ClosedError('The certificate has been closed.');
    return { chain: Buffer.concat([this.#leaf, ...this.#chain].map((certificate) => encodePem('CERTIFICATE', certificate.der))) };
  }

  // Hands `use` the options with this certificate's key and chain, and wipes the key once it returns.
  #withTlsKey<T>(options: SecureContextOptions, use: (options: SecureContextOptions) => T): T {
    const { chain } = this.#tlsOptions(options);
    const key = this.#key!.tlsKey();
    try {
      return use({ ...options, key, cert: chain });
    } finally {
      wipe(key);
    }
  }

  async #use<T>(operation: (key: KeySource) => Promise<T>): Promise<T> {
    if (this.#closed) throw new ClosedError('The certificate has been closed.');
    const key = this.#key;
    if (key === undefined) throw new NoPrivateKeyError('The certificate came without its private key.');
    this.#inFlight++;
    try {
      return await operation(key);
    } finally {
      if (--this.#inFlight === 0) for (const resolve of this.#idle.splice(0)) resolve();
    }
  }

  /**
   * Waits for uses of the key in flight, then wipes a key file's key and releases a store's handles.
   * Safe to call more than once; every call resolves once the release is done.
   */
  async close(): Promise<void> {
    if (!this.#closed) {
      this.#closed = true;
      if (this.#inFlight > 0) await new Promise<void>((resolve) => this.#idle.push(resolve));
      try {
        this.#key?.close();
      } finally {
        for (const release of this.#releases) release.close();
      }
      return;
    }
    if (this.#inFlight > 0) await new Promise<void>((resolve) => this.#idle.push(resolve));
  }

  /** The subject and whether it came with a key; never anything of the key itself. */
  toString(): string {
    return `LoadedCertificate(subject='${this.subject}', hasPrivateKey=${this.hasPrivateKey})`;
  }
}

/**
 * privateDecrypt's refusal of PKCS #1 v1.5 for a key whose OpenSSL can't do it with implicit rejection
 * (CVE-2023-46809) - a provider key, or an OpenSSL before 3.2 - as UnsupportedCertificateError; any
 * other error as it is.
 */
function decryptionRefused(error: unknown): never {
  if (/RSA_PKCS1_PADDING is no longer supported/.test((error as Error).message)) {
    throw new UnsupportedCertificateError("Node refuses RSA PKCS #1 v1.5 decryption with this key: it can't do it with implicit rejection, "
      + "the defence against Bleichenbacher's attack (CVE-2023-46809). Decrypt with OAEP.", { cause: error });
  }
  throw error;
}

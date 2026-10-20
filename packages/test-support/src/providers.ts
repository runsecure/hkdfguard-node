import { createCipheriv, createDecipheriv, randomBytes, randomFillSync } from 'node:crypto';
import {
  AuthenticationFailedError, ClosedError, RefreshFailurePolicy, wipe,
  type CryptoProvider, type CryptoProviderFactory, type CryptoProviderOptions, type DataEncryptionKey, type KeyWrapper,
} from '@runsecure/hkdfguard-abstractions';

/**
 * A minimal, real AES-256-GCM CryptoProvider with no refresh machinery - so the dek and cache
 * packages are tested against working crypto without depending on a cipher package. Records closes.
 */
export class TestProvider implements CryptoProvider {
  readonly key = randomBytes(32);
  closes = 0;
  closeError: unknown;
  /** Extra bytes encryptedAllocationLength over-allocates, to test trimming. */
  overAllocate = 0;

  encrypt(plaintext: Uint8Array, result: Uint8Array, aad?: Uint8Array): number {
    try {
      if (this.closes > 0) throw new ClosedError();
      const nonce = randomFillSync(new Uint8Array(12));
      const cipher = createCipheriv('aes-256-gcm', this.key, nonce);
      if (aad) cipher.setAAD(aad);
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      result.set(nonce, 0);
      result.set(ciphertext, 12);
      result.set(cipher.getAuthTag(), 12 + ciphertext.length);
      return plaintext.length + 28;
    } finally {
      wipe(plaintext);
    }
  }

  decrypt(ciphertext: Uint8Array, result: Uint8Array, aad?: Uint8Array): number {
    if (this.closes > 0) throw new ClosedError();
    const length = ciphertext.length - 28;
    const decipher = createDecipheriv('aes-256-gcm', this.key, ciphertext.subarray(0, 12));
    decipher.setAuthTag(ciphertext.subarray(12 + length));
    if (aad) decipher.setAAD(aad);
    const plaintext = decipher.update(ciphertext.subarray(12, 12 + length));
    try {
      decipher.final();
    } catch (error) {
      throw new AuthenticationFailedError(undefined, { cause: error });
    }
    if (result.length < length) throw new RangeError('result too small');
    result.set(plaintext);
    return length;
  }

  encryptedAllocationLength(n: number): number {
    return n + 28 + this.overAllocate;
  }

  decryptedAllocationLength(n: number): number {
    return Math.max(0, n - 28);
  }

  async close(): Promise<void> {
    this.closes++;
    if (this.closeError !== undefined) throw this.closeError;
  }
}

/** A DataEncryptionKey over a TestProvider, recording the AAD of every call. */
export class RecordingKey implements DataEncryptionKey {
  readonly provider = new TestProvider();
  readonly encryptAads: Uint8Array[] = [];
  readonly decryptAads: Uint8Array[] = [];

  encrypt(plaintext: Uint8Array, aad?: Uint8Array): Uint8Array {
    this.encryptAads.push(Uint8Array.from(aad ?? []));
    const result = new Uint8Array(plaintext.length + 28);
    this.provider.encrypt(plaintext, result, aad);
    return result;
  }

  decrypt(ciphertext: Uint8Array, result: Uint8Array, aad?: Uint8Array): number {
    this.decryptAads.push(Uint8Array.from(aad ?? []));
    return this.provider.decrypt(ciphertext, result, aad);
  }

  close(): Promise<void> {
    return this.provider.close();
  }
}

/** A CryptoProviderFactory creating TestProviders, recording what it was asked for. */
export class RecordingFactory implements CryptoProviderFactory {
  readonly created: TestProvider[] = [];
  readonly wrapped: Uint8Array[] = [];
  readonly options: CryptoProviderOptions[] = [];
  ephemerals = 0;
  failNext: unknown;
  /** Called inside createEphemeral, before it resolves. */
  onCreate: (() => void) | undefined;

  async create(_wrapper: KeyWrapper, wrapped: Uint8Array, options: CryptoProviderOptions): Promise<CryptoProvider> {
    options.signal?.throwIfAborted();
    this.wrapped.push(wrapped);
    return this.#record(options);
  }

  async createEphemeral(_wrapper: KeyWrapper, options: CryptoProviderOptions): Promise<CryptoProvider> {
    options.signal?.throwIfAborted();
    this.ephemerals++;
    this.onCreate?.();
    return this.#record(options);
  }

  #record(options: CryptoProviderOptions): TestProvider {
    if (this.failNext !== undefined) {
      const error = this.failNext;
      this.failNext = undefined;
      throw error;
    }
    const provider = new TestProvider();
    this.created.push(provider);
    this.options.push({ ...options, refreshFailurePolicy: options.refreshFailurePolicy ?? RefreshFailurePolicy.default });
    return provider;
  }
}

import type { CryptoProvider, DataEncryptionKey as DataEncryptionKeyContract } from '@runsecure/hkdfguard-abstractions';
import { AttributeNames, HkdfGuardTelemetry, SpanNames } from '@runsecure/hkdfguard-diagnostics';

/**
 * A data encryption key backed by a {@link CryptoProvider}, which owns the key material - how it is
 * revealed and refreshed - and performs the AEAD. This class sizes the output through the provider,
 * trims it to exactly what was written, and records telemetry. It owns its provider: close() closes
 * it, stopping any background refresh and zeroing its key.
 */
export class DataEncryptionKey implements DataEncryptionKeyContract {
  #closed = false;

  constructor(private readonly provider: CryptoProvider) {}

  /** Encrypts `plaintext` bound to `aad`, returning the ciphertext. `plaintext` is zeroed. */
  encrypt(plaintext: Uint8Array, aad?: Uint8Array): Uint8Array {
    const telemetry = HkdfGuardTelemetry.dataProtection;
    return telemetry.withSpan(SpanNames.dataProtection.keyWrappedKeyEncrypt, (span) => {
      telemetry.logSensitiveOperation(span, SpanNames.dataProtection.keyWrappedKeyEncrypt, {
        [AttributeNames.plaintextLength]: plaintext.length, [AttributeNames.aadLength]: aad?.length ?? 0,
      });
      const buffer = new Uint8Array(this.provider.encryptedAllocationLength(plaintext.length));
      const written = this.provider.encrypt(plaintext, buffer, aad);
      // Providers that size exactly (AES-GCM) need no trim; others may over-allocate.
      return written === buffer.length ? buffer : buffer.slice(0, written);
    });
  }

  /** Decrypts `ciphertext` encrypted with the same `aad` into `result`, returning the bytes written. */
  decrypt(ciphertext: Uint8Array, result: Uint8Array, aad?: Uint8Array): number {
    const telemetry = HkdfGuardTelemetry.dataProtection;
    return telemetry.withSpan(SpanNames.dataProtection.keyWrappedKeyDecrypt, (span) => {
      telemetry.logSensitiveOperation(span, SpanNames.dataProtection.keyWrappedKeyDecrypt, {
        [AttributeNames.ciphertextLength]: ciphertext.length, [AttributeNames.aadLength]: aad?.length ?? 0,
      });
      return this.provider.decrypt(ciphertext, result, aad);
    });
  }

  /** Closes the provider. Safe to call more than once; only the first call reaches it. */
  async close(): Promise<void> {
    if (!this.#closed) {
      this.#closed = true;
      await this.provider.close();
    }
  }
}

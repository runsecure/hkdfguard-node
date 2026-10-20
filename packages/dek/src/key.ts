import {
  EncryptionLimitReachedError, wipe, type CryptoProvider, type DataEncryptionKey as DataEncryptionKeyContract,
} from '@runsecure/hkdfguard-abstractions';
import { AttributeNames, HkdfGuardTelemetry, SpanNames } from '@runsecure/hkdfguard-diagnostics';

/**
 * A wall-clock point after which a key stops encrypting, and an earlier one from which that is
 * announced. Decryption is never limited. buildKeyRing gives every key-file key one, from the
 * file's age, so a key file that is never rotated stops encrypting rather than encrypting without
 * bound: the per-process encryption budget can't see earlier runs of the process.
 */
export interface EncryptionDeadline {
  /** Epoch milliseconds from which {@link onWarning} is called, once. */
  warnAt: number;
  /** Epoch milliseconds from which encrypt throws EncryptionLimitReachedError. */
  refuseAt: number;
  /** The EncryptionLimitReachedError message. */
  reason: string;
  /** Called once, the first time the deadline is checked at or after warnAt but before refuseAt. */
  onWarning?: () => void;
  /** Called once, the first time the deadline is checked at or after refuseAt. */
  onExpired?: () => void;
}

/**
 * A data encryption key backed by a {@link CryptoProvider}, which owns the key material - how it is
 * revealed and refreshed - and performs the AEAD. This class sizes the output through the provider,
 * trims it to exactly what was written, and records telemetry. It owns its provider: close() closes
 * it, stopping any background refresh and zeroing its key.
 */
export class DataEncryptionKey implements DataEncryptionKeyContract {
  #closed = false;
  #warned = false;
  #expired = false;

  /** @param deadline When this key stops encrypting; it encrypts without a time limit when omitted. */
  constructor(private readonly provider: CryptoProvider, readonly deadline?: EncryptionDeadline) {}

  /**
   * Encrypts `plaintext` bound to `aad`, returning the ciphertext. `plaintext` is zeroed.
   * @throws EncryptionLimitReachedError the key has passed its deadline; it must be rotated, and decryption still works.
   */
  encrypt(plaintext: Uint8Array, aad?: Uint8Array): Uint8Array {
    const telemetry = HkdfGuardTelemetry.dataProtection;
    return telemetry.withSpan(SpanNames.dataProtection.keyWrappedKeyEncrypt, (span) => {
      telemetry.logSensitiveOperation(span, SpanNames.dataProtection.keyWrappedKeyEncrypt, {
        [AttributeNames.plaintextLength]: plaintext.length, [AttributeNames.aadLength]: aad?.length ?? 0,
      });
      if (this.checkDeadline()) {
        wipe(plaintext); // the provider never sees it, so honor the contract here
        throw new EncryptionLimitReachedError(this.deadline!.reason);
      }
      const buffer = new Uint8Array(this.provider.encryptedAllocationLength(plaintext.length));
      const written = this.provider.encrypt(plaintext, buffer, aad);
      // Providers that size exactly (AES-GCM) need no trim; others may over-allocate.
      return written === buffer.length ? buffer : buffer.slice(0, written);
    });
  }

  /**
   * Checks the deadline against the clock, announcing a warning or expiry the first time each is
   * reached; returns whether this key has stopped encrypting. A throwing callback is ignored, so a
   * faulty logger never decides whether a value is encrypted. @internal Also called by buildKeyRing,
   * so a current key file nearing or past its age is reported at startup.
   */
  checkDeadline(now = Date.now()): boolean {
    const deadline = this.deadline;
    if (deadline === undefined) return false;
    if (now >= deadline.refuseAt) {
      if (!this.#expired) {
        this.#expired = this.#warned = true;
        try { deadline.onExpired?.(); } catch { /* see above */ }
      }
      return true;
    }
    if (now >= deadline.warnAt && !this.#warned) {
      this.#warned = true;
      try { deadline.onWarning?.(); } catch { /* see above */ }
    }
    return false;
  }

  /** Decrypts `ciphertext` encrypted with the same `aad` into `result`, returning the bytes written. Never limited by the deadline. */
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

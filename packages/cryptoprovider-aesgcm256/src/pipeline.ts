import { randomFillSync } from 'node:crypto';
import {
  ClosedError, configurationAad, InvalidArgumentError, KeyNotFoundError, wipe,
  type EncryptedFormatProvider, type PipelineDataProtector,
} from '@runsecure/hkdfguard-abstractions';
import { AttributeNames, HkdfGuardTelemetry, SpanNames } from '@runsecure/hkdfguard-diagnostics';
import { AesGcmSession, EncryptionBudget, KEY_SIZE, OVERHEAD } from './session.js';

const encoder = new TextEncoder();

/**
 * The AES-256-GCM {@link PipelineDataProtector}: generates a random 32-byte key in memory and uses
 * it for its whole life - no key wrapper, no key ring, no refresh. Each value is bound to its secret
 * identifier (the configuration key it will be stored under) and stamped with the key version.
 * close() zeroes the key and its base64 form; every later operation throws ClosedError.
 */
export class AesGcmPipelineDataProtector implements PipelineDataProtector {
  readonly #session: AesGcmSession;
  readonly #key: Uint8Array;
  #base64: Uint8Array | undefined;
  #closed = false;

  /**
   * @param formatProvider Formats and parses the protected values - e.g. the dek package's DefaultFormatProvider.
   * @param keyVersion The version stamped on every value - the version this key will be registered under once wrapped.
   */
  constructor(
    private readonly formatProvider: EncryptedFormatProvider,
    readonly keyVersion: number,
    /** @internal Tests supply their own key and budget. */
    internals: { key?: Uint8Array; budget?: EncryptionBudget } = {},
  ) {
    if (formatProvider === undefined || formatProvider === null) {
      throw new InvalidArgumentError('A format provider is required.');
    }
    this.#key = internals.key ?? randomFillSync(new Uint8Array(KEY_SIZE));
    this.#session = new AesGcmSession(this.#key, internals.budget ?? new EncryptionBudget());
  }

  /** Encryptions performed under this key so far. */
  get encryptionCount(): number {
    return this.#session.budget.count;
  }

  /** The key, base64-encoded as ASCII bytes: encoded once, into a buffer zeroed on close. */
  keyBase64(): Uint8Array {
    this.#requireOpen();
    this.#base64 ??= encoder.encode(Buffer.from(this.#key.buffer, this.#key.byteOffset, this.#key.byteLength).toString('base64'));
    return this.#base64;
  }

  encrypt(plaintext: Uint8Array | string, secretIdentifier: string): string {
    const telemetry = HkdfGuardTelemetry.dataProtection;
    return telemetry.withSpan(SpanNames.dataProtection.protectorEncrypt, (span) => {
      telemetry.logSensitiveOperation(span, SpanNames.dataProtection.protectorEncrypt, {
        [AttributeNames.name]: secretIdentifier, [AttributeNames.plaintextLength]: plaintext.length,
      });
      this.#requireOpen();
      const aad = configurationAad(secretIdentifier);

      // The session zeroes what it encrypts; the caller's plaintext is theirs to keep.
      const scratch = typeof plaintext === 'string' ? encoder.encode(plaintext) : Uint8Array.from(plaintext);
      try {
        const ciphertext = new Uint8Array(scratch.length + OVERHEAD);
        this.#session.encrypt(scratch, ciphertext, aad);
        return this.formatProvider.format({ keyVersion: this.keyVersion, value: ciphertext });
      } finally {
        wipe(scratch);
      }
    });
  }

  /**
   * @throws KeyNotFoundError the value names a different key version.
   * @throws AuthenticationFailedError the value was encrypted for a different identifier, or altered.
   */
  decrypt(encrypted: string, secretIdentifier: string, result: Uint8Array): number {
    const telemetry = HkdfGuardTelemetry.dataProtection;
    return telemetry.withSpan(SpanNames.dataProtection.protectorDecrypt, (span) => {
      telemetry.logSensitiveOperation(span, SpanNames.dataProtection.protectorDecrypt, {
        [AttributeNames.name]: secretIdentifier, [AttributeNames.encryptedLength]: encrypted.length,
      });
      this.#requireOpen();
      const aad = configurationAad(secretIdentifier);
      const value = this.formatProvider.parse(encrypted);
      if (value.keyVersion !== this.keyVersion) {
        throw new KeyNotFoundError(`No key is registered for version ${value.keyVersion}.`);
      }
      return this.#session.decrypt(value.value, result, aad);
    });
  }

  maxDecryptedLength(encrypted: string): number {
    return this.formatProvider.maxDecryptedLength(encrypted);
  }

  /** Zeroes the key and its base64 form. Safe to call more than once. */
  close(): void {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this.#session.close();
    wipe(this.#base64);
  }

  #requireOpen(): void {
    if (this.#closed) {
      throw new ClosedError('This pipeline data protector has been closed.');
    }
  }
}

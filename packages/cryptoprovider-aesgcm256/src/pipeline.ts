import { randomFillSync } from 'node:crypto';
import { Transform, type Writable } from 'node:stream';
import {
  ClosedError, configurationAad, InvalidArgumentError, KeyNotFoundError, wipe,
  type EncryptedFormatProvider, type PipelineDataProtector,
} from '@runsecure/hkdfguard-abstractions';
import { isWritable, writeChunks } from '@runsecure/hkdfguard-abstractions/internal';
import { AttributeNames, HkdfGuardTelemetry, SpanNames } from '@runsecure/hkdfguard-diagnostics';
import { AesGcmSession, EncryptionBudget, KEY_SIZE, OVERHEAD } from './session.js';

const encoder = new TextEncoder();

// What pipelineForTests hands the next constructor call: a key and budget of the test's own.
let pendingInternals: { key?: Uint8Array; budget?: EncryptionBudget } | undefined;

/**
 * Tests only: a pipeline protector over a given key and budget. Exported from this module for the
 * package's own tests, never from the package index - the exports map keeps it out of reach.
 */
export function pipelineForTests(formatProvider: EncryptedFormatProvider, keyVersion: number,
  internals: { key?: Uint8Array; budget?: EncryptionBudget }): AesGcmPipelineDataProtector {
  pendingInternals = internals;
  try {
    return new AesGcmPipelineDataProtector(formatProvider, keyVersion);
  } finally {
    pendingInternals = undefined;
  }
}

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
  ) {
    // Set only by pipelineForTests, for the length of this synchronous constructor call.
    const internals = pendingInternals ?? {};
    pendingInternals = undefined;
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

  /**
   * The key, base64-encoded as ASCII bytes: encoded once, into a buffer zeroed on close. Encoded
   * byte to byte, so the key never exists as a string, which could not be zeroed.
   */
  keyBase64(): Uint8Array {
    this.#requireOpen();
    this.#base64 ??= base64Bytes(this.#key);
    return this.#base64;
  }

  /**
   * Writes the key to `destination` as the wrap tool's `--dek-stdin` reads it: its base64 form as
   * ASCII, no line ending. Encoded straight from the key into a Buffer of its own - never through a
   * string, nor the buffer {@link keyBase64} returns - which is zeroed once the stream is done with
   * it: its write called back, or the stream closed. An abort destroys `destination` first, so no
   * more of the key is written, and still zeroes the buffer only once the stream lets go of it.
   * Resolves once the stream has accepted the bytes; `destination` is left open. See
   * PipelineDataProtector.writeDek.
   * @throws TypeError (rejecting) destination isn't a Writable, or is a Transform (a PassThrough among
   *   them), which hands the very buffer it is given to its reader, so zeroing it would zero what the
   *   reader gets
   * @throws ClosedError (rejecting) the protector has been closed; nothing is written
   * @throws HkdfGuardError (rejecting; ERR_HKDFGUARD_INVALID_STATE) destination has already ended or been destroyed
   */
  async writeDek(destination: Writable, signal?: AbortSignal): Promise<void> {
    if (!isWritable(destination)) throw new TypeError('destination must be a Writable stream.');
    if (destination instanceof Transform) {
      throw new TypeError("destination is a Transform (such as a PassThrough), which hands the key's buffer to its reader as it is: "
        + 'it would read zeros once the buffer is zeroed. Write to the process\'s stdin, a socket or a file stream.');
    }
    this.#requireOpen();
    signal?.throwIfAborted();

    const encoded = base64Bytes(this.#key);
    const ascii = Buffer.from(encoded.buffer, encoded.byteOffset, encoded.length);
    // Zeroed by writeChunks, exactly once, when the stream is done with it - never sooner.
    await writeChunks(destination, [ascii], signal, wipe);
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

/** The ASCII code of the standard-base64 digit for `v` (0-63), computed without branches or a table indexed by secret bits. */
function base64Digit(v: number): number {
  let c = v + 65; //              0-25 -> 'A'-'Z'
  c += ((25 - v) >> 8) & 6; //    26-51 -> 'a'-'z'
  c -= ((51 - v) >> 8) & 75; //   52-61 -> '0'-'9'
  c -= ((61 - v) >> 8) & 15; //   62 -> '+'
  c += ((62 - v) >> 8) & 3; //    63 -> '/'
  return c;
}

/**
 * `data` as padded standard base64, written straight into a new byte buffer - never through a
 * string - in time that depends only on its length. @internal Exported for tests.
 */
export function base64Bytes(data: Uint8Array): Uint8Array {
  const out = new Uint8Array(Math.ceil(data.length / 3) * 4);
  let o = 0;
  let i = 0;
  for (; i + 3 <= data.length; i += 3) {
    const n = (data[i]! << 16) | (data[i + 1]! << 8) | data[i + 2]!;
    out[o++] = base64Digit((n >> 18) & 63);
    out[o++] = base64Digit((n >> 12) & 63);
    out[o++] = base64Digit((n >> 6) & 63);
    out[o++] = base64Digit(n & 63);
  }
  const remaining = data.length - i;
  if (remaining > 0) {
    const n = (data[i]! << 16) | (remaining === 2 ? data[i + 1]! << 8 : 0);
    out[o++] = base64Digit((n >> 18) & 63);
    out[o++] = base64Digit((n >> 12) & 63);
    out[o++] = remaining === 2 ? base64Digit((n >> 6) & 63) : 0x3d;
    out[o++] = 0x3d;
  }
  return out;
}

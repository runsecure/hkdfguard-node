import { HkdfGuardError, InvalidArgumentError, type EncryptedFormatProvider, type KeyTrackingValue } from '@runsecure/hkdfguard-abstractions';
import { AttributeNames, HkdfGuardTelemetry, SpanNames } from '@runsecure/hkdfguard-diagnostics';

/** The longest formatted value, in characters, unless configured otherwise - room for about 3 KB of UTF-8 plaintext. */
export const DEFAULT_MAX_ENCRYPTED_LENGTH = 4096;

/** A stored value that isn't in the enc::v<version>::<base64> form, or is over the length limit. */
export class InvalidFormatError extends HkdfGuardError {
  constructor(message: string) {
    super('ERR_HKDFGUARD_INVALID_FORMAT', message);
  }
}

const MALFORMED = "Invalid encrypted format. Expected 'enc::v<version>::<base64>'.";
const INT32_MIN = -(2 ** 31);
const INT32_MAX = 2 ** 31 - 1;

/**
 * The enc::v<version>::<base64> wire format, identical across ports. Formatted values are capped at
 * {@link maxEncryptedLength} characters: parse rejects anything longer before decoding it, so
 * oversized input can't force a large allocation ahead of any cryptographic check, and format
 * refuses to produce a value parse would then reject.
 */
export class DefaultFormatProvider implements EncryptedFormatProvider {
  /** @param maxEncryptedLength The longest formatted value, in characters; positive. */
  constructor(readonly maxEncryptedLength = DEFAULT_MAX_ENCRYPTED_LENGTH) {
    if (!Number.isInteger(maxEncryptedLength) || maxEncryptedLength <= 0) {
      throw new InvalidArgumentError(`The maximum encrypted length must be a positive integer, got ${maxEncryptedLength}.`);
    }
  }

  format(value: KeyTrackingValue): string {
    const telemetry = HkdfGuardTelemetry.dataProtection;
    return telemetry.withSpan(SpanNames.dataProtection.formatProviderFormat, (span) => {
      telemetry.logSensitiveOperation(span, SpanNames.dataProtection.formatProviderFormat, {
        [AttributeNames.keyVersion]: value.keyVersion, [AttributeNames.valueLength]: value.value.length,
      });
      const formatted = `enc::v${value.keyVersion}::${Buffer.from(value.value.buffer, value.value.byteOffset, value.value.byteLength).toString('base64')}`;
      if (formatted.length > this.maxEncryptedLength) {
        throw new InvalidFormatError(`The formatted value would be ${formatted.length} characters, over the ${this.maxEncryptedLength}-character limit.`);
      }
      return formatted;
    });
  }

  parse(encrypted: string): KeyTrackingValue {
    const telemetry = HkdfGuardTelemetry.dataProtection;
    return telemetry.withSpan(SpanNames.dataProtection.formatProviderParse, (span) => {
      telemetry.logSensitiveOperation(span, SpanNames.dataProtection.formatProviderParse, { [AttributeNames.encryptedLength]: encrypted.length });
      const { version, payload } = this.#segments(encrypted);
      if (decodedLength(payload) === undefined) throw new InvalidFormatError('Encrypted value is not valid base64.');
      return { keyVersion: version, value: new Uint8Array(Buffer.from(payload, 'base64')) };
    });
  }

  /** The decoded payload's length - an upper bound on the plaintext - without decoding it. */
  maxDecryptedLength(encrypted: string): number {
    const telemetry = HkdfGuardTelemetry.dataProtection;
    return telemetry.withSpan(SpanNames.dataProtection.formatProviderGetMaxDecryptedLength, (span) => {
      telemetry.logSensitiveOperation(span, SpanNames.dataProtection.formatProviderGetMaxDecryptedLength, { [AttributeNames.encryptedLength]: encrypted.length });
      const length = decodedLength(this.#segments(encrypted).payload);
      if (length === undefined) throw new InvalidFormatError('Encrypted value is not valid base64.');
      return length;
    });
  }

  // Only the canonical form format writes, shared by parse and maxDecryptedLength so both agree.
  #segments(encrypted: string): { version: number; payload: string } {
    if (encrypted.length > this.maxEncryptedLength) {
      throw new InvalidFormatError(`Encrypted value is ${encrypted.length} characters, over the ${this.maxEncryptedLength}-character limit.`);
    }
    const first = encrypted.indexOf('::');
    const second = first < 0 ? -1 : encrypted.indexOf('::', first + 2);
    if (second < 0 || encrypted.slice(0, first) !== 'enc') throw new InvalidFormatError(MALFORMED);
    const versionSegment = encrypted.slice(first + 2, second);
    const payload = encrypted.slice(second + 2);
    // ASCII digits with an optional leading '-', within the 32-bit range every port shares.
    if (!/^v-?[0-9]+$/.test(versionSegment)) throw new InvalidFormatError(MALFORMED);
    const version = Number(versionSegment.slice(1));
    if (!Number.isSafeInteger(version) || version < INT32_MIN || version > INT32_MAX) throw new InvalidFormatError(MALFORMED);
    // Node's decoder skips whitespace and invalid characters; both are refused here instead.
    if (/[ \t\r\n]/.test(payload)) throw new InvalidFormatError(MALFORMED);
    return { version, payload };
  }
}

/** Validates padded standard base64 by its characters alone and returns its decoded length, or undefined. */
function decodedLength(s: string): number | undefined {
  if (s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return undefined;
  const padding = s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0;
  return (s.length / 4) * 3 - padding;
}

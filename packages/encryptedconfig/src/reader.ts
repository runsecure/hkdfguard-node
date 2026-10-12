import { configurationPurpose, type DataProtector, type ProtectedReadOnlyCache } from '@runsecure/hkdfguard-abstractions';
import { AttributeNames, HkdfGuardTelemetry, SpanNames } from '@runsecure/hkdfguard-diagnostics';

/**
 * The value stored under a configuration key, or undefined if there is none. Keys are the
 * identifiers the pipeline encrypted under - full configuration paths such as
 * "ConnectionStrings:Admin".
 */
export type Lookup = (key: string) => string | undefined;

/** Creates the DataProtector for a purpose - satisfied by the dek package's KeyRing. */
export interface ProtectorFactory {
  createProtector(name: string): DataProtector;
}

/**
 * Decrypts protected configuration values: looks a value up by its configuration key and decrypts it
 * with the protector for that key's purpose, so a value moved to any other key fails authentication.
 * It holds no plaintext and caches nothing - each decrypt looks the value up fresh, so a
 * configuration reload takes effect immediately. As a ProtectedReadOnlyCache it can sit in a
 * ProtectedCacheCollection beside other secret sources.
 */
export class EncryptedConfigurationReader implements ProtectedReadOnlyCache {
  constructor(
    private readonly protectors: ProtectorFactory,
    private readonly lookup: Lookup,
  ) {}

  /**
   * Decrypts the value under configuration key `name` into `result`, resolving to the bytes written,
   * or 0 if there is no value. A value written for another key fails with AuthenticationFailedError;
   * one that isn't a protected value fails to parse. Size `result` with maxDecryptedLength.
   */
  async decrypt(name: string, result: Uint8Array, signal?: AbortSignal): Promise<number> {
    signal?.throwIfAborted();
    const telemetry = HkdfGuardTelemetry.encryptedConfiguration;
    return telemetry.withSpan(SpanNames.encryptedConfiguration.decrypt, (span) => {
      telemetry.logSensitiveOperation(span, SpanNames.encryptedConfiguration.decrypt, { [AttributeNames.name]: name });
      const value = this.lookup(name);
      return value === undefined ? 0 : this.#protectorFor(name).decrypt(value, result);
    });
  }

  /** An upper bound on how many bytes decrypt writes for `name`, or undefined if there is no value. */
  async maxDecryptedLength(name: string, signal?: AbortSignal): Promise<number | undefined> {
    signal?.throwIfAborted();
    const value = this.lookup(name);
    return value === undefined ? undefined : this.#protectorFor(name).maxDecryptedLength(value);
  }

  // Bound to this one key, so a value copied in from another key fails its tag check.
  #protectorFor(name: string): DataProtector {
    return this.protectors.createProtector(configurationPurpose(name));
  }
}

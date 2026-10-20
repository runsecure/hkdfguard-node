/**
 * Span (operation) names, grouped per component - lowercase, dot-separated (OpenTelemetry
 * semantic-convention style: `hkdfguard.<component>.<operation>`). The values are identical to the
 * .NET and Go ports', so every port reports the same span names.
 */
export const SpanNames = {
  cache: {
    add: 'hkdfguard.cache.add',
    addOrUpdate: 'hkdfguard.cache.add_or_update',
    decrypt: 'hkdfguard.cache.decrypt',
  },
  dataProtection: {
    protectorEncrypt: 'hkdfguard.data_protection.protector.encrypt',
    protectorDecrypt: 'hkdfguard.data_protection.protector.decrypt',
    keyWrappedKeyEncrypt: 'hkdfguard.data_protection.key_wrapped_key.encrypt',
    keyWrappedKeyDecrypt: 'hkdfguard.data_protection.key_wrapped_key.decrypt',
    ephemeralKeyInitialize: 'hkdfguard.data_protection.ephemeral_key.initialize',
    keyRingAdd: 'hkdfguard.data_protection.key_ring.add',
    keyRingGet: 'hkdfguard.data_protection.key_ring.get',
    keyRingGetCurrent: 'hkdfguard.data_protection.key_ring.get_current',
    keyRingRotateEphemeral: 'hkdfguard.data_protection.key_ring.rotate_ephemeral',
    formatProviderFormat: 'hkdfguard.data_protection.format.format',
    formatProviderParse: 'hkdfguard.data_protection.format.parse',
    formatProviderGetMaxDecryptedLength: 'hkdfguard.data_protection.format.get_max_decrypted_length',
  },
  cryptoProviderAesGcm256: {
    encrypt: 'hkdfguard.crypto_provider_aes_gcm256.encrypt',
    decrypt: 'hkdfguard.crypto_provider_aes_gcm256.decrypt',
    backgroundRefresh: 'hkdfguard.crypto_provider_aes_gcm256.background_refresh',
  },
  encryptedConfiguration: {
    decrypt: 'hkdfguard.encrypted_configuration.decrypt',
  },
} as const;

/**
 * Attribute keys shared across every component's spans, events, metrics, and log entries -
 * identical to the other ports'.
 */
export const AttributeNames = {
  name: 'hkdfguard.name',
  plaintextLength: 'hkdfguard.plaintext_length',
  ciphertextLength: 'hkdfguard.ciphertext_length',
  encryptedLength: 'hkdfguard.encrypted_length',
  aadLength: 'hkdfguard.aad_length',
  valueLength: 'hkdfguard.value_length',
  keyVersion: 'hkdfguard.key_version',
  keyRingBecameCurrent: 'hkdfguard.key_ring.became_current',
  operationName: 'hkdfguard.operation.name',
  result: 'hkdfguard.result',
  encryptionCount: 'hkdfguard.encryption_count',
  encryptionLimit: 'hkdfguard.encryption_limit',
  consecutiveFailures: 'hkdfguard.consecutive_failures',
} as const;

/** Values for {@link AttributeNames.result}. */
export const Results = {
  success: 'success',
  error: 'error',
} as const;

/**
 * Fixed span event names. Unlike the operation-specific span names, an event's own name stays
 * constant whichever operation raised it - the operation is carried as the
 * {@link AttributeNames.operationName} attribute - so event names stay low-cardinality and stable
 * for dashboards and queries.
 */
export const EventNames = {
  sensitiveOperation: 'hkdfguard.sensitive_operation',

  /**
   * Raised once, on the encrypt span that crosses a key's encryption-count warning threshold -
   * carries {@link AttributeNames.encryptionCount} and {@link AttributeNames.encryptionLimit}.
   */
  encryptionBudgetWarning: 'hkdfguard.encryption_budget_warning',

  /**
   * Raised on the background-refresh span whose failure reached the configured consecutive-failure
   * limit: the provider has zeroed its key and suspended encrypt/decrypt until a refresh succeeds.
   * Carries {@link AttributeNames.consecutiveFailures}.
   */
  keyAccessSuspended: 'hkdfguard.key_access_suspended',
} as const;

/** Metric instrument names, following the same `hkdfguard.<component>.<noun>` convention. */
export const MetricNames = {
  cacheOperations: 'hkdfguard.cache.operations',
} as const;

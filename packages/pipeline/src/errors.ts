import { HkdfGuardError } from '@runsecure/hkdfguard-abstractions';

/**
 * A pull found no value for one or more of the secrets named - .NET's KeyNotFoundException from
 * PullSecretsAsync: a secret that doesn't exist, has no such key, or whose value there is empty or
 * isn't a value. Every other secret was kept, and can still be written. Names every secret missing,
 * in the order they were named; never a value.
 */
export class SecretsNotFoundError extends HkdfGuardError {
  /** Every secret name missing, as it was given, key and all. */
  readonly secretNames: readonly string[];

  constructor(secretNames: readonly string[]) {
    super('ERR_HKDFGUARD_SECRETS_NOT_FOUND', `The secret store holds no value for: ${secretNames.join(', ')}.`);
    this.secretNames = Object.freeze([...secretNames]);
  }
}

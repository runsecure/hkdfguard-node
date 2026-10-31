import { HkdfGuardError } from '@runsecure/hkdfguard-abstractions';

/**
 * A secret, or a secret store's response holding one, can't be trusted as it was read: a body that
 * isn't the JSON expected, is too large, or holds more than one value, or a secret's JSON object
 * naming a key twice - .NET's InvalidDataException and Java's InvalidSecretDataException for
 * secrets. Its message says where, never what: no part of a secret is ever quoted, nor is any error
 * chained as its cause that could. It passes through a fetch unchanged, like any other failure.
 */
export class InvalidSecretDataError extends HkdfGuardError {
  constructor(message: string) {
    super('ERR_HKDFGUARD_INVALID_SECRET_DATA', message);
  }
}

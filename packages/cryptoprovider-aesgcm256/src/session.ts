import { createCipheriv, createDecipheriv, createHmac, randomBytes, randomFillSync } from 'node:crypto';
import {
  AuthenticationFailedError, ClosedError, EncryptionLimitReachedError, InvalidArgumentError, isZero, wipe,
} from '@runsecure/hkdfguard-abstractions';
import { AttributeNames, EventNames, HkdfGuardLog, HkdfGuardTelemetry, SpanNames, type Logger } from '@runsecure/hkdfguard-diagnostics';

/** The AES-256 key length, in bytes. */
export const KEY_SIZE = 32;
/** The random nonce prepended to every ciphertext. */
export const NONCE_SIZE = 12;
/** The GCM tag appended to every ciphertext. */
export const TAG_SIZE = 16;
/** How many bytes longer a ciphertext is than its plaintext: [nonce | ciphertext | tag]. */
export const OVERHEAD = NONCE_SIZE + TAG_SIZE;

/**
 * Encryptions after which a key refuses to encrypt (decryption keeps working): half of NIST SP
 * 800-38D's 2^32 random-nonce limit, since a per-process counter can't see the other processes
 * sharing the same key file. Counted per key, across every provider in the process, and only for
 * this process's life: a key that outlives it (a key file) needs a bound of its own, which the dek
 * package's buildKeyRing applies as a maximum key-file age (keyFileMaxAgeDays).
 */
export const MAX_ENCRYPTIONS_PER_KEY = 2 ** 31;
/** Encryptions after which a warning is raised, once - one eighth of the limit. */
export const ENCRYPTION_WARNING_THRESHOLD = 2 ** 28;

/**
 * Counts how many times one AES-256-GCM key has encrypted. With random 96-bit nonces, past 2^32
 * encryptions the chance of a repeated nonce - which breaks confidentiality and integrity for
 * everything under the key - is no longer negligible.
 */
export class EncryptionBudget {
  #count = 0;

  constructor(
    readonly warningThreshold = ENCRYPTION_WARNING_THRESHOLD,
    readonly limit = MAX_ENCRYPTIONS_PER_KEY,
  ) {
    if (!(limit >= 1)) {
      throw new InvalidArgumentError(`The encryption limit must be positive, got ${limit}.`);
    }
    if (!(warningThreshold >= 1 && warningThreshold <= limit)) {
      throw new InvalidArgumentError(`The warning threshold must be between 1 and the limit, got ${warningThreshold}.`);
    }
  }

  /** Encryptions performed so far under this key. */
  get count(): number {
    return this.#count;
  }

  /**
   * Reserves one encryption, returning true exactly once - for the reservation that reaches the
   * warning threshold.
   *
   * @throws EncryptionLimitReachedError the limit has been reached.
   */
  consume(): boolean {
    if (this.#count >= this.limit) {
      throw new EncryptionLimitReachedError(
        `This key has reached its AES-GCM encryption limit of ${this.limit} and must be rotated; decryption still works.`);
    }
    this.#count++;
    return this.#count === this.warningThreshold;
  }
}

// Budgets by key, for the life of the process. Indexed by an HMAC under a key generated for this
// process, never by the DEK or a plain hash of it - a plain hash would be the same in every process
// and on every machine, a stable fingerprint of the key sitting in memory.
const registryKey = randomBytes(32);
const budgetsByKey = new Map<string, EncryptionBudget>();

/** The budget shared by every provider in this process that reveals `key`. */
export function budgetFor(key: Uint8Array): EncryptionBudget {
  const id = createHmac('sha256', registryKey).update(key).digest('hex');
  let budget = budgetsByKey.get(id);
  if (budget === undefined) {
    budget = new EncryptionBudget();
    budgetsByKey.set(id, budget);
  }
  return budget;
}

// Set by AesGcmSession's static block.
let keyOf: (session: AesGcmSession) => Uint8Array;

/** Tests only: a session's key buffer, to check it is zeroed. Never exported from the package index. */
export function sessionKeyForTests(session: AesGcmSession): Uint8Array {
  return keyOf(session);
}

/**
 * An AES-256-GCM cipher bound to one 32-byte key, held until it is closed - by a provider until its
 * next refresh, or by a pipeline protector for its whole life. Ciphertext is
 * [12-byte random nonce | ciphertext | 16-byte tag], identical to the other ports.
 *
 * Node's OpenSSL bindings copy the key into each cipher context they create, and free it when the
 * context is collected: those copies can't be zeroed. The key buffer this session holds is.
 */
export class AesGcmSession {
  #key: Uint8Array;
  #closed = false;

  /** Takes ownership of `key`, which close() zeroes. */
  constructor(
    key: Uint8Array,
    readonly budget: EncryptionBudget,
    private readonly logger?: Logger,
  ) {
    if (key.length !== KEY_SIZE) {
      throw new InvalidArgumentError(`An AES-256 key must be exactly ${KEY_SIZE} bytes, got ${key.length}.`);
    }
    if (isZero(key)) {
      throw new InvalidArgumentError('An AES key must not be all zero.');
    }
    this.#key = key;
  }

  get closed(): boolean {
    return this.#closed;
  }

  static {
    keyOf = (session) => session.#key;
  }

  /**
   * Encrypts `plaintext` into `result` as [nonce | ciphertext | tag], returning the bytes written.
   * `plaintext` is zeroed on success and on every failure.
   */
  encrypt(plaintext: Uint8Array, result: Uint8Array, aad?: Uint8Array): number {
    const telemetry = HkdfGuardTelemetry.cryptoProviderAesGcm256;
    try {
      return telemetry.withSpan(SpanNames.cryptoProviderAesGcm256.encrypt, (span) => {
        telemetry.logSensitiveOperation(span, SpanNames.cryptoProviderAesGcm256.encrypt, {
          [AttributeNames.plaintextLength]: plaintext.length, [AttributeNames.aadLength]: aad?.length ?? 0,
        });
        this.#requireOpen();

        const needed = plaintext.length + OVERHEAD;
        if (result.length < needed) {
          throw new InvalidArgumentError(`The result buffer holds ${result.length} bytes; encrypting ${plaintext.length} bytes needs ${needed}.`);
        }

        if (this.budget.consume()) {
          span.addEvent(EventNames.encryptionBudgetWarning, {
            [AttributeNames.encryptionCount]: this.budget.count, [AttributeNames.encryptionLimit]: this.budget.limit,
          });
          // A span event alone is lost without a tracer provider; the log is not.
          HkdfGuardLog.encryptionBudgetWarning(this.logger, this.budget.count, this.budget.limit);
        }

        const nonce = result.subarray(0, NONCE_SIZE);
        randomFillSync(nonce);
        const cipher = createCipheriv('aes-256-gcm', this.#key, nonce, { authTagLength: TAG_SIZE });
        if (aad !== undefined) {
          cipher.setAAD(aad);
        }
        const ciphertext = cipher.update(plaintext);
        result.set(ciphertext, NONCE_SIZE);
        result.set(cipher.final(), NONCE_SIZE + ciphertext.length);
        result.set(cipher.getAuthTag(), NONCE_SIZE + plaintext.length);
        return needed;
      });
    } finally {
      wipe(plaintext);
    }
  }

  /**
   * Decrypts and authenticates `ciphertext` into `result`, returning the bytes written. Nothing is
   * written to `result` unless the tag verifies.
   *
   * @throws AuthenticationFailedError the ciphertext was altered, or the key or AAD differ.
   */
  decrypt(ciphertext: Uint8Array, result: Uint8Array, aad?: Uint8Array): number {
    const telemetry = HkdfGuardTelemetry.cryptoProviderAesGcm256;
    return telemetry.withSpan(SpanNames.cryptoProviderAesGcm256.decrypt, (span) => {
      telemetry.logSensitiveOperation(span, SpanNames.cryptoProviderAesGcm256.decrypt, {
        [AttributeNames.ciphertextLength]: ciphertext.length, [AttributeNames.aadLength]: aad?.length ?? 0,
      });
      this.#requireOpen();

      if (ciphertext.length < OVERHEAD) {
        throw new InvalidArgumentError(`A ciphertext of ${ciphertext.length} bytes is shorter than the ${OVERHEAD}-byte nonce and tag.`);
      }
      const plaintextLength = ciphertext.length - OVERHEAD;
      if (result.length < plaintextLength) {
        throw new InvalidArgumentError(`The result buffer holds ${result.length} bytes; this ciphertext decrypts to ${plaintextLength}.`);
      }

      const decipher = createDecipheriv('aes-256-gcm', this.#key, ciphertext.subarray(0, NONCE_SIZE), { authTagLength: TAG_SIZE });
      decipher.setAuthTag(ciphertext.subarray(NONCE_SIZE + plaintextLength));
      if (aad !== undefined) {
        decipher.setAAD(aad);
      }
      // update() returns plaintext before the tag is checked; it reaches result only after final()
      // has authenticated it, and the intermediate copy is always zeroed.
      const plaintext = decipher.update(ciphertext.subarray(NONCE_SIZE, NONCE_SIZE + plaintextLength));
      try {
        try {
          decipher.final();
        } catch (error) {
          throw new AuthenticationFailedError(undefined, { cause: error });
        }
        result.set(plaintext);
        return plaintextLength;
      } finally {
        wipe(plaintext);
      }
    });
  }

  /** Zeroes the key. Safe to call more than once. */
  close(): void {
    if (!this.#closed) {
      this.#closed = true;
      wipe(this.#key);
    }
  }

  #requireOpen(): void {
    if (this.#closed) {
      throw new ClosedError('This AES-GCM session has been closed.');
    }
  }
}

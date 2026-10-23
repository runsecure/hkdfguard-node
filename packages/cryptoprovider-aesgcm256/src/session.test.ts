import { strict as assert } from 'node:assert';
import { createDecipheriv, randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import { AuthenticationFailedError, ClosedError, EncryptionLimitReachedError, InvalidArgumentError, isZero } from '@runsecure/hkdfguard-abstractions';
import { HkdfGuardTelemetry } from '@runsecure/hkdfguard-diagnostics';
import { useSpanRecorder } from '@runsecure/hkdfguard-test-support';
import { AesGcmSession, budgetFor, EncryptionBudget, OVERHEAD, sessionKeyForTests } from './session.js';

const utf8 = (s: string) => new TextEncoder().encode(s);
const newSession = (key = new Uint8Array(randomBytes(32))) => new AesGcmSession(key, new EncryptionBudget());

function encrypt(session: AesGcmSession, plaintext: string, aad?: Uint8Array): Uint8Array {
  const result = new Uint8Array(utf8(plaintext).length + OVERHEAD);
  assert.equal(session.encrypt(utf8(plaintext), result, aad), result.length);
  return result;
}

function decrypt(session: AesGcmSession, ciphertext: Uint8Array, aad?: Uint8Array): string {
  const result = new Uint8Array(ciphertext.length - OVERHEAD);
  return new TextDecoder().decode(result.subarray(0, session.decrypt(ciphertext, result, aad)));
}

describe('AesGcmSession', () => {
  it('round-trips with and without AAD', () => {
    const session = newSession();
    assert.equal(decrypt(session, encrypt(session, 'hello')), 'hello');
    assert.equal(decrypt(session, encrypt(session, 'héllo ✓', utf8('purpose')), utf8('purpose')), 'héllo ✓');
  });

  it('writes [nonce | ciphertext | tag], decryptable by standard AES-GCM - the layout every port shares', () => {
    const key = new Uint8Array(randomBytes(32));
    const ciphertext = encrypt(newSession(Uint8Array.from(key)), 'interop', utf8('aad'));
    const decipher = createDecipheriv('aes-256-gcm', key, ciphertext.subarray(0, 12));
    decipher.setAAD(utf8('aad'));
    decipher.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
    const plaintext = Buffer.concat([decipher.update(ciphertext.subarray(12, ciphertext.length - 16)), decipher.final()]);
    assert.equal(plaintext.toString(), 'interop');
  });

  it('refuses wrong AAD or tampered ciphertext, writing nothing to the result', () => {
    const session = newSession();
    const ciphertext = encrypt(session, 'hello', utf8('right'));
    const tampered = Uint8Array.from(ciphertext);
    tampered[12]! ^= 0xff;
    for (const [bytes, aad] of [[ciphertext, utf8('wrong')], [tampered, utf8('right')]] as const) {
      const result = new Uint8Array(5).fill(0xab);
      assert.throws(() => session.decrypt(bytes, result, aad), AuthenticationFailedError);
      assert.deepEqual(result, new Uint8Array(5).fill(0xab));
    }
  });

  it('refuses bad lengths', () => {
    const session = newSession();
    const ciphertext = encrypt(session, 'hello');
    assert.throws(() => session.encrypt(utf8('hello'), new Uint8Array(5 + OVERHEAD - 1)), InvalidArgumentError);
    assert.throws(() => session.decrypt(new Uint8Array(OVERHEAD - 1), new Uint8Array(4)), InvalidArgumentError);
    assert.throws(() => session.decrypt(ciphertext, new Uint8Array(4)), InvalidArgumentError);
  });

  it('refuses a bad key', () => {
    for (const key of [new Uint8Array(16), new Uint8Array(33), new Uint8Array(32)]) {
      assert.throws(() => newSession(key), InvalidArgumentError);
    }
  });

  it('encrypts an empty plaintext to an authenticated empty message', () => {
    const session = newSession();
    const ciphertext = encrypt(session, '', utf8('aad'));
    assert.equal(ciphertext.length, OVERHEAD);
    assert.equal(session.decrypt(ciphertext, new Uint8Array(0), utf8('aad')), 0);
    assert.throws(() => session.decrypt(ciphertext, new Uint8Array(0), utf8('other')), AuthenticationFailedError);
  });

  it('zeroes the plaintext on success and on failure', () => {
    const session = newSession();
    const ok = utf8('secret');
    session.encrypt(ok, new Uint8Array(64));
    const failed = utf8('secret');
    assert.throws(() => session.encrypt(failed, new Uint8Array(1)));
    assert.ok(isZero(ok) && isZero(failed));
  });

  it('close zeroes the key, and later operations throw ClosedError', () => {
    const session = newSession();
    const ciphertext = encrypt(session, 'x');
    session.close();
    session.close();
    assert.ok(isZero(sessionKeyForTests(session)));
    const plaintext = utf8('still here');
    assert.throws(() => session.encrypt(plaintext, new Uint8Array(64)), ClosedError);
    assert.ok(isZero(plaintext), 'Encrypt zeroes its plaintext even when closed');
    assert.throws(() => session.decrypt(ciphertext, new Uint8Array(4)), ClosedError);
  });

  it('uses a fresh nonce every time', () => {
    const session = newSession();
    const nonces = new Set<string>();
    for (let i = 0; i < 2000; i++) {
      nonces.add(Buffer.from(encrypt(session, 'x').subarray(0, 12)).toString('hex'));
    }
    assert.equal(nonces.size, 2000);
  });

  it('still round-trips with sensitive logging and a tracer', async () => {
    const recorder = useSpanRecorder();
    const telemetry = HkdfGuardTelemetry.cryptoProviderAesGcm256;
    telemetry.enableSensitiveLogging = true;
    try {
      const session = newSession();
      assert.equal(decrypt(session, encrypt(session, 'hello')), 'hello');
      assert.ok(recorder.spans().some((s) => s.events.length > 0));
    } finally {
      telemetry.enableSensitiveLogging = false;
      await recorder.dispose();
    }
  });
});

describe('EncryptionBudget', () => {
  it('defaults to half and an eighth of the NIST limit', () => {
    const budget = new EncryptionBudget();
    assert.equal(budget.limit, 2 ** 31);
    assert.equal(budget.warningThreshold, 2 ** 28);
  });

  it('warns exactly once, at the threshold', () => {
    const budget = new EncryptionBudget(3, 10);
    assert.deepEqual(Array.from({ length: 6 }, () => budget.consume()), [false, false, true, false, false, false]);
  });

  it('refuses past the limit, leaving the count at the limit', () => {
    const budget = new EncryptionBudget(1, 2);
    budget.consume();
    budget.consume();
    assert.throws(() => budget.consume(), EncryptionLimitReachedError);
    assert.equal(budget.count, 2);
  });

  it('refuses an invalid threshold or limit', () => {
    for (const [threshold, limit] of [[0, 10], [11, 10], [1, 0]] as const) {
      assert.throws(() => new EncryptionBudget(threshold, limit), InvalidArgumentError);
    }
  });

  it('is shared per key through the registry', () => {
    const key = new Uint8Array(randomBytes(32));
    assert.equal(budgetFor(key), budgetFor(Uint8Array.from(key)));
    assert.notEqual(budgetFor(key), budgetFor(new Uint8Array(randomBytes(32))));
  });
});

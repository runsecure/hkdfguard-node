import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  AuthenticationFailedError, ClosedError, EncryptionLimitReachedError, InvalidArgumentError, InvalidConfigurationKeyError, isZero,
  KeyNotFoundError, type EncryptedFormatProvider,
} from '@runsecure/hkdfguard-abstractions';
import { TestFormatProvider } from '@runsecure/hkdfguard-test-support';
import { AesGcmPipelineDataProtector, base64Bytes } from './pipeline.js';
import { EncryptionBudget } from './session.js';

const id = 'Pipeline:Secret';
const newPipeline = () => new AesGcmPipelineDataProtector(new TestFormatProvider(), 42);

function decrypt(p: AesGcmPipelineDataProtector, formatted: string, identifier: string): string {
  const result = new Uint8Array(p.maxDecryptedLength(formatted));
  return new TextDecoder().decode(result.subarray(0, p.decrypt(formatted, identifier, result)));
}

describe('AesGcmPipelineDataProtector', () => {
  it('round-trips strings and bytes', () => {
    const p = newPipeline();
    for (const plaintext of ['hello', 'héllo wörld ✓ 🔐', '']) {
      assert.equal(decrypt(p, p.encrypt(plaintext, id), id), plaintext);
    }
    assert.equal(decrypt(p, p.encrypt(new TextEncoder().encode('bytes'), id), id), 'bytes');
  });

  it("leaves the caller's plaintext bytes alone", () => {
    const plaintext = new TextEncoder().encode("caller's copy");
    newPipeline().encrypt(plaintext, id);
    assert.equal(new TextDecoder().decode(plaintext), "caller's copy");
  });

  it('refuses an empty or invalid identifier', () => {
    const p = newPipeline();
    const formatted = p.encrypt('hello', id);
    for (const identifier of ['', 'Key\uD800']) {
      assert.throws(() => p.encrypt('hello', identifier), InvalidConfigurationKeyError);
      assert.throws(() => decrypt(p, formatted, identifier), InvalidConfigurationKeyError);
    }
  });

  it('treats identifiers as case-insensitive, like configuration keys', () => {
    const p = newPipeline();
    const formatted = p.encrypt('hello', id);
    for (const lookup of ['pipeline:secret', 'PIPELINE:SECRET']) assert.equal(decrypt(p, formatted, lookup), 'hello');
  });

  it('binds each value to its identifier exactly', () => {
    const p = newPipeline();
    const long = `${'Section:'.repeat(60)}Leaf`;
    assert.equal(decrypt(p, p.encrypt('hello', long), long), 'hello');
    assert.throws(() => decrypt(p, p.encrypt('hello', long), `${long}X`), AuthenticationFailedError);
    const admin = p.encrypt('admin-secret', 'ConnectionStrings:Admin');
    assert.equal(decrypt(p, p.encrypt('reporting-secret', 'ConnectionStrings:Reporting'), 'ConnectionStrings:Reporting'), 'reporting-secret');
    assert.throws(() => decrypt(p, admin, 'ConnectionStrings:Reporting'), AuthenticationFailedError);
  });

  it('stamps the key version and never repeats output', () => {
    const p = newPipeline();
    const formatted = p.encrypt('hello', id);
    assert.equal(p.keyVersion, 42);
    assert.ok(formatted.startsWith('enc::v42::') && !formatted.includes('hello'));
    assert.notEqual(formatted, p.encrypt('hello', id));
  });

  it('fails for another version, another instance, or malformed input', () => {
    const p = newPipeline();
    const formatted = p.encrypt('hello', id);
    assert.throws(() => decrypt(p, formatted.replace('v42', 'v7'), id), KeyNotFoundError);
    assert.throws(() => decrypt(newPipeline(), formatted, id), AuthenticationFailedError);
    assert.throws(() => p.decrypt('not-a-valid-format', id, new Uint8Array(16)));
  });

  it('exposes its key as base64 in one reused buffer', () => {
    const key = new Uint8Array(randomBytes(32));
    const p = new AesGcmPipelineDataProtector(new TestFormatProvider(), 1, { key: Uint8Array.from(key) });
    const first = p.keyBase64();
    assert.equal(new TextDecoder().decode(first), Buffer.from(key).toString('base64'));
    assert.equal(p.keyBase64(), first);
  });

  it('encodes base64 byte to byte, matching Node for every length and byte value', () => {
    for (let length = 0; length <= 66; length++) {
      const data = new Uint8Array(randomBytes(length));
      assert.equal(new TextDecoder().decode(base64Bytes(data)), Buffer.from(data).toString('base64'), `length ${length}`);
    }
    const every = Uint8Array.from({ length: 256 * 3 }, (_, i) => (i % 3 === 0 ? i / 3 : 255 - (i % 256)));
    assert.equal(new TextDecoder().decode(base64Bytes(every)), Buffer.from(every).toString('base64'));
    const allDigits = Uint8Array.from(Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', 'base64'));
    assert.equal(new TextDecoder().decode(base64Bytes(allDigits)), 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/');
  });

  it("counts against the key's budget", () => {
    const p = new AesGcmPipelineDataProtector(new TestFormatProvider(), 1, { budget: new EncryptionBudget(1, 2) });
    const formatted = p.encrypt('one', id);
    p.encrypt('two', id);
    assert.throws(() => p.encrypt('three', id), EncryptionLimitReachedError);
    assert.equal(p.encryptionCount, 2);
    assert.equal(decrypt(p, formatted, id), 'one');
  });

  it('close zeroes the key and its base64 form, and fails later use', () => {
    const key = new Uint8Array(randomBytes(32));
    const p = new AesGcmPipelineDataProtector(new TestFormatProvider(), 1, { key });
    const formatted = p.encrypt('hello', id);
    const encoded = p.keyBase64();
    p.close();
    p.close();
    assert.ok(isZero(key) && isZero(encoded));
    assert.throws(() => p.encrypt('hello', id), ClosedError);
    assert.throws(() => decrypt(p, formatted, id), ClosedError);
    assert.throws(() => p.keyBase64(), ClosedError);
  });

  it('requires a format provider', () => {
    assert.throws(() => new AesGcmPipelineDataProtector(undefined as unknown as EncryptedFormatProvider, 1), InvalidArgumentError);
  });
});

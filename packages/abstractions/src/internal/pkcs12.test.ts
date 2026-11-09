// The shared PKCS#12 reader's building blocks: the PKCS#12 key derivation, the BMPString password,
// the iteration budget and the DER reader. Reading whole files - the fixtures OpenSSL, keytool and
// .NET wrote, and the refusals - is tested where each package reads them: options-certificate's
// pkcs12.test.ts and loader.test.ts, and integration-hashicorpvault's tls.test.ts.
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { describe, it } from 'node:test';
import * as der from './der.js';
import { DerError } from './der.js';
import { bmpPassword, IterationBudget, MAX_ITERATIONS, MAX_TOTAL_ITERATIONS, Pkcs12Error, pkcs12Kdf, readPkcs12 } from './pkcs12.js';

const utf8 = (text: string) => Buffer.from(text, 'utf8');
const kind = (expected: string) => (error: unknown) => error instanceof Pkcs12Error && error.kind === expected;

describe('password-based encryption', () => {
  it('writes the password as a big-endian UTF-16 BMPString with a terminator, and refuses one that isn\'t UTF-8', () => {
    assert.deepEqual(bmpPassword(undefined), Buffer.from([0, 0]));
    assert.deepEqual(bmpPassword(new Uint8Array(0)), Buffer.alloc(0));
    for (const text of ['a', 'pässwörd', '€', '𝄞 clef']) {
      assert.deepEqual(bmpPassword(utf8(text)), Buffer.concat([Buffer.from(text, 'utf16le').swap16(), Buffer.from([0, 0])]), text);
    }
    for (const bad of [[0xff], [0xc3], [0xed, 0xa0, 0x80], [0xc0, 0xaf], [0xf0, 0x9d, 0x84]]) {
      assert.throws(() => bmpPassword(Buffer.from(bad)), kind('wrongPassword'), String(bad));
    }
  });

  it("derives RFC 7292's keys", () => {
    // RFC 7292 B.2 written out once more, plainly, for a SHA-1 key of 24 bytes (two digests).
    const bmp = bmpPassword(utf8('pässwörd-123'));
    const salt = Buffer.from('saltsalt');
    const iterations = 3;
    const v = 64;
    const u = 20;
    const fill = (data: Buffer) => Buffer.from(Array.from({ length: v * Math.ceil(data.length / v) }, (_, i) => data[i % data.length]!));
    const input = Buffer.concat([fill(salt), fill(bmp)]);
    let out = Buffer.alloc(0);
    while (out.length < 24) {
      let a = createHash('sha1').update(Buffer.alloc(v, 1)).update(input).digest();
      for (let i = 1; i < iterations; i++) a = createHash('sha1').update(a).digest();
      out = Buffer.concat([out, a]);
      const b = BigInt(`0x${Buffer.from(Array.from({ length: v }, (_, k) => a[k % u]!)).toString('hex')}`);
      for (let block = 0; block < input.length; block += v) {
        const value = (BigInt(`0x${input.subarray(block, block + v).toString('hex')}`) + b + 1n) % (1n << BigInt(8 * v));
        Buffer.from(value.toString(16).padStart(2 * v, '0'), 'hex').copy(input, block);
      }
    }
    assert.deepEqual(pkcs12Kdf('sha1', bmp, salt, iterations, 1, 24), out.subarray(0, 24));
  });

  it("bounds an iteration count, and every file's total", () => {
    const budget = new IterationBudget();
    for (const bad of [0, -1, MAX_ITERATIONS + 1, 1.5]) assert.throws(() => budget.spend(bad), kind('malformed'));
    for (let spent = 0; spent < MAX_TOTAL_ITERATIONS; spent += MAX_ITERATIONS) budget.spend(MAX_ITERATIONS);
    assert.throws(() => budget.spend(1), (error: unknown) => kind('malformed')(error) && /iteration count/.test((error as Error).message));
  });
});

describe('readPkcs12', () => {
  it("names the file as the caller's noun, and says what isn't PKCS#12", () => {
    for (const data of [Buffer.alloc(0), Buffer.from('not a pfx at all'), Buffer.from([0x30, 0x03, 0x02, 0x01, 0x03])]) {
      assert.throws(() => readPkcs12(data, utf8('x'), { requireIntegrity: true, noun: 'store' }),
        (error: unknown) => kind('malformed')(error) && /isn't a PKCS#12 store/.test((error as Error).message));
    }
  });

  it('requires the MAC only when asked to', () => {
    // A version 3 PFX of nothing: data holding an empty authenticated safe, with no MAC.
    const empty = der.encode(der.SEQUENCE, der.encodeInteger(3), der.encode(der.SEQUENCE, der.encodeOid('1.2.840.113549.1.7.1'),
      der.encode(der.CONTEXT_0, der.encode(der.OCTET_STRING, der.encode(der.SEQUENCE)))));
    assert.throws(() => readPkcs12(empty, utf8('x'), { requireIntegrity: true }), kind('noMac'));
    const contents = readPkcs12(empty, undefined, { requireIntegrity: false });
    assert.equal(contents.certificates.length + contents.keys.length, 0);
  });
});

describe('the DER reader', () => {
  it("refuses what isn't DER", () => {
    for (const data of [[0x30], [0x30, 0x05, 0x02, 0x01], [0x04, 0x80, 0x00, 0x00], [0x30, 0x80, 0x02, 0x01, 0x01], [0x30, 0x85, 0xff, 0xff, 0xff, 0xff, 0xff],
      [0x02, 0x01, 0x01, 0x00], [0x1f, 0x81, 0x00, 0x00]]) {
      assert.throws(() => der.read(Buffer.from(data)), DerError, String(data));
    }
  });

  it('reads back what it writes', () => {
    assert.equal(der.oid(der.read(der.encodeOid('1.2.840.113549.1.12.10.1.2'))), '1.2.840.113549.1.12.10.1.2');
    assert.equal(der.oid(der.read(der.encodeOid('2.999.3'))), '2.999.3');
    assert.equal(der.integer(der.read(der.encodeInteger(600000)), 'n'), 600000);
    assert.equal(der.integer(der.read(der.encodeInteger(128)), 'n'), 128);
    const long = Buffer.alloc(70000, 7);
    assert.deepEqual(der.octets(der.read(der.encode(der.OCTET_STRING, long)), 'x'), long);
    const spki = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'der', type: 'spki' });
    assert.ok(createPublicKey({ key: der.read(spki).encoding, format: 'der', type: 'spki' }));
  });
});

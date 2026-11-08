// The PKCS#12 and encrypted PKCS#8 reader against files other tools wrote, in testdata (the Go and
// Python ports' fixtures):
//
//   openssl req -x509 -newkey rsa:2048 -nodes -keyout rsa.key -out rsa.crt -days 3650 -subj "/O=Contoso/CN=api.example.com"
//   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ec.key -out ec.crt -days 3650 -subj "/O=Contoso/CN=api.example.com"
//   openssl pkcs12 -export -in rsa.crt -inkey rsa.key -out openssl-aes.pfx -passout file:pw.txt     # PBES2 AES-256, SHA-256 MAC
//   openssl pkcs12 -export ... -out openssl-3des.pfx -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1
//   openssl pkcs12 -export -in ec.crt -inkey ec.key -out openssl-ec.pfx -passout file:pw.txt
//   openssl pkcs12 -export ... -out openssl-nopass.pfx -passout pass: -keypbe NONE -certpbe NONE
//   openssl pkcs12 -export ... -out openssl-rc2.pfx -passout file:pw.txt -legacy                    # RC2-40 certificates
//   openssl pkcs8 -topk8 -in rsa.key -out rsa-encrypted.key -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter 100000 -passout file:pw.txt
//   openssl pkcs8 -topk8 -in ec.key -out ec-encrypted.key -v2 aes-128-cbc -passout file:pw.txt
//
// and, from openssl-aes.pfx, by .NET 10 on Windows 11: dotnet-default.pfx (3DES, SHA-1 MAC, as Windows
// writes), dotnet-nopassword.pfx, dotnet-aes.pfx (PBES2 AES-256 SHA-256) and dotnet-encrypted.key.
import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { certificate, ecKey, fixture, fixtureCertificateDer, pkcs12, rsaKey, utf8 } from './certificates.test-support.js';
import * as der from './der.js';
import { DerError } from './der.js';
import { InvalidCertificateFileError, UnsupportedCertificateError, WrongPasswordError } from './errors.js';
import { decryptPemKey, publicKeyOf } from './files.js';
import * as pbe from './pbe.js';
import { decodePkcs12 } from './pkcs12.js';

const spkiOf = (der: Buffer) => createPublicKey({ key: der, format: 'der', type: 'spki' });
const certificateSpki = (certificateDer: Buffer) => createPublicKey(`-----BEGIN CERTIFICATE-----\n${certificateDer.toString('base64')}\n-----END CERTIFICATE-----`)
  .export({ format: 'der', type: 'spki' });
const isZero = (buffer: Buffer) => buffer.every((b) => b === 0);

describe('decodePkcs12', () => {
  const files: [string, boolean, string][] = [
    ['openssl-aes.pfx', true, 'rsa.crt'], ['openssl-3des.pfx', true, 'rsa.crt'], ['openssl-ec.pfx', true, 'ec.crt'], ['openssl-nopass.pfx', false, 'rsa.crt'],
    ['dotnet-default.pfx', true, 'rsa.crt'], ['dotnet-aes.pfx', true, 'rsa.crt'], ['dotnet-nopassword.pfx', false, 'rsa.crt'],
  ];
  for (const [file, hasPassword, certificateFile] of files) {
    it(`reads ${file}, and wipes its key; a wrong password is refused`, () => {
      const expected = fixtureCertificateDer(certificateFile);
      const contents = decodePkcs12(readFileSync(fixture(file)), hasPassword ? utf8() : undefined);
      assert.deepEqual(contents.certificates, [expected]);
      assert.equal(contents.keys.length, 1);
      assert.deepEqual(publicKeyOf(contents.keys[0]!).export({ format: 'der', type: 'spki' }), certificateSpki(expected));
      const keys = [...contents.keys];
      contents.wipe();
      assert.ok(keys.every(isZero), "the keys aren't wiped");
      if (hasPassword) assert.throws(() => decodePkcs12(readFileSync(fixture(file)), utf8('wrong')), WrongPasswordError);
    });
  }

  it('refuses a tampered file: its MAC fails', () => {
    const data = readFileSync(fixture('openssl-aes.pfx'));
    const tampered = Buffer.from(data);
    tampered[200] = tampered[200]! ^ 0x01;
    assert.throws(() => decodePkcs12(tampered, utf8()), (error: Error) => error instanceof WrongPasswordError || error instanceof InvalidCertificateFileError);
    // A byte of the MAC itself.
    const macTampered = Buffer.from(data);
    macTampered[macTampered.length - 30] = macTampered[macTampered.length - 30]! ^ 0x01;
    assert.throws(() => decodePkcs12(macTampered, utf8()), WrongPasswordError);
  });

  it('refuses a legacy RC2 file, saying how to re-export it with AES', () => {
    assert.throws(() => decodePkcs12(readFileSync(fixture('openssl-rc2.pfx')), utf8()),
      (error: Error) => error instanceof UnsupportedCertificateError && /re-export it with AES/.test(error.message) && error.code === 'ERR_HKDFGUARD_UNSUPPORTED_CERTIFICATE');
  });

  it('refuses a PBMAC1 integrity check', () => {
    const file = pkcs12({ keys: [ecKey().privateKey], certificates: [certificate(ecKey())], password: utf8(), mac: 'pbmac1' });
    assert.throws(() => decodePkcs12(file, utf8()), (error: Error) => error instanceof UnsupportedCertificateError && /PBMAC1/.test(error.message));
  });

  it("refuses what isn't a PKCS#12 file", () => {
    for (const data of [Buffer.alloc(0), Buffer.from([0x30, 0x03, 0x02, 0x01]), Buffer.from('not a pfx at all'), readFileSync(fixture('rsa.crt'))]) {
      assert.throws(() => decodePkcs12(data, utf8()), InvalidCertificateFileError);
    }
  });

  it('refuses public-key (enveloped) contents', () => {
    const enveloped = der.encode(der.SEQUENCE, der.encodeOid('1.2.840.113549.1.7.3'), der.encode(der.CONTEXT_0, der.encode(der.SEQUENCE)));
    const authSafe = der.encode(der.SEQUENCE, enveloped);
    const file = der.encode(der.SEQUENCE, der.encodeInteger(3),
      der.encode(der.SEQUENCE, der.encodeOid('1.2.840.113549.1.7.1'), der.encode(der.CONTEXT_0, der.encode(der.OCTET_STRING, authSafe))));
    assert.throws(() => decodePkcs12(file, undefined), (error: Error) => error instanceof UnsupportedCertificateError && /enveloped/.test(error.message));
  });

  it('reads files written with every encryption and MAC', () => {
    const key = ecKey();
    const leaf = certificate(key);
    for (const [keyEncryption, certificateEncryption, mac] of [['pbes2', 'pbes2', 'sha256'], ['3des', '3des', 'sha1'], ['pbes2', 'none', 'sha512'],
      ['3des', 'pbes2', 'sha256']] as const) {
      const file = pkcs12({ keys: [key.privateKey], certificates: [leaf], password: utf8(), keyEncryption, certificateEncryption, mac });
      const contents = decodePkcs12(file, utf8());
      assert.deepEqual(contents.certificates, [leaf], `${keyEncryption}/${certificateEncryption}/${mac}`);
      assert.deepEqual(publicKeyOf(contents.keys[0]!).export({ format: 'der', type: 'spki' }), key.publicKey.export({ format: 'der', type: 'spki' }));
    }
    // Nothing protected and nothing claimed: read without a password, as AllowUnprotectedPrivateKey does.
    const plain = decodePkcs12(pkcs12({ keys: [key.privateKey], certificates: [leaf], keyEncryption: 'none', certificateEncryption: 'none', mac: 'none' }), undefined);
    assert.deepEqual(plain.certificates, [leaf]);
    assert.equal(plain.keys.length, 1);
  });

  it('refuses, with a password, a file without its MAC - however its contents are protected', () => {
    const key = ecKey();
    const leaf = certificate(key);
    for (const [keyEncryption, certificateEncryption] of [['pbes2', 'pbes2'], ['3des', 'none'], ['none', 'none']] as const) {
      const file = pkcs12({ keys: [key.privateKey], certificates: [leaf], password: utf8(), keyEncryption, certificateEncryption, mac: 'none' });
      assert.throws(() => decodePkcs12(file, utf8()), (error: Error) => error instanceof InvalidCertificateFileError && /no integrity MAC/.test(error.message),
        `${keyEncryption}/${certificateEncryption}`);
    }
    // A real file with its MAC cut off.
    const pfx = der.sequence(der.read(readFileSync(fixture('openssl-aes.pfx'))), 'pfx');
    const stripped = der.encode(der.SEQUENCE, pfx[0]!.encoding, pfx[1]!.encoding);
    assert.throws(() => decodePkcs12(stripped, utf8()), (error: Error) => error instanceof InvalidCertificateFileError && /no integrity MAC/.test(error.message));
  });

  it("refuses anyone's plaintext key and certificate under any password: what the MAC is for", () => {
    // Someone who can write the file but doesn't know the password plants their own key, unencrypted, with no MAC.
    const theirs = rsaKey(1);
    const planted = pkcs12({ keys: [theirs.privateKey], certificates: [certificate(theirs)], keyEncryption: 'none', certificateEncryption: 'none', mac: 'none' });
    for (const password of [utf8(), utf8('anything')]) {
      assert.throws(() => decodePkcs12(planted, password), InvalidCertificateFileError);
    }
  });

  it("refuses, with a password, a key that isn't encrypted, even under a MAC", () => {
    const key = ecKey();
    const file = pkcs12({ keys: [key.privateKey], certificates: [certificate(key)], password: utf8(), keyEncryption: 'none', certificateEncryption: 'pbes2', mac: 'sha256' });
    assert.throws(() => decodePkcs12(file, utf8()),
      (error: Error) => error instanceof InvalidCertificateFileError && /isn't encrypted/.test(error.message) && /AllowUnprotectedPrivateKey/.test(error.message));
    // The same file, certificates alone: nothing to refuse.
    const certificatesOnly = pkcs12({ certificates: [certificate(key)], password: utf8(), certificateEncryption: 'none', mac: 'sha256' });
    assert.equal(decodePkcs12(certificatesOnly, utf8()).certificates.length, 1);
  });

  it('reads a BER file - indefinite lengths and segmented strings - as its DER', () => {
    // Only the outer PFX and its unencrypted contents are rewritten: the MAC covers the authenticated
    // safe's bytes, so a BER writer's MAC is over its own BER; here there is none.
    const file = pkcs12({ keys: [rsaKey().privateKey], certificates: [], keyEncryption: 'none', certificateEncryption: 'none', mac: 'none' });
    const toBer = (element: der.Element): Buffer => {
      if (element.constructed) return Buffer.concat([Buffer.from([element.tag, 0x80]), ...der.children(element).map(toBer), Buffer.from([0, 0])]);
      if (element.tag === der.OCTET_STRING && element.contents.length > 16) {
        const segments: Buffer[] = [];
        for (let i = 0; i < element.contents.length; i += 16) segments.push(der.encode(der.OCTET_STRING, element.contents.subarray(i, i + 16)));
        return Buffer.concat([Buffer.from([0x24, 0x80]), ...segments, Buffer.from([0, 0])]);
      }
      return Buffer.from(element.encoding);
    };
    const pfx = der.sequence(der.read(file), 'pfx');
    const info = der.sequence(pfx[1], 'authSafe');
    const authSafe = der.octets(der.only(info[1], der.CONTEXT_0, 'content'), 'authSafe');
    const berSafe = toBer(der.read(authSafe));
    const ber = Buffer.concat([Buffer.from([0x30, 0x80]), pfx[0]!.encoding, Buffer.from([0x30, 0x80]), info[0]!.encoding, Buffer.from([0xa0, 0x80]),
      toBer(der.read(der.encode(der.OCTET_STRING, berSafe))), Buffer.from([0, 0, 0, 0, 0, 0])]);
    const contents = decodePkcs12(ber, undefined);
    assert.equal(contents.certificates.length, 0);
    assert.deepEqual(publicKeyOf(contents.keys[0]!).export({ format: 'der', type: 'spki' }), rsaKey().publicKey.export({ format: 'der', type: 'spki' }));
  });

  it('bounds the iterations a file may ask for', () => {
    const file = pkcs12({ keys: [ecKey().privateKey], certificates: [certificate(ecKey())], password: utf8(), mac: 'sha256', macIterations: pbe.MAX_ITERATIONS + 1 });
    assert.throws(() => decodePkcs12(file, utf8()), (error: Error) => error instanceof InvalidCertificateFileError && /iteration count/.test(error.message));
  });
});

describe('encrypted PKCS#8 keys', () => {
  for (const [file, certificateFile] of [['rsa-encrypted.key', 'rsa.crt'], ['ec-encrypted.key', 'ec.crt'], ['dotnet-encrypted.key', 'rsa.crt']]) {
    it(`reads ${file}; a wrong password is refused`, () => {
      const data = readFileSync(fixture(file!));
      const key = decryptPemKey(data, utf8(), file!);
      assert.deepEqual(publicKeyOf(key).export({ format: 'der', type: 'spki' }), certificateSpki(fixtureCertificateDer(certificateFile!)));
      assert.throws(() => decryptPemKey(data, utf8('wrong'), file!), WrongPasswordError);
    });
  }

  it('refuses a legacy encrypted PEM key, saying how to convert it, and a file with no key', () => {
    const legacy = Buffer.from('-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00000000000000000000000000000000\n\n'
      + 'AAAA\n-----END RSA PRIVATE KEY-----\n');
    assert.throws(() => decryptPemKey(legacy, utf8(), 'legacy.key'), (error: Error) => error instanceof UnsupportedCertificateError && /openssl pkcs8 -topk8/.test(error.message));
    assert.throws(() => decryptPemKey(Buffer.from('no key here'), utf8(), 'none.key'), InvalidCertificateFileError);
  });
});

describe('password-based encryption', () => {
  it('writes the password as a big-endian UTF-16 BMPString with a terminator, and refuses one that isn\'t UTF-8', () => {
    assert.deepEqual(pbe.bmpPassword(undefined), Buffer.from([0, 0]));
    assert.deepEqual(pbe.bmpPassword(new Uint8Array(0)), Buffer.alloc(0));
    for (const text of ['a', 'pässwörd', '€', '𝄞 clef']) {
      assert.deepEqual(pbe.bmpPassword(utf8(text)), Buffer.concat([Buffer.from(text, 'utf16le').swap16(), Buffer.from([0, 0])]), text);
    }
    for (const bad of [[0xff], [0xc3], [0xed, 0xa0, 0x80], [0xc0, 0xaf], [0xf0, 0x9d, 0x84]]) {
      assert.throws(() => pbe.bmpPassword(Buffer.from(bad)), WrongPasswordError, String(bad));
    }
  });

  it("derives RFC 7292's keys", () => {
    // RFC 7292 B.2 written out once more, plainly, for a SHA-1 key of 24 bytes (two digests).
    const bmp = pbe.bmpPassword(utf8());
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
    assert.deepEqual(pbe.pkcs12Kdf('sha1', bmp, salt, iterations, 1, 24), out.subarray(0, 24));
  });

  it('bounds an iteration count, and every file\'s total', () => {
    const budget = new pbe.IterationBudget();
    for (const bad of [0, -1, pbe.MAX_ITERATIONS + 1, 1.5]) assert.throws(() => budget.spend(bad), InvalidCertificateFileError);
    for (let i = 0; i < 4; i++) budget.spend(pbe.MAX_ITERATIONS);
    assert.throws(() => budget.spend(1), InvalidCertificateFileError);
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
    assert.ok(spkiOf(rsaKey().publicKey.export({ format: 'der', type: 'spki' })));
  });
});

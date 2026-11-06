import assert from 'node:assert/strict';
import { constants, publicEncrypt, verify, X509Certificate } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { ClosedError, KeyNotFoundError } from '@runsecure/hkdfguard-abstractions';
import {
  certificate, ecKey, entry, FakePasswords, FakeStore, FakeStoreCertificate, fixture, fixtureCertificateDer, loader, NOW, pem, pemOptions, pfxOptions, pkcs12,
  rsaKey, SUBJECT, utf8,
} from './certificates.test-support.js';
import {
  CertificateNotFoundError, CertificateNotValidNowError, CertificateStoreError, InvalidCertificateFileError, InvalidCertificateOptionsError,
  NativeProviderRequiredError, NoPasswordSourceError, NoPrivateKeyError, PasswordNotFoundError, UnsupportedCertificateError, WrongPasswordError,
  type CertificateOptions,
} from './index.js';

const directory = mkdtempSync(join(tmpdir(), 'hkdfguard-certificate-test-'));
after(() => rmSync(directory, { recursive: true, force: true }));
let counter = 0;
function write(name: string, data: Buffer | string): string {
  const path = join(directory, `${counter++}-${name}`);
  writeFileSync(path, data);
  return path;
}

const storeOptions = (subject = SUBJECT, requirePrivateKey = true): CertificateOptions => ({
  windows: { storeLocation: 'CurrentUser', storeName: 'My', subject }, requirePrivateKey,
});
const platform = 'windows';
const data = Buffer.from('to sign');

describe('CertificateOptionsLoader from a store', () => {
  it('gives the certificate valid now, with its key, that expires last, and releases every other', async () => {
    const expired = entry(-30, -1);
    const notYet = entry(1, 90);
    const withoutKey = entry(-1, 400, { withKey: false });
    const older = entry(-10, 100);
    const newest = entry(-5, 200);
    const other = entry(-1, 900, { subject: 'CN=other.example.com, O=Contoso' });
    const store = new FakeStore([expired, notYet, withoutKey, older, newest, other]);
    const loaded = await loader({ platform, store }).load(storeOptions());
    assert.deepEqual(store.reads, [['CurrentUser', 'My']]);
    assert.ok(loaded.certificate.raw.equals(newest.der));
    assert.equal(loaded.keyLocation, 'the Windows certificate store');
    assert.equal(loaded.chain.length, 0);
    assert.deepEqual([expired, notYet, withoutKey, older, other].map((c) => c.closed), [true, true, true, true, true]);
    assert.equal(newest.closed, false);
    const signature = await loaded.sign('sha256', data);
    assert.ok(verify('sha256', data, loaded.publicKey, signature));
    await loaded.close();
    assert.ok(newest.closed && newest.opened!.closed);
  });

  it('signs with an ECDSA store key, in DER or IEEE P1363', async () => {
    const store = new FakeStore([entry(-1, 30, { key: ecKey() })]);
    const loaded = await loader({ platform, store }).load(storeOptions());
    assert.ok(verify('sha384', data, loaded.publicKey, await loaded.sign('sha384', data)));
    const p1363 = await loaded.sign('sha256', data, { dsaEncoding: 'ieee-p1363' });
    assert.equal(p1363.length, 64);
    assert.ok(verify('sha256', data, { key: loaded.publicKey, dsaEncoding: 'ieee-p1363' }, p1363));
    await assert.rejects(loaded.sign('sha256', data, { padding: constants.RSA_PKCS1_PSS_PADDING }), /no padding/);
    await loaded.close();
  });

  it('hashes the data and hands the store only the digest', async () => {
    const certificateEntry = entry(-1, 30);
    const loaded = await loader({ platform, store: new FakeStore([certificateEntry]) }).load(storeOptions());
    await loaded.sign('sha512', data);
    assert.equal(certificateEntry.opened!.digests[0]!.length, 64);
    await loaded.close();
  });

  it('decrypts with a store key, OAEP by default', async () => {
    const loaded = await loader({ platform, store: new FakeStore([entry(-1, 30)]) }).load(storeOptions());
    const oaep = publicEncrypt({ key: loaded.publicKey, oaepHash: 'sha256', oaepLabel: Buffer.from('label') }, Buffer.from('secret'));
    assert.equal((await loaded.decrypt(oaep, { oaepHash: 'sha256', oaepLabel: Buffer.from('label') })).toString(), 'secret');
    const sha1 = publicEncrypt(loaded.publicKey, Buffer.from('secret'));
    assert.equal((await loaded.decrypt(sha1)).toString(), 'secret');
    await loaded.close();
  });

  it('gives the newest valid certificate without its key, and trusts it alone', async () => {
    const newest = entry(-1, 400, { withKey: false });
    const store = new FakeStore([entry(-1, 100), newest]);
    const loaded = await loader({ platform, store }).load(storeOptions(SUBJECT, false));
    assert.ok(loaded.certificate.raw.equals(newest.der));
    assert.equal(loaded.hasPrivateKey, false);
    assert.equal(loaded.keyLocation, undefined);
    await assert.rejects(loaded.sign('sha256', data), NoPrivateKeyError);
    assert.ok(loaded.createSecureContext());
    await loaded.close();
  });

  it("compares a store's subject whole, ignoring case", async () => {
    const store = new FakeStore([entry(-1, 30, { subject: 'CN=api.example.com, O=Contoso' })]);
    const loaded = await loader({ platform, store }).load(storeOptions('cn=API.example.com; o=CONTOSO'));
    await loaded.close();
    await assert.rejects(loader({ platform, store }).load(storeOptions('CN=api.example.com')), CertificateNotFoundError);
  });

  it('says why a store has no certificate to give', async () => {
    await assert.rejects(loader({ platform, store: new FakeStore([]) }).load(storeOptions()),
      (error: Error) => error instanceof CertificateNotFoundError && error.message === `The CurrentUser My store holds no certificate whose subject is '${SUBJECT}'.`);
    await assert.rejects(loader({ platform, store: new FakeStore([entry(-30, -1), entry(-1, 30, { withKey: false })]) }).load(storeOptions()),
      (error: Error) => error instanceof CertificateNotFoundError && /2 certificate\(s\) .* are all expired, not yet valid, or without a private key/.test(error.message));
    await assert.rejects(loader({ platform, store: new FakeStore([entry(-30, -1)]) }).load(storeOptions(SUBJECT, false)),
      /are all expired or not yet valid\.$/);
  });

  it('reads a macOS keychain as a store', async () => {
    const store = new FakeStore([entry(-1, 30)]);
    const loaded = await loader({ platform: 'macos', store }).load({ macOS: { storeLocation: 'LocalMachine', subject: SUBJECT } });
    assert.equal(loaded.keyLocation, 'the macOS keychain');
    assert.deepEqual(store.reads, [['LocalMachine', 'My']]);
    await loaded.close();
  });

  it("reports a store key that won't open, naming the certificate, and releases it", async () => {
    const failing = new FakeStoreCertificate(certificate(rsaKey()), rsaKey(), new NoPrivateKeyError('CNG says no.'));
    await assert.rejects(loader({ platform, store: new FakeStore([failing]) }).load(storeOptions()),
      (error: Error) => error instanceof NoPrivateKeyError && error.message === `The certificate '${SUBJECT}' in the CurrentUser My store: CNG says no.`);
    assert.ok(failing.closed);
  });

  it('reports a store that fails to read', async () => {
    const failure = new CertificateStoreError('the store broke', 5);
    await assert.rejects(loader({ platform, store: new FakeStore([], failure) }).load(storeOptions()), (error) => error === failure);
  });

  it("can't make a TLS context from a store key: Node's TLS can't reach it", async () => {
    const loaded = await loader({ platform, store: new FakeStore([entry(-1, 30)]) }).load(storeOptions());
    assert.throws(() => loaded.createSecureContext(), (error: Error) => error instanceof NativeProviderRequiredError
      && error.code === 'ERR_HKDFGUARD_CERTIFICATE_NATIVE_PROVIDER_REQUIRED' && error instanceof UnsupportedCertificateError);
    await loaded.close();
  });

  it('waits on close for a use in flight, then refuses every use', async () => {
    const certificateEntry = entry(-1, 30);
    const loaded = await loader({ platform, store: new FakeStore([certificateEntry]) }).load(storeOptions());
    const signing = loaded.sign('sha256', data);
    const closing = loaded.close();
    assert.equal(loaded.closed, true);
    assert.ok(verify('sha256', data, loaded.publicKey, await signing));
    await closing;
    assert.ok(certificateEntry.opened!.closed && certificateEntry.closed);
    await assert.rejects(loaded.sign('sha256', data), ClosedError);
    await assert.rejects(loaded.decrypt(Buffer.alloc(256)), ClosedError);
    assert.throws(() => loaded.createSecureContext(), ClosedError);
    await loaded.close(); // again: nothing to do
  });

  it('refuses a hash, padding or salt that is not one', async () => {
    const loaded = await loader({ platform, store: new FakeStore([entry(-1, 30)]) }).load(storeOptions());
    await assert.rejects(loaded.sign('md5' as 'sha256', data), /The hash must be/);
    await assert.rejects(loaded.sign('sha256', data, { padding: constants.RSA_NO_PADDING }), /RSA_PKCS1_PADDING or RSA_PKCS1_PSS_PADDING/);
    await assert.rejects(loaded.sign('sha256', data, { padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 1000 }), /doesn't fit/);
    await assert.rejects(loaded.decrypt(Buffer.alloc(1), { padding: constants.RSA_NO_PADDING }), /RSA_PKCS1_OAEP_PADDING or RSA_PKCS1_PADDING/);
    await assert.rejects(loaded.sign('sha256', 'text' as unknown as Uint8Array), /must be a Uint8Array/);
    await loaded.close();
  });
});

describe('CertificateOptionsLoader from a file', () => {
  it('opens a PKCS#12 file with its password from the password source, and zeroes the password', async () => {
    const key = rsaKey();
    const path = write('tls.pfx', pkcs12({ keys: [key.privateKey], certificates: [certificate(key)], password: utf8() }));
    const passwords = new FakePasswords();
    const loaded = await loader({ passwords }).load(pfxOptions(path));
    assert.equal(loaded.keyLocation, 'a key file');
    assert.equal(loaded.subject, SUBJECT);
    assert.ok(verify('sha256', data, loaded.publicKey, await loaded.sign('sha256', data)));
    const pss = await loaded.sign('sha256', data, { padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST });
    assert.ok(verify('sha256', data, { key: loaded.publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, pss));
    const oaep = publicEncrypt({ key: loaded.publicKey, oaepHash: 'sha384' }, Buffer.from('secret'));
    assert.equal((await loaded.decrypt(oaep, { oaepHash: 'sha384' })).toString(), 'secret');
    assert.equal(passwords.buffers.length, 1);
    assert.ok(passwords.buffers.every((buffer) => buffer.every((b) => b === 0)), "the password buffer isn't zeroed");
    await loaded.close();
  });

  for (const file of ['openssl-aes.pfx', 'openssl-3des.pfx', 'openssl-ec.pfx', 'dotnet-default.pfx', 'dotnet-aes.pfx']) {
    it(`opens ${file} through the loader`, async () => {
      const loaded = await loader({ passwords: new FakePasswords() }).load(pfxOptions(fixture(file)));
      assert.ok(verify('sha256', data, loaded.publicKey, await loaded.sign('sha256', data)));
      await loaded.close();
    });
  }

  it('refuses a wrong password', async () => {
    await assert.rejects(loader({ passwords: new FakePasswords({ 'tls-password': 'wrong' }) }).load(pfxOptions(fixture('openssl-aes.pfx'))), WrongPasswordError);
  });

  it('refuses a missing password, or no password source', async () => {
    await assert.rejects(loader({ passwords: new FakePasswords({}) }).load(pfxOptions(fixture('openssl-aes.pfx'))),
      (error: Error) => error instanceof PasswordNotFoundError && error instanceof KeyNotFoundError && error.message.includes("'tls-password'"));
    await assert.rejects(loader().load(pfxOptions(fixture('openssl-aes.pfx'))), NoPasswordSourceError);
  });

  it("reports the password source's own failure", async () => {
    const passwords = new FakePasswords();
    passwords.failure = new Error('vault unreachable');
    await assert.rejects(loader({ passwords }).load(pfxOptions(fixture('openssl-aes.pfx'))), /vault unreachable/);
  });

  it('opens an unprotected PKCS#12 file when allowed', async () => {
    for (const file of ['openssl-nopass.pfx', 'dotnet-nopassword.pfx']) {
      const loaded = await loader().load(pfxOptions(fixture(file), null, { allowUnprotected: true }));
      assert.equal(loaded.keyLocation, 'an unprotected key file');
      await loaded.close();
    }
  });

  it('needs a PKCS#12 password even for the certificate alone', async () => {
    const passwords = new FakePasswords();
    const loaded = await loader({ passwords }).load(pfxOptions(fixture('openssl-aes.pfx'), 'tls-password', { requirePrivateKey: false }));
    assert.equal(passwords.buffers.length, 1);
    await loaded.close();
  });

  it('keeps the other certificates of a PKCS#12 file after the one with the key, in file order', async () => {
    const caKey = rsaKey(1);
    const ca = certificate(caKey, { subject: 'CN=Test CA' });
    const intermediate = certificate(rsaKey(2), { subject: 'CN=Intermediate', issuer: { key: caKey, name: 'CN=Test CA' } });
    const leaf = certificate(ecKey(), { issuer: { key: rsaKey(2), name: 'CN=Intermediate' }, ca: false });
    const path = write('chain.pfx', pkcs12({ keys: [ecKey().privateKey], certificates: [ca, leaf, intermediate], password: utf8() }));
    const loaded = await loader({ passwords: new FakePasswords() }).load(pfxOptions(path));
    assert.ok(loaded.certificate.raw.equals(leaf));
    assert.deepEqual(loaded.chain.map((c) => c.raw), [ca, intermediate]);
    await loaded.close();
  });

  it('gives a PKCS#12 file\'s certificates without a key when none is theirs', async () => {
    const path = write('nokey.pfx', pkcs12({ keys: [rsaKey(1).privateKey], certificates: [certificate(ecKey())], password: utf8() }));
    await assert.rejects(loader({ passwords: new FakePasswords() }).load(pfxOptions(path)), NoPrivateKeyError);
    const loaded = await loader({ passwords: new FakePasswords() }).load(pfxOptions(path, 'tls-password', { requirePrivateKey: false }));
    assert.equal(loaded.hasPrivateKey, false);
    await loaded.close();
  });

  it('refuses a legacy RC2 PKCS#12 file through the loader', async () => {
    await assert.rejects(loader({ passwords: new FakePasswords() }).load(pfxOptions(fixture('openssl-rc2.pfx'))),
      (error: Error) => error instanceof UnsupportedCertificateError && /re-export it with AES/.test(error.message));
  });

  it('opens a PEM certificate and chain with its encrypted PKCS#8 key', async () => {
    const key = ecKey();
    const ca = certificate(rsaKey(1), { subject: 'CN=Test CA' });
    const leaf = certificate(key, { issuer: { key: rsaKey(1), name: 'CN=Test CA' } });
    const certificatePath = write('chain.crt', pem(ca, leaf));
    const keyPath = write('tls.key', key.privateKey.export({ format: 'pem', type: 'pkcs8', cipher: 'aes-256-cbc', passphrase: utf8() }));
    const passwords = new FakePasswords();
    const loaded = await loader({ passwords }).load(pemOptions(certificatePath, keyPath));
    assert.ok(loaded.certificate.raw.equals(leaf));
    assert.deepEqual(loaded.chain.map((c) => c.raw), [ca]);
    assert.ok(verify('sha256', data, loaded.publicKey, await loaded.sign('sha256', data)));
    assert.ok(passwords.buffers.every((buffer) => buffer.every((b) => b === 0)));
    await loaded.close();
  });

  it("loads the fixtures' encrypted PKCS#8 keys beside their certificates", async () => {
    for (const [keyFile, certificateFile] of [['rsa-encrypted.key', 'rsa.crt'], ['ec-encrypted.key', 'ec.crt'], ['dotnet-encrypted.key', 'rsa.crt']]) {
      const loaded = await loader({ passwords: new FakePasswords() }).load(pemOptions(fixture(certificateFile!), fixture(keyFile!)));
      assert.ok(loaded.certificate.raw.equals(fixtureCertificateDer(certificateFile!)));
      await loaded.close();
    }
  });

  it('needs a PEM key to be encrypted, or not, as the password says', async () => {
    const certificatePath = write('tls.crt', pem(certificate(ecKey())));
    const plain = write('plain.key', ecKey().privateKey.export({ format: 'pem', type: 'pkcs8' }));
    await assert.rejects(loader({ passwords: new FakePasswords() }).load(pemOptions(certificatePath, plain)),
      (error: Error) => error instanceof InvalidCertificateFileError && /isn't encrypted/.test(error.message));
    const encrypted = write('enc.key', ecKey().privateKey.export({ format: 'pem', type: 'pkcs8', cipher: 'aes-256-cbc', passphrase: utf8() }));
    await assert.rejects(loader().load(pemOptions(certificatePath, encrypted, null, { allowUnprotected: true })),
      (error: Error) => error instanceof InvalidCertificateFileError && /is encrypted/.test(error.message));
  });

  it('opens a PEM certificate with a plain key when allowed - PKCS#8, PKCS#1 or SEC 1', async () => {
    for (const [key, type] of [[rsaKey(), 'pkcs1'], [ecKey(), 'sec1'], [ecKey(), 'pkcs8']] as const) {
      const certificatePath = write('tls.crt', pem(certificate(key)));
      const keyPath = write('plain.key', key.privateKey.export({ format: 'pem', type } as never) as unknown as Buffer);
      const loaded = await loader().load(pemOptions(certificatePath, keyPath, null, { allowUnprotected: true }));
      assert.equal(loaded.keyLocation, 'an unprotected key file');
      assert.ok(verify('sha256', data, loaded.publicKey, await loaded.sign('sha256', data)), type);
      await loaded.close();
    }
  });

  it('refuses a PEM key that is no certificate\'s in the file', async () => {
    const certificatePath = write('tls.crt', pem(certificate(rsaKey())));
    const keyPath = write('tls.key', ecKey().privateKey.export({ format: 'pem', type: 'pkcs8', cipher: 'aes-256-cbc', passphrase: utf8() }));
    await assert.rejects(loader({ passwords: new FakePasswords() }).load(pemOptions(certificatePath, keyPath)),
      (error: Error) => error instanceof InvalidCertificateFileError && /is the key's/.test(error.message));
  });

  it('opens a PEM or DER certificate alone, needing no key or password', async () => {
    const der = certificate(rsaKey());
    for (const path of [write('alone.crt', pem(der)), write('alone.der', der)]) {
      const loaded = await loader().load(pemOptions(path, undefined, null, { requirePrivateKey: false }));
      assert.ok(loaded.certificate.raw.equals(der));
      await loaded.close();
    }
  });

  it('refuses a file certificate not valid now, or without its key', async () => {
    const key = rsaKey();
    for (const [notBefore, notAfter] of [[-30, -1], [1, 30]]) {
      const path = write('expired.pfx', pkcs12({ keys: [key.privateKey], certificates: [certificate(key, { notBeforeDays: notBefore!, notAfterDays: notAfter! })], password: utf8() }));
      await assert.rejects(loader({ passwords: new FakePasswords() }).load(pfxOptions(path)),
        (error: Error) => error instanceof CertificateNotValidNowError && /is valid from \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z to .*, not now\./.test(error.message));
    }
    const path = write('certonly.pfx', pkcs12({ certificates: [certificate(key)], password: utf8() }));
    await assert.rejects(loader({ passwords: new FakePasswords() }).load(pfxOptions(path)), NoPrivateKeyError);
  });

  it('reports a missing or broken file', async () => {
    await assert.rejects(loader({ passwords: new FakePasswords() }).load(pfxOptions(join(directory, 'missing.pfx'))), (error: Error & { code?: string }) => error.code === 'ENOENT');
    await assert.rejects(loader({ passwords: new FakePasswords() }).load(pfxOptions(write('junk.pfx', 'junk'))), InvalidCertificateFileError);
    await assert.rejects(loader().load(pemOptions(write('junk.crt', '-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n'), undefined, undefined,
      { requirePrivateKey: false })), InvalidCertificateFileError);
    await assert.rejects(loader().load(pemOptions(write('empty.crt', 'nothing'), undefined, null, { requirePrivateKey: false })), InvalidCertificateFileError);
  });

  it('wipes a closed file key and refuses every use', async () => {
    const loaded = await loader({ passwords: new FakePasswords() }).load(pfxOptions(fixture('openssl-ec.pfx')));
    await loaded.close();
    await assert.rejects(loaded.sign('sha256', data), ClosedError);
    assert.throws(() => loaded.createSecureContext(), ClosedError);
    assert.equal(String(loaded), `LoadedCertificate(subject='${SUBJECT}', hasPrivateKey=true)`);
  });
});

describe('CertificateOptionsLoader', () => {
  it('reads a Linux certificate alone from its file', async () => {
    const der = certificate(ecKey());
    const loaded = await loader({ platform: 'linux' }).load({ linux: { certificateFile: write('linux.crt', pem(der)) }, requirePrivateKey: false });
    assert.ok(loaded.certificate.raw.equals(der));
    await loaded.close();
  });

  it('refuses invalid options before anything is opened', async () => {
    const store = new FakeStore([entry(-1, 30)]);
    await assert.rejects(loader({ platform: 'linux', store }).load(storeOptions(), 'tls'),
      (error: Error) => error instanceof InvalidCertificateOptionsError && /'tls' are invalid/.test(error.message));
    assert.equal(store.reads.length, 0);
  });

  it('judges validity by its clock', async () => {
    const key = rsaKey();
    const path = write('clock.pfx', pkcs12({ keys: [key.privateKey], certificates: [certificate(key, { notBeforeDays: -1, notAfterDays: 1 })], password: utf8() }));
    const later = new Date(NOW.getTime() + 2 * 24 * 60 * 60 * 1000);
    await assert.rejects(loader({ passwords: new FakePasswords(), now: later }).load(pfxOptions(path)), CertificateNotValidNowError);
    const loaded = await loader({ passwords: new FakePasswords() }).load(pfxOptions(path));
    assert.equal(loaded.notAfter.getTime(), new X509Certificate(loaded.certificate.raw).validToDate?.getTime() ?? loaded.notAfter.getTime());
    await loaded.close();
  });
});

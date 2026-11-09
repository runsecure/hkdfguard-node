// The macOS keychains themselves: read-only always, and - with HKDFGUARD_TEST_MACOS_KEYCHAIN=1 - a
// round trip through a throwaway identity imported into the login keychain, deleted afterwards.
//
// Not yet run on a Mac: written to the Go port's test of the same, which was.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { constants, createHash, publicEncrypt, randomBytes, verify } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir, userInfo } from 'node:os';
import { join } from 'node:path';
import { describe, it, type TestContext } from 'node:test';
import { certificate, ecKey, pkcs12, rsaKey, type KeyPair } from './certificates.test-support.js';
import { CertificateNotFoundError, CertificateOptionsLoader, NativeProviderRequiredError, UnsupportedCertificateError } from './index.js';
import { call, ERR_SEC_INTERACTION_NOT_ALLOWED, readMacKeychain } from './macos.js';
import { CertificateStoreError, NoPrivateKeyError } from './errors.js';

const onMac = process.platform === 'darwin';
const optedIn = process.env.HKDFGUARD_TEST_MACOS_KEYCHAIN === '1';
const OPT_IN = 'imports and deletes an identity in the login keychain: set HKDFGUARD_TEST_MACOS_KEYCHAIN=1';

/**
 * A self-signed identity imported into the login keychain, open to every application (-A) so no
 * dialog asks, deleted when the test ends; returns its subject. 3DES and a SHA-1 MAC: what every
 * macOS release's security import reads.
 */
function identity(t: TestContext, key: KeyPair): string {
  const subject = `CN=hkdfguard-node-test-${randomBytes(8).toString('hex')}`;
  const der = certificate(key, { subject, now: new Date(), notAfterDays: 2 });
  const keychain = join(userInfo().homedir, 'Library', 'Keychains', 'login.keychain-db');
  const directory = mkdtempSync(join(tmpdir(), 'hkdfguard-keychain-'));
  try {
    const path = join(directory, 'identity.p12');
    writeFileSync(path, pkcs12({ keys: [key.privateKey], certificates: [der], password: Buffer.from('test'), keyEncryption: '3des', certificateEncryption: '3des', mac: 'sha1' }));
    execFileSync('/usr/bin/security', ['import', path, '-k', keychain, '-P', 'test', '-A']);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
  const sha1 = createHash('sha1').update(der).digest('hex').toUpperCase();
  t.after(() => {
    execFileSync('/usr/bin/security', ['delete-identity', '-Z', sha1, keychain]);
  });
  return subject;
}

describe('keychain failures', () => {
  const failing = (status: number) => () => Promise.reject(Object.assign(new Error(`SecKeyCreateSignature failed (${status})`), { status }));

  it('report a key the keychain would have asked about as having no usable private key, saying how to grant it', async () => {
    await assert.rejects(call(failing(ERR_SEC_INTERACTION_NOT_ALLOWED), 'sign'),
      (e: unknown) => e instanceof NoPrivateKeyError && /never asked/.test((e as Error).message) && /access list/.test((e as Error).message));
  });

  it('report any other keychain failure as the store failing, with its status', async () => {
    await assert.rejects(call(failing(-25300), 'decrypt'), (e: unknown) => e instanceof CertificateStoreError);
    await assert.rejects(call(failing(-1), 'decrypt'), (e: unknown) => e instanceof UnsupportedCertificateError);
  });
});

describe('the macOS keychains', { skip: onMac ? false : 'the macOS keychains' }, () => {
  it('are opened read-only, and a subject they lack is not found', async () => {
    for (const storeLocation of ['CurrentUser', 'LocalMachine']) {
      await assert.rejects(new CertificateOptionsLoader().load({ macOS: { storeLocation, subject: `CN=hkdfguard-node-test-${randomBytes(8).toString('hex')}` } }),
        (error: Error) => error instanceof CertificateNotFoundError && /holds no certificate/.test(error.message));
    }
  });

  it('read only the My store', () => {
    assert.throws(() => readMacKeychain('CurrentUser', 'Root'), UnsupportedCertificateError);
  });

  for (const [name, key] of [['RSA', rsaKey], ['ECDSA', ecKey]] as const) {
    it(`sign and decrypt with an ${name} identity through the Security framework`, { skip: optedIn ? false : OPT_IN }, async (t) => {
      const subject = identity(t, key());
      const loaded = await new CertificateOptionsLoader().load({ macOS: { storeLocation: 'CurrentUser', subject } });
      try {
        assert.equal(loaded.keyLocation, 'the macOS keychain');
        const data = Buffer.from('to sign');
        if (loaded.publicKey.asymmetricKeyType === 'rsa') {
          assert.ok(verify('sha256', data, loaded.publicKey, await loaded.sign('sha256', data)));
          const pss = { padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST };
          assert.ok(verify('sha256', data, { key: loaded.publicKey, ...pss }, await loaded.sign('sha256', data, pss)));
          await assert.rejects(loaded.sign('sha256', data, { padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 5 }), UnsupportedCertificateError);
          const pkcs1 = publicEncrypt({ key: loaded.publicKey, padding: constants.RSA_PKCS1_PADDING }, Buffer.from('secret'));
          // The store answers bad padding with an error of its own: PKCS #1 v1.5 decryption is refused before it is asked.
          await assert.rejects(loaded.decrypt(pkcs1, { padding: constants.RSA_PKCS1_PADDING }), UnsupportedCertificateError);
          const oaep = publicEncrypt({ key: loaded.publicKey, oaepHash: 'sha256' }, Buffer.from('secret'));
          assert.equal((await loaded.decrypt(oaep, { oaepHash: 'sha256' })).toString(), 'secret');
        } else {
          assert.ok(verify('sha256', data, loaded.publicKey, await loaded.sign('sha256', data)));
          const p1363 = await loaded.sign('sha384', data, { dsaEncoding: 'ieee-p1363' });
          assert.ok(verify('sha384', data, { key: loaded.publicKey, dsaEncoding: 'ieee-p1363' }, p1363));
        }
        assert.throws(() => loaded.createSecureContext(), NativeProviderRequiredError);
      } finally {
        await loaded.close();
      }
    });
  }
});

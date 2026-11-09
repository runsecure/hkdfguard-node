// The Windows certificate store itself: read-only always, and - with HKDFGUARD_TEST_WINDOWS_CERT_STORE=1 -
// a round trip through throwaway self-signed certificates New-SelfSignedCertificate makes in
// CurrentUser\My with non-exportable CNG keys, removed with their keys afterwards, however the test ends.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { constants, publicEncrypt, randomBytes, verify } from 'node:crypto';
import { describe, it, type TestContext } from 'node:test';
import { ClosedError } from '@runsecure/hkdfguard-abstractions';
import {
  CertificateNotFoundError, CertificateOptionsLoader, CertificateStoreError, NativeProviderRequiredError, StoreName, UnsupportedCertificateError,
  type CertificateOptions,
} from './index.js';
import { readWindowsStore, windowsStoreName } from './windows.js';
import { parseCertificate } from './x509.js';

const onWindows = process.platform === 'win32';
const optedIn = process.env.HKDFGUARD_TEST_WINDOWS_CERT_STORE === '1';
const OPT_IN = 'makes and removes certificates in CurrentUser\\My: set HKDFGUARD_TEST_WINDOWS_CERT_STORE=1';

function powershell(script: string): string {
  // Windows PowerShell 5.1 started from PowerShell 7 inherits PowerShell 7's PSModulePath, can't
  // load its own PKI module and so has no Cert: drive. Drop it so 5.1 uses its default.
  const env = { ...process.env };
  for (const name of Object.keys(env)) {
    if (name.toUpperCase() === 'PSMODULEPATH') {
      delete env[name];
    }
  }
  return execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { encoding: 'utf8', timeout: 120_000, env }).trim();
}

const options = (subject: string, requirePrivateKey = true): CertificateOptions => ({
  windows: { storeLocation: 'CurrentUser', storeName: 'My', subject }, requirePrivateKey,
});

/**
 * A self-signed certificate in CurrentUser\My with a non-exportable key of `keyAlgorithm` in the
 * Microsoft Software Key Storage Provider, removed with its key when the test ends; returns its subject.
 */
function throwaway(t: TestContext, keyAlgorithm: string): string {
  const subject = `CN=hkdfguard-node-test-${randomBytes(8).toString('hex')}`;
  const thumbprint = powershell("$ErrorActionPreference = 'Stop'; "
    + `$c = New-SelfSignedCertificate -Subject '${subject}' -CertStoreLocation Cert:/CurrentUser/My -KeyAlgorithm ${keyAlgorithm} `
    + "-KeyExportPolicy NonExportable -Provider 'Microsoft Software Key Storage Provider' -KeyUsage DigitalSignature,KeyEncipherment "
    + '-NotAfter (Get-Date).AddDays(2); $c.Thumbprint');
  assert.match(thumbprint, /^[0-9A-F]{40}$/);
  t.after(() => {
    powershell(`Remove-Item -Path Cert:/CurrentUser/My/${thumbprint} -DeleteKey -ErrorAction Stop`);
    assert.equal(powershell(`Test-Path Cert:/CurrentUser/My/${thumbprint}`), 'False');
  });
  return subject;
}

describe('the Windows certificate store', { skip: onWindows ? false : 'the Windows certificate store' }, () => {
  it('is opened read-only, and a subject it lacks is not found', async () => {
    await assert.rejects(new CertificateOptionsLoader().load(options(`CN=hkdfguard-node-test-${randomBytes(8).toString('hex')}`)),
      (error: Error) => error instanceof CertificateNotFoundError && /holds no certificate/.test(error.message));
  });

  it('opens every StoreName as a Windows system store, and a store that does not exist as empty', () => {
    for (const name of Object.values(StoreName)) {
      for (const entry of readWindowsStore('CurrentUser', name)) entry.close();
    }
    assert.equal(windowsStoreName('CertificateAuthority'), 'CA');
    assert.equal(windowsStoreName('My'), 'My');
    assert.deepEqual(readWindowsStore('CurrentUser', `hkdfguard-no-such-store-${randomBytes(4).toString('hex')}` as StoreName), []);
  });

  it('loads a root certificate for trust, without a key', async (t) => {
    const now = new Date();
    const roots = readWindowsStore('LocalMachine', 'Root');
    let subject: string | undefined;
    try {
      for (const root of roots) {
        try {
          const parsed = parseCertificate(root.der, 'root');
          if (parsed.notBefore <= now && now <= parsed.notAfter) {
            subject = parsed.subject.toString();
            break;
          }
        } catch {
          // a root this reader can't parse
        }
      }
    } finally {
      for (const root of roots) root.close();
    }
    if (subject === undefined) {
      t.skip('LocalMachine Root holds no root valid now');
      return;
    }
    const loaded = await new CertificateOptionsLoader().load({ windows: { storeLocation: 'LocalMachine', storeName: 'Root', subject }, requirePrivateKey: false });
    assert.equal(loaded.hasPrivateKey, false);
    assert.ok(loaded.createSecureContext());
    await loaded.close();
  });

  it('signs and decrypts with a non-exportable RSA key through CNG', { skip: optedIn ? false : OPT_IN }, async (t) => {
    const subject = throwaway(t, 'RSA -KeyLength 2048');
    const loaded = await new CertificateOptionsLoader().load(options(subject));
    try {
      assert.equal(loaded.keyLocation, 'the Windows certificate store');
      assert.equal(loaded.subject, subject);
      const data = Buffer.from('to sign');
      for (const hash of ['sha256', 'sha384', 'sha512', 'sha1'] as const) {
        assert.ok(verify(hash, data, loaded.publicKey, await loaded.sign(hash, data)), `PKCS #1 ${hash}`);
        for (const saltLength of [constants.RSA_PSS_SALTLEN_DIGEST, constants.RSA_PSS_SALTLEN_MAX_SIGN, 20]) {
          const signature = await loaded.sign(hash, data, { padding: constants.RSA_PKCS1_PSS_PADDING, saltLength });
          assert.ok(verify(hash, data, { key: loaded.publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_AUTO }, signature),
            `PSS ${hash} salt ${saltLength}`);
        }
      }
      await assert.rejects(loaded.sign('sha224', data), (error: Error) => error instanceof UnsupportedCertificateError && /SHA-224|sha224/.test(error.message));
      const pkcs1 = publicEncrypt({ key: loaded.publicKey, padding: constants.RSA_PKCS1_PADDING }, Buffer.from('secret'));
      // The store answers bad padding with an error of its own: PKCS #1 v1.5 decryption is refused before it is asked.
      await assert.rejects(loaded.decrypt(pkcs1, { padding: constants.RSA_PKCS1_PADDING }), UnsupportedCertificateError);
      for (const hash of ['sha1', 'sha256', 'sha512'] as const) {
        const oaep = publicEncrypt({ key: loaded.publicKey, oaepHash: hash, oaepLabel: Buffer.from('label') }, Buffer.from('secret'));
        assert.equal((await loaded.decrypt(oaep, { oaepHash: hash, oaepLabel: Buffer.from('label') })).toString(), 'secret', `OAEP ${hash}`);
      }
      await assert.rejects(loaded.decrypt(Buffer.alloc(256, 1)), CertificateStoreError);
      assert.throws(() => loaded.createSecureContext(), NativeProviderRequiredError);
      // Operations in flight together, then a close that waits for them.
      const signatures = Array.from({ length: 8 }, () => loaded.sign('sha256', data));
      const closing = loaded.close();
      for (const signature of await Promise.all(signatures)) assert.ok(verify('sha256', data, loaded.publicKey, signature));
      await closing;
      await assert.rejects(loaded.sign('sha256', data), ClosedError);
    } finally {
      await loaded.close();
    }
  });

  it('signs with a non-exportable ECDSA key through CNG, in DER or IEEE P1363', { skip: optedIn ? false : OPT_IN }, async (t) => {
    const subject = throwaway(t, 'ECDSA_nistP256');
    const loaded = await new CertificateOptionsLoader().load(options(subject));
    try {
      const data = Buffer.from('to sign');
      for (const hash of ['sha256', 'sha384', 'sha512', 'sha1'] as const) {
        assert.ok(verify(hash, data, loaded.publicKey, await loaded.sign(hash, data)), hash);
        const p1363 = await loaded.sign(hash, data, { dsaEncoding: 'ieee-p1363' });
        assert.equal(p1363.length, 64);
        assert.ok(verify(hash, data, { key: loaded.publicKey, dsaEncoding: 'ieee-p1363' }, p1363), `${hash} P1363`);
      }
      await assert.rejects(loaded.decrypt(Buffer.alloc(64)), UnsupportedCertificateError);
    } finally {
      await loaded.close();
    }
  });

  it('loads the certificate alone without opening its key', { skip: optedIn ? false : OPT_IN }, async (t) => {
    const subject = throwaway(t, 'RSA -KeyLength 2048');
    const loaded = await new CertificateOptionsLoader().load(options(subject, false));
    assert.equal(loaded.hasPrivateKey, false);
    assert.ok(loaded.createSecureContext());
    await loaded.close();
  });
});

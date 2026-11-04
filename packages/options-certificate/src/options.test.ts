import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { certificateOptionsFromJson, certificateOptionsFromObject, InvalidCertificateOptionsError, type CertificateOptions } from './index.js';
import { CertificateOptionsValidator } from './validator.js';

describe('certificateOptionsFromJson', () => {
  it('binds the documented .NET shapes', () => {
    const windows = certificateOptionsFromJson('{"Certificate": {"Windows": {"StoreLocation": "LocalMachine", "StoreName": "My", "Subject": "CN=api.example.com"}}}');
    assert.deepEqual(windows, { windows: { storeLocation: 'LocalMachine', storeName: 'My', subject: 'CN=api.example.com' } });
    const macOS = certificateOptionsFromJson('{"Certificate": {"MacOS": {"StoreLocation": "LocalMachine", "Subject": "CN=api.example.com"}}}');
    assert.deepEqual(macOS, { macOS: { storeLocation: 'LocalMachine', subject: 'CN=api.example.com' } });
    const linux = certificateOptionsFromJson(
      '{"Certificate": {"Linux": {"Provider": "pkcs11", "KeyUri": "pkcs11:token=tls;object=api;type=private", "CertificateFile": "/etc/myapp/tls.crt"}}}');
    assert.deepEqual(linux, { linux: { provider: 'pkcs11', keyUri: 'pkcs11:token=tls;object=api;type=private', certificateFile: '/etc/myapp/tls.crt' } });
    const file = certificateOptionsFromJson('{"Certificate": {"File": {"Path": "/etc/myapp/tls.pfx", "PasswordSecretName": "tls-pfx-password"}}}');
    assert.deepEqual(file, { file: { path: '/etc/myapp/tls.pfx', passwordSecretName: 'tls-pfx-password' } });
  });

  it('reads a nested section, ignoring case, and the whole document for ""', () => {
    const document = '{"kestrel": {"CERTIFICATE": {"file": {"path": "/x.pfx", "format": "pem", "keyPath": "/x.key", "allowUnprotectedPrivateKey": "TRUE"}, "requirePrivateKey": false}}}';
    assert.deepEqual(certificateOptionsFromJson(document, 'Kestrel:Certificate'), {
      file: { path: '/x.pfx', format: 'Pem', keyPath: '/x.key', allowUnprotectedPrivateKey: true }, requirePrivateKey: false,
    });
    assert.deepEqual(certificateOptionsFromJson('{"windows": {"subject": "CN=a"}}', ''), { windows: { subject: 'CN=a' } });
  });

  it('takes camelCase as well as .NET keys', () => {
    assert.deepEqual(certificateOptionsFromObject({ macOS: { storeLocation: 'currentuser', subject: 'CN=a' } }),
      { macOS: { storeLocation: 'CurrentUser', subject: 'CN=a' } });
  });

  it("takes .NET's enum numbers, and keeps an unknown enum for the validator to report", () => {
    assert.deepEqual(certificateOptionsFromObject({ Windows: { StoreLocation: 1, StoreName: '6', Subject: 'CN=a' } }),
      { windows: { storeLocation: 'CurrentUser', storeName: 'Root', subject: 'CN=a' } });
    assert.deepEqual(certificateOptionsFromObject({ File: { Path: '/a', Format: 1 } }), { file: { path: '/a', format: 'Pem' } });
    const options = certificateOptionsFromObject({ Windows: { StoreLocation: 'Elsewhere', StoreName: 42, Subject: 'CN=a' } });
    assert.deepEqual(options.windows, { storeLocation: 'Elsewhere', storeName: '42', subject: 'CN=a' });
    const failures = new CertificateOptionsValidator('windows').validate(options);
    assert.ok(failures.some((f) => f.includes('StoreLocation must be CurrentUser or LocalMachine, not Elsewhere')));
    assert.ok(failures.some((f) => f.includes('StoreName must be')));
  });

  it('leaves a null value unset', () => {
    assert.deepEqual(certificateOptionsFromObject({ File: { Path: '/a', KeyPath: null }, Windows: null }), { file: { path: '/a' } });
  });

  it('refuses an unknown key, a key given twice, and a value of the wrong type, naming the key but never the value', () => {
    const refuses = (settings: unknown, pattern: RegExp) => assert.throws(() => certificateOptionsFromObject(settings),
      (error: Error & { code?: string }) => error.code === 'ERR_HKDFGUARD_INVALID_OPTIONS_JSON' && pattern.test(error.message));
    refuses({ Windws: {} }, /unknown key 'Windws'.*Known keys: Windows, MacOS, Linux, File, RequirePrivateKey/);
    refuses({ File: { Path: '/a', Password: 'hunter2' } }, /'Certificate:File' has an unknown key 'Password'/);
    refuses({ File: { Path: '/a', path: '/b' } }, /gives 'Path' more than once/);
    refuses({ File: { Path: 42 } }, /'Certificate:File:Path' must be a string, got an integer/);
    refuses({ RequirePrivateKey: 'maybe' }, /must be true or false/);
    refuses({ Windows: 'CN=a' }, /'Certificate:Windows' must be an object/);
    refuses([], /'Certificate' must be an object/);
    try {
      certificateOptionsFromObject({ File: { PasswordSecretName: 12345678 } });
    } catch (error) {
      assert.doesNotMatch((error as Error).message, /12345678/);
    }
  });

  it('refuses bad JSON and a missing section', () => {
    assert.throws(() => certificateOptionsFromJson('{'), /invalid JSON/);
    assert.throws(() => certificateOptionsFromJson('{"Other": {}}'), /has no 'Certificate' section/);
  });

  it('has the safe defaults: a private key required, LocalMachine My, PKCS#12, tpm2, no unprotected key', () => {
    const options: CertificateOptions = { file: { path: process.platform === 'win32' ? 'C:\\etc\\tls.pfx' : '/etc/tls.pfx' } };
    const failures = new CertificateOptionsValidator('linux').validate(options);
    assert.deepEqual(failures, ['File.PasswordSecretName is required: a private key file must be protected by a password, read from a protected secret. '
      + 'Set File.AllowUnprotectedPrivateKey to accept a plaintext key, for development only.']);
  });
});

describe('InvalidCertificateOptionsError', () => {
  it('lists every failure and names the options', () => {
    const error = new InvalidCertificateOptionsError(['a', 'b'], 'tls');
    assert.equal(error.code, 'ERR_HKDFGUARD_INVALID_CERTIFICATE_OPTIONS');
    assert.equal(error.message, "The certificate options 'tls' are invalid:\n  a\n  b");
    assert.deepEqual(error.failures, ['a', 'b']);
  });
});

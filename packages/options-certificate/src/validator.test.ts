import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { CertificateOptionsValidator, currentPlatform, InvalidCertificateOptionsError, validateCertificateOptions, type CertificateOptions } from './index.js';

const store = { storeLocation: 'LocalMachine', storeName: 'My', subject: 'CN=api.example.com' };
// A path is judged by the host's rules, as .NET judges it: these are absolute on the host the tests run on.
const onWindows = process.platform === 'win32';
const abs = (name: string) => (onWindows ? `C:\\certs\\${name}` : `/etc/certs/${name}`);

const VALID: [string, CertificateOptions][] = [
  ['windows', { windows: store }],
  ['macos', { macOS: { storeLocation: 'CurrentUser', subject: 'CN=api.example.com' } }],
  ['linux', { linux: { provider: 'pkcs11', keyUri: 'pkcs11:token=t;object=k', certificateFile: abs('tls.crt') } }],
  ['linux', { linux: { keyUri: abs('tls-key.pem'), certificateFile: abs('tls.crt') } }],
  ['windows', { file: { path: abs('tls.pfx'), passwordSecretName: 'pw' } }],
  ['linux', { file: { path: abs('tls.pfx'), passwordSecretName: 'pw' } }],
  ['macos', { file: { path: abs('tls.crt'), format: 'Pem', keyPath: abs('tls.key'), passwordSecretName: 'pw' } }],
];

describe('CertificateOptionsValidator', () => {
  for (const [platform, options] of VALID) {
    it(`accepts ${Object.keys(options)[0]} on ${platform}`, () => {
      assert.deepEqual(new CertificateOptionsValidator(platform).validate(options), []);
    });
  }

  it('refuses a native source on another platform', () => {
    for (const [source, options, platform] of [['Windows', { windows: store }, 'linux'], ['MacOS', { macOS: store }, 'windows'],
      ['Linux', { linux: { keyUri: 'pkcs11:x', certificateFile: abs('a') } }, 'macos']] as const) {
      const failures = new CertificateOptionsValidator(platform).validate(options);
      assert.ok(failures.includes(`The ${source} certificate source can only be used on ${source}; this is ${platform === 'macos' ? 'macOS' : platform === 'linux' ? 'Linux' : 'Windows'}.`),
        failures.join('\n'));
    }
  });

  it('names an unknown platform as it is', () => {
    assert.ok(new CertificateOptionsValidator('freebsd').validate({ windows: store }).includes('The Windows certificate source can only be used on Windows; this is freebsd.'));
  });

  it('refuses no source, or more than one', () => {
    assert.deepEqual(new CertificateOptionsValidator('windows').validate({}), ['One certificate source is required: Windows, MacOS, Linux or File.']);
    const failures = new CertificateOptionsValidator('windows').validate({ windows: store, file: { path: abs('tls.pfx'), passwordSecretName: 'pw' } });
    assert.ok(failures.includes('Only one certificate source can be set, but Windows, File are.'));
  });

  it('takes a subject that is a distinguished name, and nothing else', () => {
    const validator = new CertificateOptionsValidator('windows');
    for (const subject of ['CN=api.example.com', 'CN=api.example.com, O=Contoso', 'CN="a, b" + OU=x; O=y', 'OID.2.5.4.3=x', '2.5.4.3=x']) {
      assert.deepEqual(validator.validate({ windows: { subject } }), [], subject);
    }
    for (const subject of [undefined, '', '   ']) {
      assert.ok(validator.validate({ windows: { ...(subject === undefined ? {} : { subject }) } }).some((f) => f.startsWith('Windows.Subject is required')));
    }
    for (const subject of ['api.example.com', 'XX=a', 'CN="unterminated', 'CN=a\\']) {
      assert.ok(validator.validate({ windows: { subject } }).some((f) => f.startsWith('Windows.Subject must be a distinguished name')), subject);
    }
  });

  it('refuses a store location or name that is not one', () => {
    const failures = new CertificateOptionsValidator('windows').validate({ windows: { storeLocation: 'Nowhere', storeName: 'Mine', subject: 'CN=a' } });
    assert.ok(failures.includes('Windows.StoreLocation must be CurrentUser or LocalMachine, not Nowhere.'));
    assert.ok(failures.some((f) => f.startsWith('Windows.StoreName must be a store\'s name')));
  });

  it('reads only the My store on macOS', () => {
    assert.ok(new CertificateOptionsValidator('macos').validate({ macOS: { storeName: 'Root', subject: 'CN=a' } })
      .includes('MacOS.StoreName must be My - the keychain itself, the only store this port reads on macOS - not Root.'));
    // Elsewhere the platform failure says enough.
    assert.ok(!new CertificateOptionsValidator('windows').validate({ macOS: { storeName: 'Root', subject: 'CN=a' } }).some((f) => f.startsWith('MacOS.StoreName')));
  });

  it("takes a Linux provider's name, with hyphens and underscores, and nothing else", () => {
    const validator = new CertificateOptionsValidator('linux');
    for (const provider of ['tpm2', 'pkcs11', 'my-provider_2']) {
      assert.deepEqual(validator.validate({ linux: { provider, keyUri: 'pkcs11:x', certificateFile: abs('a') } }), []);
    }
    for (const provider of ['', 'a b', '../evil', 'tpm2;rm']) {
      assert.ok(validator.validate({ linux: { provider, keyUri: 'pkcs11:x', certificateFile: abs('a') } }).some((f) => f.startsWith('Linux.Provider must be')), provider);
    }
  });

  it('needs a Linux key only with a private key', () => {
    const validator = new CertificateOptionsValidator('linux');
    assert.ok(validator.validate({ linux: { certificateFile: abs('a') } }).some((f) => f.startsWith('Linux.KeyUri is required')));
    assert.deepEqual(validator.validate({ linux: { certificateFile: abs('a') }, requirePrivateKey: false }), []);
  });

  it('refuses a TPM handle or a relative key on Linux, as Node reads a provider key only from PEM', () => {
    const validator = new CertificateOptionsValidator('linux');
    const handle = validator.validate({ linux: { keyUri: 'handle:0x81000001', certificateFile: abs('a') } });
    assert.ok(handle.some((f) => f.includes('persistent TPM handle') && f.includes('TSS2 PRIVATE KEY')), handle.join('\n'));
    assert.ok(validator.validate({ linux: { keyUri: 'keys/tls.pem', certificateFile: abs('a') } }).some((f) => f.startsWith('Linux.KeyUri must be')));
    assert.deepEqual(validator.validate({ linux: { keyUri: `file:${abs('tls-key.pem')}`, certificateFile: abs('a') } }), []);
  });

  it("needs absolute paths, by the host's rules", () => {
    const validator = new CertificateOptionsValidator('linux');
    const relative = onWindows ? ['tls.pfx', '\\tls.pfx', 'C:tls.pfx', '/tls.pfx'] : ['tls.pfx', './tls.pfx', 'C:\\tls.pfx'];
    for (const path of relative) {
      assert.ok(validator.validate({ file: { path, passwordSecretName: 'pw' } }).includes(`File.Path must be an absolute path, not '${path}'.`), path);
    }
    const absolute = onWindows ? ['C:\\tls.pfx', 'c:/tls.pfx', '\\\\server\\share\\tls.pfx', '\\\\?\\C:\\tls.pfx'] : ['/tls.pfx', '/etc/x/../tls.pfx'];
    for (const path of absolute) assert.deepEqual(validator.validate({ file: { path, passwordSecretName: 'pw' } }), [], path);
    assert.ok(validator.validate({ file: { passwordSecretName: 'pw' } }).includes('File.Path is required.'));
  });

  it('needs a PEM key path only with a private key', () => {
    const validator = new CertificateOptionsValidator('linux');
    assert.ok(validator.validate({ file: { path: abs('a.crt'), format: 'Pem', passwordSecretName: 'pw' } }).includes('File.KeyPath is required.'));
    assert.deepEqual(validator.validate({ file: { path: abs('a.crt'), format: 'Pem' }, requirePrivateKey: false }), []);
  });

  it('refuses a file format that is not one', () => {
    assert.ok(new CertificateOptionsValidator('linux').validate({ file: { path: abs('a'), format: 'Der', passwordSecretName: 'pw' } })
      .includes('File.Format must be Pkcs12 or Pem, not Der.'));
  });

  it('needs a key file password unless an unprotected key is allowed', () => {
    const validator = new CertificateOptionsValidator('linux');
    assert.ok(validator.validate({ file: { path: abs('a.pfx') } }).some((f) => f.startsWith('File.PasswordSecretName is required')));
    assert.deepEqual(validator.validate({ file: { path: abs('a.pfx'), allowUnprotectedPrivateKey: true } }), []);
    assert.deepEqual(validator.validate({ file: { path: abs('a.pfx') }, requirePrivateKey: false }), []);
  });

  it('refuses an empty password secret name', () => {
    for (const passwordSecretName of ['', '  ']) {
      assert.ok(new CertificateOptionsValidator('linux').validate({ file: { path: abs('a.pfx'), passwordSecretName, allowUnprotectedPrivateKey: true } })
        .includes("File.PasswordSecretName can't be empty: name the secret holding the key's password, or leave it unset."));
    }
  });

  it('reports every failure at once, and the error names the options', () => {
    const options: CertificateOptions = { windows: { storeLocation: 'x', subject: '' }, file: { path: 'relative' } };
    const validator = new CertificateOptionsValidator('linux');
    const failures = validator.validate(options);
    assert.ok(failures.length >= 5, failures.join('\n'));
    assert.throws(() => validator.requireValid(options, 'tls'), (error: InvalidCertificateOptionsError) =>
      error instanceof InvalidCertificateOptionsError && error.optionsName === 'tls' && error.failures.length === failures.length);
  });

  it('judges the running platform, and refuses what isn\'t options', () => {
    assert.equal(new CertificateOptionsValidator().platform, currentPlatform());
    assert.deepEqual(validateCertificateOptions({ file: { path: abs('tls.pfx'), passwordSecretName: 'pw' } }), []);
    assert.throws(() => new CertificateOptionsValidator().validate(null as unknown as CertificateOptions), TypeError);
  });
});

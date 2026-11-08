// A Linux OpenSSL provider key: the key file Node's OpenSSL reads through the provider's decoder, and -
// with HKDFGUARD_TEST_OPENSSL_PROVIDER=<provider>, HKDFGUARD_TEST_OPENSSL_PROVIDER_KEY_URI and
// HKDFGUARD_TEST_OPENSSL_PROVIDER_CERTIFICATE set - a real TLS handshake through it, signed by the TPM
// or the token, and signatures (and, for an RSA key, OAEP decryption, when the token can) made by it.
// Run under a Node started with --openssl-config naming a configuration that activates the provider,
// with the provider's own settings (TPM2OPENSSL_TCTI, SOFTHSM2_CONF...) in the environment; see
// docs/how-to/use-certificate-options.md.
import assert from 'node:assert/strict';
import { constants, publicEncrypt, verify } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { createServer } from 'node:tls';
import { certificate, ecKey, FILE_TRUST, handshake, loader, pem, trustedDirectory } from './certificates.test-support.js';
import * as der from './der.js';
import {
  CertificateOptionsLoader, InvalidCertificateFileError, OpenSslProviderUnavailableError, UnsupportedCertificateError, type CertificateOptions,
} from './index.js';
import { decodeBase64, pemBlocks } from './pem.js';
import { pkcs11UriPem } from './provider.js';

// Where the files the tests write go: a folder readTrustedFile trusts, or none, with those tests skipped.
const { directory, skip, cleanUp } = trustedDirectory('hkdfguard-certificate-provider-');
after(cleanUp);

describe('Linux OpenSSL provider keys', () => {
  it("writes a pkcs11: URI as pkcs11-provider's URI PEM", () => {
    const text = pkcs11UriPem('pkcs11:token=hkdfguard;object=tls;type=private');
    assert.ok(text.toString('latin1').startsWith('-----BEGIN PKCS#11 PROVIDER URI-----\n'));
    assert.ok(text.toString('latin1').endsWith('-----END PKCS#11 PROVIDER URI-----\n'));
    const [block] = pemBlocks(text, (problem) => new Error(problem));
    const [description, uri] = der.sequence(der.read(decodeBase64(block!.body, (problem) => new Error(problem))), 'uri', 2, 2);
    assert.equal(description!.tag, 0x1a);
    assert.equal(description!.contents.toString(), 'PKCS#11 Provider URI v1.0');
    assert.equal(uri!.tag, der.UTF8_STRING);
    assert.equal(uri!.contents.toString(), 'pkcs11:token=hkdfguard;object=tls;type=private');
  });

  it("refuses at load time a provider key this Node's OpenSSL can't decode", { skip }, async () => {
    // A Node without the provider configured - as this test's is, unless it was started with one - has
    // no decoder for a TSS2 key or a PKCS#11 URI.
    const certificatePath = join(directory!,'tls.crt');
    writeFileSync(certificatePath, pem(certificate(ecKey())));
    const keyPath = join(directory!,'tls-key.pem');
    writeFileSync(keyPath, '-----BEGIN TSS2 PRIVATE KEY-----\nAAAA\n-----END TSS2 PRIVATE KEY-----\n');
    for (const keyUri of [keyPath, 'pkcs11:token=hkdfguard-no-such-token;object=none;type=private']) {
      await assert.rejects(loader({ platform: 'linux' }).load({ linux: { provider: 'tpm2', keyUri, certificateFile: certificatePath } }),
        (error: Error) => error instanceof UnsupportedCertificateError, keyUri);
    }
    if (process.env.HKDFGUARD_TEST_OPENSSL_PROVIDER === undefined) {
      await assert.rejects(loader({ platform: 'linux' }).load({ linux: { provider: 'tpm2', keyUri: keyPath, certificateFile: certificatePath } }),
        (error: Error) => error instanceof OpenSslProviderUnavailableError && error.code === 'ERR_HKDFGUARD_OPENSSL_PROVIDER_UNAVAILABLE'
          && /--openssl-config/.test(error.message));
    }
  });

  it('refuses a key file OpenSSL would read into the process', { skip }, async () => {
    const certificatePath = join(directory!,'plain.crt');
    writeFileSync(certificatePath, pem(certificate(ecKey())));
    const keyPath = join(directory!,'plain-key.pem');
    writeFileSync(keyPath, ecKey().privateKey.export({ format: 'pem', type: 'pkcs8' }));
    await assert.rejects(loader({ platform: 'linux' }).load({ linux: { keyUri: keyPath, certificateFile: certificatePath } }),
      (error: Error) => error instanceof InvalidCertificateFileError && /a key OpenSSL would read into the process/.test(error.message));
  });
});

const provider = process.env.HKDFGUARD_TEST_OPENSSL_PROVIDER;

const realOptions = (requirePrivateKey = true): CertificateOptions => ({
  linux: { provider: provider!, keyUri: process.env.HKDFGUARD_TEST_OPENSSL_PROVIDER_KEY_URI!, certificateFile: process.env.HKDFGUARD_TEST_OPENSSL_PROVIDER_CERTIFICATE! },
  requirePrivateKey,
});

describe('a real OpenSSL provider key', {
  skip: provider === undefined ? 'set HKDFGUARD_TEST_OPENSSL_PROVIDER, HKDFGUARD_TEST_OPENSSL_PROVIDER_KEY_URI and HKDFGUARD_TEST_OPENSSL_PROVIDER_CERTIFICATE' : false,
}, () => {
  it('serves TLS handshakes, and signs, through the provider', async () => {
    const loaded = await new CertificateOptionsLoader({ fileTrust: FILE_TRUST }).load(realOptions());
    const trusted = await new CertificateOptionsLoader({ fileTrust: FILE_TRUST }).load(realOptions(false));
    try {
      assert.equal(loaded.keyLocation, `the OpenSSL provider '${provider}'`);
      // The provisioning scripts' certificates name whatever they were given, not this host. Each
      // context decodes the key through the provider again - a TPM object each, which a TPM with no
      // resource manager (swtpm over TCP) holds only two of at once, freed only when V8 collects the
      // context - so one server, configured once, serves both handshakes.
      const clientContext = trusted.createSecureContext();
      const checks = { servername: 'localhost', checkHostname: false };
      const server = createServer();
      loaded.configureServer(server);
      try {
        for (let i = 0; i < 2; i++) {
          assert.ok((await handshake(server, clientContext, checks)).serverCertificate.equals(loaded.certificate.raw));
        }
      } finally {
        await new Promise((resolve) => server.close(resolve));
      }
      const data = Buffer.from('to sign');
      assert.ok(verify('sha256', data, loaded.publicKey, await loaded.sign('sha256', data)), 'sign');
      if (loaded.publicKey.asymmetricKeyType === 'rsa') {
        const pss = { padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST };
        assert.ok(verify('sha384', data, { key: loaded.publicKey, ...pss }, await loaded.sign('sha384', data, pss)), 'PSS');
        if (process.env.HKDFGUARD_TEST_OPENSSL_PROVIDER_OAEP !== '0') {
          const oaep = publicEncrypt({ key: loaded.publicKey, oaepHash: 'sha256' }, Buffer.from('secret'));
          assert.equal((await loaded.decrypt(oaep, { oaepHash: 'sha256' })).toString(), 'secret');
        }
        // Node does PKCS #1 v1.5 decryption only with implicit rejection, which a provider key can't do.
        const pkcs1 = publicEncrypt({ key: loaded.publicKey, padding: constants.RSA_PKCS1_PADDING }, Buffer.from('secret'));
        await assert.rejects(loaded.decrypt(pkcs1, { padding: constants.RSA_PKCS1_PADDING }), UnsupportedCertificateError);
      } else {
        const p1363 = await loaded.sign('sha384', data, { dsaEncoding: 'ieee-p1363' });
        assert.ok(verify('sha384', data, { key: loaded.publicKey, dsaEncoding: 'ieee-p1363' }, p1363), 'P1363');
      }
    } finally {
      await loaded.close();
      await trusted.close();
    }
  });
});

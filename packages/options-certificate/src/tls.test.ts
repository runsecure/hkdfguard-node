// TLS handshakes with file keys, over a local node:tls server: a server presenting the certificate
// and chain a PKCS#12 or PEM file gives (configureServer, and an SNICallback's context), a client
// that trusts it alone, and client authentication.
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import {
  certificate, ecKey, FakePasswords, fixture, fixtureCertificateDer, handshake, loader, pem, pemOptions, pfxOptions, pkcs12, rsaKey, trustedDirectory, utf8,
} from './certificates.test-support.js';
import { createServer, type Server } from 'node:tls';
import { ClosedError, InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';
import { NoPrivateKeyError } from './index.js';

// Where the files the tests write go: a folder readTrustedFile trusts, or none, with the tests skipped.
const { directory, skip, cleanUp } = trustedDirectory('hkdfguard-certificate-tls-');
after(cleanUp);

const realNow = {};

describe('createSecureContext with a file key', { skip }, () => {
  for (const [file, certificateFile] of [['openssl-aes.pfx', 'rsa.crt'], ['openssl-ec.pfx', 'ec.crt'], ['dotnet-default.pfx', 'rsa.crt']] as const) {
    it(`serves a TLS handshake from ${file}, to a client trusting the certificate alone`, async () => {
      const server = await loader({ passwords: new FakePasswords(), ...realNow }).load(pfxOptions(fixture(file)));
      // The certificate alone, from its PEM file: a PKCS#12 file's key is loaded even when none is required, as .NET loads it.
      const trusted = await loader(realNow).load(pemOptions(fixture(certificateFile), undefined, null, { requirePrivateKey: false }));
      const { serverCertificate } = await handshake((s) => server.configureServer(s), trusted.createSecureContext());
      assert.ok(serverCertificate.equals(server.certificate.raw));
      await server.close();
      await trusted.close();
    });
  }

  it('serves the chain of a PEM file with an encrypted key, and authenticates a client', async () => {
    const caKey = rsaKey(1);
    const ca = certificate(caKey, { subject: 'CN=Test CA', now: new Date(), notAfterDays: 2 });
    const serverLeaf = certificate(ecKey(), { issuer: { key: caKey, name: 'CN=Test CA' }, ca: false, now: new Date(), notAfterDays: 2 });
    const clientLeaf = certificate(rsaKey(), { subject: 'CN=client.example.com', issuer: { key: caKey, name: 'CN=Test CA' }, ca: false, now: new Date(), notAfterDays: 2 });
    const write = (name: string, data: Buffer | string) => {
      const path = join(directory!, name);
      writeFileSync(path, data);
      return path;
    };
    const serverCertificatePath = write('server.crt', pem(serverLeaf, ca));
    const serverKeyPath = write('server.key', ecKey().privateKey.export({ format: 'pem', type: 'pkcs8', cipher: 'aes-256-cbc', passphrase: utf8() }));
    const clientPath = write('client.pfx', pkcs12({ keys: [rsaKey().privateKey], certificates: [clientLeaf, ca], password: utf8() }));
    const caPath = write('ca.crt', pem(ca));

    const server = await loader({ passwords: new FakePasswords(), ...realNow }).load(pemOptions(serverCertificatePath, serverKeyPath));
    const client = await loader({ passwords: new FakePasswords(), ...realNow }).load(pfxOptions(clientPath));
    const trust = await loader(realNow).load(pemOptions(caPath, undefined, null, { requirePrivateKey: false }));
    const caPem = pem(ca);
    const result = await handshake((s) => server.configureServer(s, { ca: caPem, minVersion: 'TLSv1.3' }), client.createSecureContext({ ca: caPem }),
      { clientCertificate: true });
    assert.ok(result.serverCertificate.equals(serverLeaf));
    assert.ok(result.clientCertificate?.equals(clientLeaf));
    // A client trusting the CA alone, through a certificate loaded without its key.
    const again = await handshake((s) => server.configureServer(s), trust.createSecureContext());
    assert.ok(again.serverCertificate.equals(serverLeaf));
    // A context for an SNICallback; each keeps its own copy of the key, and outlives close().
    const context = server.createSecureContext();
    await server.close();
    assert.ok((await handshake(() => {}, trust.createSecureContext(), { sni: context })).serverCertificate.equals(serverLeaf));
    assert.throws(() => server.configureServer(createServer()), ClosedError);
    await client.close();
    await trust.close();
  });

  it("refuses options that are the certificate's own to set", async () => {
    const loaded = await loader({ passwords: new FakePasswords(), ...realNow }).load(pfxOptions(fixture('openssl-ec.pfx')));
    for (const name of ['key', 'cert', 'pfx', 'passphrase', 'privateKeyEngine', 'privateKeyIdentifier']) {
      assert.throws(() => loaded.createSecureContext({ [name]: 'x' }), InvalidArgumentError, name);
    }
    const trusted = await loader(realNow).load(pemOptions(fixture('ec.crt'), undefined, null, { requirePrivateKey: false }));
    assert.throws(() => trusted.createSecureContext({ ca: 'x' }), InvalidArgumentError);
    assert.throws(() => trusted.configureServer(createServer()), NoPrivateKeyError);
    assert.throws(() => loaded.configureServer({} as Server), InvalidArgumentError);
    assert.ok(trusted.certificate.raw.equals(fixtureCertificateDer('ec.crt')));
    await loaded.close();
    await trusted.close();
  });
});

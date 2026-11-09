import { strict as assert } from 'node:assert';
import { createHmac, createPrivateKey, randomBytes } from 'node:crypto';
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { Agent as HttpsAgent, createServer, get, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { TLSSocket } from 'node:tls';
import { once } from 'node:events';
import { afterEach, describe, it } from 'node:test';
import { InvalidArgumentError, type DataProtector } from '@runsecure/hkdfguard-abstractions';
import { KeyRing } from '@runsecure/hkdfguard-dek';
import { KeyFileTrust } from '@runsecure/hkdfguard-securefile';
import { linuxKeyFileRoot, RecordingKey, trustedFixtureCopy, windowsCurrentUserSid } from '@runsecure/hkdfguard-test-support';
import { apiBase, checkTlsOptions } from './connection.js';
import { createVaultAgent as createVaultAgentAsGiven, VaultConnector } from './http.js';
import { pkcs12 } from '@runsecure/hkdfguard-abstractions/internal';
import { UNVERIFIED_WARNING_CODE, VaultTlsOptions } from './tls.js';

/**
 * The account running the tests, besides administrators: it owns the fixtures in this checkout and
 * the files the tests write, which the trusted-file checks otherwise refuse.
 */
const FILE_TRUST = process.platform === 'win32'
  ? new KeyFileTrust({ windowsPrincipals: [windowsCurrentUserSid()] })
  : new KeyFileTrust({ unixUserIds: [process.geteuid!()], unixGroupIds: [process.getegid!()] });

/** createVaultAgent, trusting the test account's files unless the options say otherwise. */
const createVaultAgent = (tls: VaultTlsOptions, options?: Parameters<typeof createVaultAgentAsGiven>[1]) =>
  createVaultAgentAsGiven({ fileTrust: FILE_TRUST, ...tls }, options);

// Where the tests write files: never under Linux's /tmp, which every user can write, so the
// trusted-file checks would refuse anything in it (test-support's private root instead).
const scratchRoot = () => (process.platform === 'linux' ? linuxKeyFileRoot().root ?? tmpdir() : tmpdir());

// Made by test-fixtures/generate.sh: throwaway keys, trusted nowhere else. Read from a private copy,
// since the checkout's folder may not pass the trusted-file checks (see trustedFixtureCopy).
const FIXTURES = trustedFixtureCopy(join(__dirname, '..', 'test-fixtures'));
const fixture = (name: string) => join(FIXTURES, name);
const PASSWORD = 'store-pass-1';

const cleanups: (() => void)[] = [];
afterEach(() => {
  for (const cleanup of cleanups.splice(0).reverse()) cleanup();
});

function makeProtector(): DataProtector {
  const ring = new KeyRing();
  ring.add(1, new RecordingKey());
  return ring.createProtector(VaultTlsOptions.PASSWORD_PURPOSE);
}

const protector = makeProtector();
const protectedPassword = VaultTlsOptions.protectPassword(protector, PASSWORD);

// A trust store and client key store, each with the password protected.
const trustStore = (file = 'truststore.p12'): VaultTlsOptions => ({
  trustStoreFile: fixture(file), trustStorePassword: protectedPassword, passwordProtector: protector, serverName: 'vault.test', fileTrust: FILE_TRUST,
});
const keyStore = (file: string, alias?: string): VaultTlsOptions => ({
  ...trustStore(), clientKeyStoreFile: fixture(file), clientKeyStorePassword: protectedPassword, clientKeyStoreAlias: alias,
});

interface Answer {
  readonly authorized: boolean;
  readonly client: string | undefined;
}

// An https server for vault.test, signed by the test CA, asking for - and, if `requireClient`,
// requiring - a client certificate chaining to that CA. Answers with whom it saw.
async function startServer(requireClient = false): Promise<number> {
  const server: Server = createServer({
    key: readFileSync(fixture('server.key')), cert: readFileSync(fixture('server.pem')), ca: readFileSync(fixture('ca.pem')),
    requestCert: true, rejectUnauthorized: requireClient,
  }, (request, response) => {
    const socket = request.socket as TLSSocket;
    const peer = socket.getPeerCertificate();
    const answer: Answer = { authorized: socket.authorized, client: peer?.subject?.CN as string | undefined };
    response.end(JSON.stringify(answer));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  cleanups.push(() => server.close());
  return (server.address() as AddressInfo).port;
}

function call(agent: HttpsAgent, port: number): Promise<Answer> {
  cleanups.push(() => agent.destroy());
  return new Promise((resolve, reject) => {
    get({ hostname: '127.0.0.1', port, path: '/', agent }, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk: string) => { body += chunk; });
      response.on('end', () => resolve(JSON.parse(body) as Answer));
    }).on('error', reject);
  });
}

const refused = (pattern: RegExp) => (error: unknown) => error instanceof InvalidArgumentError && pattern.test(error.message);

// --- PKCS#12 stores these tests write: DER, enough of it for a PFX. ---

function tlv(tag: number, ...parts: Buffer[]): Buffer {
  const body = Buffer.concat(parts);
  const n = body.length;
  const length = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : n < 0x10000 ? [0x82, n >> 8, n & 0xff] : [0x83, n >> 16, (n >> 8) & 0xff, n & 0xff];
  return Buffer.concat([Buffer.from([tag, ...length]), body]);
}
const oidTlv = (hex: string) => tlv(0x06, Buffer.from(hex, 'hex'));
const DATA = '2a864886f70d010701';
const dataInfo = (contents: Buffer) => tlv(0x30, oidTlv(DATA), tlv(0xa0, tlv(0x04, contents)));
const bag = (type: string, value: Buffer) => tlv(0x30, oidTlv(type), tlv(0xa0, value));
const certificateBag = (der: Buffer) => bag('2a864886f70d010c0a0103', tlv(0x30, oidTlv('2a864886f70d01091601'), tlv(0xa0, tlv(0x04, der))));
const pemDer = (file: string) => Buffer.from(readFileSync(fixture(file), 'latin1').replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''), 'base64');

// The encodings of the elements of the one DER SEQUENCE `der` is.
function elements(der: Buffer): Buffer[] {
  const span = (offset: number) => {
    let start = offset + 2;
    let length = der[offset + 1]!;
    if (length & 0x80) {
      const count = length & 0x7f;
      length = 0;
      for (let i = 0; i < count; i++) length = length * 256 + der[start++]!;
    }
    return { start, end: start + length };
  };
  const outer = span(0);
  const result: Buffer[] = [];
  for (let offset = outer.start; offset < outer.end;) {
    const { end } = span(offset);
    result.push(der.subarray(offset, end));
    offset = end;
  }
  return result;
}

// A version 3 PFX of `authSafe`, under an HMAC-SHA-256 MAC keyed from `password` - or with none.
function pfx(authSafe: Buffer, password: string | undefined): Buffer {
  const parts = [tlv(0x02, Buffer.from([3])), dataInfo(authSafe)];
  if (password !== undefined) {
    const salt = randomBytes(8);
    const bmp = Buffer.concat([Buffer.from(password, 'utf16le').swap16(), Buffer.alloc(2)]);
    const digest = createHmac('sha256', pkcs12.pkcs12Kdf('sha256', bmp, salt, 2048, 3, 32)).update(authSafe).digest();
    parts.push(tlv(0x30, tlv(0x30, tlv(0x30, oidTlv('608648016503040201'), tlv(0x05)), tlv(0x04, digest)), tlv(0x04, salt), tlv(0x02, Buffer.from([0x08, 0x00]))));
  }
  return tlv(0x30, ...parts);
}

// Writes `data` to a new file, removed when the test ends, and returns its path.
function writeStore(name: string, data: Buffer): string {
  const directory = mkdtempSync(join(scratchRoot(), 'hkdfguard-p12-'));
  cleanups.push(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, name);
  writeFileSync(path, data);
  return path;
}

describe('VaultTlsOptions.protectPassword', () => {
  it('protects a password under the protector, as a string or as bytes', () => {
    for (const password of [PASSWORD, Buffer.from(PASSWORD, 'utf8')]) {
      const encrypted = VaultTlsOptions.protectPassword(protector, password);
      assert.notEqual(encrypted, PASSWORD);
      const result = new Uint8Array(protector.maxDecryptedLength(encrypted));
      const length = protector.decrypt(encrypted, result);
      assert.equal(Buffer.from(result.subarray(0, length)).toString('utf8'), PASSWORD);
    }
  });

  it('names its purpose', () => {
    assert.equal(VaultTlsOptions.PASSWORD_PURPOSE, 'HkdfGuard.Integration.HashiCorpVault.KeyStorePassword');
  });

  it('refuses an empty password, a missing protector and a password of the wrong type', () => {
    assert.throws(() => VaultTlsOptions.protectPassword(protector, ''), InvalidArgumentError);
    assert.throws(() => VaultTlsOptions.protectPassword(undefined as unknown as DataProtector, PASSWORD), TypeError);
    assert.throws(() => VaultTlsOptions.protectPassword(protector, 42 as unknown as string), TypeError);
  });
});

describe('VaultTlsOptions: trusting Vault', () => {
  it("refuses Vault's certificate by default, signed by a CA Node doesn't trust", async () => {
    const port = await startServer();
    await assert.rejects(call(createVaultAgent({}), port), (e: NodeJS.ErrnoException) => /CERT|SIGNATURE|ISSUER/.test(e.code ?? ''));
  });

  it('warns the process every time certificate verification is off, and only then', async () => {
    const warned = once(process, 'warning');
    createVaultAgent({ insecureSkipVerify: true }).destroy();
    const [warning] = await warned as [Error & { code?: string }];
    assert.equal(warning.code, UNVERIFIED_WARNING_CODE);
    assert.match(warning.message, /not verified.*VAULT_SKIP_VERIFY.*every token and secret/);
    const seen: unknown[] = [];
    const listener = (w: Error & { code?: string }) => { if (w.code === UNVERIFIED_WARNING_CODE) seen.push(w); };
    process.on('warning', listener);
    try {
      createVaultAgent({ insecureSkipVerify: false }).destroy();
      createVaultAgent({ serverCertificateFile: fixture('ca.pem') }).destroy();
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(seen.length, 0);
    } finally {
      process.off('warning', listener);
    }
  });

  it("refuses, by default, files anyone but administrators could have replaced - the CA, a key, a store", (t) => {
    if (process.getuid?.() === 0) {
      t.skip('Running as root, whose files are trusted.');
      return;
    }
    // The fixtures belong to the account that checked them out.
    const notTrusted = refused(/can't be read: EACCES.*not trusted/);
    assert.throws(() => createVaultAgentAsGiven({ serverCertificateFile: fixture('ca.pem') }), notTrusted);
    assert.throws(() => createVaultAgentAsGiven({ ...trustStore(), fileTrust: undefined }), notTrusted);
    assert.throws(() => createVaultAgentAsGiven({ ...keyStore('client.p12'), fileTrust: KeyFileTrust.administratorsOnly }), notTrusted);
    assert.throws(() => createVaultAgentAsGiven({ clientCertificateFile: fixture('client.pem'), clientCertificateKeyFile: fixture('client.key') }), notTrusted);
  });

  it('takes only a KeyFileTrust as fileTrust', () => {
    for (const fileTrust of [{ windowsPrincipals: [] }, 'S-1-5-18', 1001]) {
      assert.throws(() => createVaultAgentAsGiven({ serverCertificateFile: fixture('ca.pem'), fileTrust: fileTrust as unknown as KeyFileTrust }),
        refused(/fileTrust must be a KeyFileTrust/));
    }
  });

  it('trusts any certificate with insecureSkipVerify', async () => {
    const port = await startServer();
    const answer = await call(createVaultAgent({ insecureSkipVerify: true }), port);
    assert.equal(answer.client, undefined);
  });

  for (const file of ['truststore.p12', 'truststore-openssl.p12']) {
    it(`trusts the CA certificates in a PKCS#12 trust store (${file})`, async () => {
      const port = await startServer();
      await assert.doesNotReject(call(createVaultAgent(trustStore(file)), port));
    });
  }

  it('checks the host name against serverName, not the address', async () => {
    const port = await startServer();
    const { serverName, ...withoutName } = trustStore();
    assert.equal(serverName, 'vault.test');
    await assert.rejects(call(createVaultAgent(withoutName), port), (e: NodeJS.ErrnoException) => e.code === 'ERR_TLS_CERT_ALTNAME_INVALID');
    await assert.rejects(call(createVaultAgent({ ...trustStore(), serverName: 'other.test' }), port),
      (e: NodeJS.ErrnoException) => e.code === 'ERR_TLS_CERT_ALTNAME_INVALID');
  });

  it('trusts the CA certificates in a PEM file, PEM in memory or a directory of PEM files', async () => {
    const port = await startServer();
    const directory = mkdtempSync(join(scratchRoot(), 'hkdfguard-ca-'));
    cleanups.push(() => rmSync(directory, { recursive: true, force: true }));
    copyFileSync(fixture('ca.pem'), join(directory, 'ca.pem'));
    for (const tls of [
      { serverCertificateFile: fixture('ca.pem') },
      { serverCertificatePem: readFileSync(fixture('ca.pem'), 'latin1') },
      { serverCertificatePem: readFileSync(fixture('ca.pem')) },
      { serverCertificateDirectory: directory },
    ]) {
      await assert.doesNotReject(call(createVaultAgent({ ...tls, serverName: 'vault.test' }), port));
    }
  });

  it('refuses a JKS trust store, naming the conversion', () => {
    assert.throws(() => createVaultAgent(trustStore('truststore.jks')), refused(/JKS or JCEKS.*keytool -importkeystore/));
  });

  it('refuses a trust store whose password is wrong', () => {
    const wrong = VaultTlsOptions.protectPassword(protector, 'not-the-password');
    assert.throws(() => createVaultAgent({ ...trustStore(), trustStorePassword: wrong }), refused(/password is wrong/));
  });

  it("refuses a password the protector didn't protect, without quoting it", () => {
    assert.throws(() => createVaultAgent({ ...trustStore(), trustStorePassword: PASSWORD }), (e: unknown) =>
      refused(/isn't protected by tls.passwordProtector/)(e) && !(e as Error).message.includes(PASSWORD));
    const other = makeProtector();
    assert.throws(() => createVaultAgent({ ...trustStore(), passwordProtector: other }), refused(/isn't protected/));
  });

  it('refuses a file that is missing, PEM where PKCS#12 belongs, or not a key store', () => {
    assert.throws(() => createVaultAgent({ ...trustStore(), trustStoreFile: fixture('missing.p12') }), refused(/missing\.p12' can't be read: ENOENT/));
    assert.throws(() => createVaultAgent({ ...trustStore(), trustStoreFile: fixture('ca.pem') }), refused(/is PEM, not PKCS#12/));
    const directory = mkdtempSync(join(scratchRoot(), 'hkdfguard-p12-'));
    cleanups.push(() => rmSync(directory, { recursive: true, force: true }));
    const garbage = join(directory, 'garbage.p12');
    writeFileSync(garbage, Buffer.from('3082ffff0201', 'hex'));
    assert.throws(() => createVaultAgent({ ...trustStore(), trustStoreFile: garbage }), refused(/isn't a PKCS#12 store/));
    const truncated = join(directory, 'truncated.p12');
    writeFileSync(truncated, readFileSync(fixture('truststore.p12')).subarray(0, 200));
    assert.throws(() => createVaultAgent({ ...trustStore(), trustStoreFile: truncated }), refused(/isn't a PKCS#12 store/));
  });

  it('refuses a store whose contents were altered, as its MAC no longer matches', () => {
    const directory = mkdtempSync(join(scratchRoot(), 'hkdfguard-p12-'));
    cleanups.push(() => rmSync(directory, { recursive: true, force: true }));
    const store = Buffer.from(readFileSync(fixture('truststore.p12')));
    store[store.length - 120]! ^= 1;
    const altered = join(directory, 'altered.p12');
    writeFileSync(altered, store);
    assert.throws(() => createVaultAgent({ ...trustStore(), trustStoreFile: altered }), refused(/password is wrong, or the store was altered/));
  });

  it('refuses a PEM file holding no certificate', () => {
    assert.throws(() => createVaultAgent({ serverCertificateFile: fixture('server.key') }), refused(/holds no PEM certificate/));
  });

  for (const file of ['truststore.p12', 'truststore-openssl.p12']) {
    it(`refuses a trust store whose MAC was cut off (${file})`, () => {
      const [version, authSafe] = elements(readFileSync(fixture(file)));
      const stripped = writeStore('stripped.p12', tlv(0x30, version!, authSafe!));
      assert.throws(() => createVaultAgent({ ...trustStore(), trustStoreFile: stripped }), refused(/has no integrity MAC.*-nomac/));
    });
  }

  it("refuses a planted trust store of anyone's CA, in plain contents with no MAC, whatever its password", () => {
    // What someone who can write the trust store, but knows neither its password nor the key ring,
    // could put there: a CA of their own (the test CA stands in for it), nothing encrypted, no MAC.
    const planted = writeStore('planted.p12', pfx(tlv(0x30, dataInfo(tlv(0x30, certificateBag(pemDer('ca.pem'))))), undefined));
    assert.throws(() => createVaultAgent({ ...trustStore(), trustStoreFile: planted }), refused(/has no integrity MAC/));
  });

  it('trusts a trust store in plain contents under its MAC, as `openssl pkcs12 -certpbe NONE` writes', async () => {
    const port = await startServer();
    const store = writeStore('plain.p12', pfx(tlv(0x30, dataInfo(tlv(0x30, certificateBag(pemDer('ca.pem'))))), PASSWORD));
    await assert.doesNotReject(call(createVaultAgent({ ...trustStore(), trustStoreFile: store }), port));
    // The same store under a MAC keyed from another password: the MAC is checked, not just present.
    const other = writeStore('other.p12', pfx(tlv(0x30, dataInfo(tlv(0x30, certificateBag(pemDer('ca.pem'))))), 'not-the-password'));
    assert.throws(() => createVaultAgent({ ...trustStore(), trustStoreFile: other }), refused(/password is wrong, or the store was altered/));
  });
});

describe('VaultTlsOptions: presenting a client certificate', () => {
  for (const file of ['client.p12', 'client-3des.p12']) {
    it(`presents the key and chain in a PKCS#12 client key store (${file})`, async () => {
      const port = await startServer(true);
      const answer = await call(createVaultAgent(keyStore(file)), port);
      // Authorized: the intermediate went with the client certificate, so it chains to the CA.
      assert.deepEqual(answer, { authorized: true, client: 'hkdfguard-client' });
    });
  }

  it('presents the key the alias names, ignoring case, from a store of two (written by keytool)', async () => {
    const port = await startServer(true);
    assert.equal((await call(createVaultAgent(keyStore('two-keys.p12', 'OTHER')), port)).client, 'hkdfguard-other');
    assert.equal((await call(createVaultAgent(keyStore('two-keys.p12', 'vault-client')), port)).client, 'hkdfguard-client');
    assert.equal((await call(createVaultAgent(keyStore('client.p12', 'Vault-Client')), port)).client, 'hkdfguard-client');
  });

  it('refuses a store of two keys without an alias, and an alias no key has, naming the aliases', () => {
    assert.throws(() => createVaultAgent(keyStore('two-keys.p12')), refused(/holds 2 private keys \('vault-client', 'other'\).*clientKeyStoreAlias/));
    assert.throws(() => createVaultAgent(keyStore('two-keys.p12', 'missing')), refused(/no private key named 'missing'/));
    assert.throws(() => createVaultAgent(keyStore('client.p12', 'other')), refused(/no private key named 'other'/));
  });

  it('refuses a key store holding no key', () => {
    assert.throws(() => createVaultAgent(keyStore('truststore.p12')), refused(/holds no private key/));
  });

  it('refuses a key store encrypted with legacy RC2, naming how to re-export it', () => {
    assert.throws(() => createVaultAgent(keyStore('client-rc2.p12')), refused(/legacy RC2.*AES-256-CBC/));
  });

  it('refuses a key store whose password is wrong', () => {
    const wrong = VaultTlsOptions.protectPassword(protector, 'store-pass-2');
    assert.throws(() => createVaultAgent({ ...keyStore('client.p12'), clientKeyStorePassword: wrong }), refused(/password is wrong/));
  });

  it('refuses a client key store whose MAC was cut off', () => {
    const [version, authSafe] = elements(readFileSync(fixture('client.p12')));
    const stripped = writeStore('stripped.p12', tlv(0x30, version!, authSafe!));
    assert.throws(() => createVaultAgent({ ...keyStore('client.p12'), clientKeyStoreFile: stripped }), refused(/has no integrity MAC/));
  });

  it("refuses a client key store whose key isn't encrypted, even under its MAC", () => {
    const pkcs8 = createPrivateKey(readFileSync(fixture('client.key'))).export({ format: 'der', type: 'pkcs8' });
    const safe = tlv(0x30, certificateBag(pemDer('client.pem')), bag('2a864886f70d010c0a0101', pkcs8));
    const store = writeStore('plainkey.p12', pfx(tlv(0x30, dataInfo(safe)), PASSWORD));
    assert.throws(() => createVaultAgent({ ...keyStore('client.p12'), clientKeyStoreFile: store }), refused(/holds a private key that isn't encrypted/));
    // As a trust store, its keys aren't read: only its certificates are.
    assert.doesNotThrow(() => createVaultAgent({ ...trustStore(), trustStoreFile: store }));
  });

  it('refuses a JKS client key store', () => {
    assert.throws(() => createVaultAgent(keyStore('truststore.jks')), refused(/JKS or JCEKS/));
  });

  it('presents a PEM certificate chain and key, from files or memory', async () => {
    const port = await startServer(true);
    const chain = readFileSync(fixture('client.pem'), 'latin1') + readFileSync(fixture('intermediate.pem'), 'latin1');
    const key = readFileSync(fixture('client.key'));
    const directory = mkdtempSync(join(scratchRoot(), 'hkdfguard-pem-'));
    cleanups.push(() => rmSync(directory, { recursive: true, force: true }));
    writeFileSync(join(directory, 'chain.pem'), chain);
    for (const identity of [
      { clientCertificateFile: join(directory, 'chain.pem'), clientCertificateKeyFile: fixture('client.key') },
      { clientCertificatePem: chain, clientCertificateKeyPem: key },
    ]) {
      const answer = await call(createVaultAgent({ ...identity, serverCertificateFile: fixture('ca.pem'), serverName: 'vault.test' }), port);
      assert.deepEqual(answer, { authorized: true, client: 'hkdfguard-client' });
    }
    // The caller's key buffer is the caller's: never zeroed for them.
    assert.deepEqual(key, readFileSync(fixture('client.key')));
  });

  it("refuses a key that doesn't match its certificate", () => {
    assert.throws(() => createVaultAgent({ clientCertificateFile: fixture('client.pem'), clientCertificateKeyFile: fixture('server.key') }),
      refused(/can't be used/));
  });
});

describe('VaultTlsOptions: what is set together', () => {
  const both = { trustStoreFile: fixture('truststore.p12'), trustStorePassword: protectedPassword, passwordProtector: protector };
  const inconsistent: [string, VaultTlsOptions][] = [
    ['two CA sources', { serverCertificateFile: fixture('ca.pem'), serverCertificatePem: 'x' }],
    ['a PEM CA and a trust store', { ...both, serverCertificateDirectory: FIXTURES }],
    ['a certificate file and PEM', { clientCertificateFile: 'a', clientCertificatePem: 'b', clientCertificateKeyFile: 'c' }],
    ['a key file and PEM', { clientCertificateFile: 'a', clientCertificateKeyFile: 'c', clientCertificateKeyPem: 'd' }],
    ['a certificate without its key', { clientCertificateFile: fixture('client.pem') }],
    ['a key without its certificate', { clientCertificateKeyFile: fixture('client.key') }],
    ['a key store and a PEM identity', {
      ...keyStore('client.p12'), clientCertificateFile: fixture('client.pem'), clientCertificateKeyFile: fixture('client.key'),
    }],
    ['a trust store without its password', { trustStoreFile: fixture('truststore.p12'), passwordProtector: protector }],
    ['a trust store password without the store', { trustStorePassword: protectedPassword, passwordProtector: protector }],
    ['a key store without its password', { clientKeyStoreFile: fixture('client.p12'), passwordProtector: protector }],
    ['an alias without a key store', { clientKeyStoreAlias: 'vault-client' }],
    ['a password without its protector', { trustStoreFile: fixture('truststore.p12'), trustStorePassword: protectedPassword }],
    ['an empty server name', { serverName: '' }],
    ['insecureSkipVerify that is not a boolean', { insecureSkipVerify: 'yes' as unknown as boolean }],
    ['a protector that is not one', { ...both, passwordProtector: {} as DataProtector }],
    ['a PEM of the wrong type', { serverCertificatePem: 42 as unknown as string }],
  ];
  for (const [name, tls] of inconsistent) {
    it(`refuses ${name}`, () => {
      assert.throws(() => createVaultAgent(tls), InvalidArgumentError);
    });
  }

  it('refuses an agent and tls together', () => {
    const agent = new HttpsAgent();
    cleanups.push(() => agent.destroy());
    assert.throws(() => checkTlsOptions(agent, {}), refused(/agent or tls, not both/));
    assert.throws(() => new VaultConnector(apiBase('https://vault.test', 'a token'), agent, {}), refused(/agent or tls, not both/));
    assert.throws(() => checkTlsOptions('agent', undefined), InvalidArgumentError);
    assert.throws(() => checkTlsOptions(undefined, 'tls'), InvalidArgumentError);
    checkTlsOptions(agent, undefined);
    checkTlsOptions(undefined, {});
  });

  it('builds the connector its agent from tls, and ignores tls for http', async () => {
    const port = await startServer(true);
    const connector = new VaultConnector(apiBase(`https://127.0.0.1:${port}`, 'a token'), undefined, keyStore('client.p12'));
    cleanups.push(() => connector.close());
    const answer = await new Promise<Answer>((resolve, reject) => {
      const request = connector.request('GET', '/', {});
      request.on('response', (response) => {
        let body = '';
        response.on('data', (chunk: Buffer) => { body += chunk.toString(); });
        response.on('end', () => resolve(JSON.parse(body) as Answer));
      }).on('error', reject).end();
    });
    assert.deepEqual(answer, { authorized: true, client: 'hkdfguard-client' });
    // A loopback http address reads nothing: a store that can't be opened isn't noticed.
    new VaultConnector(apiBase('http://127.0.0.1:8200', 'a token'), undefined, { trustStoreFile: 'missing', trustStorePassword: 'x', passwordProtector: protector })
      .close();
  });
});

import { strict as assert } from 'node:assert';
import { randomBytes, randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { Agent as HttpsAgent } from 'node:https';
import { dirname, join } from 'node:path';
import { after, describe, it } from 'node:test';
import { isZero, MAX_WRAPPED_KEY_BYTES } from '@runsecure/hkdfguard-abstractions';
import { AesGcmCryptoProviderFactory } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { HashiCorpVaultTransitError } from './errors.js';
import { StaticVaultTokenSource } from './token.js';
import { HashiCorpVaultTransitKeyWrapper } from './wrapper.js';

/*
 * Real calls against a transit key the caller provides, with a token the caller provides - on a dev
 * server, the ones scripts/provision-vault-transit-test-key.sh creates and prints:
 *
 *   HKDFGUARD_TEST_VAULT_ADDR=http://127.0.0.1:8200 HKDFGUARD_TEST_VAULT_TOKEN=... \
 *   HKDFGUARD_TEST_VAULT_TRANSIT_KEY=hkdfguard-test HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY=hkdfguard-test-other \
 *   npm test --workspace packages/keywrapping-hashicorpvault
 *
 * Without HKDFGUARD_TEST_VAULT_TRANSIT_KEY every test here is reported as skipped - never as passed -
 * the same variables the .NET, Java and Python integration tests read; once it is set, a failing
 * call is a test failure. HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY names a second key, for the
 * cross-key test (skipped without it); HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT a mount other than
 * "transit"; and HKDFGUARD_TEST_VAULT_CACERT a CA for a server certificate Node doesn't trust - it is
 * then the only CA trusted. The address, token and CA are the variables the Vault cache's
 * integration tests read. The token needs only update on encrypt, decrypt and datakey/wrapped for the
 * keys; the tests never create, rotate, read or delete a key. See
 * docs/how-to/run-hashicorp-vault-transit-integration-tests.md.
 *
 * The keys, mount, address and CA certificate are read from the environment, else from
 * vault.test.properties at the repository root - the file the Vault cache's integration tests read,
 * and the same file as hkdfguard-java's and hkdfguard-python's: a local file, ignored by git. The
 * token, a secret, is read from the environment only, never from a file, and never printed.
 */

const KEY_VARIABLE = 'HKDFGUARD_TEST_VAULT_TRANSIT_KEY';
const OTHER_KEY_VARIABLE = 'HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY';
const MOUNT_VARIABLE = 'HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT';
const ADDRESS_VARIABLE = 'HKDFGUARD_TEST_VAULT_ADDR';
const TOKEN_VARIABLE = 'HKDFGUARD_TEST_VAULT_TOKEN';
const CA_CERTIFICATE_VARIABLE = 'HKDFGUARD_TEST_VAULT_CACERT';
const SETTINGS_FILE = 'vault.test.properties';
// .NET's default: a dev server listens on plain http.
const DEFAULT_ADDRESS = 'http://127.0.0.1:8200';
const CONTEXT = 'hkdfguard.integrationtest';

/**
 * The settings file at the repository root - the nearest directory above this file that holds
 * package-lock.json - as NAME=value lines, '#' and '!' starting a comment; empty if there is none.
 */
function settings(): Map<string, string> {
  const values = new Map<string, string>();
  for (let directory = __dirname; ; directory = dirname(directory)) {
    if (existsSync(join(directory, 'package-lock.json'))) {
      const file = join(directory, SETTINGS_FILE);
      if (!existsSync(file)) return values;
      for (const raw of readFileSync(file, 'utf8').split(/\r?\n/)) {
        const line = raw.trim();
        const equals = line.indexOf('=');
        if (line !== '' && !line.startsWith('#') && !line.startsWith('!') && equals > 0) {
          values.set(line.slice(0, equals).trim(), line.slice(equals + 1).trim());
        }
      }
      return values;
    }
    if (dirname(directory) === directory) return values;
  }
}

/** `variable` from the environment, else from the settings file; undefined if neither sets it. */
function configured(variable: string): string | undefined {
  return process.env[variable] || settings().get(variable) || undefined;
}

const keyName = configured(KEY_VARIABLE);
const otherKeyName = configured(OTHER_KEY_VARIABLE);

/** An agent trusting HKDFGUARD_TEST_VAULT_CACERT, and only it, when set; otherwise the wrapper's own. */
function agent(): HttpsAgent | undefined {
  const caCertificate = configured(CA_CERTIFICATE_VARIABLE);
  return caCertificate === undefined ? undefined : new HttpsAgent({ ca: readFileSync(caCertificate), keepAlive: true });
}

describe('HashiCorp Vault transit integration', {
  skip: keyName === undefined && `Set ${KEY_VARIABLE} (with ${ADDRESS_VARIABLE} and ${TOKEN_VARIABLE}) to a transit key, in the environment or `
    + `${SETTINGS_FILE}, to run Vault transit integration tests.`,
}, () => {
  const tls = agent();
  const wrappers: HashiCorpVaultTransitKeyWrapper[] = [];
  const sources: StaticVaultTokenSource[] = [];
  after(() => {
    for (const wrapper of wrappers) wrapper.close();
    for (const source of sources) source.close();
    tls?.destroy();
  });

  /**
   * A wrapper binding `context` (null for none), calling with `token`, or with HKDFGUARD_TEST_VAULT_TOKEN's, copied out of
   * the environment as soon as it is read.
   */
  function create(context: string | null = CONTEXT, key: string = keyName!, token?: string): HashiCorpVaultTransitKeyWrapper {
    const fromEnvironment = token ?? process.env[TOKEN_VARIABLE];
    if (!fromEnvironment) {
      assert.fail(`Set ${TOKEN_VARIABLE} in the environment (never in ${SETTINGS_FILE}) to a token allowed to use ${KEY_VARIABLE}.`);
    }
    const source = new StaticVaultTokenSource(fromEnvironment);
    sources.push(source);
    const wrapper = new HashiCorpVaultTransitKeyWrapper(configured(ADDRESS_VARIABLE) ?? DEFAULT_ADDRESS, key, source,
      { context: context ?? undefined, mountPath: configured(MOUNT_VARIABLE) ?? 'transit', agent: tls });
    wrappers.push(wrapper);
    return wrapper;
  }

  it('round-trips a 32-byte DEK through wrap and unwrap', async () => {
    const vault = create();
    const dek = new Uint8Array(randomBytes(32));
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await vault.wrap(dek, wrapped);
    const revealed = new Uint8Array(32);

    assert.match(Buffer.from(wrapped.subarray(0, length)).toString('latin1'), /^vault:v\d+:/);
    assert.equal(await vault.unwrap(wrapped.subarray(0, length), revealed), 32);
    assert.deepEqual(revealed, dek);
  });

  it('generates in Vault, with no context, a wrapped DEK that reveals', async () => {
    const vault = create(null);
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await vault.generateAndWrap(wrapped);
    const revealed = new Uint8Array(32);

    assert.equal(await vault.unwrap(wrapped.subarray(0, length), revealed), 32);
    assert.ok(!isZero(revealed));
  });

  it('generates, with a context, a wrapped DEK that reveals', async () => {
    const vault = create();
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await vault.generateAndWrap(wrapped);
    const revealed = new Uint8Array(32);

    assert.equal(await vault.unwrap(wrapped.subarray(0, length), revealed), 32);
    assert.ok(!isZero(revealed));
  });

  it('refuses to unwrap under another context, or none', async () => {
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await create().generateAndWrap(wrapped);

    await assert.rejects(create('hkdfguard.integrationtest.other').unwrap(wrapped.subarray(0, length), new Uint8Array(32)), HashiCorpVaultTransitError);
    await assert.rejects(create(null).unwrap(wrapped.subarray(0, length), new Uint8Array(32)), HashiCorpVaultTransitError);
  });

  it('refuses to unwrap a tampered DEK with 400', async () => {
    const vault = create();
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await vault.generateAndWrap(wrapped);
    // Another base64 character, so it reaches Vault and fails there.
    wrapped[12] = wrapped[12] === 0x41 ? 0x42 : 0x41;

    await assert.rejects(vault.unwrap(wrapped.subarray(0, length), new Uint8Array(32)),
      (e: unknown) => e instanceof HashiCorpVaultTransitError && e.statusCode === 400 && e.message.includes('400'));
  });

  it('refuses to unwrap under another key', {
    skip: otherKeyName === undefined && `Set ${KEY_VARIABLE} and ${OTHER_KEY_VARIABLE} to two transit keys to check one refuses the other's DEKs.`,
  }, async () => {
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await create().generateAndWrap(wrapped);

    await assert.rejects(create(CONTEXT, otherKeyName!).unwrap(wrapped.subarray(0, length), new Uint8Array(32)), HashiCorpVaultTransitError);
  });

  it('refuses a token Vault doesn\'t know with 403', async () => {
    const vault = create(CONTEXT, keyName!, `hvs.not-a-real-token-${randomUUID()}`);
    await assert.rejects(vault.generateAndWrap(new Uint8Array(MAX_WRAPPED_KEY_BYTES)),
      (e: unknown) => e instanceof HashiCorpVaultTransitError && e.statusCode === 403 && e.message.includes('403'));
  });

  it('lets a crypto provider generate and reveal its DEK through Vault', async () => {
    const provider = await new AesGcmCryptoProviderFactory().createEphemeral(create(), { expirySeconds: 60 });
    try {
      const expected = new TextEncoder().encode('hello, vault transit');
      const encrypted = new Uint8Array(provider.encryptedAllocationLength(expected.length));
      const encryptedLength = provider.encrypt(Uint8Array.from(expected), encrypted);
      const decrypted = new Uint8Array(provider.decryptedAllocationLength(encryptedLength));
      const decryptedLength = provider.decrypt(encrypted.subarray(0, encryptedLength), decrypted);
      assert.deepEqual(decrypted.subarray(0, decryptedLength), expected);
    } finally {
      await provider.close();
    }
  });
});

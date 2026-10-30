import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { after, describe, it, type TestContext } from 'node:test';
import {
  AuthenticationFailedError, MAX_WRAPPED_KEY_BYTES, wipe, type DataProtector, type ProtectedReadOnlyCache,
} from '@runsecure/hkdfguard-abstractions';
import { ProtectedCache } from '@runsecure/hkdfguard-cache';
import { AesGcmCryptoProviderFactory, AesGcmPipelineDataProtector, KEY_SIZE } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { buildKeyRing, DefaultFormatProvider, type KeyRing } from '@runsecure/hkdfguard-dek';
import { EncryptedConfigurationReader, mapLookup } from '@runsecure/hkdfguard-encryptedconfig';
import { keyFileDirectory } from '@runsecure/hkdfguard-test-support';
import {
  KeyFileRefusedError, NativeKeyWrapperV1, NotInstalledError, Status, StatusError, UnsupportedPlatformError,
} from '@runsecure/hkdfguard-keywrapping-native-v1';
import { otherServiceName, testServiceName } from './testservice.js';

// End to end over the real native KEK: the paths a deployment and a running application actually
// take, from a pipeline encrypting configuration through to the application reading it back, and
// the runtime keys a process generates for itself - the Node port of the .NET NativeEndToEndTests.

const KEY_FILE_VERSION = 3;

const open: KeyRing[] = [];
after(async () => {
  await Promise.all(open.map((ring) => ring.close()));
});

/*
 * Key files go in keyFileDirectory's folder (the test-support package), removed after each test: the
 * native library reads every key file, and refuses one under an 8.3 short name on Windows, or in a
 * directory chain a group or other user can write on Linux - so never under /tmp there.
 */

interface RingOptions {
  keyFile?: string;
  ephemeral?: number[];
  refreshSeconds?: number;
}

/** A ring over the native KEK of `service`, assembled exactly as an application does. */
async function buildRing(service: string, options: RingOptions): Promise<KeyRing> {
  const ring = await buildKeyRing({
    keyWrapper: NativeKeyWrapperV1.create(service),
    cryptoProviderFactory: new AesGcmCryptoProviderFactory(),
    keyRefreshInterval: options.refreshSeconds ?? 60,
    keyFiles: options.keyFile === undefined ? undefined : { [KEY_FILE_VERSION]: options.keyFile },
    ephemeralKeys: options.ephemeral,
  });
  open.push(ring);
  return ring;
}

/**
 * Does what the release pipeline does: protects configuration under a fresh in-memory key, then hands
 * that key to the native KEK and writes the wrapped result as the release's key file in `directory`.
 * Returns the key file's path and the configuration values.
 */
async function runPipeline(service: string, directory: string, secrets: Record<string, string>): Promise<{ keyFile: string; values: Record<string, string> }> {
  const pipeline = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), KEY_FILE_VERSION);
  const dek = new Uint8Array(KEY_SIZE);
  try {
    const values = Object.fromEntries(Object.entries(secrets).map(([key, secret]) => [key, pipeline.encrypt(new TextEncoder().encode(secret), key)]));

    const base64 = pipeline.keyBase64();
    const decoded = Buffer.from(base64.buffer, base64.byteOffset, base64.byteLength);
    const n = Buffer.from(decoded.toString('latin1'), 'base64').copy(dek); // test only: the tool takes the base64 directly
    assert.equal(n, KEY_SIZE);

    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const length = await NativeKeyWrapperV1.create(service).wrap(dek, wrapped);
    const keyFile = join(directory, 'wrapped-dek-v3.bin');
    writeFileSync(keyFile, wrapped.subarray(0, length), { mode: 0o600 });
    return { keyFile, values };
  } finally {
    wipe(dek);
    pipeline.close();
  }
}

const configReader = (ring: KeyRing, values: Record<string, string>) => new EncryptedConfigurationReader(ring, mapLookup(values));

/** Decrypts `name` from `source`, as an application does: size the buffer, then decrypt. */
async function reveal(source: ProtectedReadOnlyCache, name: string): Promise<string> {
  const length = await source.maxDecryptedLength(name);
  assert.notEqual(length, undefined, `'${name}' is not stored`);
  const result = new Uint8Array(length!);
  return new TextDecoder().decode(result.subarray(0, await source.decrypt(name, result)));
}

const protect = (protector: DataProtector, plaintext: string) => protector.encrypt(new TextEncoder().encode(plaintext));

function unprotect(protector: DataProtector, formatted: string): string {
  const result = new Uint8Array(protector.maxDecryptedLength(formatted));
  return new TextDecoder().decode(result.subarray(0, protector.decrypt(formatted, result)));
}

/** Runs `body` against the test service, or skips. */
function native(name: string, body: (service: string, t: TestContext) => Promise<void>): void {
  // The assertions are in each caller's body, which S2699 can't follow into.
  it(name, async (t) => { // NOSONAR
    const service = await testServiceName(t);
    if (service !== undefined) await body(service, t);
  });
}

/**
 * Where a wrapped payload names its format, which each platform's library checks when it reads a key
 * file. Linux and Windows payloads start with a version byte. A macOS payload starts with the
 * 32-byte KEK fingerprint, followed by the suite byte (hkdfguard.h): changing byte 0 there leaves a
 * well-formed payload naming another KEK, which only unwrap can refuse.
 */
const FORMAT_BYTE_OFFSET = process.platform === 'darwin' ? 32 : 0;

/** Runs `body` against the test service with a fresh folder for its key files (keyFileDirectory), or skips. */
function nativeWithKeyFiles(name: string, body: (service: string, directory: string, t: TestContext) => Promise<void>): void {
  native(name, async (service, t) => {
    const directory = keyFileDirectory(t, 'hkdfguard-e2e-');
    if (directory !== undefined) await body(service, directory, t);
  });
}

describe('a deployment', () => {
  nativeWithKeyFiles('decrypts pipeline-encrypted configuration through its natively wrapped key file', async (service, directory) => {
    const { keyFile, values } = await runPipeline(service, directory, {
      'ConnectionStrings:Admin': 'Server=db;User=admin;Password=s3cret',
      'Api:Key': 'k-0123456789abcdef',
    });
    const reader = configReader(await buildRing(service, { keyFile }), values);
    assert.equal(await reveal(reader, 'ConnectionStrings:Admin'), 'Server=db;User=admin;Password=s3cret');
    assert.equal(await reveal(reader, 'Api:Key'), 'k-0123456789abcdef');
  });

  nativeWithKeyFiles('fails authentication for a value moved to another key', async (service, directory) => {
    const { keyFile, values } = await runPipeline(service, directory, { 'ConnectionStrings:Admin': 'admin-only', 'ConnectionStrings:Reports': 'reports' });
    values['ConnectionStrings:Reports'] = values['ConnectionStrings:Admin']!; // an edited configuration file
    const reader = configReader(await buildRing(service, { keyFile }), values);
    await assert.rejects(reveal(reader, 'ConnectionStrings:Reports'), AuthenticationFailedError);
  });

  nativeWithKeyFiles('reveals the same key after a restart that reads the same key file', async (service, directory) => {
    const { keyFile, values } = await runPipeline(service, directory, { Secret: 'survives a restart' });
    const first = await buildRing(service, { keyFile });
    assert.equal(await reveal(configReader(first, values), 'Secret'), 'survives a restart');
    await first.close();

    const second = await buildRing(service, { keyFile });
    assert.equal(await reveal(configReader(second, values), 'Secret'), 'survives a restart');
  });

  nativeWithKeyFiles('refuses to build from a key file wrapped under another service', async (service, directory) => {
    const { keyFile } = await runPipeline(service, directory, { Secret: 'value' });
    await assert.rejects(buildRing(await otherServiceName(), { keyFile }), StatusError);
  });

  nativeWithKeyFiles('refuses to build from a tampered key file', async (service, directory) => {
    const { keyFile } = await runPipeline(service, directory, { Secret: 'value' });
    const wrapped = readFileSync(keyFile);
    // The last byte is part of the AEAD tag, which no platform's library can check without the
    // KEK, so the file reads back fine and the build fails at unwrap. (A change to the payload's
    // structure is refused earlier, when the file is read, as a KeyFileRefusedError.)
    wrapped[wrapped.length - 1]! ^= 0x01;
    writeFileSync(keyFile, wrapped, { mode: 0o600 });
    await assert.rejects(buildRing(service, { keyFile }), (e: unknown) => e instanceof StatusError);
  });

  nativeWithKeyFiles('reads its key file through the native library: one with an unknown version is refused before any unwrap', async (service, directory) => {
    const { keyFile } = await runPipeline(service, directory, { Secret: 'value' });
    const wrapped = readFileSync(keyFile);
    wrapped[FORMAT_BYTE_OFFSET]! ^= 0xff;
    writeFileSync(keyFile, wrapped, { mode: 0o600 });
    await assert.rejects(buildRing(service, { keyFile }), (e: unknown) =>
      e instanceof KeyFileRefusedError && e.status === Status.fileMalformed && e.code === 'ERR_HKDFGUARD_INVALID_KEY_FILE');
  });

  // Needs only the installed library - reading a file never touches a KEK. Windows only, where it
  // has been run against the real library; its key file goes in keyFileDirectory's folder, which on
  // Linux is a private one outside /tmp, as the library requires.
  it('refuses to build from a plaintext key file', { skip: process.platform !== 'win32' }, async (t) => {
    let wrapper: NativeKeyWrapperV1;
    try {
      wrapper = NativeKeyWrapperV1.create('hkdfguard.keyfile.reader');
    } catch (error) {
      if (error instanceof NotInstalledError || error instanceof UnsupportedPlatformError) {
        t.skip(`the native library can't be used here: ${error.message}`);
        return;
      }
      throw error;
    }
    const directory = keyFileDirectory(t, 'hkdfguard-e2e-');
    if (directory === undefined) return;
    const keyFile = join(directory, 'plaintext.bin');
    writeFileSync(keyFile, randomBytes(32));
    await assert.rejects(buildKeyRing({
      keyWrapper: wrapper, cryptoProviderFactory: new AesGcmCryptoProviderFactory(), keyRefreshInterval: 60, keyFiles: { 1: keyFile },
    }), (e: unknown) => e instanceof KeyFileRefusedError && e.status === Status.filePlaintextKey && e.message.includes('key exposure'));
  });
});

describe('runtime keys', () => {
  native('generated through the native KEK protect values and the cache', async (service) => {
    const ring = await buildRing(service, { ephemeral: [100] });
    const protector = ring.createProtector('session');
    const formatted = protect(protector, 'runtime value');
    assert.match(formatted, /^enc::v100::/);
    assert.equal(unprotect(protector, formatted), 'runtime value');

    const cache = new ProtectedCache(ring);
    cache.add('token', new TextEncoder().encode('cached secret'));
    assert.equal(await reveal(cache, 'token'), 'cached secret');
  });

  nativeWithKeyFiles('and a deployed key in one ring each do their job', async (service, directory) => {
    const { keyFile, values } = await runPipeline(service, directory, { Secret: 'from the release' });
    const ring = await buildRing(service, { keyFile, ephemeral: [100] });

    // Configuration decrypts under the release's key file; new values encrypt under the runtime key.
    assert.equal(await reveal(configReader(ring, values), 'Secret'), 'from the release');
    assert.equal(ring.currentVersion, 100);
    assert.match(protect(ring.createProtector('new'), 'value'), /^enc::v100::/);
  });

  native('stay in service while the background refresh re-reveals them through the real KEK', async (service) => {
    const ring = await buildRing(service, { ephemeral: [1], refreshSeconds: 1 });
    const protector = ring.createProtector('refresh');
    const before = protect(protector, 'written before the refreshes');

    await sleep(2500); // two background re-reveals through the native KEK

    assert.equal(unprotect(protector, before), 'written before the refreshes');
    assert.equal(unprotect(protector, protect(protector, 'written after')), 'written after');
  });
});

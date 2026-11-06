import { strict as assert } from 'node:assert';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { EOL, tmpdir } from 'node:os';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { describe, it, type TestContext } from 'node:test';
import { configurationPurpose, type PipelineDataProtector } from '@runsecure/hkdfguard-abstractions';
import { FilePerSecretCache } from '@runsecure/hkdfguard-cache';
import { AesGcmCryptoProviderFactory, AesGcmPipelineDataProtector } from '@runsecure/hkdfguard-cryptoprovider-aesgcm256';
import { DataEncryptionKey, DefaultFormatProvider, KeyRing } from '@runsecure/hkdfguard-dek';
import { KeyFileTrust } from '@runsecure/hkdfguard-securefile';
import {
  CollectingStream, decryptPipelineValue, FakeKeyWrapper, keyFileDirectory, PIPELINE_FORMAT_LIMIT, readTar, windowsCurrentUserSid,
} from '@runsecure/hkdfguard-test-support';
import { SecretPipelineWriter, type SecretRequest } from './index.js';
import { tarArchive } from './tar.js';

// The stream writes - a tar archive of the files, and the JSON object - beyond what the shared
// contract checks: the exact layout, real tar programs, a real child process's stdin, backpressure
// and failures.

const isWindows = process.platform === 'win32';
const utf8 = (s: string) => new TextEncoder().encode(s);

/** A writer over values held in memory: a name maps to its whole value, or is missing when absent. */
class InMemoryWriter extends SecretPipelineWriter {
  constructor(protector: PipelineDataProtector, private readonly secrets: ReadonlyMap<string, string>, names = [...secrets.keys()]) {
    super(protector, names, () => true);
  }

  protected override async readSecret(name: string, requests: readonly SecretRequest[], values: Map<string, string>): Promise<void> {
    const value = this.secrets.get(name);
    if (value !== undefined) this.protectSecret(utf8(value), requests, values);
  }
}

// A name past ustar's 100 bytes, which only the PAX path record carries whole - and short enough
// that the unpacked path stays within Windows' MAX_PATH, which readTrustedFile reads within.
const LONG_NAME = `long-${'n'.repeat(145)}`;
const SECRETS = new Map([
  ['db-password', 'pässwörd'],
  ['api-key', 'key'],
  ['Zeta', 'zeta'],
  ['a.b_c-d', 'dotted'],
  [LONG_NAME, 'long'],
]);

async function pulled(t: TestContext, secrets: ReadonlyMap<string, string> = SECRETS): Promise<{ protector: AesGcmPipelineDataProtector; writer: InMemoryWriter }> {
  const protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(PIPELINE_FORMAT_LIMIT), 3);
  t.after(() => protector.close());
  const writer = new InMemoryWriter(protector, secrets);
  await writer.pullSecrets();
  return { protector, writer };
}

/** The key ring the application holds once the protector's key is wrapped and unwrapped. */
async function ringFor(t: TestContext, protector: PipelineDataProtector): Promise<KeyRing> {
  const key = new Uint8Array(Buffer.from(new TextDecoder().decode(protector.keyBase64()), 'base64'));
  const provider = await new AesGcmCryptoProviderFactory().create(new FakeKeyWrapper(key), utf8('wrapped'), { expirySeconds: 60 });
  const ring = new KeyRing(new DefaultFormatProvider());
  ring.add(protector.keyVersion, new DataEncryptionKey(provider));
  t.after(() => ring.close());
  return ring;
}

async function scratchFolder(t: TestContext): Promise<string> {
  const folder = await mkdtemp(join(tmpdir(), 'hkdfguard-pipeline-streams-'));
  t.after(() => rm(folder, { recursive: true, force: true }));
  return folder;
}

/** This host's tar - Windows' bsdtar by its full path, else whatever tar is on PATH - and its version line; undefined without one. */
function hostTar(): { path: string; version: string } | undefined {
  const path = isWindows ? join(process.env['SystemRoot'] ?? 'C:\\Windows', 'System32', 'tar.exe') : 'tar';
  if (isWindows && !existsSync(path)) return undefined;
  const probe = spawnSync(path, ['--version'], { encoding: 'utf8' });
  return probe.status === 0 ? { path, version: probe.stdout.split('\n')[0]!.trim() } : undefined;
}

describe('SecretPipelineWriter: the JSON object', () => {
  it('is indented by two spaces with the platform\'s line ending, in ordinal file-name order, with no final line ending', async (t) => {
    const { writer } = await pulled(t);
    const folder = await scratchFolder(t);
    const s = (name: string) => writer.protectedSecrets.get(name)!;

    await writer.writeJsonSecrets(join(folder, 'secrets.json'));

    // As .NET's Utf8JsonWriter writes it (Indented, Environment.NewLine, UnsafeRelaxedJsonEscaping).
    const expected = `{${EOL}  "Zeta": "${s('Zeta')}",${EOL}  "a.b_c-d": "${s('a.b_c-d')}",${EOL}  "api-key": "${s('api-key')}",${EOL}`
      + `  "db-password": "${s('db-password')}",${EOL}  "${LONG_NAME}": "${s(LONG_NAME)}"${EOL}}`;
    assert.equal(await readFile(join(folder, 'secrets.json'), 'utf8'), expected);
  });

  it('is an empty object when the pull found nothing', async (t) => {
    const protector = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), 3);
    t.after(() => protector.close());
    const writer = new InMemoryWriter(protector, new Map(), ['absent']);
    await assert.rejects(writer.pullSecrets(), { code: 'ERR_HKDFGUARD_SECRETS_NOT_FOUND' });
    const folder = await scratchFolder(t);
    const stdin = new CollectingStream();

    await writer.writeJsonSecrets(join(folder, 'secrets.json'));
    await writer.writeJsonSecretsTo(stdin);

    assert.equal(await readFile(join(folder, 'secrets.json'), 'utf8'), '{}');
    assert.equal(stdin.bytes.toString('utf8'), '{}');
  });

  it('escapes what a format provider might write as valid JSON', async (t) => {
    const formatter = new DefaultFormatProvider();
    const odd = { format: (v: Parameters<typeof formatter.format>[0]) => `"\\\n${formatter.format(v)}`, parse: formatter.parse.bind(formatter),
      maxDecryptedLength: formatter.maxDecryptedLength.bind(formatter) };
    const protector = new AesGcmPipelineDataProtector(odd, 3);
    t.after(() => protector.close());
    const writer = new InMemoryWriter(protector, new Map([['item', 'x']]));
    await writer.pullSecrets();
    const stdin = new CollectingStream();

    await writer.writeJsonSecretsTo(stdin);

    assert.equal((JSON.parse(stdin.bytes.toString('utf8')) as Record<string, string>)['item'], writer.protectedSecrets.get('item'));
  });
});

describe('SecretPipelineWriter: the tar archive', () => {
  it('is one PAX entry per file, in ordinal order, each a whole number of blocks', async (t) => {
    const { writer } = await pulled(t);
    const stdin = new CollectingStream();

    await writer.writeProtectedSecretFilesTo(stdin);

    const archive = stdin.bytes;
    assert.equal(archive.length % 512, 0);
    const entries = readTar(archive);
    assert.deepEqual(entries.map((e) => e.name), ['Zeta', 'a.b_c-d', 'api-key', 'db-password', LONG_NAME]);
    for (const entry of entries) assert.equal(entry.data.toString('utf8'), writer.protectedSecrets.get(entry.name));
    // Each file's own header names an 'x' header before it, and truncates a long name to 100 bytes.
    assert.equal(archive[156], 'x'.charCodeAt(0));
    const longHeader = archive.lastIndexOf(Buffer.from(LONG_NAME.slice(0, 100)));
    assert.ok(longHeader > 0 && archive[longHeader + 100] !== 'n'.charCodeAt(0));
  });

  it('counts each PAX record\'s length, its own digits included, across a change in digit count', () => {
    // A record of 99 bytes before its length grows to 3 digits; 8 digit-free bytes around the name.
    for (const length of [85, 86, 87, 88, 89, 90, 91, 92, 93]) {
      const name = 'n'.repeat(length);
      const [entry] = [...tarArchive([{ name, data: new Uint8Array(0), mode: 0o644, mtime: 1 }])];
      const records = Buffer.from(entry!.subarray(512, 1024)).toString('latin1').replace(/\0+$/, '');
      for (const record of records.split('\n').filter((r) => r !== '')) {
        assert.equal(Number(record.split(' ')[0]), Buffer.byteLength(`${record}\n`), record);
      }
      assert.equal(readTar(Buffer.concat([...tarArchive([{ name, data: new Uint8Array(0), mode: 0o644, mtime: 1 }])]))[0]!.name, name);
    }
  });

  it('unpacks with this host\'s tar into files FilePerSecretCache reads', async (t) => {
    const tar = hostTar();
    if (tar === undefined) {
      t.skip('No tar on this host.');
      return;
    }
    const folder = keyFileDirectory(t, 'hkdfguard-pipeline-tar-');
    if (folder === undefined) return;
    const { protector, writer } = await pulled(t);

    // As over ssh: tar reading the archive from its stdin.
    const child = spawn(tar.path, ['-x', '--no-same-owner', '-f', '-', '-C', folder], { stdio: ['pipe', 'inherit', 'pipe'] });
    let stderr = '';
    child.stderr.setEncoding('utf8').on('data', (c: string) => { stderr += c; });
    const exited = once(child, 'exit');
    await writer.writeProtectedSecretFilesTo(child.stdin);
    child.stdin.end();
    assert.deepEqual(await exited, [0, null], `${tar.version}: ${stderr}`);
    assert.equal(stderr, '', tar.version);

    assert.deepEqual((await readdir(folder)).sort(), [...SECRETS.keys()].sort());
    const trust = isWindows
      ? new KeyFileTrust({ windowsPrincipals: [windowsCurrentUserSid()] })
      : new KeyFileTrust({ unixUserIds: [process.geteuid!()], unixGroupIds: [process.getegid!()] });
    const cache = new FilePerSecretCache(folder, trust, await ringFor(t, protector), new DefaultFormatProvider(PIPELINE_FORMAT_LIMIT));
    for (const [name, value] of SECRETS) {
      const result = new Uint8Array((await cache.maxDecryptedLength(name))!);
      assert.equal(new TextDecoder().decode(result.subarray(0, await cache.decrypt(name, result))), value, `${tar.version}: ${name}`);
    }
  });

  it('waits for a slow reader, never handing it more than one write at a time', async (t) => {
    const { writer } = await pulled(t);
    const stdin = new CollectingStream();

    await writer.writeProtectedSecretFilesTo(stdin);
    await writer.writeJsonSecretsTo(stdin);

    assert.equal(stdin.maxPending, 1);
  });
});

describe('SecretPipelineWriter: streaming failures', () => {
  it('rejects with the stream\'s error, never leaving it uncaught', async (t) => {
    const { writer } = await pulled(t);
    const failing = () => new Writable({ write: (_chunk, _encoding, callback) => setImmediate(() => callback(new Error('EPIPE'))) });

    await assert.rejects(writer.writeProtectedSecretFilesTo(failing()), /EPIPE/);
    await assert.rejects(writer.writeJsonSecretsTo(failing()), /EPIPE/);
    await new Promise((resolve) => setImmediate(resolve));
  });

  it('refuses a stream that has ended, and stops once the signal is aborted', async (t) => {
    const { writer } = await pulled(t);
    const ended = new CollectingStream();
    ended.end();

    await assert.rejects(writer.writeProtectedSecretFilesTo(ended), { code: 'ERR_HKDFGUARD_INVALID_STATE' });
    await assert.rejects(writer.writeJsonSecretsTo(ended), { code: 'ERR_HKDFGUARD_INVALID_STATE' });
    const stdin = new CollectingStream();
    await assert.rejects(writer.writeProtectedSecretFilesTo(stdin, AbortSignal.abort()), { name: 'AbortError' });
    await assert.rejects(writer.writeJsonSecretsTo(stdin, AbortSignal.abort()), { name: 'AbortError' });
    assert.equal(stdin.bytes.length, 0);
  });

  it('writes values a ring decrypts under each file name', async (t) => {
    const { protector, writer } = await pulled(t);
    const ring = await ringFor(t, protector);
    const value = writer.protectedSecrets.get('db-password')!;

    const result = new Uint8Array(64);
    const written = ring.createProtector(configurationPurpose('db-password')).decrypt(value, result);
    assert.equal(new TextDecoder().decode(result.subarray(0, written)), 'pässwörd');
    assert.equal(decryptPipelineValue(protector, value, 'db-password'), 'pässwörd');
  });
});

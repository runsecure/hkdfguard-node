import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, type TestContext } from 'node:test';
import { InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';
import { keyFileDirectory, windowsCurrentUserSid } from '@runsecure/hkdfguard-test-support';
import { FILE_TOO_LARGE, KeyFileError, UnsupportedPlatformError } from './errors.js';
import { KeyFileTrust } from './trust.js';
import { parseFileContents, readFileContents, readTrustedFile, readTrustedFileWith, withTrustedFile } from './trustedfile.js';

const isWindows = process.platform === 'win32';
const isUnix = process.platform === 'linux' || (process.platform === 'darwin' && process.arch === 'arm64');
const isRoot = process.getuid?.() === 0;

const LIMIT = 64;

/** A reader over `contents`, as the platform reads hand readFileContents, recording how far it read. */
function reader(contents: Uint8Array): { read: (view: Uint8Array) => number; position: () => number } {
  let offset = 0;
  return {
    read: (view) => {
      const count = Math.min(view.length, contents.length - offset);
      view.set(contents.subarray(offset, offset + count));
      offset += count;
      return count;
    },
    position: () => offset,
  };
}

const random = (length: number) => new Uint8Array(randomBytes(length));
const readBytes = (contents: Uint8Array, maxBytes = LIMIT) => readFileContents(reader(contents).read, 'secret.enc', maxBytes);
const readLength = (contents: Uint8Array, maxBytes = LIMIT) => parseFileContents(reader(contents).read, 'secret.enc', maxBytes, (c) => c.length);

/** A predicate for assert.throws/rejects: a KeyFileError with `code` whose message holds every one of `contains`. */
function fileError(code: string, ...contains: string[]): (e: unknown) => boolean {
  return (e: unknown) => {
    assert.ok(e instanceof KeyFileError, String(e));
    assert.equal(e.code, code, e.message);
    for (const s of contains) assert.ok(e.message.includes(s), `"${e.message}" lacks "${s}"`);
    return true;
  };
}

describe('trusted file contents', () => {
  it('returns the contents exactly, in a buffer the caller owns', () => {
    const contents = random(40);
    const result = readBytes(contents);
    assert.deepEqual(result, contents);
    assert.notEqual(result.buffer, contents.buffer);
  });

  it('accepts exactly the limit', () => {
    const contents = random(LIMIT);
    assert.deepEqual(readBytes(contents), contents);
    assert.equal(readLength(contents), LIMIT);
  });

  it('returns an empty file empty', () => {
    assert.deepEqual(readBytes(new Uint8Array(0)), new Uint8Array(0));
    assert.equal(readLength(new Uint8Array(0)), 0);
  });

  it('refuses a file over the limit, reading only one byte past it, without calling the parser', () => {
    let source = reader(new Uint8Array(LIMIT * 4));
    assert.throws(() => readFileContents(source.read, 'secret.enc', LIMIT), fileError(FILE_TOO_LARGE, `larger than ${LIMIT} bytes`, 'secret.enc'));
    assert.equal(source.position(), LIMIT + 1);

    let parsed = false;
    source = reader(new Uint8Array(LIMIT * 4));
    assert.throws(() => parseFileContents(source.read, 'secret.enc', LIMIT, () => { parsed = true; }), fileError(FILE_TOO_LARGE));
    assert.ok(!parsed);
    assert.equal(source.position(), LIMIT + 1);
  });

  it('applies none of a key file\'s rules', () => {
    // readTrustedKeyFile refuses exactly 32 bytes as a probable plaintext key; a trusted file leaves
    // its contents to its caller.
    const contents = random(32);
    assert.deepEqual(readBytes(contents), contents);
  });

  it('reads until the end however the reads are split', () => {
    const contents = random(50);
    const chunks = [contents.subarray(0, 1), contents.subarray(1, 20), contents.subarray(20)];
    const read = (view: Uint8Array) => {
      const chunk = chunks.shift();
      if (chunk === undefined) return 0;
      view.set(chunk);
      return chunk.length;
    };
    assert.deepEqual(readFileContents(read, 'secret.enc', LIMIT), contents);
  });

  it('hands the parser the contents and returns its result', () => {
    const contents = random(40);
    assert.deepEqual(parseFileContents(reader(contents).read, 'secret.enc', LIMIT, (c) => Array.from(c)), Array.from(contents));
  });

  it('passes on what the parser throws', () => {
    assert.throws(() => parseFileContents(reader(random(3)).read, 'secret.enc', LIMIT, () => { throw new SyntaxError('not a PEM'); }), SyntaxError);
  });

  it('zeroes its buffer whether the parser returns or throws, and when it refuses', () => {
    for (const [length, parse] of [[40, (c: Uint8Array) => c.length], [40, () => { throw new SyntaxError(); }], [LIMIT + 1, () => 0]] as const) {
      let seen: Uint8Array | undefined;
      const read = (view: Uint8Array) => {
        if (seen !== undefined) return 0;
        seen = view;
        view.fill(0xab, 0, length);
        return length;
      };
      try {
        parseFileContents(read, 'secret.enc', LIMIT, parse);
      } catch (error) {
        assert.ok(error instanceof SyntaxError || error instanceof KeyFileError, String(error));
      }
      const whole = new Uint8Array(seen!.buffer);
      assert.equal(whole.length, LIMIT + 1);
      assert.ok(whole.every((b) => b === 0), 'buffer not zeroed');
    }
  });

  it('passes on an error reading', () => {
    assert.throws(() => readFileContents(() => { throw new Error('disk on fire'); }, 'secret.enc', LIMIT), /disk on fire/);
  });
});

describe('readTrustedFile arguments', () => {
  const trust = KeyFileTrust.administratorsOnly;

  it('refuses invalid arguments before anything is opened', async () => {
    for (const path of [undefined, null, 42, '', 'secret\0.enc']) {
      await assert.rejects(readTrustedFile(path as string, trust, LIMIT), InvalidArgumentError, String(path));
      await assert.rejects(readTrustedFileWith(path as string, trust, LIMIT, (c) => c.length), InvalidArgumentError, String(path));
    }
    for (const badTrust of [null, 'S-1-5-18', { windowsPrincipals: [] }]) {
      await assert.rejects(readTrustedFile('secret.enc', badTrust as unknown as KeyFileTrust, LIMIT), InvalidArgumentError);
    }
    for (const maxBytes of [0, -1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER, '64']) {
      await assert.rejects(readTrustedFile('secret.enc', trust, maxBytes as number), InvalidArgumentError, String(maxBytes));
      await assert.rejects(readTrustedFileWith('secret.enc', trust, maxBytes as number, (c) => c.length), InvalidArgumentError, String(maxBytes));
    }
    await assert.rejects(readTrustedFileWith('secret.enc', trust, LIMIT, null as unknown as (c: Uint8Array) => number), InvalidArgumentError);
  });

  it('is cancelled by an aborted signal before anything is examined', async () => {
    await assert.rejects(readTrustedFile('', trust, LIMIT, AbortSignal.abort()), { name: 'AbortError' });
    await assert.rejects(readTrustedFileWith('', trust, LIMIT, (c) => c.length, AbortSignal.abort()), { name: 'AbortError' });
  });

  it('is unsupported off Windows, Linux and macOS, and on an Intel Mac', () => {
    const use = () => assert.fail('nothing should be opened');
    assert.throws(() => withTrustedFile('freebsd', 'x64', '/etc/hkdfguard/secret.enc', trust, use),
      (e: unknown) => e instanceof UnsupportedPlatformError && e.message.includes('Windows, Linux and macOS only'));
    assert.throws(() => withTrustedFile('darwin', 'x64', '/etc/hkdfguard/secret.enc', trust, use),
      (e: unknown) => e instanceof UnsupportedPlatformError && e.message.includes('Apple silicon Macs only; this process is x64'));
  });
});

/** Trusts the account running the tests, which owns, and may modify, its own folders. */
const trustCurrentUser = () => (isWindows
  ? new KeyFileTrust({ windowsPrincipals: [windowsCurrentUserSid()] })
  : new KeyFileTrust({ unixUserIds: [process.geteuid!()], unixGroupIds: [process.getegid!()] }));

/** A fresh folder the trust checks accept once the current user is trusted (see keyFileDirectory), or undefined with the test skipped. */
const trustedDirectory = (t: TestContext) => keyFileDirectory(t, 'hkdfguard-trustedfile-');

describe('readTrustedFile, real files', { skip: !isWindows && !isUnix && 'Windows, Linux and Apple silicon macOS only.' }, () => {
  it('reads a file through either form with the user trusted, contents unchecked', async (t) => {
    const directory = trustedDirectory(t);
    if (directory === undefined) return;
    const contents = random(32); // a key file's size: refused by readTrustedKeyFile, not here
    const path = join(directory, 'secret.enc');
    writeFileSync(path, contents);

    assert.deepEqual(await readTrustedFile(path, trustCurrentUser(), LIMIT), contents);
    assert.deepEqual(await readTrustedFileWith(path, trustCurrentUser(), LIMIT, (c) => c.slice()), contents);
  });

  it('reads an empty file as empty', async (t) => {
    const directory = trustedDirectory(t);
    if (directory === undefined) return;
    const path = join(directory, 'empty.enc');
    writeFileSync(path, new Uint8Array(0));
    assert.deepEqual(await readTrustedFile(path, trustCurrentUser(), LIMIT), new Uint8Array(0));
  });

  it('refuses a file over the limit', async (t) => {
    const directory = trustedDirectory(t);
    if (directory === undefined) return;
    const path = join(directory, 'secret.enc');
    writeFileSync(path, new Uint8Array(LIMIT + 1));
    await assert.rejects(readTrustedFile(path, trustCurrentUser(), LIMIT), fileError(FILE_TOO_LARGE, `larger than ${LIMIT} bytes`));
    await assert.rejects(readTrustedFileWith(path, trustCurrentUser(), LIMIT, () => assert.fail('parsed')), fileError(FILE_TOO_LARGE));
  });

  it('refuses a file the user owns by default', async (t) => {
    if (isRoot) {
      t.skip('Running as root, whose files are trusted.');
      return;
    }
    const directory = trustedDirectory(t);
    if (directory === undefined) return;
    const path = join(directory, 'secret.enc');
    writeFileSync(path, random(40));
    await assert.rejects(readTrustedFile(path, KeyFileTrust.administratorsOnly, LIMIT), fileError('EACCES', 'not trusted'));
    await assert.rejects(readTrustedFileWith(path, KeyFileTrust.administratorsOnly, LIMIT, () => assert.fail('parsed')), fileError('EACCES', 'not trusted'));
  });

  it('reports a missing file or folder as not found', async (t) => {
    const directory = trustedDirectory(t);
    if (directory === undefined) return;
    await assert.rejects(readTrustedFile(join(directory, 'missing.enc'), trustCurrentUser(), LIMIT), fileError('ENOENT'));
    await assert.rejects(readTrustedFile(join(directory, 'missing', 'secret.enc'), trustCurrentUser(), LIMIT), fileError('ENOENT'));
  });
});

describe('readTrustedFile on Linux and macOS, system files', { skip: !isUnix && 'Linux and Apple silicon macOS only.' }, () => {
  it('reads a root-owned system file through either form', async () => {
    // /etc/hosts: root-owned all the way up (through macOS's root-owned /etc link), and any
    // contents at all are accepted.
    const expected = new Uint8Array(readFileSync('/etc/hosts'));
    assert.deepEqual(await readTrustedFile('/etc/hosts', KeyFileTrust.administratorsOnly, 1024 * 1024), expected);
    assert.equal(await readTrustedFileWith('/etc/hosts', KeyFileTrust.administratorsOnly, 1024 * 1024, (c) => c.length), expected.length);
  });

  it('refuses a file under the shared temp directory', async (t) => {
    const directory = mkdtempSync('/tmp/hkdfguard-');
    t.after(() => rmSync(directory, { recursive: true, force: true }));
    const path = join(directory, 'secret.enc');
    writeFileSync(path, random(40));
    await assert.rejects(readTrustedFile(path, trustCurrentUser(), LIMIT), fileError('EACCES', 'not trusted'));
  });

  it('reports a missing file as not found', async () => {
    await assert.rejects(readTrustedFile(`/hkdfguard-missing-${randomBytes(8).toString('hex')}.enc`, KeyFileTrust.administratorsOnly, LIMIT),
      fileError('ENOENT'));
  });
});

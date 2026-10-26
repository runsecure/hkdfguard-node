import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { chmodSync, closeSync, mkdirSync, mkdtempSync, openSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { basename, isAbsolute, join, parse, relative } from 'node:path';
import { describe, it, type TestContext } from 'node:test';
import { InvalidArgumentError, MAX_WRAPPED_KEY_BYTES } from '@runsecure/hkdfguard-abstractions';
import { icacls, keyFileDirectory, windowsCurrentUserSid, windowsShortPath } from '@runsecure/hkdfguard-test-support';
import { INVALID_KEY_FILE, KeyFileError, UnsupportedPlatformError } from './errors.js';
import { KeyFileTrust } from './trust.js';
import {
  expandShortNames, looksLikePlaintextKey, PLAINTEXT_TEXT_SCAN_LIMIT, readContents, readOnPlatform, readTrustedKeyFile,
} from './trustedkeyfile.js';

const isWindows = process.platform === 'win32';
const isUnix = process.platform === 'linux' || (process.platform === 'darwin' && process.arch === 'arm64');
const isRoot = process.getuid?.() === 0;

/** About the size of a KMS ciphertext blob for a 32-byte DEK. */
const wrapped = () => new Uint8Array(randomBytes(184));

/** A reader over `contents`, as the platform reads hand readContents, recording how far it read. */
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

const readBytes = (contents: Uint8Array) => readContents(reader(contents).read, 'v1.key');

/** A predicate for assert.throws/rejects: a KeyFileError with `code` whose message holds every one of `contains`. */
function keyFileError(code: string, ...contains: string[]): (e: unknown) => boolean {
  return (e: unknown) => {
    assert.ok(e instanceof KeyFileError, String(e));
    assert.equal(e.code, code, e.message);
    for (const s of contains) assert.ok(e.message.includes(s), `"${e.message}" lacks "${s}"`);
    return true;
  };
}

describe('key file contents', () => {
  it('returns a wrapped key exactly, in a buffer the caller owns', () => {
    const key = wrapped();
    const result = readBytes(key);
    assert.deepEqual(result, key);
    assert.notEqual(result.buffer, key.buffer);
  });

  it('accepts exactly the limit', () => {
    const key = new Uint8Array(randomBytes(MAX_WRAPPED_KEY_BYTES));
    assert.deepEqual(readBytes(key), key);
  });

  it('refuses an empty file', () => {
    assert.throws(() => readBytes(new Uint8Array(0)), keyFileError(INVALID_KEY_FILE, 'empty'));
  });

  it('refuses a file over the limit, reading only one byte past it', () => {
    const source = reader(new Uint8Array(MAX_WRAPPED_KEY_BYTES * 4).fill(1));
    assert.throws(() => readContents(source.read, 'v1.key'), keyFileError(INVALID_KEY_FILE, 'larger than 512 bytes'));
    assert.equal(source.position(), MAX_WRAPPED_KEY_BYTES + 1);
  });

  it('refuses a plaintext key as exposed', () => {
    assert.throws(() => readBytes(new Uint8Array(randomBytes(32))), keyFileError(INVALID_KEY_FILE, 'exposed'));
  });

  it('reads until the end however the reads are split', () => {
    const key = wrapped();
    const chunks = [key.subarray(0, 1), key.subarray(1, 100), key.subarray(100)];
    const read = (view: Uint8Array) => {
      const chunk = chunks.shift();
      if (chunk === undefined) return 0;
      view.set(chunk);
      return chunk.length;
    };
    assert.deepEqual(readContents(read, 'v1.key'), key);
  });

  it('zeroes its buffer whether it returns or refuses', () => {
    for (const length of [32, 184]) {
      const seen: Uint8Array[] = [];
      const read = (view: Uint8Array) => {
        seen.push(view);
        if (seen.length > 1) return 0;
        view.fill(0xab, 0, length);
        return length;
      };
      try {
        readContents(read, 'v1.key');
      } catch (error) {
        assert.ok(error instanceof KeyFileError);
      }
      const whole = new Uint8Array(seen[0]!.buffer);
      assert.equal(whole.length, MAX_WRAPPED_KEY_BYTES + 1);
      assert.ok(whole.every((b) => b === 0), `buffer not zeroed after a ${length}-byte read`);
    }
  });

  it('passes on an error reading', () => {
    assert.throws(() => readContents(() => { throw new Error('disk on fire'); }, 'v1.key'), /disk on fire/);
  });
});

describe('plaintext key detection', () => {
  // Fixed, so the standard and URL-safe encodings always differ: FB EF BE encodes as "++++", FF FF FF
  // as "////". A random key would sometimes encode with neither, merging two rows.
  const key = Buffer.from(Array.from({ length: 32 }, (_, i) => [0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff][i % 6]!));
  const hex = key.toString('hex').toUpperCase();
  const standard = key.toString('base64');
  const urlSafe = key.toString('base64url');
  const ascii = (s: string) => new Uint8Array(Buffer.from(s, 'latin1'));

  it('detects a key written as text', () => {
    for (const text of [hex, `${hex.toLowerCase()}\n`, standard, standard.replace(/=+$/, ''), `${urlSafe}=`, `${urlSafe}\r\n`,
      `  \t${standard} \n`, `\v${hex}\f`]) {
      assert.ok(looksLikePlaintextKey(ascii(text)), JSON.stringify(text));
    }
  });

  it('detects a raw key', () => {
    assert.ok(looksLikePlaintextKey(new Uint8Array(randomBytes(32))));
    assert.ok(looksLikePlaintextKey(new Uint8Array(32)));
  });

  it('does not detect other text', () => {
    for (const text of [
      'a'.repeat(63), // one hex digit short
      `${'a'.repeat(62)}zz`, // not hex
      'A'.repeat(42), // too short for base64
      'A'.repeat(45), // too long for base64
      `${'A'.repeat(41)}+-`, // mixes the two alphabets
      `${'A'.repeat(42)}!`, // not base64
      `${'A'.repeat(43)}==`, // 45 characters
      `${'A'.repeat(42)}==`, // 44, but padded for 31 bytes
    ]) {
      assert.ok(!looksLikePlaintextKey(ascii(text)), text);
    }
  });

  it('does not detect a wrapped key', () => {
    assert.ok(!looksLikePlaintextKey(wrapped()));
    assert.ok(!looksLikePlaintextKey(new Uint8Array(randomBytes(PLAINTEXT_TEXT_SCAN_LIMIT + 1))));
  });
});

describe('readTrustedKeyFile arguments', () => {
  it('refuses a missing or unusable path before anything is examined', async () => {
    for (const path of [undefined, null, 42, '', 'v1\0.key']) {
      await assert.rejects(readTrustedKeyFile(path as string, KeyFileTrust.administratorsOnly), InvalidArgumentError, String(path));
    }
  });

  it('refuses a trust that is not a KeyFileTrust', async () => {
    for (const trust of [null, 'S-1-5-18', { windowsPrincipals: [] }]) {
      await assert.rejects(readTrustedKeyFile('v1.key', trust as unknown as KeyFileTrust), InvalidArgumentError);
    }
  });

  it('is cancelled by an aborted signal before anything is examined', async () => {
    await assert.rejects(readTrustedKeyFile('', KeyFileTrust.administratorsOnly, AbortSignal.abort()), { name: 'AbortError' });
  });

  it('is unsupported off Windows, Linux and macOS', () => {
    assert.throws(() => readOnPlatform('freebsd', 'x64', '/etc/hkdfguard/v1.key', KeyFileTrust.administratorsOnly),
      (e: unknown) => e instanceof UnsupportedPlatformError && e.message.includes('Windows, Linux and macOS only') && e.code === 'ERR_HKDFGUARD_UNSUPPORTED_PLATFORM');
  });

  it('is unsupported on an Intel Mac', () => {
    assert.throws(() => readOnPlatform('darwin', 'x64', '/etc/hkdfguard/v1.key', KeyFileTrust.administratorsOnly),
      (e: unknown) => e instanceof UnsupportedPlatformError && e.message.includes('Apple silicon Macs only; this process is x64'));
  });
});

describe('KeyFileTrust', () => {
  it('copies its lists and freezes them', () => {
    const sids = ['S-1-5-21-1-2-3-1005'];
    const trust = new KeyFileTrust({ windowsPrincipals: sids, unixUserIds: [1001], unixGroupIds: new Set([2001]) });
    sids.push('S-1-1-0');

    assert.deepEqual(trust.windowsPrincipals, ['S-1-5-21-1-2-3-1005']);
    assert.deepEqual(trust.unixUserIds, [1001]);
    assert.deepEqual(trust.unixGroupIds, [2001]);
    assert.ok(Object.isFrozen(trust) && Object.isFrozen(trust.windowsPrincipals) && Object.isFrozen(trust.unixUserIds));
    assert.throws(() => (trust.unixUserIds as number[]).push(0), TypeError);
    assert.deepEqual(new KeyFileTrust({ unixUserIds: [4294967295] }).unixUserIds, [4294967295]);
  });

  it('trusts no one else by default', () => {
    for (const trust of [KeyFileTrust.administratorsOnly, new KeyFileTrust(), new KeyFileTrust({})]) {
      assert.deepEqual([trust.windowsPrincipals, trust.unixUserIds, trust.unixGroupIds], [[], [], []]);
    }
    assert.ok(Object.isFrozen(KeyFileTrust.administratorsOnly));
  });

  it('refuses what is not an id or a SID', () => {
    for (const options of [{ unixUserIds: [-1] }, { unixGroupIds: [0x1_0000_0000] }, { unixUserIds: [1.5] }, { unixUserIds: [true] },
      { unixGroupIds: ['2001'] }, { windowsPrincipals: 'S-1-5-21-1-2-3-1005' }, { windowsPrincipals: [1005] }, { unixUserIds: 1001 }]) {
      assert.throws(() => new KeyFileTrust(options as never), InvalidArgumentError, JSON.stringify(options));
    }
    assert.throws(() => new KeyFileTrust(null as never), InvalidArgumentError);
  });
});

describe('8.3 short name expansion', () => {
  const longNames = new Map([['C:\\PROGRA~1', 'C:\\Program Files'], ['C:\\PROGRA~1\\HKDFGU~1', 'C:\\Program Files\\HkdfGuard Keys']]);
  const longPath = (path: string) => longNames.get(path) ?? null;

  it('expands the longest leading part that exists, keeping the rest', () => {
    assert.equal(expandShortNames('C:\\PROGRA~1\\HKDFGU~1', longPath), 'C:\\Program Files\\HkdfGuard Keys');
    assert.equal(expandShortNames('C:\\PROGRA~1\\HKDFGU~1\\MISSING~1.KEY', longPath), 'C:\\Program Files\\HkdfGuard Keys\\MISSING~1.KEY');
    assert.equal(expandShortNames('C:\\PROGRA~1\\missing\\v1.key', longPath), 'C:\\Program Files\\missing\\v1.key');
  });

  it('leaves a path with nothing to expand as it is', () => {
    assert.equal(expandShortNames('C:\\NOSUCH~1\\v1.key', longPath), 'C:\\NOSUCH~1\\v1.key');
  });
});

/** A fresh folder for key files under the temp folder, by its long path, with its inherited permissions (the user's own folder). */
function windowsKeyDirectory(t: TestContext): string {
  return keyFileDirectory(t, 'hkdfguard-securefile-')!;
}

/** Trusts the account running the tests, which owns, and may modify, its own temp folder. */
const trustCurrentUser = () => new KeyFileTrust({ windowsPrincipals: [windowsCurrentUserSid()] });

describe('readTrustedKeyFile on Windows, real files', { skip: !isWindows && 'Windows only.' }, () => {
  it('refuses a file in the user\'s own folder by default', async (t) => {
    const path = join(windowsKeyDirectory(t), 'v1.key');
    writeFileSync(path, wrapped());
    await assert.rejects(readTrustedKeyFile(path), keyFileError('EACCES', 'not trusted'));
    await assert.rejects(readTrustedKeyFile(path, KeyFileTrust.administratorsOnly), keyFileError('EACCES', 'is owned by'));
  });

  it('reads the file with the user trusted', async (t) => {
    const key = wrapped();
    const path = join(windowsKeyDirectory(t), 'v1.key');
    writeFileSync(path, key);
    assert.deepEqual(await readTrustedKeyFile(path, trustCurrentUser()), key);
    assert.deepEqual(await readTrustedKeyFile(path.replace(/\\/g, '/'), trustCurrentUser()), key);
  });

  it('reads a relative path from the working directory', async (t) => {
    const key = wrapped();
    const path = join(windowsKeyDirectory(t), 'v1.key');
    writeFileSync(path, key);
    if (parse(process.cwd()).root.toUpperCase() !== parse(path).root.toUpperCase()) {
      t.skip('The temp folder is on another drive than the working directory.');
      return;
    }
    const relativePath = relative(process.cwd(), path);
    assert.ok(!isAbsolute(relativePath));
    assert.deepEqual(await readTrustedKeyFile(relativePath, trustCurrentUser()), key);
  });

  it('refuses a file others may write, even with the user trusted', async (t) => {
    const path = join(windowsKeyDirectory(t), 'v1.key');
    writeFileSync(path, wrapped());
    icacls(path, '/grant', '*S-1-5-32-545:(W)'); // Users: Write
    await assert.rejects(readTrustedKeyFile(path, trustCurrentUser()), keyFileError('EACCES', 'grants', 'BUILTIN\\Users'));
  });

  it('refuses a folder others may write, even with the user trusted', async (t) => {
    const directory = windowsKeyDirectory(t);
    const path = join(directory, 'v1.key');
    writeFileSync(path, wrapped());
    icacls(directory, '/grant', '*S-1-5-32-545:(AD)'); // Users: create subfolders, on the folder only
    await assert.rejects(readTrustedKeyFile(path, trustCurrentUser()), keyFileError('EACCES', `'${directory}' grants`));
  });

  it('refuses a path through a junction', async (t) => {
    const directory = windowsKeyDirectory(t);
    const real = join(directory, 'real');
    mkdirSync(real);
    writeFileSync(join(real, 'v1.key'), wrapped());
    const junction = join(directory, 'junction');
    symlinkSync(real, junction, 'junction');
    await assert.rejects(readTrustedKeyFile(join(junction, 'v1.key'), trustCurrentUser()), keyFileError('EACCES', 'it opens', join(real, 'v1.key')));
  });

  it('expands a short name and checks the real path', async (t) => {
    const key = wrapped();
    const path = join(windowsKeyDirectory(t), 'a-long-key-file-name.key');
    writeFileSync(path, key);
    const short = windowsShortPath(path);

    // The full path expands 8.3 names, so the folders checked are the real ones.
    assert.deepEqual(await readTrustedKeyFile(short, trustCurrentUser()), key);
    await assert.rejects(readTrustedKeyFile(short, KeyFileTrust.administratorsOnly), keyFileError('EACCES', basename(path)));
  });

  it('reports a missing file or folder as not found', async (t) => {
    const directory = windowsKeyDirectory(t);
    await assert.rejects(readTrustedKeyFile(join(directory, 'missing.key'), trustCurrentUser()), keyFileError('ENOENT'));
    await assert.rejects(readTrustedKeyFile(join(directory, 'missing', 'v1.key'), trustCurrentUser()), keyFileError('ENOENT'));
  });

  it('refuses a folder', async (t) => {
    await assert.rejects(readTrustedKeyFile(windowsKeyDirectory(t), trustCurrentUser()), keyFileError('EACCES'));
  });

  it('refuses a file another process has open for writing', async (t) => {
    const path = join(windowsKeyDirectory(t), 'v1.key');
    writeFileSync(path, wrapped());
    const writer = openSync(path, 'a');
    try {
      await assert.rejects(readTrustedKeyFile(path, trustCurrentUser()), keyFileError('EBUSY', 'open for writing by another process'));
    } finally {
      closeSync(writer);
    }
  });

  it('refuses a UNC or device path without opening it', async () => {
    for (const path of ['\\\\hkdfguard-no-such-server.invalid\\share\\v1.key', '//hkdfguard-no-such-server.invalid/share/v1.key',
      '\\\\?\\C:\\HkdfGuardKeys\\v1.key']) {
      await assert.rejects(readTrustedKeyFile(path), keyFileError('EACCES', 'UNC or device path'), path);
    }
  });

  it('refuses to trust everyone', async (t) => {
    const path = join(windowsKeyDirectory(t), 'v1.key');
    writeFileSync(path, wrapped());
    await assert.rejects(readTrustedKeyFile(path, new KeyFileTrust({ windowsPrincipals: ['S-1-1-0'] })),
      (e: unknown) => e instanceof InvalidArgumentError && e.message.includes('every account'));
  });

  it('refuses a plaintext key once its location passes', async (t) => {
    const path = join(windowsKeyDirectory(t), 'v1.key');
    writeFileSync(path, randomBytes(32).toString('hex'));
    await assert.rejects(readTrustedKeyFile(path, trustCurrentUser()), keyFileError(INVALID_KEY_FILE, 'unwrapped'));
  });
});

const unixTrustCurrentUser = () => new KeyFileTrust({ unixUserIds: [process.geteuid!()], unixGroupIds: [process.getegid!()] });

/** A private (0700) directory whose whole chain is root's or this user's (see keyFileDirectory), or undefined with the test skipped. */
function unixKeyDirectory(t: TestContext): string | undefined {
  return keyFileDirectory(t, 'hkdfguard-securefile-');
}

describe('readTrustedKeyFile on Linux and macOS, real files', { skip: !isUnix && 'Linux and Apple silicon macOS only.' }, () => {
  it('refuses a file under the shared temp directory', async (t) => {
    // /tmp is writable by everyone (sticky or not), so nothing beneath it is trusted.
    const directory = mkdtempSync('/tmp/hkdfguard-');
    t.after(() => rmSync(directory, { recursive: true, force: true }));
    const path = join(directory, 'v1.key');
    writeFileSync(path, wrapped());
    await assert.rejects(readTrustedKeyFile(path, unixTrustCurrentUser()), keyFileError('EACCES', 'not trusted'));
  });

  it('refuses a file the user owns by default', async (t) => {
    if (isRoot) {
      t.skip('Running as root, whose files are trusted.');
      return;
    }
    const directory = unixKeyDirectory(t);
    if (directory === undefined) return;
    const path = join(directory, 'v1.key');
    writeFileSync(path, wrapped());
    await assert.rejects(readTrustedKeyFile(path), keyFileError('EACCES', 'not trusted'));
  });

  it('reports a missing file as not found', async () => {
    await assert.rejects(readTrustedKeyFile(`/hkdfguard-missing-${randomBytes(8).toString('hex')}.key`), keyFileError('ENOENT'));
  });

  it('passes a root-owned system file\'s location', async () => {
    // /etc/hosts: root-owned all the way up, and not a key - so it may be refused for its contents
    // (or size), never for where it lives.
    try {
      await readTrustedKeyFile('/etc/hosts');
    } catch (error) {
      assert.ok(error instanceof KeyFileError && error.code === INVALID_KEY_FILE, `/etc/hosts was refused for its location: ${String(error)}`);
    }
  });

  it('reads a file only its trusted owner can replace, and follows a link to it only when trusted', async (t) => {
    const directory = unixKeyDirectory(t);
    if (directory === undefined) return;
    const trust = unixTrustCurrentUser();
    const key = wrapped();
    const path = join(directory, 'v1.key');
    writeFileSync(path, key);
    chmodSync(path, 0o600);
    const link = join(directory, 'current.key');
    symlinkSync('v1.key', link);

    assert.deepEqual(await readTrustedKeyFile(path, trust), key);
    assert.deepEqual(await readTrustedKeyFile(link, trust), key);
    assert.deepEqual(await readTrustedKeyFile(`${directory}/../${basename(directory)}/./v1.key`, trust), key);
    const workingDirectory = process.cwd();
    process.chdir(directory);
    try {
      assert.deepEqual(await readTrustedKeyFile('v1.key', trust), key);
    } finally {
      process.chdir(workingDirectory);
    }
    if (!isRoot) {
      // The same file and link, owned by a user only the first trust names.
      await assert.rejects(readTrustedKeyFile(link, KeyFileTrust.administratorsOnly), keyFileError('EACCES'));
    }
  });

  it('reads a group-writable file only when its group is trusted', async (t) => {
    const directory = unixKeyDirectory(t);
    if (directory === undefined) return;
    const key = wrapped();
    const path = join(directory, 'v1.key');
    writeFileSync(path, key);
    chmodSync(path, 0o660);

    assert.deepEqual(await readTrustedKeyFile(path, unixTrustCurrentUser()), key);
    await assert.rejects(readTrustedKeyFile(path, new KeyFileTrust({ unixUserIds: [process.geteuid!()] })), keyFileError('EACCES', 'writable by group'));
  });

  it('refuses a plaintext key once its location passes', async (t) => {
    const directory = unixKeyDirectory(t);
    if (directory === undefined) return;
    const path = join(directory, 'v1.key');
    writeFileSync(path, `${randomBytes(32).toString('base64')}\n`);
    await assert.rejects(readTrustedKeyFile(path, unixTrustCurrentUser()), keyFileError(INVALID_KEY_FILE, 'unwrapped'));
  });

  it('refuses a directory as not a regular file', async (t) => {
    const directory = unixKeyDirectory(t);
    if (directory === undefined) return;
    await assert.rejects(readTrustedKeyFile(directory, unixTrustCurrentUser()), keyFileError('EACCES', 'not a regular file'));
  });
});

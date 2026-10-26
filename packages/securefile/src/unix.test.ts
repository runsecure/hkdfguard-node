import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';
import { KeyFileError } from './errors.js';
import { KeyFileTrust } from './trust.js';
import { MAX_SYMBOLIC_LINKS, parentOf, resolveTrusted, type UnixFileStatus } from './unix.js';

/*
 * The Linux and macOS key-file location rules, checked against simulated filesystems so they run on
 * every platform. trustedkeyfile.test.ts runs them against the real filesystem.
 */

const ROOT = 0;
const DEPLOYER = 1001;
const APP = 1002;
const DEPLOYERS_GROUP = 2001;

const KEY_FILE = '/etc/hkdfguard/keys/v1.key';
const DEPLOYER_TRUST = new KeyFileTrust({ unixUserIds: [DEPLOYER], unixGroupIds: [DEPLOYERS_GROUP] });

/** A simulated filesystem: what lstat sees, and what each symbolic link holds. */
class FileSystem {
  readonly entries = new Map<string, UnixFileStatus>();
  readonly links = new Map<string, string>();

  dir(path: string, { owner = ROOT, mode = 0o755, group = ROOT } = {}): this {
    this.entries.set(path, { ownerId: owner, groupId: group, mode, type: 'directory' });
    return this;
  }

  file(path: string, { owner = ROOT, mode = 0o640, group = ROOT } = {}): this {
    this.entries.set(path, { ownerId: owner, groupId: group, mode, type: 'regular file' });
    return this;
  }

  link(path: string, target: string, owner = ROOT): this {
    this.entries.set(path, { ownerId: owner, groupId: owner, mode: 0o777, type: 'symbolic link' });
    this.links.set(path, target);
    return this;
  }

  other(path: string): this {
    this.entries.set(path, { ownerId: ROOT, groupId: ROOT, mode: 0o640, type: 'other' });
    return this;
  }

  resolve(path: string, trust = KeyFileTrust.administratorsOnly): string {
    return resolveTrusted(path, trust, (p) => this.entries.get(p), (p) => this.links.get(p));
  }
}

const standard = () => new FileSystem().dir('/').dir('/etc').dir('/etc/hkdfguard').dir('/etc/hkdfguard/keys');

/** Asserts `fn` throws a KeyFileError with `code` whose message holds every one of `contains`. */
function refused(fn: () => unknown, code: string, ...contains: string[]): void {
  assert.throws(fn, (e: unknown) => {
    assert.ok(e instanceof KeyFileError, String(e));
    assert.equal(e.code, code, e.message);
    for (const s of contains) assert.ok(e.message.includes(s), `"${e.message}" lacks "${s}"`);
    return true;
  });
}

describe('Unix key-file location rules', () => {
  it('resolve a root-owned path', () => {
    assert.equal(standard().file(KEY_FILE).resolve(KEY_FILE), KEY_FILE);
  });

  it('never refuse a file for being readable by others', () => {
    assert.equal(standard().file(KEY_FILE, { mode: 0o644 }).resolve(KEY_FILE), KEY_FILE);
  });

  it('refuse a file owned by the application', () => {
    refused(() => standard().file(KEY_FILE, { owner: APP, group: APP }).resolve(KEY_FILE), 'EACCES', 'uid 1002', 'not trusted');
  });

  it('resolve a file owned by a trusted deployer', () => {
    assert.equal(standard().file(KEY_FILE, { owner: DEPLOYER, group: DEPLOYER }).resolve(KEY_FILE, DEPLOYER_TRUST), KEY_FILE);
  });

  it('refuse a directory owned by an untrusted user', () => {
    refused(() => standard().dir('/etc/hkdfguard/keys', { owner: APP, group: APP }).file(KEY_FILE).resolve(KEY_FILE), 'EACCES', "'/etc/hkdfguard/keys'");
  });

  it('refuse an untrusted root, and one that cannot be examined', () => {
    refused(() => standard().dir('/', { mode: 0o777 }).file(KEY_FILE).resolve(KEY_FILE), 'EACCES');
    refused(() => new FileSystem().resolve(KEY_FILE), 'EACCES');
  });

  it('refuse a world-writable directory even with the sticky bit', () => {
    const fs = new FileSystem().dir('/').dir('/tmp', { mode: 0o1777 }).dir('/tmp/keys').file('/tmp/keys/v1.key');
    refused(() => fs.resolve('/tmp/keys/v1.key'), 'EACCES', 'writable by every user');
  });

  it('refuse a world-writable file whatever is trusted', () => {
    refused(() => standard().file(KEY_FILE, { mode: 0o777 }).resolve(KEY_FILE, DEPLOYER_TRUST), 'EACCES');
  });

  it('refuse group-writable unless the group is trusted', () => {
    const fs = standard().dir('/etc/hkdfguard/keys', { mode: 0o775, group: DEPLOYERS_GROUP }).file(KEY_FILE, { mode: 0o660, group: DEPLOYERS_GROUP });
    refused(() => fs.resolve(KEY_FILE), 'EACCES', 'group 2001');
    assert.equal(fs.resolve(KEY_FILE, DEPLOYER_TRUST), KEY_FILE);
  });

  it('refuse group-writable by another group even with a trusted group', () => {
    refused(() => standard().file(KEY_FILE, { mode: 0o660, group: APP }).resolve(KEY_FILE, DEPLOYER_TRUST), 'EACCES');
  });

  it("follow a root-owned symbolic link and check its target (macOS's /etc)", () => {
    const fs = new FileSystem().dir('/').link('/etc', 'private/etc').dir('/private').dir('/private/etc').dir('/private/etc/hkdfguard')
      .file('/private/etc/hkdfguard/v1.key');
    assert.equal(fs.resolve('/etc/hkdfguard/v1.key'), '/private/etc/hkdfguard/v1.key');
  });

  it('restart from root for an absolute symbolic link', () => {
    assert.equal(standard().file(KEY_FILE).dir('/srv').link('/srv/current.key', KEY_FILE).resolve('/srv/current.key'), KEY_FILE);
  });

  it('never follow a symbolic link owned by an untrusted user', () => {
    const fs = standard().file(KEY_FILE).dir('/srv').link('/srv/current.key', KEY_FILE, APP);
    refused(() => fs.resolve('/srv/current.key'), 'EACCES', 'symbolic link owned by uid 1002');
  });

  it('follow a symbolic link owned by a trusted deployer', () => {
    const fs = standard().file(KEY_FILE).dir('/srv').link('/srv/current.key', KEY_FILE, DEPLOYER);
    assert.equal(fs.resolve('/srv/current.key', DEPLOYER_TRUST), KEY_FILE);
  });

  it('refuse a symbolic link into an untrusted directory', () => {
    const fs = standard().dir('/home').dir('/home/app', { owner: APP, group: APP }).file('/home/app/v1.key', { owner: APP, group: APP })
      .link(KEY_FILE, '/home/app/v1.key');
    refused(() => fs.resolve(KEY_FILE), 'EACCES');
  });

  it('refuse a symbolic link loop', () => {
    refused(() => new FileSystem().dir('/').link('/a', '/b').link('/b', '/a').resolve('/a'), 'EACCES', `more than ${MAX_SYMBOLIC_LINKS} symbolic links`);
  });

  it('refuse a symbolic link that cannot be read', () => {
    const fs = standard().file(KEY_FILE).dir('/srv').link('/srv/current.key', KEY_FILE);
    fs.links.delete('/srv/current.key');
    refused(() => fs.resolve('/srv/current.key'), 'EACCES', 'could not be read as a symbolic link');
  });

  it('resolve . and .. after links, the way the kernel does', () => {
    const fs = standard().file(KEY_FILE);
    assert.equal(fs.resolve('/etc/./hkdfguard/keys/../keys//v1.key'), KEY_FILE);
    assert.equal(fs.resolve('/../etc/hkdfguard/keys/v1.key'), KEY_FILE);
  });

  it('report a missing file, and a path through a file, as not found', () => {
    refused(() => standard().resolve(KEY_FILE), 'ENOENT', 'was not found');
    refused(() => standard().file(KEY_FILE).resolve(`${KEY_FILE}/more`), 'ENOENT', 'not a directory');
  });

  it('refuse a directory or a device', () => {
    refused(() => standard().resolve('/etc/hkdfguard/keys'), 'EACCES', 'not a regular file');
    refused(() => standard().other(KEY_FILE).resolve(KEY_FILE), 'EACCES', 'not a regular file');
  });

  it('refuse a relative path as an argument error', () => {
    assert.throws(() => standard().resolve('keys/v1.key'), (e: unknown) => e instanceof InvalidArgumentError && e.message.includes('not an absolute path'));
  });

  it('pass on an error examining a component', () => {
    const fs = standard().file(KEY_FILE);
    const failing = (path: string) => {
      if (path === '/etc/hkdfguard') throw new KeyFileError('EACCES', path, 'EACCES from lstat');
      return fs.entries.get(path);
    };
    assert.throws(() => resolveTrusted(KEY_FILE, KeyFileTrust.administratorsOnly, failing, () => undefined), /EACCES from lstat/);
  });

  it('take the lexical parent of a path', () => {
    assert.equal(parentOf('/etc/hkdfguard'), '/etc');
    assert.equal(parentOf('/etc'), '/');
    assert.equal(parentOf('/'), '/');
  });
});

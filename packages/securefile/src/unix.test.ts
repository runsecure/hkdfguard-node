import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';
import { KeyFileError } from './errors.js';
import { KeyFileTrust } from './trust.js';
import type { MacAclEntry, UnixAddon } from './native.js';
import {
  aclWriters, MAC_WRITE_RIGHTS, macAclWriters, MAX_SYMBOLIC_LINKS, parentOf, posixAclWriters, resolveTrusted, type AclWriter, type UnixFileStatus,
} from './unix.js';

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

describe('access control lists', () => {
  /** A Linux system.posix_acl_access value: version 2, then each entry's tag, permissions and id. */
  const posixAcl = (...entries: [tag: number, perm: number, id?: number][]) => {
    const bytes = new Uint8Array(4 + entries.length * 8);
    const view = new DataView(bytes.buffer);
    view.setUint32(0, 2, true);
    entries.forEach(([tag, perm, id = 0xffffffff], i) => {
      view.setUint16(4 + i * 8, tag, true);
      view.setUint16(6 + i * 8, perm, true);
      view.setUint32(8 + i * 8, id, true);
    });
    return bytes;
  };
  const [USER_OBJ, USER, GROUP_OBJ, GROUP, MASK, OTHER] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20];
  const RWX = 7;
  const RX = 5;

  it('reads the named users and groups a POSIX ACL lets write, as its mask leaves them', () => {
    // root:deploy 2770 key folder, with www-data (33) given rwx by setfacl: the mask shows as the group's bits.
    const acl = posixAcl([USER_OBJ, RWX], [USER, RWX, 33], [GROUP_OBJ, RWX], [GROUP, RX, 4000], [GROUP, RWX, DEPLOYERS_GROUP], [MASK, RWX], [OTHER, 0]);
    assert.deepEqual(posixAclWriters(acl), [{ kind: 'user', id: 33, rights: 'write' }, { kind: 'group', id: DEPLOYERS_GROUP, rights: 'write' }]);
    // A mask without write leaves no named entry able to write, whatever it says.
    assert.deepEqual(posixAclWriters(posixAcl([USER_OBJ, RWX], [USER, RWX, 33], [GROUP_OBJ, RX], [MASK, RX], [OTHER, 0])), []);
    // A minimal ACL - the permission bits alone - names no one.
    assert.deepEqual(posixAclWriters(posixAcl([USER_OBJ, RWX], [GROUP_OBJ, RX], [OTHER, RX])), []);
  });

  it("refuses a POSIX ACL it can't read", () => {
    for (const bytes of [new Uint8Array(0), new Uint8Array([1, 0, 0, 0]), posixAcl([USER, RWX, 33]).subarray(0, 9)]) {
      assert.throws(() => posixAclWriters(bytes), /form this does not read/);
    }
  });

  it('reads the principals a macOS ACL lets change a path: allow entries for the path itself', () => {
    const entries: MacAclEntry[] = [
      { allow: true, inheritOnly: false, kind: 'group', id: 12, rights: 0b1 }, // everyone: write data
      { allow: false, inheritOnly: false, kind: 'user', id: 501, rights: 0b100 }, // deny: takes nothing
      { allow: true, inheritOnly: true, kind: 'user', id: 501, rights: 0b1 }, // only for what is created inside
      { allow: true, inheritOnly: false, kind: 'user', id: 502, rights: 0 }, // read rights only
      { allow: true, inheritOnly: false, kind: 'unknown', id: -1, rights: 0b10000000 },
    ];
    assert.deepEqual(macAclWriters(entries), [
      { kind: 'group', id: 12, rights: MAC_WRITE_RIGHTS[0] },
      { kind: 'unknown', id: -1, rights: 'change owner' },
    ]);
  });

  it('refuses a folder or file whose ACL lets an untrusted principal write, and passes trusted ones', () => {
    const writers = new Map<string, AclWriter[]>();
    const resolve = (trust: KeyFileTrust) => resolveTrusted(KEY_FILE, trust, (p) => fs.entries.get(p), (p) => fs.links.get(p), (p) => writers.get(p) ?? []);
    const fs = standard().file(KEY_FILE);
    assert.equal(resolve(KeyFileTrust.administratorsOnly), KEY_FILE);

    writers.set('/etc/hkdfguard', [{ kind: 'user', id: APP, rights: 'write' }]);
    refused(() => resolve(DEPLOYER_TRUST), 'EACCES', "'/etc/hkdfguard' has an access control list letting uid 1002", 'not trusted');
    writers.set('/etc/hkdfguard', [{ kind: 'user', id: DEPLOYER, rights: 'write' }, { kind: 'group', id: DEPLOYERS_GROUP, rights: 'write' }]);
    assert.equal(resolve(DEPLOYER_TRUST), KEY_FILE);
    refused(() => resolve(KeyFileTrust.administratorsOnly), 'EACCES', 'uid 1001');

    writers.set(KEY_FILE, [{ kind: 'group', id: 12, rights: 'write data (add file)' }]);
    refused(() => resolve(DEPLOYER_TRUST), 'EACCES', `'${KEY_FILE}' has an access control list letting gid 12`, 'write data');
    writers.set(KEY_FILE, [{ kind: 'unknown', id: -1, rights: 'delete' }]);
    refused(() => resolve(DEPLOYER_TRUST), 'EACCES', 'resolves to no user or group');
    writers.set(KEY_FILE, [{ kind: 'user', id: ROOT, rights: 'write' }]);
    assert.equal(resolve(DEPLOYER_TRUST), KEY_FILE);
  });

  it("reads a path's ACL through the add-on, refusing one it can't read, on Linux and macOS alike", () => {
    const linux: UnixAddon = {
      posixAcl: (path) => (path === '/none' ? null : path === '/broken' ? 5 : posixAcl([USER_OBJ, RWX], [USER, RWX, 33], [GROUP_OBJ, RX], [MASK, RWX], [OTHER, 0])),
    };
    assert.deepEqual(aclWriters('/none', linux, 'linux'), []);
    assert.deepEqual(aclWriters('/x', linux, 'linux'), [{ kind: 'user', id: 33, rights: 'write' }]);
    refused(() => aclWriters('/broken', linux, 'linux'), 'EACCES', 'could not be read (errno 5)');
    refused(() => aclWriters('/x', { posixAcl: () => new Uint8Array([9, 9, 9]) }, 'linux'), 'EACCES', 'form this does not read');

    const mac: UnixAddon = { extendedAcl: (path) => (path === '/broken' ? 13 : [{ allow: true, inheritOnly: false, kind: 'group', id: 12, rights: 1 }]) };
    assert.deepEqual(aclWriters('/x', mac, 'darwin'), [{ kind: 'group', id: 12, rights: MAC_WRITE_RIGHTS[0] }]);
    refused(() => aclWriters('/broken', mac, 'darwin'), 'EACCES', 'errno 13');
  });
});

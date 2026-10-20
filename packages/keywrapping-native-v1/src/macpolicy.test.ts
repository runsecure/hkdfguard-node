import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { NotInstalledError, UnsupportedPlatformError, UntrustedError } from './errors.js';
import {
  MAC_CODE_REQUIREMENT, MAC_SYSTEM_DIRECTORY, MAC_SYSTEM_PATH, MAC_TEAM_ID, macChoosePath, macParentOf, macRefuseShadowing,
  macRequireSupportedPlatform, macUserPath, macVerifyLoadedImage, macVerifyLocation, macVerifySignature, PROBE_EXPORT,
} from './macpolicy.js';
import { ENOENT, ENOTDIR, FileType, type FileStatus } from './unixpath.js';

const ROOT = 0, USER = 501, OTHER_USER = 502, WHEEL = 0, ADMIN = 80, STAFF = 20;
const HOME = '/Users/dev';
const SYSTEM_OWNERS = [ROOT];
const USER_OWNERS = [ROOT, USER];

const dir = (uid: number, gid: number, perm: number): FileStatus => ({ uid, gid, perm, type: FileType.Directory });
const file = (uid: number, gid: number, perm: number): FileStatus => ({ uid, gid, perm, type: FileType.Regular });

const systemInstall = () => new Map<string, FileStatus>([
  ['/', dir(ROOT, WHEEL, 0o755)],
  ['/Library', dir(ROOT, WHEEL, 0o755)],
  ['/Library/Application Support', dir(ROOT, ADMIN, 0o775)],
  ['/Library/Application Support/HkdfGuard', dir(ROOT, WHEEL, 0o755)],
  [MAC_SYSTEM_DIRECTORY, dir(ROOT, WHEEL, 0o755)],
  [MAC_SYSTEM_PATH, file(ROOT, WHEEL, 0o644)],
]);

const userInstall = () => new Map<string, FileStatus>([
  ['/', dir(ROOT, WHEEL, 0o755)],
  ['/Users', dir(ROOT, ADMIN, 0o755)],
  [HOME, dir(USER, STAFF, 0o755)],
  [`${HOME}/.hkdfguard`, dir(USER, STAFF, 0o700)],
  [`${HOME}/.hkdfguard/v1`, dir(USER, STAFF, 0o700)],
  [macUserPath(HOME), file(USER, STAFF, 0o644)],
]);

function verify(fs: Map<string, FileStatus>, path: string, owners: number[]): void {
  macVerifyLocation(path, (p) => fs.get(p) ?? assert.fail(`lstat('${p}') failed`), owners);
}

function untrusted(fn: () => unknown, ...contains: string[]): void {
  assert.throws(fn, (e: unknown) => {
    assert.ok(e instanceof UntrustedError, String(e));
    for (const s of contains) assert.ok(e.message.includes(s), `'${e.message}' does not contain '${s}'`);
    return true;
  });
}

describe('macOS platform', () => {
  it('accepts arm64 on macOS 13 or later', () => {
    for (const version of ['13.0', '15.4', '26.6.2']) macRequireSupportedPlatform('arm64', version);
  });

  it('refuses x64, naming Rosetta, and every other architecture', () => {
    assert.throws(() => macRequireSupportedPlatform('x64', '15.0'), (e: unknown) => e instanceof UnsupportedPlatformError && /Apple silicon/.test(e.message) && /Rosetta/.test(e.message));
    for (const arch of ['ia32', 'arm']) {
      assert.throws(() => macRequireSupportedPlatform(arch, '15.0'), (e: unknown) => e instanceof UnsupportedPlatformError && e.message.includes(arch));
    }
  });

  it('refuses macOS older than 13, or an unknown version', () => {
    assert.throws(() => macRequireSupportedPlatform('arm64', '12.7.6'), (e: unknown) => e instanceof UnsupportedPlatformError && /macOS 13/.test(e.message) && /12\.7\.6/.test(e.message));
    assert.throws(() => macRequireSupportedPlatform('arm64', ''), UnsupportedPlatformError);
  });
});

describe('macOS locations', () => {
  it('are the agreed paths', () => {
    assert.equal(MAC_SYSTEM_PATH, '/Library/Application Support/HkdfGuard/v1/libhkdfguard.dylib');
    assert.equal(macUserPath('/Users/dev'), '/Users/dev/.hkdfguard/v1/libhkdfguard.dylib');
    assert.equal(macUserPath('/Users/dev/'), '/Users/dev/.hkdfguard/v1/libhkdfguard.dylib');
  });

  it('prefer the system install, even when a user install exists', () => {
    assert.deepEqual(macChoosePath(() => 0, HOME), { path: MAC_SYSTEM_PATH, isSystem: true });
  });

  it('use the user install only when there is no system install', () => {
    for (const errno of [ENOENT, ENOTDIR]) {
      assert.deepEqual(macChoosePath((p) => (p === macUserPath(HOME) ? 0 : errno), HOME), { path: macUserPath(HOME), isSystem: false });
    }
  });

  it('refuse rather than fall back when the system install cannot be examined', () => {
    for (const errno of [13, 62, 5]) {
      const probed: string[] = [];
      untrusted(() => macChoosePath((p) => { probed.push(p); return errno; }, HOME), MAC_SYSTEM_PATH, `errno ${errno}`);
      assert.deepEqual(probed, [MAC_SYSTEM_PATH]);
    }
    untrusted(() => macChoosePath((p) => (p === MAC_SYSTEM_PATH ? ENOENT : 13), HOME), macUserPath(HOME));
  });

  it('report neither install usable as not installed, naming both', () => {
    for (const home of [HOME, '', 'relative/home']) {
      assert.throws(() => macChoosePath((p) => (!p.startsWith('/') && p.endsWith('.dylib') ? 0 : ENOENT), home),
        (e: unknown) => e instanceof NotInstalledError && e.message.includes(MAC_SYSTEM_PATH) && e.message.includes('.hkdfguard/v1/libhkdfguard.dylib'));
    }
  });

  it('walk slash-separated parents up to root', () => {
    assert.equal(macParentOf('/a/b/c.dylib'), '/a/b');
    assert.equal(macParentOf('/a/b/'), '/a');
    assert.equal(macParentOf('/a'), '/');
    assert.equal(macParentOf('/'), undefined);
  });
});

describe('macOS path integrity', () => {
  it('passes standard installs', () => {
    verify(systemInstall(), MAC_SYSTEM_PATH, SYSTEM_OWNERS);
    verify(userInstall(), macUserPath(HOME), USER_OWNERS);
  });

  it('refuses the wrong owners', () => {
    const system = systemInstall();
    system.set(MAC_SYSTEM_DIRECTORY, dir(USER, STAFF, 0o755));
    untrusted(() => verify(system, MAC_SYSTEM_PATH, SYSTEM_OWNERS), 'owned by uid 501', 'owned by root.');
    const user = userInstall();
    user.set(macUserPath(HOME), file(OTHER_USER, STAFF, 0o644));
    untrusted(() => verify(user, macUserPath(HOME), USER_OWNERS), 'owned by uid 502', 'root or the current user');
  });

  it('refuses world-writable and user-owned group-writable components', () => {
    const world = userInstall();
    world.set(`${HOME}/.hkdfguard`, dir(USER, STAFF, 0o702));
    untrusted(() => verify(world, macUserPath(HOME), USER_OWNERS), 'writable by every user');
    const group = userInstall();
    group.set(HOME, dir(USER, STAFF, 0o775));
    untrusted(() => verify(group, macUserPath(HOME), USER_OWNERS), 'writable by group 20');
  });

  it('lets only the system directories above an install be wheel- or admin-writable', () => {
    const staffWritable = systemInstall();
    staffWritable.set('/Library/Application Support', dir(ROOT, STAFF, 0o775));
    untrusted(() => verify(staffWritable, MAC_SYSTEM_PATH, SYSTEM_OWNERS));
    for (const directory of ['/', '/Library', '/Library/Application Support']) {
      const fs = systemInstall();
      fs.set(directory, dir(ROOT, ADMIN, 0o775));
      verify(fs, MAC_SYSTEM_PATH, SYSTEM_OWNERS);
    }
    const users = userInstall();
    users.set('/Users', dir(ROOT, ADMIN, 0o775));
    verify(users, macUserPath(HOME), USER_OWNERS);

    for (const directory of ['/Library/Application Support/HkdfGuard', MAC_SYSTEM_DIRECTORY]) {
      for (const group of [WHEEL, ADMIN]) {
        const fs = systemInstall();
        fs.set(directory, dir(ROOT, group, 0o775));
        untrusted(() => verify(fs, MAC_SYSTEM_PATH, SYSTEM_OWNERS), `'${directory}' is writable by group ${group}`);
      }
    }
    const library = systemInstall();
    library.set(MAC_SYSTEM_PATH, file(ROOT, ADMIN, 0o664));
    untrusted(() => verify(library, MAC_SYSTEM_PATH, SYSTEM_OWNERS));
    const home = userInstall();
    home.set(HOME, dir(ROOT, ADMIN, 0o775));
    untrusted(() => verify(home, macUserPath(HOME), USER_OWNERS));
  });

  it('refuses symbolic links and anything but a regular file', () => {
    const linked = userInstall();
    linked.set(`${HOME}/.hkdfguard`, { uid: USER, gid: STAFF, perm: 0o755, type: FileType.Symlink });
    untrusted(() => verify(linked, macUserPath(HOME), USER_OWNERS), 'is not a directory (it is a symbolic link)');
    for (const type of [FileType.Symlink, FileType.Directory, FileType.Other]) {
      const fs = systemInstall();
      fs.set(MAC_SYSTEM_PATH, { uid: ROOT, gid: WHEEL, perm: 0o644, type });
      untrusted(() => verify(fs, MAC_SYSTEM_PATH, SYSTEM_OWNERS), `(it is a ${type})`);
    }
    const fileAsDirectory = systemInstall();
    fileAsDirectory.set('/Library/Application Support/HkdfGuard', file(ROOT, WHEEL, 0o755));
    untrusted(() => verify(fileAsDirectory, MAC_SYSTEM_PATH, SYSTEM_OWNERS), '(it is a regular file)');
  });
});

describe('macOS code signature and dyld', () => {
  it('pins the HkdfGuard team', () => {
    assert.equal(MAC_TEAM_ID, 'MFW3T8R8J3');
    assert.equal(MAC_CODE_REQUIREMENT, 'identifier "libhkdfguard" and anchor apple generic'
      + ' and certificate 1[field.1.2.840.113635.100.6.2.6] exists'
      + ' and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
      + ' and certificate leaf[subject.OU] = "MFW3T8R8J3"');
  });

  it('passes the requirement to the check, and refuses any failure', () => {
    let checked = '';
    macVerifySignature('/x.dylib', (_, requirement) => { checked = requirement; return 0; });
    assert.equal(checked, MAC_CODE_REQUIREMENT);
    for (const status of [-67050, -67062]) untrusted(() => macVerifySignature('/x.dylib', () => status), 'MFW3T8R8J3', String(status));
  });

  it('refuses a library of the same name on DYLD_LIBRARY_PATH, consulting only that variable', () => {
    for (const searchPath of [undefined, '', '/opt/lib:/usr/local/lib']) macRefuseShadowing(() => searchPath, () => false);
    const decoy = '/tmp/decoy/libhkdfguard.dylib';
    for (const searchPath of ['/tmp/decoy', '/opt/lib:/tmp/decoy/:/usr/local/lib']) {
      untrusted(() => macRefuseShadowing(() => searchPath, (p) => p === decoy), decoy, 'DYLD_LIBRARY_PATH');
    }
    const asked: string[] = [];
    macRefuseShadowing((name) => { asked.push(name); return undefined; }, () => true);
    assert.deepEqual(asked, ['DYLD_LIBRARY_PATH']);
  });

  it('accepts only the verified file as what dyld loaded', () => {
    macVerifyLoadedImage(MAC_SYSTEM_PATH, MAC_SYSTEM_PATH);
    untrusted(() => macVerifyLoadedImage(MAC_SYSTEM_PATH, '/tmp/decoy/libhkdfguard.dylib'), '/tmp/decoy/libhkdfguard.dylib', MAC_SYSTEM_PATH, 'unloaded');
    untrusted(() => macVerifyLoadedImage(MAC_SYSTEM_PATH, null), PROBE_EXPORT);
    assert.equal(PROBE_EXPORT, 'hkdfguard_wrap_dek');
  });
});

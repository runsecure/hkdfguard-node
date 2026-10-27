import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { NotInstalledError, UnsupportedPlatformError, UntrustedError } from './errors.js';
import {
  LINUX_MAX_SYMBOLIC_LINKS, linuxCandidatePaths, linuxChoosePath, linuxListingEnvironment, linuxParentOf, linuxParseListing,
  linuxReadEnvironment, linuxResolveTrusted, linuxVerifyDependencies, linuxVerifyEnvironment, linuxVerifyListing,
  linuxVerifyLoadedImage,
} from './linuxpolicy.js';
import { PROBE_EXPORT } from './macpolicy.js';
import { ENOENT, ENOTDIR, FileType, type FileStatus } from './unixpath.js';

const ROOT = 0, USER = 1000;
const LIB_DIR = '/usr/lib/x86_64-linux-gnu';
const LIBRARY = `${LIB_DIR}/libhkdfguard.so.1`;
const ESYS = `${LIB_DIR}/libtss2-esys.so.0.0.1`;

/** A simulated filesystem: what lstat sees, and what each symbolic link holds. */
class SimFs {
  entries = new Map<string, FileStatus>();
  links = new Map<string, string>();
  dir(path: string, owner = ROOT, perm = 0o755): this { this.entries.set(path, { uid: owner, gid: owner, perm, type: FileType.Directory }); return this; }
  file(path: string, owner = ROOT, perm = 0o644): this { this.entries.set(path, { uid: owner, gid: owner, perm, type: FileType.Regular }); return this; }
  link(path: string, target: string, owner = ROOT): this {
    this.entries.set(path, { uid: owner, gid: owner, perm: 0o777, type: FileType.Symlink });
    this.links.set(path, target);
    return this;
  }
  resolve(path: string, expected = FileType.Regular, allowMissing = false): string | undefined {
    return linuxResolveTrusted(path, expected, (p) => this.entries.get(p), (p) => this.links.get(p), allowMissing);
  }
}

const standardHost = () => new SimFs()
  .dir('/').dir('/usr').dir('/usr/lib').dir(LIB_DIR).dir('/usr/lib64').dir('/opt')
  .link('/lib', 'usr/lib').link('/lib64', 'usr/lib64')
  .file(LIBRARY).link(`${LIB_DIR}/libtss2-esys.so.0`, 'libtss2-esys.so.0.0.1').file(ESYS).file(`${LIB_DIR}/libc.so.6`)
  .dir('/home').dir('/home/dev', USER).dir('/home/dev/lib', USER).file('/home/dev/lib/libtss2-esys.so.0', USER)
  .dir('/tmp', ROOT, 0o1777);

function untrusted(fn: () => unknown, ...contains: string[]): void {
  assert.throws(fn, (e: unknown) => {
    assert.ok(e instanceof UntrustedError, String(e));
    for (const s of contains) assert.ok(e.message.includes(s), `'${e.message}' does not contain '${s}'`);
    return true;
  });
}

describe('Linux locations', () => {
  it("are the package's install paths for each architecture", () => {
    assert.deepEqual(linuxCandidatePaths('x64'), ['/usr/lib/x86_64-linux-gnu/libhkdfguard.so.1', '/usr/lib64/libhkdfguard.so.1']);
    assert.deepEqual(linuxCandidatePaths('arm64'), ['/usr/lib/aarch64-linux-gnu/libhkdfguard.so.1', '/usr/lib64/libhkdfguard.so.1']);
    for (const arch of ['ia32', 'arm', 'riscv64']) {
      assert.throws(() => linuxCandidatePaths(arch), (e: unknown) => e instanceof UnsupportedPlatformError && e.message.includes(arch));
    }
  });

  it('prefer multiarch, fall back to lib64 only when nothing is there, and refuse what cannot be examined', () => {
    const candidates = linuxCandidatePaths('x64');
    assert.equal(linuxChoosePath(candidates, () => 0), candidates[0]);
    for (const errno of [ENOENT, ENOTDIR]) assert.equal(linuxChoosePath(candidates, (p) => (p === candidates[0] ? errno : 0)), candidates[1]);
    const asked: string[] = [];
    untrusted(() => linuxChoosePath(candidates, (p) => { asked.push(p); return 13; }), 'errno 13');
    assert.deepEqual(asked, [candidates[0]]);
    assert.throws(() => linuxChoosePath(candidates, () => ENOENT),
      (e: unknown) => e instanceof NotInstalledError && ['libhkdfguard1', ...candidates].every((s) => e.message.includes(s)));
  });
});

describe('Linux path integrity', () => {
  it('resolves a standard install, root-owned links, and .. against the real directory', () => {
    const fs = standardHost().link(`${LIB_DIR}/HkdfGuard.Kms.Linux.v1.so`, 'libhkdfguard.so.1').link('/opt/app', '../usr/lib');
    assert.equal(fs.resolve(LIBRARY), LIBRARY);
    assert.equal(fs.resolve('/lib/x86_64-linux-gnu/libtss2-esys.so.0'), ESYS);
    assert.equal(fs.resolve(`${LIB_DIR}/HkdfGuard.Kms.Linux.v1.so`), LIBRARY);
    assert.equal(fs.resolve('/lib/x86_64-linux-gnu/', FileType.Directory), LIB_DIR);
    assert.equal(fs.resolve('/opt/app/x86_64-linux-gnu/libhkdfguard.so.1'), LIBRARY);
    assert.equal(fs.resolve('/opt/app/..', FileType.Directory), '/usr');
    assert.equal(fs.resolve('/..', FileType.Directory), '/');
    assert.equal(fs.resolve('/usr/./lib/x86_64-linux-gnu//libhkdfguard.so.1'), LIBRARY);
  });

  it('refuses relative paths', () => {
    for (const path of ['usr/lib/x86_64-linux-gnu/libhkdfguard.so.1', './libhkdfguard.so.1', '']) untrusted(() => standardHost().resolve(path), 'not an absolute path');
  });

  it('refuses user-owned or group/other-writable components, wherever they are', () => {
    untrusted(() => standardHost().file(LIBRARY, USER).resolve(LIBRARY), 'uid 1000');
    untrusted(() => standardHost().dir('/usr/lib', USER).resolve(LIBRARY), "'/usr/lib'");
    for (const [path, perm] of [['/', 0o775], ['/usr', 0o775], [LIB_DIR, 0o775], [LIB_DIR, 0o777], [LIBRARY, 0o664]] as const) {
      const fs = standardHost();
      fs.entries.set(path, { ...fs.entries.get(path)!, perm });
      untrusted(() => fs.resolve(LIBRARY), `'${path}' is writable`);
    }
    untrusted(() => standardHost().file('/tmp/libtss2-esys.so.0').resolve('/tmp/libtss2-esys.so.0'));
  });

  it('refuses user-owned links, links into user directories, loops and unreadable links', () => {
    untrusted(() => standardHost().link('/opt/lib', '/usr/lib', USER).resolve('/opt/lib/x86_64-linux-gnu/libhkdfguard.so.1'), 'symbolic link owned by uid 1000');
    untrusted(() => standardHost().link('/opt/lib', '/home/dev/lib').resolve('/opt/lib/libtss2-esys.so.0'), "'/home/dev'");
    untrusted(() => standardHost().link('/opt/a', '/opt/b').link('/opt/b', '/opt/a').resolve('/opt/a/x'), `${LINUX_MAX_SYMBOLIC_LINKS} symbolic links`);
    const broken = standardHost();
    broken.entries.set('/opt/broken', { uid: ROOT, gid: ROOT, perm: 0o777, type: FileType.Symlink });
    untrusted(() => broken.resolve('/opt/broken/x'), 'could not be read');
  });

  it('allows a missing path only where only root could create it', () => {
    const fs = standardHost();
    untrusted(() => fs.resolve(`${LIB_DIR}/nothing.so`), 'does not exist');
    assert.equal(fs.resolve(`${LIB_DIR}/nothing.so`, FileType.Regular, true), undefined);
    assert.equal(fs.resolve('/opt/not/yet/created', FileType.Directory, true), undefined);
    untrusted(() => fs.resolve('/home/dev/lib/nothing.so', FileType.Regular, true));
  });

  it('refuses the wrong kind of object, a path through a file, and an unexaminable root', () => {
    const fs = standardHost();
    fs.entries.set('/opt/fifo', { uid: ROOT, gid: ROOT, perm: 0o644, type: FileType.Other });
    untrusted(() => fs.resolve(LIB_DIR), 'is a directory, not a regular file');
    untrusted(() => fs.resolve(LIBRARY, FileType.Directory), 'is a regular file, not a directory');
    untrusted(() => fs.resolve('/opt/fifo'), 'is a special file');
    untrusted(() => fs.resolve(`${LIBRARY}/x`), 'not a directory');
    untrusted(() => linuxResolveTrusted(LIBRARY, FileType.Regular, () => undefined, () => undefined), "'/'");
    assert.deepEqual(['/', '/usr', '/usr/lib'].map(linuxParentOf), ['/', '/', '/usr']);
  });
});

describe('Linux environment', () => {
  const block = (...entries: string[]) => new TextEncoder().encode(`${entries.join('\0')}\0`);
  const verifyEnv = (fs: SimFs, variable: string, ...values: string[]) =>
    linuxVerifyEnvironment(new Map([[variable, values]]), (p, type) => { fs.resolve(p, type, true); });

  it("collects the linker variables' initial and current values", () => {
    const values = linuxReadEnvironment({ LD_LIBRARY_PATH: '/now', LD_PRELOAD: '/same.so' },
      block('PATH=/usr/bin', 'LD_LIBRARY_PATH=/at/exec', 'LD_PRELOAD=/same.so', 'LD_AUDIT=/a.so=b', '=junk', 'NOEQUALS'));
    assert.deepEqual(Object.fromEntries(values), { LD_LIBRARY_PATH: ['/at/exec', '/now'], LD_PRELOAD: ['/same.so'], LD_AUDIT: ['/a.so=b'] });
    assert.deepEqual(linuxReadEnvironment({ LD_PRELOAD: 'x.so' }, undefined).get('LD_PRELOAD'), ['x.so']);
  });

  it('passes root-controlled library paths', () => {
    linuxVerifyEnvironment(new Map(), () => assert.fail('nothing to resolve'));
    for (const value of ['', LIB_DIR, '/lib/x86_64-linux-gnu:/usr/lib64', '/usr/lib;/usr/lib64', '/opt/not/installed/yet']) verifyEnv(standardHost(), 'LD_LIBRARY_PATH', value);
  });

  it('refuses library paths others can write, empty entries, and unverifiable entries', () => {
    for (const value of ['/home/dev/lib', '/usr/lib:/home/dev/lib', '/tmp', '/home/dev/lib/not-yet']) untrusted(() => verifyEnv(standardHost(), 'LD_LIBRARY_PATH', value), 'LD_LIBRARY_PATH', 'Remove it');
    for (const value of [':/usr/lib', '/usr/lib:', '/usr/lib::/usr/lib64']) untrusted(() => verifyEnv(standardHost(), 'LD_LIBRARY_PATH', value), 'working directory');
    for (const [value, reason] of [['lib', 'relative'], ['./lib', 'relative'], ['$ORIGIN/lib', 'dynamic string token'], ['/usr/${LIB}', 'dynamic string token']] as const) {
      untrusted(() => verifyEnv(standardHost(), 'LD_LIBRARY_PATH', value), reason);
    }
    untrusted(() => verifyEnv(standardHost(), 'LD_LIBRARY_PATH', '/usr/lib', '/home/dev/lib'));
  });

  it('checks preloaded and audited objects', () => {
    for (const [variable, value] of [['LD_PRELOAD', 'libjemalloc.so.2'], ['LD_PRELOAD', '/usr/lib/x86_64-linux-gnu/libc.so.6'],
      ['LD_PRELOAD', 'libjemalloc.so.2 /lib/x86_64-linux-gnu/libc.so.6'], ['LD_PRELOAD', '   '], ['LD_AUDIT', '/usr/lib/x86_64-linux-gnu/libc.so.6:libaudit.so']] as const) {
      verifyEnv(standardHost(), variable, value);
    }
    for (const [variable, value] of [['LD_PRELOAD', '/home/dev/lib/libtss2-esys.so.0'], ['LD_PRELOAD', 'libjemalloc.so.2 /home/dev/lib/libtss2-esys.so.0'],
      ['LD_PRELOAD', 'libjemalloc.so.2:/home/dev/lib/libtss2-esys.so.0'], ['LD_PRELOAD', './evil.so'], ['LD_PRELOAD', '$LIB/evil.so'],
      ['LD_AUDIT', '/home/dev/lib/libtss2-esys.so.0'], ['LD_AUDIT', 'lib/evil.so']] as const) {
      untrusted(() => verifyEnv(standardHost(), variable, value), variable);
    }
  });

  it('refuses a location that cannot be examined, keeping the cause', () => {
    const cause = new Error("statx('/srv') failed with errno 13");
    assert.throws(() => linuxVerifyEnvironment(new Map([['LD_LIBRARY_PATH', ['/srv/lib']]]), () => { throw cause; }),
      (e: unknown) => e instanceof UntrustedError && e.message.includes('errno 13') && e.cause === cause);
  });
});

describe('Linux loaded image and dependencies', () => {
  it('accepts only the verified file', () => {
    linuxVerifyLoadedImage(LIBRARY, LIBRARY);
    untrusted(() => linuxVerifyLoadedImage(LIBRARY, '/usr/lib64/libhkdfguard.so.1'), '/usr/lib64/libhkdfguard.so.1');
    untrusted(() => linuxVerifyLoadedImage(LIBRARY, null), PROBE_EXPORT);
  });

  const needed: Record<string, string[]> = {
    [LIBRARY]: ['libtss2-esys.so.0', 'libgcc_s.so.1', 'libc.so.6'],
    [ESYS]: ['libtss2-mu.so.0', 'libcrypto.so.3', 'libc.so.6'],
    [`${LIB_DIR}/libtss2-mu.so.0.0.1`]: ['libc.so.6'],
    [`${LIB_DIR}/libcrypto.so.3`]: ['libc.so.6'],
    [`${LIB_DIR}/libgcc_s.so.1`]: ['libc.so.6'],
    [`${LIB_DIR}/libc.so.6`]: ['ld-linux-x86-64.so.2'],
    [`${LIB_DIR}/ld-linux-x86-64.so.2`]: [],
  };
  const loaded = (): Record<string, string> => ({
    'libtss2-esys.so.0': '/lib/x86_64-linux-gnu/libtss2-esys.so.0',
    'libtss2-mu.so.0': '/lib/x86_64-linux-gnu/libtss2-mu.so.0',
    'libcrypto.so.3': '/lib/x86_64-linux-gnu/libcrypto.so.3',
    'libgcc_s.so.1': '/lib/x86_64-linux-gnu/libgcc_s.so.1',
    'libc.so.6': '/lib/x86_64-linux-gnu/libc.so.6',
    'ld-linux-x86-64.so.2': '/lib64/ld-linux-x86-64.so.2',
  });
  const hostWithClosure = () => standardHost()
    .link(`${LIB_DIR}/libtss2-mu.so.0`, 'libtss2-mu.so.0.0.1').file(`${LIB_DIR}/libtss2-mu.so.0.0.1`)
    .file(`${LIB_DIR}/libcrypto.so.3`).file(`${LIB_DIR}/libgcc_s.so.1`)
    .link('/usr/lib64/ld-linux-x86-64.so.2', '../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2').file(`${LIB_DIR}/ld-linux-x86-64.so.2`);
  const verifyDeps = (fs: SimFs, bound: Record<string, string>, read?: string[]) => linuxVerifyDependencies(LIBRARY,
    (f) => { read?.push(f); return needed[f]!; }, (n) => bound[n] ?? null, (p) => fs.resolve(p)!);

  it('passes a trusted closure, reading each file once', () => {
    const read: string[] = [];
    verifyDeps(hostWithClosure(), loaded(), read);
    assert.deepEqual(read.sort(), Object.keys(needed).sort());
  });

  it('refuses a dependency loaded from anywhere untrusted, or that nothing answers to', () => {
    untrusted(() => verifyDeps(hostWithClosure(), { ...loaded(), 'libtss2-esys.so.0': '/home/dev/lib/libtss2-esys.so.0' }), "'libtss2-esys.so.0'", LIBRARY);
    untrusted(() => verifyDeps(hostWithClosure().file('/tmp/libcrypto.so.3'), { ...loaded(), 'libcrypto.so.3': '/tmp/libcrypto.so.3' }), `'libcrypto.so.3' (needed by '${ESYS}')`);
    const missing = loaded();
    delete missing['libgcc_s.so.1'];
    untrusted(() => verifyDeps(hostWithClosure(), missing), 'libgcc_s.so.1');
    const cause = new Error('statx failed with errno 13');
    assert.throws(() => linuxVerifyDependencies(LIBRARY, () => ['libc.so.6'], () => '/lib/x86_64-linux-gnu/libc.so.6', () => { throw cause; }),
      (e: unknown) => e instanceof UntrustedError && e.cause === cause);
  });
});

describe("Linux dynamic linker's list mode", () => {
  it('reports every file, skipping the vDSO', () => {
    const output = '\tlinux-vdso.so.1 (0x00007ffd2a5f2000)\n'
      + '\tlibtss2-esys.so.0 => /lib/x86_64-linux-gnu/libtss2-esys.so.0 (0x00007f1c2a000000)\n'
      + '\t/usr/lib/libpreloaded.so (0x00007f1c29e00000)\n'
      + '\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f1c29c00000)\n'
      + '\t/lib64/ld-linux-x86-64.so.2 (0x00007f1c2a200000)\n';
    assert.deepEqual(linuxParseListing('lib', output),
      ['/lib/x86_64-linux-gnu/libtss2-esys.so.0', '/usr/lib/libpreloaded.so', '/lib/x86_64-linux-gnu/libc.so.6', '/lib64/ld-linux-x86-64.so.2']);
  });

  it('refuses a name it cannot find, or a line it cannot read', () => {
    untrusted(() => linuxParseListing('lib', '\tlibmissing.so.1 => not found\n'), "can't find 'libmissing.so.1'");
    untrusted(() => linuxParseListing('lib', '\tstatically linked\n'), "doesn't understand");
    untrusted(() => linuxParseListing('lib', '\tlibx.so => relative/libx.so (0x1000)\n'), 'not an absolute path');
  });

  it('runs with only the startup LD_LIBRARY_PATH and LD_PRELOAD', () => {
    const initial = new TextEncoder().encode('HOME=/root\0LD_LIBRARY_PATH=/opt/lib\0LD_AUDIT=/opt/audit.so\0PATH=/usr/bin\0LD_PRELOAD=/opt/pre.so\0');
    assert.deepEqual(linuxListingEnvironment(initial), { LD_LIBRARY_PATH: '/opt/lib', LD_PRELOAD: '/opt/pre.so' });
    assert.deepEqual(linuxListingEnvironment(undefined), {});
    assert.deepEqual(linuxListingEnvironment(new Uint8Array(0)), {});
  });

  it('refuses the first untrusted path', () => {
    const checked: string[] = [];
    const trusted = (path: string) => {
      checked.push(path);
      if (path.startsWith('/tmp/')) throw new UntrustedError(`'${path}' is writable by others.`);
      return path;
    };
    linuxVerifyListing('lib', ['/lib/libc.so.6', '/lib64/ld-linux-x86-64.so.2'], trusted);
    checked.length = 0;
    untrusted(() => linuxVerifyListing('lib', ['/lib/libc.so.6', '/tmp/libtss2-esys.so.0', '/tmp/libcrypto.so.3'], trusted), '/tmp/libtss2-esys.so.0', 'nothing was loaded');
    assert.deepEqual(checked, ['/lib/libc.so.6', '/tmp/libtss2-esys.so.0']);
    // Against the simulated host's own path checks, too.
    const fs = standardHost();
    linuxVerifyListing(LIBRARY, [ESYS, `${LIB_DIR}/libc.so.6`], (p) => fs.resolve(p)!);
    untrusted(() => linuxVerifyListing(LIBRARY, [ESYS, '/home/dev/lib/libtss2-esys.so.0'], (p) => fs.resolve(p)!), '/home/dev/lib/libtss2-esys.so.0', 'uid 1000');
  });
});

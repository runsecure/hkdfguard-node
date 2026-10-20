import { mkdirSync, mkdtempSync, realpathSync, rmSync, statSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, isAbsolute, join } from 'node:path';
import type { TestContext } from 'node:test';

/*
 * Where the tests write the key files the real native library reads (hkdfguard_open_file, through
 * NativeKeyWrapperV1.readKeyFile) or the hkdfguard CLI writes.
 *
 * - Windows: a fresh folder under the temp folder, by its long path. hkdfguard_open_file refuses an
 *   8.3 short name anywhere in a path, and Windows can hand out %TEMP% in short form
 *   (C:\Users\RUNNER~1\... on GitHub-hosted runners); realpathSync.native expands it, realpathSync
 *   would not.
 * - Linux: the native library refuses a key file if any directory up its chain is group- or
 *   other-writable - sticky or not - so never under /tmp, /var/tmp or /dev/shm. The folder is a
 *   private (0700) one under $XDG_RUNTIME_DIR when that passes the same check, else under
 *   ~/.cache/hkdfguard-tests; every directory up its chain must be owned by root or this user and
 *   writable by neither group nor others. Without one the test is skipped, saying why - never passed.
 * - macOS: a fresh folder under the temp folder, as before.
 *
 * Each folder is removed when its test ends.
 */

const PRIVATE_ROOT_NAME = 'hkdfguard-tests';

/**
 * Why `directory`, or a directory above it, would make the Linux native library refuse a key file
 * inside it - owned by someone other than root or `uid`, or writable by group or others (the sticky
 * bit excuses nothing) - or undefined when the whole chain passes. Follows symbolic links first.
 */
export function untrustedDirectoryChain(directory: string, uid: number = process.getuid?.() ?? -1): string | undefined {
  let current = realpathSync(directory);
  for (;;) {
    const status = statSync(current);
    const mode = (status.mode & 0o7777).toString(8).padStart(4, '0');
    if (!status.isDirectory()) return `${current} is not a directory`;
    if (status.uid !== 0 && status.uid !== uid) return `${current} is owned by uid ${status.uid}, neither root nor this user (uid ${uid})`;
    if ((status.mode & 0o022) !== 0) return `${current} is writable by its group or others (mode ${mode})`;
    const parent = dirname(current);
    if (parent === current) return undefined;
    current = parent;
  }
}

let linuxRoot: { root?: string; skipReason?: string } | undefined;

/** The trusted directory the Linux key-file folders are made in, chosen once per process. */
export function linuxKeyFileRoot(): { root?: string; skipReason?: string } {
  linuxRoot ??= (() => {
    const reasons: string[] = [];
    const runtime = process.env['XDG_RUNTIME_DIR'];
    if (runtime === undefined || runtime === '') {
      reasons.push('$XDG_RUNTIME_DIR is not set');
    } else if (!isAbsolute(runtime)) {
      reasons.push(`$XDG_RUNTIME_DIR (${runtime}) is not an absolute path`);
    } else {
      const why = attempt(() => untrustedDirectoryChain(runtime));
      if (why === undefined) return { root: runtime };
      reasons.push(`$XDG_RUNTIME_DIR: ${why}`);
    }

    const home = process.env['HOME'] || homedir();
    if (home === '' || !isAbsolute(home)) {
      reasons.push('there is no home directory');
    } else {
      // The home directory's chain first, so nothing is created under one that would not pass.
      const homeWhy = attempt(() => untrustedDirectoryChain(home));
      if (homeWhy !== undefined) {
        reasons.push(`the home directory: ${homeWhy}`);
      } else {
        const root = join(home, '.cache', PRIVATE_ROOT_NAME);
        const why = attempt(() => {
          mkdirSync(root, { recursive: true, mode: 0o700 });
          return untrustedDirectoryChain(root);
        });
        if (why === undefined) return { root };
        reasons.push(`${root}: ${why}`);
      }
    }
    return {
      skipReason: 'No private directory for key files: the Linux native library refuses a key file under any group- or '
        + `world-writable directory, sticky or not (so never under /tmp, /var/tmp or /dev/shm), and ${reasons.join('; ')}. `
        + 'Set XDG_RUNTIME_DIR or HOME to a directory only this user (or root) can write.',
    };
  })();
  return linuxRoot;
}

/** `check`'s answer, or the message of what it threw. */
function attempt(check: () => string | undefined): string | undefined {
  try {
    return check();
  } catch (error) {
    return (error as Error).message;
  }
}

/**
 * A fresh, empty folder for key files the native library will read, removed when the test ends
 * (see the comment at the top); undefined, with the test skipped, when this host has none.
 */
export function keyFileDirectory(t: TestContext, prefix = 'hkdfguard-keyfile-'): string | undefined {
  let directory: string;
  if (process.platform === 'linux') {
    const { root, skipReason } = linuxKeyFileRoot();
    if (root === undefined) {
      t.skip(skipReason);
      return undefined;
    }
    directory = realpathSync(mkdtempSync(join(root, prefix))); // mkdtemp makes it 0700
    t.after(() => rmSync(directory, { recursive: true, force: true }));
    const why = untrustedDirectoryChain(directory);
    if (why !== undefined) {
      t.skip(`No private directory for key files: ${why}.`);
      return undefined;
    }
    return directory;
  }
  directory = realpathSync.native(mkdtempSync(join(tmpdir(), prefix)));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}

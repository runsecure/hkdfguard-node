import { UnsupportedPlatformError } from './errors.js';
import type { WinSecurity } from './windows.js';

/** An opaque handle to a file the add-on opened. */
export type OpenFileHandle = { readonly __brand: 'hkdfguard-securefile-open-file' };

/**
 * What native/hkdfguard_securefile.c exports on Windows: facts only, every decision is made in
 * TypeScript. A call that returns a number in place of its result is reporting a Windows error.
 */
export interface WindowsAddon {
  /** GetFullPathNameW: absolute and normalized, short names left as they are. @throws Error when it fails. */
  fullPath(path: string): string;
  /** GetLongPathNameW: every 8.3 short name expanded; null when it fails (as it does when the last component is missing). */
  longPath(path: string): string | null;
  /** GetDriveTypeW of a drive root: a DRIVE_* value. */
  driveType(root: string): number;
  /** GetFileAttributesW, a link not followed; INVALID_FILE_ATTRIBUTES when it can't be read. */
  fileAttributes(path: string): number;
  /** CreateFileW for reading with read sharing only, or the Windows error. */
  openFile(path: string): OpenFileHandle | number;
  /** GetFinalPathNameByHandleW (\\?\C:\...). @throws Error when it fails. */
  finalPath(file: OpenFileHandle): string;
  /** The opened file's owner and DACL, through its handle (GetSecurityInfo), or the Windows error. */
  fileSecurity(file: OpenFileHandle): WinSecurity | number;
  /** ReadFile straight into `view`: the count, 0 at the end of the file. @throws Error when it fails. */
  readFile(file: OpenFileHandle, view: Uint8Array): number;
  /** Closes the handle; safe to call more than once. */
  closeFile(file: OpenFileHandle): void;
  /** A file or folder's owner and DACL by path (GetNamedSecurityInfoW), or the Windows error. */
  namedSecurity(path: string): WinSecurity | number;
  /** A descriptor written in SDDL, described as the others are; null for invalid SDDL. For the tests. */
  sddlSecurity(sddl: string): WinSecurity | null;
  /** A SID string's canonical form (SDDL aliases such as "BA" accepted), or null if it isn't one. */
  canonicalSid(sid: string): string | null;
  /** The account a SID string names (DOMAIN\name), or null. */
  accountName(sid: string): string | null;
}

/** One entry of a macOS extended ACL, as native/hkdfguard_securefile.c reads it. */
export interface MacAclEntry {
  /** An allow entry (true) or a deny entry. */
  readonly allow: boolean;
  /** Whether it applies only to what is created inside a folder, never the folder itself. */
  readonly inheritOnly: boolean;
  /** Whom it names: a user or group id, or 'unknown' (id -1) for a principal that doesn't resolve to one. */
  readonly kind: 'user' | 'group' | 'unknown';
  readonly id: number;
  /** The write rights it names, one bit each, in MAC_WRITE_RIGHTS' order. */
  readonly rights: number;
}

/** What native/hkdfguard_securefile.c exports on Linux and macOS: a path's ACL, as facts. */
export interface UnixAddon {
  /** Linux: the raw system.posix_acl_access attribute of the path itself, null for none, or the errno. */
  posixAcl?(path: string): Uint8Array | null | number;
  /** macOS: the entries of the path's own extended ACL, [] for none, or the errno. */
  extendedAcl?(path: string): MacAclEntry[] | number;
}

let addon: WindowsAddon | undefined;
let unix: UnixAddon | undefined;

/**
 * The compiled add-on on Linux and macOS, loaded on first use, for reading ACLs, which Node's fs
 * can't. Built by node-gyp when the package is installed; a build that failed (no C toolchain) is
 * reported here, and no file is trusted without it.
 */
export function unixAddon(): UnixAddon {
  if (unix === undefined) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      unix = require('../build/Release/hkdfguard_securefile.node') as UnixAddon;
    } catch (error) {
      throw new UnsupportedPlatformError(
        'The native add-on of @runsecure/hkdfguard-securefile is not built. It reads access control lists, which Node can\'t, and is compiled at '
        + 'install by node-gyp, which needs Python 3 and a C compiler (build-essential on Debian and Ubuntu, the Xcode command line tools on '
        + 'macOS); install them and run "npm rebuild @runsecure/hkdfguard-securefile".',
        { cause: error });
    }
  }
  return unix;
}

/**
 * The compiled add-on, loaded on first use - Windows only. It is built from this package's own C
 * source by node-gyp when the package is installed on Windows; a build that failed (no C toolchain)
 * is reported here. It is loaded by its absolute path, beside this file, and it links only kernel32
 * and advapi32, which its build tells the loader to take from System32 alone.
 */
export function windowsAddon(): WindowsAddon {
  if (addon === undefined) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      addon = require('../build/Release/hkdfguard_securefile.node') as WindowsAddon;
    } catch (error) {
      throw new UnsupportedPlatformError(
        'The native add-on of @runsecure/hkdfguard-securefile is not built. On Windows it is compiled at install by node-gyp, which needs Python 3 and '
        + 'Visual Studio Build Tools (the "Desktop development with C++" workload); install them and run "npm rebuild @runsecure/hkdfguard-securefile".',
        { cause: error });
    }
  }
  return addon;
}

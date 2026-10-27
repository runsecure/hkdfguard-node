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

let addon: WindowsAddon | undefined;

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

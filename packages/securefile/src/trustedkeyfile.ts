import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { win32 } from 'node:path';
import { InvalidArgumentError, MAX_WRAPPED_KEY_BYTES, wipe } from '@runsecure/hkdfguard-abstractions';
import { INVALID_KEY_FILE, KeyFileError, UnsupportedPlatformError } from './errors.js';
import { windowsAddon, type OpenFileHandle, type WindowsAddon } from './native.js';
import { KeyFileTrust } from './trust.js';
import { readLink, resolveTrusted, statusOrUndefined, untrusted as unixUntrusted } from './unix.js';
import {
  DriveType, GUARDED_RIGHTS, GUARDED_ROOT_RIGHTS, trustedPrincipals, verifyFinalPath, verifyNotReparsePoint, verifyPathForm, verifyTrustedOnly,
  type WinSecurity,
} from './windows.js';

/** The length of an unwrapped DEK; a file this size is probably a plaintext key. */
export const PLAINTEXT_KEY_LENGTH = 32;

/** A 32-byte key as text is at most 64 hex digits; this allows surrounding whitespace. */
export const PLAINTEXT_TEXT_SCAN_LIMIT = 96;

/**
 * Reads the key file at `path`, still wrapped, refusing it unless only the operating system's
 * administrators and `trust` could have written or replaced it, and refusing contents that aren't a
 * wrapped key: the TypeScript equivalent of the native library's hkdfguard_open_file, for a
 * KeyWrapper.readKeyFile with no native library to read through - a network KMS's key wrapper, say.
 *
 * - Windows: the file must be on a local fixed drive, reached through real folders (no symbolic
 *   link, junction, mount point or substituted drive; an 8.3 short name that exists is expanded
 *   first), and it and every folder above it must be owned by, and modifiable only by, SYSTEM,
 *   Administrators, TrustedInstaller or a trusted principal. The file's owner and DACL are read
 *   through the handle it is read from, opened with read sharing only. These checks are Win32 calls
 *   made through this package's add-on.
 * - Linux and Apple silicon macOS: it and every directory above it must be owned by root or a
 *   trusted user and writable by nobody else (by its group only if that group is trusted), and only
 *   symbolic links a trusted user owns are followed; the resolved path is then opened with
 *   O_NOFOLLOW and must still be a regular file. These checks are Node's own fs calls.
 * - Everywhere: the contents must be 1 to MAX_WRAPPED_KEY_BYTES bytes - never more than one byte
 *   past that is read - and must not look like an unwrapped key (exactly 32 bytes, or a 32-byte key
 *   as hex or base64).
 *
 * A key file is a few hundred bytes on a local drive, so the checks and the read are made on the
 * calling thread rather than libuv's thread pool.
 *
 * @param path The key file's path, absolute or relative to the working directory.
 * @param trust Who besides administrators is trusted; {@link KeyFileTrust.administratorsOnly} (the default) for no one.
 * @param signal Checked before anything is examined.
 * @returns The file's contents, still wrapped, in a buffer the caller owns.
 * @throws KeyFileError 'ENOENT' (the file or a folder on its path doesn't exist), 'EACCES' (this
 *   account may not read it, or its location isn't trusted), ERR_HKDFGUARD_INVALID_KEY_FILE (empty,
 *   too long, or what looks like an unwrapped key), 'EBUSY' (another process has it open for
 *   writing), or the system's code for another failure.
 * @throws InvalidArgumentError `path` is empty or holds a NUL, `trust` isn't a KeyFileTrust, or it
 *   names a Windows principal that can't be trusted.
 * @throws UnsupportedPlatformError not Windows, Linux or an Apple silicon Mac, or the Windows add-on isn't built.
 */
export async function readTrustedKeyFile(path: string, trust: KeyFileTrust = KeyFileTrust.administratorsOnly, signal?: AbortSignal): Promise<Uint8Array> {
  signal?.throwIfAborted();
  return readOnPlatform(process.platform, process.arch, path, trust);
}

/**
 * {@link readTrustedKeyFile} for a given platform and architecture - exported from this module for
 * the tests, which check the platform dispatch, never from the package index.
 */
export function readOnPlatform(platform: string, arch: string, path: string, trust: KeyFileTrust): Uint8Array {
  if (typeof path !== 'string' || path === '') throw new InvalidArgumentError('A key file path is required.');
  if (path.includes('\0')) throw new InvalidArgumentError("A key file path can't contain a NUL character.");
  if (!(trust instanceof KeyFileTrust)) throw new InvalidArgumentError('trust must be a KeyFileTrust.');

  // Dispatches to one platform's wiring; each is exercised by the real-file tests on its own platform.
  switch (platform) {
    case 'win32':
      return readWindows(windowsAddon(), path, trust);
    case 'linux':
      return readUnix(path, trust);
    case 'darwin':
      // .NET and Java read struct stat at arm64 offsets; Node's lstat has no such limit, but the
      // supported platforms are kept the same in every port.
      if (arch !== 'arm64') throw new UnsupportedPlatformError(`Key files are read on Apple silicon Macs only; this process is ${arch}.`);
      return readUnix(path, trust);
    default:
      throw new UnsupportedPlatformError('Key files are read on Windows, Linux and macOS only.');
  }
}

// Windows errors (winerror.h) the read reports by Node's codes.
const ERROR_FILE_NOT_FOUND = 2;
const ERROR_PATH_NOT_FOUND = 3;
const ERROR_ACCESS_DENIED = 5;
const ERROR_SHARING_VIOLATION = 32;
const ERROR_INVALID_NAME = 123;

// Wires the windows.ts rules to real files through the add-on; exercised by the Windows-only real-file tests.
function readWindows(addon: WindowsAddon, path: string, trust: KeyFileTrust): Uint8Array {
  const trusted = trustedPrincipals(trust, addon.canonicalSid, addon.accountName);
  const full = fullPath(addon, path);
  verifyPathForm(full, full.startsWith('\\\\') ? DriveType.network : addon.driveType(win32.parse(full).root));

  // Read sharing only: refused if another process has it open for writing, and no one can open it
  // for writing while it's read.
  const file = open(addon, full);
  try {
    verifyFinalPath(full, native(full, () => addon.finalPath(file)));

    // The file through its own handle; the folders by path, which the final-path check ties to the
    // folders it was opened through, and which no untrusted principal can then change.
    verifyTrustedOnly(security(addon.fileSecurity(file), full, full), full, full, GUARDED_RIGHTS, trusted, addon.accountName);
    for (let folder = win32.dirname(full); ; folder = win32.dirname(folder)) {
      const descriptor = security(addon.namedSecurity(folder), full, folder);
      if (win32.dirname(folder) === folder) {
        verifyTrustedOnly(descriptor, full, folder, GUARDED_ROOT_RIGHTS, trusted, addon.accountName);
        break;
      }
      verifyNotReparsePoint(addon.fileAttributes(folder), full, folder);
      verifyTrustedOnly(descriptor, full, folder, GUARDED_RIGHTS, trusted, addon.accountName);
    }

    return readContents((view) => native(full, () => addon.readFile(file, view)), full);
  } finally {
    addon.closeFile(file);
  }
}

/**
 * What .NET's Path.GetFullPath returns: GetFullPathNameW's absolute, normalized form (a relative path
 * resolved against the working directory), with every 8.3 short name that exists on disk expanded to
 * its long name. A short name for something that doesn't exist stays short, and the final-path check
 * then refuses it.
 */
function fullPath(addon: WindowsAddon, path: string): string {
  const full = native(path, () => addon.fullPath(path));
  return full.includes('~') ? expandShortNames(full, addon.longPath) : full;
}

/**
 * Expands the longest leading part of `full` that exists, as .NET does: GetLongPathNameW fails
 * outright for a path whose last component is missing. Exported from this module for the tests.
 */
export function expandShortNames(full: string, longPath: (path: string) => string | null): string {
  let prefix = full;
  let rest = '';
  for (;;) {
    const expanded = longPath(prefix);
    if (expanded !== null) return expanded + rest;
    const separator = prefix.lastIndexOf('\\');
    // Stop at the root ("C:\" or "\\server\share\"): nothing left to expand.
    if (separator <= 2) return full;
    rest = prefix.slice(separator) + rest;
    prefix = prefix.slice(0, separator);
  }
}

function open(addon: WindowsAddon, full: string): OpenFileHandle {
  const opened = addon.openFile(full);
  if (typeof opened !== 'number') return opened;
  switch (opened) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_INVALID_NAME:
      throw new KeyFileError('ENOENT', full, `Key file '${full}' was not found.`);
    case ERROR_ACCESS_DENIED:
      throw new KeyFileError('EACCES', full, `This account may not read key file '${full}' (or it is a folder).`);
    case ERROR_SHARING_VIOLATION:
      throw new KeyFileError('EBUSY', full, `Key file '${full}' is open for writing by another process.`);
    default:
      throw new KeyFileError('EIO', full, `Could not open key file '${full}' (Windows error ${opened}).`);
  }
}

function security(descriptor: WinSecurity | number, full: string, item: string): WinSecurity {
  if (typeof descriptor !== 'number') return descriptor;
  if (descriptor === ERROR_ACCESS_DENIED) {
    throw new KeyFileError('EACCES', full, `Key file '${full}': this account may not read the permissions of '${item}'.`);
  }
  throw new KeyFileError('EIO', full, `Key file '${full}': could not read the security descriptor of '${item}' (Windows error ${descriptor}).`);
}

// A call into the add-on, whose own failures are reported as the key file's.
function native<T>(path: string, call: () => T): T {
  try {
    return call();
  } catch (error) {
    throw new KeyFileError('EIO', path, `Could not read key file '${path}': ${(error as Error).message}.`, { cause: error });
  }
}

// Wires the unix.ts rules to real files; exercised by the Unix-only real-file tests.
function readUnix(path: string, trust: KeyFileTrust): Uint8Array {
  // The working directory is already a resolved path; resolveTrusted handles ".." itself.
  let absolute = path;
  if (!path.startsWith('/')) {
    const workingDirectory = process.cwd();
    absolute = workingDirectory.endsWith('/') ? workingDirectory + path : `${workingDirectory}/${path}`;
  }
  const resolved = resolveTrusted(absolute, trust, statusOrUndefined, readLink);

  // resolved holds no symbolic link, so O_NOFOLLOW changes nothing for a file that passed; it only
  // makes certain the last component is still not one when it is opened. (libuv adds O_CLOEXEC.)
  let descriptor: number;
  try {
    descriptor = openSync(resolved, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code ?? 'EIO';
    if (code === 'ELOOP') throw unixUntrusted(path, `'${resolved}' became a symbolic link after it was checked`);
    throw new KeyFileError(code, path, `Could not open key file '${path}' (${code}).`, { cause: error });
  }
  try {
    // The descriptor itself is still a regular file: never a FIFO or device swapped in, which an
    // untrusted account can't do here anyway.
    if (!fstatSync(descriptor).isFile()) throw unixUntrusted(path, `'${resolved}' is no longer a regular file`);
    return readContents((view) => readSync(descriptor, view, 0, view.length, null), path);
  } finally {
    closeSync(descriptor);
  }
}

/**
 * Reads at most one byte past MAX_WRAPPED_KEY_BYTES through `read` - so a wrong path (a log, a
 * device) can't make startup allocate an unbounded buffer - and refuses an empty file, one over the
 * limit, and one that looks like an unwrapped key. Whatever is read is zeroed once copied out or
 * refused. Exported from this module for the tests.
 *
 * @param read Reads into the view it is given, returning the count; 0 at the end.
 * @param path The path, for messages.
 * @returns The contents, in a buffer the caller owns.
 * @throws KeyFileError ERR_HKDFGUARD_INVALID_KEY_FILE when the contents are refused.
 */
export function readContents(read: (view: Uint8Array) => number, path: string): Uint8Array {
  const buffer = new Uint8Array(MAX_WRAPPED_KEY_BYTES + 1);
  try {
    let total = 0;
    while (total < buffer.length) {
      const count = read(buffer.subarray(total));
      if (count <= 0) break;
      total += count;
    }

    if (total === 0) throw new KeyFileError(INVALID_KEY_FILE, path, `Key file '${path}' is empty.`);
    if (total > MAX_WRAPPED_KEY_BYTES) {
      throw new KeyFileError(INVALID_KEY_FILE, path,
        `Key file '${path}' is larger than ${MAX_WRAPPED_KEY_BYTES} bytes (MAX_WRAPPED_KEY_BYTES); a wrapped key never is.`);
    }
    if (looksLikePlaintextKey(buffer.subarray(0, total))) {
      throw new KeyFileError(INVALID_KEY_FILE, path, `Key file '${path}' holds what looks like an unwrapped 32-byte key, not a wrapped one. `
        + 'Treat that key as exposed: replace it, and write key files with the key wrapper.');
    }

    // Copied straight from the buffer: no intermediate copy outlives the zeroing below.
    return buffer.slice(0, total);
  } finally {
    wipe(buffer);
  }
}

// What .NET trims: space, tab, LF, VT, FF and CR.
const isWhitespace = (c: number) => c === 0x20 || (c >= 0x09 && c <= 0x0d);
const isDigit = (c: number) => c >= 0x30 && c <= 0x39;
const isHexDigit = (c: number) => isDigit(c) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66);
const isAlphanumeric = (c: number) => isDigit(c) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);

/**
 * The native library's test for a plaintext key written to disk: exactly 32 bytes, or a 32-byte key
 * as 64 hex digits or as base64 (standard or URL-safe, padded or not), with any surrounding
 * whitespace. Reads `contents` in place, making no copy of it.
 */
export function looksLikePlaintextKey(contents: Uint8Array): boolean {
  if (contents.length === PLAINTEXT_KEY_LENGTH) return true;
  if (contents.length > PLAINTEXT_TEXT_SCAN_LIMIT) return false;

  let start = 0;
  let end = contents.length;
  while (start < end && isWhitespace(contents[start]!)) start++;
  while (end > start && isWhitespace(contents[end - 1]!)) end--;
  return isHexKey(contents, start, end) || isBase64Key(contents, start, end);
}

function isHexKey(text: Uint8Array, start: number, end: number): boolean {
  if (end - start !== PLAINTEXT_KEY_LENGTH * 2) return false;
  for (let i = start; i < end; i++) {
    if (!isHexDigit(text[i]!)) return false;
  }
  return true;
}

function isBase64Key(text: Uint8Array, start: number, end: number): boolean {
  // 32 bytes: 43 characters, then one '=' when padded.
  if (end - start === 44 && text[start + 43] === 0x3d) end--;
  if (end - start !== 43) return false;

  let urlSafe = false;
  let standard = false;
  for (let i = start; i < end; i++) {
    const c = text[i]!;
    if (isAlphanumeric(c)) continue;
    if (c === 0x2b || c === 0x2f) standard = true; // + /
    else if (c === 0x2d || c === 0x5f) urlSafe = true; // - _
    else return false;
  }
  return !(urlSafe && standard);
}

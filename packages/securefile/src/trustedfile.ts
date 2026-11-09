import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { constants as bufferConstants } from 'node:buffer';
import { win32 } from 'node:path';
import { InvalidArgumentError, wipe } from '@runsecure/hkdfguard-abstractions';
import { FILE_TOO_LARGE, KeyFileError, UnsupportedPlatformError } from './errors.js';
import { windowsAddon, type OpenFileHandle, type WindowsAddon } from './native.js';
import { KeyFileTrust } from './trust.js';
import { readLink, resolveTrusted, statusOrUndefined, untrusted as unixUntrusted } from './unix.js';
import {
  DriveType, GUARDED_RIGHTS, GUARDED_ROOT_RIGHTS, trustedPrincipals, verifyFinalPath, verifyNotReparsePoint, verifyPathForm, verifyTrustedOnly,
  type WinSecurity,
} from './windows.js';

/**
 * Reads the file at `path`, refusing it unless only the operating system's administrators and
 * `trust` could have written or replaced it - the same symbolic-link, ownership and permission checks
 * {@link readTrustedKeyFile} applies - or if it is longer than `maxBytes`, and with none of a key
 * file's rules about its contents: for secret files, certificates and anything else that must come
 * from where only administrators and {@link KeyFileTrust} principals could have put it. What the
 * contents must look like is the caller's to check. For contents that are not themselves secret - a
 * value encrypted elsewhere, a public certificate; use {@link readTrustedFileWith} for anything that is.
 *
 * At most one byte past `maxBytes` is read, whatever the file reports as its length, so a wrong path
 * (a log, a device) can't make it read without end; the buffer is allocated at that size up front,
 * so keep it close to the largest file expected. The checks and the read are made on the calling
 * thread, as {@link readTrustedKeyFile}'s are.
 *
 * @param path The file's path, absolute or relative to the working directory.
 * @param trust Who besides administrators is trusted; {@link KeyFileTrust.administratorsOnly} for no one.
 * @param maxBytes The longest file accepted: a positive integer.
 * @param signal Checked before anything is examined.
 * @returns The file's contents, which may be empty, in a buffer the caller owns.
 * @throws KeyFileError 'ENOENT' (the file or a folder on its path doesn't exist), 'EACCES' (this
 *   account may not read it, or its location isn't trusted), ERR_HKDFGUARD_FILE_TOO_LARGE (longer
 *   than `maxBytes`), 'EBUSY' (another process has it open for writing), or the system's code for
 *   another failure.
 * @throws InvalidArgumentError `path` is empty or holds a NUL, `trust` isn't a KeyFileTrust or names
 *   a Windows principal that can't be trusted, or `maxBytes` isn't a positive integer below Node's
 *   largest buffer.
 * @throws UnsupportedPlatformError not Windows, Linux or an Apple silicon Mac, or the Windows add-on isn't built.
 */
export async function readTrustedFile(path: string, trust: KeyFileTrust, maxBytes: number, signal?: AbortSignal): Promise<Uint8Array> {
  signal?.throwIfAborted();
  validateArguments(path, trust, maxBytes);
  return withTrustedFile(process.platform, process.arch, path, trust, (file) => readFileContents(file.read, file.path, maxBytes));
}

/**
 * Reads the file at `path` as {@link readTrustedFile} does and hands the contents to `parse` - for
 * contents that are themselves secret, such as a PFX or a PEM private key. The buffer is zeroed once
 * parse returns or throws, so parse must not keep the view it is given, and should zero any copy it
 * makes. (Node has no pinned memory: zeroing reaches the buffer's own bytes, not copies V8 may have
 * made.)
 *
 * @param path The file's path, absolute or relative to the working directory.
 * @param trust Who besides administrators is trusted; {@link KeyFileTrust.administratorsOnly} for no one.
 * @param maxBytes The longest file accepted: a positive integer.
 * @param parse Turns the contents, which may be empty, into the result.
 * @param signal Checked before anything is examined.
 * @returns What `parse` returned.
 * @throws KeyFileError, InvalidArgumentError, UnsupportedPlatformError as {@link readTrustedFile};
 *   InvalidArgumentError too when `parse` isn't a function. Whatever `parse` throws propagates.
 */
export async function readTrustedFileWith<T>(path: string, trust: KeyFileTrust, maxBytes: number, parse: (contents: Uint8Array) => T,
  signal?: AbortSignal): Promise<T> {
  signal?.throwIfAborted();
  validateArguments(path, trust, maxBytes);
  if (typeof parse !== 'function') throw new InvalidArgumentError('parse must be a function.');
  return withTrustedFile(process.platform, process.arch, path, trust, (file) => parseFileContents(file.read, file.path, maxBytes, parse));
}

/**
 * {@link readTrustedFile}, synchronously - for code that must read a file where it can't wait, such
 * as a constructor that reads its TLS certificates. The checks and the read are the same, made on
 * the calling thread as readTrustedFile's are; only the result isn't a promise. For contents that
 * are themselves secret, zero the buffer once it is used.
 *
 * @param path The file's path, absolute or relative to the working directory.
 * @param trust Who besides administrators is trusted; {@link KeyFileTrust.administratorsOnly} for no one.
 * @param maxBytes The longest file accepted: a positive integer.
 * @returns The file's contents, which may be empty, in a buffer the caller owns.
 * @throws KeyFileError, InvalidArgumentError, UnsupportedPlatformError as {@link readTrustedFile}.
 */
export function readTrustedFileSync(path: string, trust: KeyFileTrust, maxBytes: number): Uint8Array {
  validateArguments(path, trust, maxBytes);
  return withTrustedFile(process.platform, process.arch, path, trust, (file) => readFileContents(file.read, file.path, maxBytes));
}

function validateArguments(path: string, trust: KeyFileTrust, maxBytes: number): void {
  if (typeof path !== 'string' || path === '') throw new InvalidArgumentError('A file path is required.');
  if (path.includes('\0')) throw new InvalidArgumentError("A file path can't contain a NUL character.");
  if (!(trust instanceof KeyFileTrust)) throw new InvalidArgumentError('trust must be a KeyFileTrust.');
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0 || maxBytes >= bufferConstants.MAX_LENGTH) {
    throw new InvalidArgumentError(`maxBytes must be a positive integer below ${bufferConstants.MAX_LENGTH}, got ${String(maxBytes)}.`);
  }
}

/** A file opened once its location passed the platform's checks: read it, then it is closed. */
export interface TrustedFile {
  /** The path the platform names in its messages: the full path on Windows, the path as given on Linux and macOS. */
  readonly path: string;
  /** Reads into the view it is given, returning the count; 0 at the end. */
  read(view: Uint8Array): number;
}

/**
 * Opens `path` for reading once the platform's checks have passed - refusing it if another process
 * has it open for writing, and while it's open no one can open it for writing - hands it to `use`,
 * and closes it whatever `use` does. The arguments must already be valid. Exported from this module
 * for trustedkeyfile.ts and the tests, which check the platform dispatch, never from the package index.
 *
 * @throws KeyFileError 'ENOENT', 'EACCES', 'EBUSY' or the system's code, as {@link readTrustedFile}.
 * @throws InvalidArgumentError `trust` names a Windows principal that can't be trusted.
 * @throws UnsupportedPlatformError not Windows, Linux or an Apple silicon Mac, or the Windows add-on isn't built.
 */
export function withTrustedFile<T>(platform: string, arch: string, path: string, trust: KeyFileTrust, use: (file: TrustedFile) => T): T {
  // Dispatches to one platform's wiring; each is exercised by the real-file tests on its own platform.
  switch (platform) {
    case 'win32':
      return withWindowsFile(windowsAddon(), path, trust, use);
    case 'linux':
      return withUnixFile(path, trust, use);
    case 'darwin':
      // .NET and Java read struct stat at arm64 offsets; Node's lstat has no such limit, but the
      // supported platforms are kept the same in every port.
      if (arch !== 'arm64') throw new UnsupportedPlatformError(`Trusted files are read on Apple silicon Macs only; this process is ${arch}.`);
      return withUnixFile(path, trust, use);
    default:
      throw new UnsupportedPlatformError('Trusted files are read on Windows, Linux and macOS only.');
  }
}

/**
 * Reads at most one byte past `maxBytes` through `read`, refusing a longer file, and returns what was
 * read. The read buffer is zeroed once copied out or refused. Exported from this module for the tests.
 *
 * @param read Reads into the view it is given, returning the count; 0 at the end.
 * @param path The path, for messages.
 * @returns The contents, which may be empty, in a buffer the caller owns.
 * @throws KeyFileError ERR_HKDFGUARD_FILE_TOO_LARGE when the contents are longer than maxBytes.
 */
export function readFileContents(read: (view: Uint8Array) => number, path: string, maxBytes: number): Uint8Array {
  // Copied straight from the buffer: no intermediate copy outlives the zeroing.
  return parseFileContents(read, path, maxBytes, (contents) => contents.slice());
}

/**
 * Reads as {@link readFileContents} does and returns what `parse` makes of the contents, a view of
 * the read buffer; the buffer is zeroed whether parse returns or throws, and parse isn't called for a
 * file that is too long. Exported from this module for the tests.
 *
 * @throws KeyFileError ERR_HKDFGUARD_FILE_TOO_LARGE when the contents are longer than maxBytes.
 */
export function parseFileContents<T>(read: (view: Uint8Array) => number, path: string, maxBytes: number, parse: (contents: Uint8Array) => T): T {
  const buffer = new Uint8Array(maxBytes + 1);
  try {
    const total = fillBounded(read, buffer);
    if (total === buffer.length) {
      throw new KeyFileError(FILE_TOO_LARGE, path, `'${path}' is larger than ${maxBytes} bytes, the most it may be.`);
    }
    return parse(buffer.subarray(0, total));
  } finally {
    wipe(buffer);
  }
}

/**
 * Fills `buffer` through `read` as far as the file goes, returning the count. Callers make buffer one
 * byte longer than the longest file they accept, so filling it means the file is too long.
 */
export function fillBounded(read: (view: Uint8Array) => number, buffer: Uint8Array): number {
  let total = 0;
  while (total < buffer.length) {
    const count = read(buffer.subarray(total));
    if (count <= 0) break;
    total += count;
  }
  return total;
}

// Windows errors (winerror.h) the read reports by Node's codes.
const ERROR_FILE_NOT_FOUND = 2;
const ERROR_PATH_NOT_FOUND = 3;
const ERROR_ACCESS_DENIED = 5;
const ERROR_SHARING_VIOLATION = 32;
const ERROR_INVALID_NAME = 123;

// Wires the windows.ts rules to real files through the add-on; exercised by the Windows-only real-file tests.
function withWindowsFile<T>(addon: WindowsAddon, path: string, trust: KeyFileTrust, use: (file: TrustedFile) => T): T {
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

    return use({ path: full, read: (view) => native(full, () => addon.readFile(file, view)) });
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
      throw new KeyFileError('ENOENT', full, `'${full}' was not found.`);
    case ERROR_ACCESS_DENIED:
      throw new KeyFileError('EACCES', full, `This account may not read '${full}' (or it is a folder).`);
    case ERROR_SHARING_VIOLATION:
      throw new KeyFileError('EBUSY', full, `'${full}' is open for writing by another process.`);
    default:
      throw new KeyFileError('EIO', full, `Could not open '${full}' (Windows error ${opened}).`);
  }
}

function security(descriptor: WinSecurity | number, full: string, item: string): WinSecurity {
  if (typeof descriptor !== 'number') return descriptor;
  if (descriptor === ERROR_ACCESS_DENIED) {
    throw new KeyFileError('EACCES', full, `'${full}': this account may not read the permissions of '${item}'.`);
  }
  throw new KeyFileError('EIO', full, `'${full}': could not read the security descriptor of '${item}' (Windows error ${descriptor}).`);
}

// A call into the add-on, whose own failures are reported as the file's.
function native<T>(path: string, call: () => T): T {
  try {
    return call();
  } catch (error) {
    throw new KeyFileError('EIO', path, `Could not read '${path}': ${(error as Error).message}.`, { cause: error });
  }
}

// Wires the unix.ts rules to real files; exercised by the Unix-only real-file tests.
function withUnixFile<T>(path: string, trust: KeyFileTrust, use: (file: TrustedFile) => T): T {
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
    throw new KeyFileError(code, path, `Could not open '${path}' (${code}).`, { cause: error });
  }
  try {
    // The descriptor itself is still a regular file: never a FIFO or device swapped in, which an
    // untrusted account can't do here anyway.
    if (!fstatSync(descriptor).isFile()) throw unixUntrusted(path, `'${resolved}' is no longer a regular file`);
    return use({ path, read: (view) => readSync(descriptor, view, 0, view.length, null) });
  } finally {
    closeSync(descriptor);
  }
}

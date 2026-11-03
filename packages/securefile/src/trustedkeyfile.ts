import { InvalidArgumentError, MAX_WRAPPED_KEY_BYTES, wipe } from '@runsecure/hkdfguard-abstractions';
import { INVALID_KEY_FILE, KeyFileError } from './errors.js';
import { KeyFileTrust } from './trust.js';
import { fillBounded, withTrustedFile } from './trustedfile.js';

// Exported from this module for the tests, which have always found it here.
export { expandShortNames } from './trustedfile.js';

/** The length of an unwrapped DEK; a file this size, or this size plus a line ending (LF or CRLF), is probably a plaintext key. */
export const PLAINTEXT_KEY_LENGTH = 32;

/** A 32-byte key as text is at most 64 hex digits; this allows surrounding whitespace. */
export const PLAINTEXT_TEXT_SCAN_LIMIT = 96;

/**
 * Reads the key file at `path`, still wrapped, refusing it unless only the operating system's
 * administrators and `trust` could have written or replaced it, and refusing contents that aren't a
 * wrapped key: the TypeScript equivalent of the native library's hkdfguard_open_file, for a
 * KeyWrapper.readKeyFile with no native library to read through - a network KMS's key wrapper, say.
 * It is opened through the same checks as {@link readTrustedFile}, then held to a key file's rules.
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
 *   past that is read - and must not look like an unwrapped key (32 raw bytes, optionally followed by
 *   one line ending (LF or CRLF), or a 32-byte key as hex or base64).
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

  return withTrustedFile(platform, arch, path, trust, (file) => readContents(file.read, file.path));
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
    const total = fillBounded(read, buffer);

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
 * The native library's test for a plaintext key written to disk: 32 raw bytes, optionally followed by
 * one line ending (LF or CRLF), or a 32-byte key as 64 hex digits or as base64 (standard or URL-safe,
 * padded or not), with any surrounding whitespace. A raw key is judged by its length and trailing
 * line ending alone, never by trimming: its own last bytes may be whitespace values. Reads
 * `contents` in place, making no copy of it.
 */
export function looksLikePlaintextKey(contents: Uint8Array): boolean {
  const length = contents.length;
  if (length === PLAINTEXT_KEY_LENGTH) return true;
  if (length === PLAINTEXT_KEY_LENGTH + 1 && contents[PLAINTEXT_KEY_LENGTH] === 0x0a) return true; // LF
  if (length === PLAINTEXT_KEY_LENGTH + 2 && contents[PLAINTEXT_KEY_LENGTH] === 0x0d && contents[PLAINTEXT_KEY_LENGTH + 1] === 0x0a) return true; // CRLF
  if (length > PLAINTEXT_TEXT_SCAN_LIMIT) return false;

  let start = 0;
  let end = length;
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

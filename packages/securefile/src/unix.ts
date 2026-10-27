import { lstatSync, readlinkSync } from 'node:fs';
import { InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';
import { KeyFileError } from './errors.js';
import type { KeyFileTrust } from './trust.js';

/*
 * The Linux and macOS key-file location rules, and the two system calls they need. Node has both,
 * so no add-on is needed here: lstat (fs.lstatSync) describes the path itself, never what a symbolic
 * link points to - its owner, group, permission bits and type - and readlink (fs.readlinkSync)
 * returns a link's stored target. The rules take those two calls as arguments, so the tests run them
 * against simulated filesystems on every platform.
 */

export type UnixFileType = 'other' | 'regular file' | 'directory' | 'symbolic link';

/** What lstat reports about one path: who owns it, its permissions, and its type. */
export interface UnixFileStatus {
  readonly ownerId: number;
  readonly groupId: number;
  /** The permission bits of st_mode (the low twelve: set-id, sticky, and read, write and execute for owner, group and others). */
  readonly mode: number;
  /** What kind of file it is - a symbolic link is reported as such, never followed. */
  readonly type: UnixFileType;
}

/** S_IWGRP: writable by the file's group. */
export const GROUP_WRITE = 0o020;
/** S_IWOTH: writable by every other user. */
export const OTHER_WRITE = 0o002;

/** The kernel's own limit on symbolic links followed in one lookup. */
export const MAX_SYMBOLIC_LINKS = 40;

/**
 * Decides whether a key file's path on Linux or macOS can be trusted: resolves it the way the kernel
 * would, from `/`, checking everything it passes through, and returns the resolved path, which
 * contains no symbolic links. Every directory and the file itself must be owned by root or a
 * {@link KeyFileTrust.unixUserIds} user, must not be writable by others, and may be writable by its
 * group only if that is a {@link KeyFileTrust.unixGroupIds} group. A symbolic link is followed only
 * if a trusted user owns it, and its target is then checked in turn - so macOS's root-owned /etc to
 * private/etc works, and a link anyone else made doesn't. Nothing under /tmp, /var/tmp or another
 * world-writable directory passes, sticky or not.
 *
 * The path is checked before it is opened, not through the opened descriptor. That is enough:
 * nobody untrusted can write to any directory on the resolved path, or to the file, so nobody
 * untrusted can change what it resolves to between the check and the open.
 *
 * @param path An absolute path.
 * @param getStatus lstat-style status of a path, or undefined if nothing is there.
 * @param readLink A symbolic link's stored target, or undefined if it can't be read as one.
 * @throws KeyFileError 'ENOENT' when nothing is at the path or a directory on it is missing; 'EACCES'
 *   when a component is not trusted or the path isn't a regular file.
 * @throws InvalidArgumentError the path is not absolute.
 */
export function resolveTrusted(path: string, trust: KeyFileTrust, getStatus: (path: string) => UnixFileStatus | undefined,
  readLink: (path: string) => string | undefined): string {
  if (!path.startsWith('/')) throw new InvalidArgumentError(`'${path}' is not an absolute path.`);

  const root = getStatus('/');
  if (root === undefined) throw new KeyFileError('EACCES', path, "'/' could not be examined.");
  requireTrusted('/', root, trust, path);

  const pending: string[] = [];
  pushComponents(pending, path);
  let resolved = '/';
  let resolvedType: UnixFileType = 'directory';
  let linksFollowed = 0;

  for (let name = pending.pop(); name !== undefined; name = pending.pop()) {
    if (name === '' || name === '.') continue;

    if (resolvedType !== 'directory') {
      throw new KeyFileError('ENOENT', path, `Key file '${path}' runs through '${resolved}', which is not a directory.`);
    }

    if (name === '..') {
      // resolved never contains a symbolic link, so its parent is its lexical parent.
      resolved = parentOf(resolved);
      continue;
    }

    const candidate = resolved === '/' ? `/${name}` : `${resolved}/${name}`;
    const status = getStatus(candidate);
    if (status === undefined) {
      throw new KeyFileError('ENOENT', path, `Key file '${path}' was not found ('${candidate}' does not exist).`);
    }

    if (status.type === 'symbolic link') {
      if (!isTrustedUser(status.ownerId, trust)) {
        throw untrusted(path, `'${candidate}' is a symbolic link owned by uid ${status.ownerId}, and only links owned by root or a trusted user are followed`);
      }
      if (++linksFollowed > MAX_SYMBOLIC_LINKS) throw untrusted(path, `it follows more than ${MAX_SYMBOLIC_LINKS} symbolic links`);

      const target = readLink(candidate);
      if (target === undefined) throw untrusted(path, `'${candidate}' could not be read as a symbolic link`);
      if (target.startsWith('/')) resolved = '/';
      pushComponents(pending, target);
      continue;
    }

    requireTrusted(candidate, status, trust, path);
    resolved = candidate;
    resolvedType = status.type;
  }

  if (resolvedType !== 'regular file') throw untrusted(path, `it resolves to '${resolved}', which is not a regular file`);
  return resolved;
}

function requireTrusted(candidate: string, status: UnixFileStatus, trust: KeyFileTrust, path: string): void {
  if (!isTrustedUser(status.ownerId, trust)) {
    throw untrusted(path, `'${candidate}' is owned by uid ${status.ownerId}, not root or a trusted user`);
  }
  if ((status.mode & OTHER_WRITE) !== 0) throw untrusted(path, `'${candidate}' is writable by every user`);
  if ((status.mode & GROUP_WRITE) !== 0 && !trust.unixGroupIds.includes(status.groupId)) {
    throw untrusted(path, `'${candidate}' is writable by group ${status.groupId}, which is not a trusted group`);
  }
}

function isTrustedUser(uid: number, trust: KeyFileTrust): boolean {
  return uid === 0 || trust.unixUserIds.includes(uid);
}

/** The refusal of a key file whose location isn't trusted: `code` 'EACCES', as Node reports a path it may not use. */
export function untrusted(path: string, why: string): KeyFileError {
  return new KeyFileError('EACCES', path,
    `Key file '${path}' is not trusted: ${why}. Keep key files where only root (or a trusted deployer, see KeyFileTrust) can write, all the way up from /.`);
}

// Empty components (from "//" or a trailing "/") are kept, as .NET's Split keeps them, and skipped like ".".
function pushComponents(pending: string[], path: string): void {
  pending.push(...path.split('/').reverse());
}

/** The lexical parent of an absolute path with no symbolic links; "/" is its own parent. */
export function parentOf(path: string): string {
  const slash = path.lastIndexOf('/');
  return slash <= 0 ? '/' : path.slice(0, slash);
}

/**
 * lstat: describes the path itself, never what a symbolic link points to; undefined when nothing is
 * there (ENOENT or ENOTDIR).
 *
 * @throws KeyFileError 'EACCES' when this account may not look; the system's code for any other failure.
 */
export function statusOrUndefined(path: string): UnixFileStatus | undefined {
  let status;
  try {
    status = lstatSync(path);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') return undefined;
    if (code === 'EACCES') throw new KeyFileError('EACCES', path, `This account may not look up '${path}' (EACCES).`, { cause: error });
    throw new KeyFileError(code ?? 'EIO', path, `Could not look up '${path}' (${code ?? 'unknown error'}).`, { cause: error });
  }
  const type: UnixFileType = status.isFile() ? 'regular file'
    : status.isDirectory() ? 'directory'
      : status.isSymbolicLink() ? 'symbolic link' : 'other';
  return { ownerId: status.uid, groupId: status.gid, mode: status.mode & 0o7777, type };
}

/**
 * readlink: a symbolic link's target, exactly as stored (possibly relative); undefined if the path
 * isn't a symbolic link or isn't there.
 *
 * @throws KeyFileError 'EACCES' when this account may not read it; the system's code for any other failure.
 */
export function readLink(path: string): string | undefined {
  try {
    return readlinkSync(path);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'EINVAL' || code === 'ENOENT' || code === 'ENOTDIR') return undefined;
    if (code === 'EACCES') throw new KeyFileError('EACCES', path, `This account may not read the symbolic link '${path}' (EACCES).`, { cause: error });
    throw new KeyFileError(code ?? 'EIO', path, `readlink('${path}') failed (${code ?? 'unknown error'}).`, { cause: error });
  }
}

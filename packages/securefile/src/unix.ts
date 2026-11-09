import { lstatSync, readlinkSync } from 'node:fs';
import { InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';
import { KeyFileError } from './errors.js';
import { unixAddon, type MacAclEntry, type UnixAddon } from './native.js';
import type { KeyFileTrust } from './trust.js';

/*
 * The Linux and macOS location rules for key files and every other trusted file, and the system
 * calls they need: lstat (fs.lstatSync) describes the path itself, never what a symbolic link points
 * to - its owner, group, permission bits and type - and readlink (fs.readlinkSync) returns a link's
 * stored target; and the add-on reads its access control list, which Node can't and the permission
 * bits don't show (aclEntries). The rules take those calls as arguments, so the tests run them
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

/** One principal an ACL lets change a path: a user or group id, or one that couldn't be resolved. */
export interface AclWriter {
  readonly kind: 'user' | 'group' | 'unknown';
  readonly id: number;
  /** What it may do, for messages: "write" (Linux), or the macOS rights by name. */
  readonly rights: string;
}

/** The macOS extended-ACL rights the add-on reports, in the order of its bits; every one lets a principal change a path. */
export const MAC_WRITE_RIGHTS: readonly string[] = [
  'write data (add file)', 'append data (add subdirectory)', 'delete', 'delete child', 'write attributes', 'write extended attributes',
  'write security', 'change owner',
];

// POSIX ACL entry tags (acl_ea.h), and the one permission bit that matters here.
const ACL_USER = 0x02;
const ACL_GROUP = 0x08;
const ACL_MASK = 0x10;
const ACL_WRITE = 0x02;
const POSIX_ACL_XATTR_VERSION = 2;

/**
 * The named users and groups a Linux POSIX ACL - system.posix_acl_access's raw bytes - lets write:
 * each USER and GROUP entry whose write permission the ACL's mask leaves in effect, as the kernel
 * decides. The owner's, owning group's and others' entries aren't listed: the permission bits
 * already show them (a group's bits, when an ACL has a mask, are the mask's).
 * @throws Error the bytes aren't a POSIX ACL this understands
 */
export function posixAclWriters(bytes: Uint8Array): AclWriter[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.length < 4 || (bytes.length - 4) % 8 !== 0 || view.getUint32(0, true) !== POSIX_ACL_XATTR_VERSION) {
    throw new Error('its POSIX ACL is in a form this does not read');
  }
  const entries: { tag: number; perm: number; id: number }[] = [];
  for (let at = 4; at < bytes.length; at += 8) {
    entries.push({ tag: view.getUint16(at, true), perm: view.getUint16(at + 2, true), id: view.getUint32(at + 4, true) });
  }
  const mask = entries.find((e) => e.tag === ACL_MASK);
  return entries
    .filter((e) => (e.tag === ACL_USER || e.tag === ACL_GROUP) && (e.perm & ACL_WRITE) !== 0 && (mask === undefined || (mask.perm & ACL_WRITE) !== 0))
    .map((e) => ({ kind: e.tag === ACL_USER ? 'user' : 'group', id: e.id, rights: 'write' }));
}

/**
 * The principals a macOS extended ACL lets change a path: each allow entry naming a write right
 * that applies to the path itself (not only to what is created inside it). A deny entry takes
 * nothing away here: it narrows what another entry allowed, and every allow is judged on its own.
 */
export function macAclWriters(entries: readonly MacAclEntry[]): AclWriter[] {
  return entries
    .filter((e) => e.allow && !e.inheritOnly && e.rights !== 0)
    .map((e) => ({
      kind: e.kind, id: e.id,
      rights: MAC_WRITE_RIGHTS.filter((_, bit) => (e.rights & (1 << bit)) !== 0).join(', ') || `rights 0x${e.rights.toString(16)}`,
    }));
}

/** The kernel's own limit on symbolic links followed in one lookup. */
export const MAX_SYMBOLIC_LINKS = 40;

/**
 * Decides whether a file's path on Linux or macOS can be trusted (a key file's, or any file
 * readTrustedFile reads): resolves it the way the kernel would, from `/`, checking everything it
 * passes through, and returns the resolved path, which contains no symbolic links. Every directory
 * and the file itself must be owned by root or a {@link KeyFileTrust.unixUserIds} user, must not be
 * writable by others, and may be writable by its group only if that is a
 * {@link KeyFileTrust.unixGroupIds} group; and an access control list on any of them may let write
 * only the same users and groups (`getAclWriters`). A symbolic link is followed only
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
 * @param getAclWriters Whom a path's ACL lets change it; none by default (the simulated filesystems).
 * @throws KeyFileError 'ENOENT' when nothing is at the path or a directory on it is missing; 'EACCES'
 *   when a component is not trusted or the path isn't a regular file.
 * @throws InvalidArgumentError the path is not absolute.
 */
export function resolveTrusted(path: string, trust: KeyFileTrust, getStatus: (path: string) => UnixFileStatus | undefined,
  readLink: (path: string) => string | undefined, getAclWriters: (path: string) => readonly AclWriter[] = () => []): string {
  if (!path.startsWith('/')) throw new InvalidArgumentError(`'${path}' is not an absolute path.`);

  const root = getStatus('/');
  if (root === undefined) throw new KeyFileError('EACCES', path, "'/' could not be examined.");
  requireTrusted('/', root, trust, path, getAclWriters);

  const pending: string[] = [];
  pushComponents(pending, path);
  let resolved = '/';
  let resolvedType: UnixFileType = 'directory';
  let linksFollowed = 0;

  for (let name = pending.pop(); name !== undefined; name = pending.pop()) {
    if (name === '' || name === '.') continue;

    if (resolvedType !== 'directory') {
      throw new KeyFileError('ENOENT', path, `'${path}' runs through '${resolved}', which is not a directory.`);
    }

    if (name === '..') {
      // resolved never contains a symbolic link, so its parent is its lexical parent.
      resolved = parentOf(resolved);
      continue;
    }

    const candidate = resolved === '/' ? `/${name}` : `${resolved}/${name}`;
    const status = getStatus(candidate);
    if (status === undefined) {
      throw new KeyFileError('ENOENT', path, `'${path}' was not found ('${candidate}' does not exist).`);
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

    requireTrusted(candidate, status, trust, path, getAclWriters);
    resolved = candidate;
    resolvedType = status.type;
  }

  if (resolvedType !== 'regular file') throw untrusted(path, `it resolves to '${resolved}', which is not a regular file`);
  return resolved;
}

function requireTrusted(candidate: string, status: UnixFileStatus, trust: KeyFileTrust, path: string,
  getAclWriters: (path: string) => readonly AclWriter[]): void {
  if (!isTrustedUser(status.ownerId, trust)) {
    throw untrusted(path, `'${candidate}' is owned by uid ${status.ownerId}, not root or a trusted user`);
  }
  if ((status.mode & OTHER_WRITE) !== 0) throw untrusted(path, `'${candidate}' is writable by every user`);
  if ((status.mode & GROUP_WRITE) !== 0 && !trust.unixGroupIds.includes(status.groupId)) {
    throw untrusted(path, `'${candidate}' is writable by group ${status.groupId}, which is not a trusted group`);
  }
  for (const writer of getAclWriters(candidate)) {
    const trusted = writer.kind === 'user' ? isTrustedUser(writer.id, trust) : writer.kind === 'group' && trust.unixGroupIds.includes(writer.id);
    if (!trusted) {
      const who = writer.kind === 'unknown' ? 'a principal that resolves to no user or group' : `${writer.kind === 'user' ? 'uid' : 'gid'} ${writer.id}`;
      throw untrusted(path, `'${candidate}' has an access control list letting ${who}, which is not trusted, ${writer.rights}`);
    }
  }
}

function isTrustedUser(uid: number, trust: KeyFileTrust): boolean {
  return uid === 0 || trust.unixUserIds.includes(uid);
}

/** The refusal of a file whose location isn't trusted (a key file, or any trusted file): `code` 'EACCES', as Node reports a path it may not use. */
export function untrusted(path: string, why: string): KeyFileError {
  return new KeyFileError('EACCES', path,
    `'${path}' is not trusted: ${why}. Keep it where only root (or a trusted deployer, see KeyFileTrust) can write, all the way up from /.`);
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
 * Whom the access control list of `path` itself lets change it, read through the add-on: on Linux,
 * its POSIX ACL's named users and groups with write in effect; on macOS, its extended ACL's allow
 * entries naming a write right. None where a filesystem keeps no ACL.
 *
 * @throws KeyFileError 'EACCES' when the ACL can't be read or understood - what can't be checked isn't trusted.
 * @throws UnsupportedPlatformError the add-on isn't built.
 */
export function aclWriters(path: string, addon: UnixAddon = unixAddon(), platform: string = process.platform): readonly AclWriter[] {
  const result = platform === 'darwin' ? addon.extendedAcl!(path) : addon.posixAcl!(path);
  if (typeof result === 'number') throw untrusted(path, `the access control list of '${path}' could not be read (errno ${result})`);
  if (result === null) return [];
  if (Array.isArray(result)) return macAclWriters(result);
  try {
    return posixAclWriters(result as Uint8Array);
  } catch (error) {
    throw untrusted(path, `'${path}': ${(error as Error).message}`);
  }
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

/**
 * What lstat reports about one path, shared by the macOS and Linux loader policies - plain data, so
 * the policies can be checked against simulated filesystems on any platform.
 */
export enum FileType {
  Other = 'special file',
  Regular = 'regular file',
  Directory = 'directory',
  Symlink = 'symbolic link',
}

/** One path itself - never what a symbolic link points to. */
export interface FileStatus {
  uid: number;
  gid: number;
  /** The low 12 mode bits. */
  perm: number;
  type: FileType;
}

export const PERM_GROUP_WRITE = 0o020;
export const PERM_OTHER_WRITE = 0o002;

/** errno values the policies distinguish; identical on Linux and macOS. */
export const ENOENT = 2;
export const ENOTDIR = 20;

/** A FileStatus from a raw st_mode. */
export function statusFromMode(uid: number, gid: number, mode: number): FileStatus {
  let type = FileType.Other;
  switch (mode & 0o170000) {
    case 0o100000: type = FileType.Regular; break;
    case 0o040000: type = FileType.Directory; break;
    case 0o120000: type = FileType.Symlink; break;
  }
  return { uid, gid, perm: mode & 0o7777, type };
}

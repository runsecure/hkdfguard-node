import { InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';
import { KeyFileError } from './errors.js';
import type { KeyFileTrust } from './trust.js';

/*
 * The Windows key-file location rules - the native library's (hkdfguard_open_file's) - kept free of
 * system calls: a security descriptor, attributes and paths are passed in as plain data, so the
 * rules are tested on every platform. trustedkeyfile.ts wires them to the add-on's Win32 calls.
 *
 * - The path names a file on a local fixed drive. UNC paths, device paths (\\?\, \\.\) and network
 *   drives are refused before anything is opened, so no server named in a path is ever contacted.
 * - The opened file's final path - with every symbolic link, junction, mount point and substituted
 *   drive resolved - is the path that was asked for, once the full path has expanded any 8.3 short
 *   name (it expands each one that exists on disk; a path still spelled with a short name doesn't
 *   match the final path and is refused). So nothing on the path redirects it, and the folders
 *   checked are the ones the file is in.
 * - The file, and every folder above it, is owned by a trusted principal, and grants no one else any
 *   right to write, append, delete, rename, change its permissions or take ownership. For a folder
 *   that also covers creating files and folders in it. The drive root is held only to what could
 *   rename or delete what's beneath it, since a default C:\ lets Authenticated Users create folders.
 *   A missing (NULL) DACL, and an entry whose trustee can't be read the plain way (an object ACE),
 *   are refused.
 *
 * Trusted principals are SYSTEM, Administrators, TrustedInstaller and KeyFileTrust.windowsPrincipals.
 */

/** What GetDriveTypeW reports for a drive root, by its DRIVE_* value. */
export const DriveType = {
  unknown: 0,
  noRootDirectory: 1,
  removable: 2,
  fixed: 3,
  network: 4,
  cdRom: 5,
  ram: 6,
} as const;

// Named in messages as .NET's DriveType names them, as every port does.
const DRIVE_TYPE_NAMES = ['Unknown', 'NoRootDirectory', 'Removable', 'Fixed', 'Network', 'CDRom', 'Ram'];

/** A drive type's name as .NET names it; anything GetDriveTypeW doesn't define is "Unknown". */
export function driveTypeName(type: number): string {
  return DRIVE_TYPE_NAMES[type] ?? 'Unknown';
}

export const SYSTEM = 'S-1-5-18';
export const ADMINISTRATORS = 'S-1-5-32-544';
/** NT SERVICE\TrustedInstaller has no well-known SID type; this is its fixed service SID. */
export const TRUSTED_INSTALLER = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464';
export const ALWAYS_TRUSTED: readonly string[] = [SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER];

/**
 * Groups every account, or every signed-in one, is in - Everyone, Authenticated Users, Users,
 * Interactive, Anonymous: trusting one trusts everybody.
 */
export const NEVER_TRUSTED: ReadonlySet<string> = new Set(['S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4', 'S-1-5-7']);

/** File access rights (winnt.h). */
export const Rights = {
  /** FILE_WRITE_DATA; FILE_ADD_FILE on a folder. */
  writeData: 0x0002,
  /** FILE_APPEND_DATA; FILE_ADD_SUBDIRECTORY on a folder. */
  appendData: 0x0004,
  /** FILE_WRITE_EA. */
  writeExtendedAttributes: 0x0010,
  /** FILE_DELETE_CHILD. */
  deleteSubdirectoriesAndFiles: 0x0040,
  delete: 0x0001_0000,
  /** WRITE_DAC. */
  changePermissions: 0x0004_0000,
  /** WRITE_OWNER. */
  takeOwnership: 0x0008_0000,
  genericAll: 0x1000_0000,
  genericWrite: 0x4000_0000,
} as const;

/**
 * Any right that lets a principal change what this path reads: write or append data (on a folder,
 * create files or folders), delete or rename (Delete on the item, DeleteSubdirectoriesAndFiles on its
 * parent), write extended attributes, or take over the ACL. Generic bits are listed too, since an ACE
 * can carry them unmapped.
 */
export const GUARDED_RIGHTS = Rights.writeData | Rights.appendData | Rights.writeExtendedAttributes | Rights.deleteSubdirectoriesAndFiles
  | Rights.delete | Rights.changePermissions | Rights.takeOwnership | Rights.genericAll | Rights.genericWrite;

/** On the drive root, only what lets a principal rename or delete an entry directly beneath it. */
export const GUARDED_ROOT_RIGHTS = Rights.deleteSubdirectoriesAndFiles | Rights.changePermissions | Rights.takeOwnership | Rights.genericAll;

/** ACE types (winnt.h). */
export const AceType = {
  allowed: 0x00,
  denied: 0x01,
  allowedObject: 0x05,
  deniedObject: 0x06,
  allowedCallback: 0x09,
  deniedCallback: 0x0a,
  allowedCallbackObject: 0x0b,
  deniedCallbackObject: 0x0c,
} as const;

/** INHERIT_ONLY_ACE: the entry applies only to what is created inside a folder, never the folder itself. */
export const INHERIT_ONLY_ACE = 0x08;

/** INVALID_FILE_ATTRIBUTES, which has every bit set - the reparse-point bit included. */
export const INVALID_FILE_ATTRIBUTES = 0xffff_ffff;
export const FILE_ATTRIBUTE_REPARSE_POINT = 0x400;

/** One DACL entry: its type, flags (inheritance), the access mask it allows or denies, and its trustee's SID - null for a type with no plain SID. */
export interface WinAce {
  readonly type: number;
  readonly flags: number;
  readonly mask: number;
  readonly sid: string | null;
}

/** An item's owner (null if the descriptor has none) and DACL; `daclAbsent` is a missing or NULL DACL, which grants every user full control. */
export interface WinSecurity {
  readonly owner: string | null;
  readonly daclAbsent: boolean;
  readonly aces: readonly WinAce[];
}

/** The account a SID string maps to, or null - for describing principals in messages. */
export type AccountName = (sid: string) => string | null;

/**
 * The principals `trust` trusts, the always-trusted ones included, as canonical SID strings.
 *
 * @param canonicalSid A SID string's canonical form, or null if it isn't one.
 * @throws InvalidArgumentError a listed SID isn't valid, or is one that every account is in.
 */
export function trustedPrincipals(trust: KeyFileTrust, canonicalSid: (sid: string) => string | null, accountName: AccountName): readonly string[] {
  const trusted = [...ALWAYS_TRUSTED];
  for (const value of trust.windowsPrincipals) {
    const sid = value === '' ? null : canonicalSid(value);
    if (sid === null) {
      throw new InvalidArgumentError(`KeyFileTrust.windowsPrincipals holds '${value}', which is not a security identifier (S-1-...).`);
    }
    if (NEVER_TRUSTED.has(sid)) {
      throw new InvalidArgumentError(`KeyFileTrust.windowsPrincipals holds ${describe(sid, accountName)}, which every account (or every signed-in one) is in; `
        + 'trusting it would trust anyone to replace a key file.');
    }
    trusted.push(sid);
  }
  return trusted;
}

/**
 * Refuses a path that isn't on a local fixed drive, before anything is opened.
 *
 * @param fullPath The absolute path.
 * @param driveType The DRIVE_* type of the drive the path's root names.
 * @throws KeyFileError 'EACCES' when it isn't.
 */
export function verifyPathForm(fullPath: string, driveType: number): void {
  if (fullPath.startsWith('\\\\') || fullPath.startsWith('//')) {
    throw untrusted(fullPath, 'it is a UNC or device path; key files are only read from a local drive');
  }
  if (driveType !== DriveType.fixed) {
    throw untrusted(fullPath, `it is on a ${driveTypeName(driveType)} drive; key files are only read from a local fixed drive`);
  }
}

/**
 * Requires the opened file's final path to be the one that was asked for.
 *
 * @param fullPath The absolute path that was opened.
 * @param finalPath GetFinalPathNameByHandleW's answer for the opened handle (\\?\C:\...).
 * @throws KeyFileError 'EACCES' when they differ.
 */
export function verifyFinalPath(fullPath: string, finalPath: string): void {
  const localPrefix = '\\\\?\\';
  const isLocal = finalPath.startsWith(localPrefix) && !equalsIgnoreCase(finalPath.slice(0, 8), '\\\\?\\UNC\\');
  const opened = isLocal ? finalPath.slice(localPrefix.length) : undefined;
  if (opened === undefined || !equalsIgnoreCase(opened, fullPath)) {
    throw untrusted(fullPath, `it opens '${finalPath}' - its path runs through a symbolic link, junction, mount point or substituted drive. `
      + 'Configure it as the full, real path');
  }
}

/**
 * Refuses a folder that is a symbolic link, junction or other reparse point. INVALID_FILE_ATTRIBUTES
 * has every bit set, so a folder that can't be examined is refused too.
 *
 * @param attributes The folder's GetFileAttributesW value.
 * @throws KeyFileError 'EACCES' when it is one.
 */
export function verifyNotReparsePoint(attributes: number, fullPath: string, folder: string): void {
  if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) !== 0) {
    throw untrusted(fullPath, `'${folder}' is a symbolic link, junction or other reparse point`);
  }
}

/**
 * Requires a trusted owner, and no Allow entry granting any of `guardedRights` ({@link GUARDED_RIGHTS}
 * for the file and folders, {@link GUARDED_ROOT_RIGHTS} for the drive root) to anyone else.
 * Inherit-only entries don't apply to the item itself, and Deny entries can only remove access, so
 * both are ignored. A missing DACL grants everyone everything, and an entry whose trustee can't be
 * read the plain way (an object ACE) can't be evaluated: both are refused.
 *
 * @throws KeyFileError 'EACCES' when the owner is untrusted, or an untrusted principal holds a guarded right.
 */
export function verifyTrustedOnly(security: WinSecurity, fullPath: string, item: string, guardedRights: number, trusted: readonly string[],
  accountName: AccountName): void {
  const owner = security.owner;
  if (owner === null || !trusted.includes(owner)) {
    throw untrusted(fullPath, `'${item}' is owned by ${describe(owner, accountName)}, not SYSTEM, Administrators, TrustedInstaller or a trusted deployer`);
  }
  if (security.daclAbsent) throw untrusted(fullPath, `'${item}' has no DACL, which grants every user full control`);

  for (const ace of security.aces) {
    if ((ace.flags & INHERIT_ONLY_ACE) !== 0) continue;
    switch (ace.type) {
      case AceType.denied:
      case AceType.deniedObject:
      case AceType.deniedCallback:
      case AceType.deniedCallbackObject:
        continue; // can only remove access
      case AceType.allowed:
      case AceType.allowedCallback:
        if ((ace.mask & guardedRights) !== 0 && (ace.sid === null || !trusted.includes(ace.sid))) {
          throw untrusted(fullPath, `'${item}' grants ${describeRights(ace.mask)} to ${describe(ace.sid, accountName)}`);
        }
        continue;
      default:
        throw untrusted(fullPath, `'${item}' has an access control entry of type 0x${hex(ace.type, 2)}, which this check can't evaluate`);
    }
  }
}

// How describeRights names an access mask's bits: .NET's FileSystemRights names, then the generic bits.
const RIGHT_NAMES: readonly (string | undefined)[] = [
  'ReadData', 'WriteData', 'AppendData', 'ReadExtendedAttributes', 'WriteExtendedAttributes', 'ExecuteFile',
  'DeleteSubdirectoriesAndFiles', 'ReadAttributes', 'WriteAttributes', undefined, undefined, undefined, undefined, undefined, undefined, undefined,
  'Delete', 'ReadPermissions', 'ChangePermissions', 'TakeOwnership', 'Synchronize', undefined, undefined, undefined,
  'AccessSystemSecurity', 'MaximumAllowed', undefined, undefined, 'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead',
];

/** An access mask as hex, then the names of its bits, such as "0x00000116 (WriteData, AppendData, ...)". */
export function describeRights(mask: number): string {
  const value = mask >>> 0;
  const names: string[] = [];
  for (let bit = 0; bit < 32; bit++) {
    const flag = (2 ** bit);
    if (Math.floor(value / flag) % 2 === 1) names.push(RIGHT_NAMES[bit] ?? `0x${hex(flag, 8)}`);
  }
  return `0x${hex(value, 8)}${names.length > 0 ? ` (${names.join(', ')})` : ''}`;
}

/** The refusal of a key file whose location isn't trusted: `code` 'EACCES', as Node reports a path it may not use. */
export function untrusted(path: string, why: string): KeyFileError {
  return new KeyFileError('EACCES', path, `Key file '${path}' is not trusted: ${why}. Keep key files in a folder of their own that only administrators `
    + '(or a trusted deployer, see KeyFileTrust) can modify, with inherited permissions removed.');
}

function describe(sid: string | null, accountName: AccountName): string {
  if (sid === null) return 'an unknown principal';
  const name = accountName(sid);
  return name === null ? sid : `${name} (${sid})`;
}

function hex(value: number, width: number): string {
  return (value >>> 0).toString(16).toUpperCase().padStart(width, '0');
}

/**
 * Ordinal comparison ignoring case, character by character with simple case mapping, as .NET's
 * OrdinalIgnoreCase and NTFS compare names: unlike toUpperCase on the whole string, it never turns
 * one character into several ("ß" is not "SS").
 */
export function equalsIgnoreCase(first: string, second: string): boolean {
  const a = [...first];
  const b = [...second];
  return a.length === b.length && a.every((c, i) => c === b[i] || simpleUpper(c) === simpleUpper(b[i]!));
}

function simpleUpper(character: string): string {
  const upper = character.toUpperCase();
  return [...upper].length === 1 ? upper : character;
}

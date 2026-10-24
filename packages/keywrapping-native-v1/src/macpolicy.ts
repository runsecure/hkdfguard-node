import { NotInstalledError, UnsupportedPlatformError, UntrustedError } from './errors.js';
import { ENOENT, ENOTDIR, FileType, PERM_GROUP_WRITE, PERM_OTHER_WRITE, type FileStatus } from './unixpath.js';

/*
 * The macOS loader's decisions, kept free of system calls (they are passed in) so they can be
 * checked against simulated filesystems on any platform. The loader (darwin.ts) loads the library
 * from one of its two install locations and nowhere else:
 *
 *  1. Location. The system install is used whenever it exists; the per-user install,
 *     ~/.hkdfguard/v1, only when there is no system install - anything running as the user can
 *     write to the user's home, so a per-user file must never override a root-owned system one. If
 *     the system install exists but fails a check, loading fails; nor does it fall back when the
 *     system install merely can't be examined: only "nothing is there" counts as "not installed".
 *     The home folder comes from the account database (getpwuid), never $HOME, so whoever sets the
 *     process's environment can't choose where the library is loaded from.
 *  2. Path integrity. No component of the path, from the file up to /, may be a symbolic link, or
 *     writable by anyone but its owner - except that the system directories above an install
 *     (/, /Library, /Library/Application Support, /Users) may also be writable by the wheel or
 *     admin group when root owns them. Every component of a system install must be owned by root;
 *     of a user install, by root or the current user.
 *  3. Code signature. The file's signature must be valid and satisfy MAC_CODE_REQUIREMENT.
 *     Its version - LC_ID_DYLIB's current_version, which the signature covers - must be at least
 *     MAC_MINIMUM_LIBRARY_VERSION, so an older genuine release can't be planted in its place.
 *  4. What dyld loaded. dlopen of an absolute path first looks for its leaf name in every
 *     DYLD_LIBRARY_PATH directory, so the loader refuses before dlopen if one holds the library's
 *     name, and after dlopen asks dyld (dladdr) which file it mapped.
 */

export const MAC_FILE_NAME = 'libhkdfguard.dylib';
export const MAC_SYSTEM_DIRECTORY = '/Library/Application Support/HkdfGuard/v1';
export const MAC_USER_DIRECTORY_UNDER_HOME = '.hkdfguard/v1';
export const MAC_SYSTEM_PATH = `${MAC_SYSTEM_DIRECTORY}/${MAC_FILE_NAME}`;

/** The Apple team ID the library must be signed by: the certificate's subject OU. */
export const MAC_TEAM_ID = 'MFW3T8R8J3';

/**
 * Matches the release build's own designated requirement: this library's identifier, signed with a
 * Developer ID Application certificate issued to the HkdfGuard team - so a development build, or
 * any other binary the team signs (such as the hkdfguard tool), is refused.
 */
export const MAC_CODE_REQUIREMENT = 'identifier "libhkdfguard" and anchor apple generic'
  + ' and certificate 1[field.1.2.840.113635.100.6.2.6] exists' // Developer ID CA
  + ' and certificate leaf[field.1.2.840.113635.100.6.1.13] exists' // Developer ID Application leaf
  + ` and certificate leaf[subject.OU] = "${MAC_TEAM_ID}"`;

/** The library's own minimum macOS major version (its LC_BUILD_VERSION minos). */
export const MAC_MINIMUM_MAJOR_VERSION = 13;

/** An export every genuine build has; its address tells dladdr which file was loaded. */
export const PROBE_EXPORT = 'hkdfguard_wrap_dek';

/**
 * The oldest native library release this package loads, in Mach-O's packed form
 * (major << 16 | minor << 8 | patch): 0.9.0. A release that fixes a security problem in the library
 * raises it, so an older, genuinely signed copy can't be put back in its place.
 */
export const MAC_MINIMUM_LIBRARY_VERSION = (0 << 16) | (9 << 8) | 0;
/** How much of the file is read to find its version. */
export const MAC_VERSION_READ_LIMIT = 64 * 1024;

const MH_MAGIC_64 = 0xfeedfacf;
const FAT_MAGIC = 0xcafebabe;
const FAT_MAGIC_64 = 0xcafebabf;
const CPU_TYPE_ARM64 = 0x0100000c;
const LC_ID_DYLIB = 0xd;

const ADMINISTRATIVE_GROUPS = [0, 80]; // wheel and admin
const SHARED_SYSTEM_DIRECTORIES = ['/', '/Library', '/Library/Application Support', '/Users'];

/** The per-user install's full path under `homeDirectory`. */
export function macUserPath(homeDirectory: string): string {
  return `${homeDirectory.replace(/\/+$/, '')}/${MAC_USER_DIRECTORY_UNDER_HOME}/${MAC_FILE_NAME}`;
}

/**
 * Requires what the library requires: an arm64 process (Apple silicon only, for its Secure Enclave)
 * on macOS 13 or later - checked first, so an unsupported Mac gets this rather than dyld's message.
 */
export function macRequireSupportedPlatform(arch: string, osVersion: string): void {
  if (arch !== 'arm64') {
    const detail = arch === 'x64'
      ? ' - an Intel Mac, or an x64 Node.js running under Rosetta; on Apple silicon, use the arm64 Node.js.'
      : '.';
    throw new UnsupportedPlatformError(`The HkdfGuard native KMS library requires Apple silicon: an arm64 process on an arm64 Mac. This process is ${arch}${detail}`);
  }
  const major = Number.parseInt(osVersion.split('.')[0] ?? '', 10);
  if (!Number.isInteger(major)) {
    throw new UnsupportedPlatformError(`Could not determine the macOS version (got '${osVersion}'); the HkdfGuard native KMS library requires macOS ${MAC_MINIMUM_MAJOR_VERSION} or later.`);
  }
  if (major < MAC_MINIMUM_MAJOR_VERSION) {
    throw new UnsupportedPlatformError(`The HkdfGuard native KMS library requires macOS ${MAC_MINIMUM_MAJOR_VERSION} or later; this is macOS ${osVersion}.`);
  }
}

// ENOENT and ENOTDIR mean nothing is installed there; anything else means something may be there
// this process can't see, and a system install hidden that way must not let the user one replace it.
function isPresent(path: string, probe: (path: string) => number, kind: string): boolean {
  const errno = probe(path);
  if (errno === 0) return true;
  if (errno === ENOENT || errno === ENOTDIR) return false;
  throw new UntrustedError(`Could not tell whether the ${kind} HkdfGuard native library '${path}' exists (lstat failed with errno ${errno}); refusing to guess or to fall back to another location.`);
}

/** The system install if it exists, otherwise the user install. `probe` is lstat's errno (0 if present). */
export function macChoosePath(probe: (path: string) => number, homeDirectory: string): { path: string; isSystem: boolean } {
  if (isPresent(MAC_SYSTEM_PATH, probe, 'system-wide')) {
    return { path: MAC_SYSTEM_PATH, isSystem: true };
  }
  const user = macUserPath(homeDirectory);
  // Only an absolute home: a relative one would resolve against the working directory.
  if (homeDirectory.startsWith('/') && isPresent(user, probe, 'per-user')) {
    return { path: user, isSystem: false };
  }
  throw new NotInstalledError(`The HkdfGuard native KMS library is not installed. Install it at '${MAC_SYSTEM_PATH}' (system-wide) or '${user}' (this user); it is never loaded from anywhere else.`);
}

/**
 * The dyld variables whose presence alone refuses the load: each makes dyld inject code into this
 * process, or load another file in place of a library it names - including the frameworks the
 * HkdfGuard native library calls with every DEK. None is set on a production host.
 */
export const MAC_REFUSED_DYLD_VARIABLES: readonly string[] = [
  'DYLD_INSERT_LIBRARIES', 'DYLD_FRAMEWORK_PATH', 'DYLD_VERSIONED_LIBRARY_PATH', 'DYLD_VERSIONED_FRAMEWORK_PATH', 'DYLD_IMAGE_SUFFIX',
];

/**
 * Refuses, before anything is loaded, if one of {@link MAC_REFUSED_DYLD_VARIABLES} is set, or a
 * DYLD_LIBRARY_PATH directory holds a file of the library's name.
 *
 * A guard against a misconfigured environment, not against whoever controls it: dyld acts on these
 * variables when the process starts, so code they injected has already run - and can hide - by the
 * time this looks. Running the host with the Hardened Runtime, which makes dyld ignore them, is what
 * keeps that code out.
 */
export function macRefuseShadowing(getenv: (name: string) => string | undefined, exists: (path: string) => boolean): void {
  for (const name of MAC_REFUSED_DYLD_VARIABLES) {
    if ((getenv(name) ?? '') !== '') {
      throw new UntrustedError(`${name} is set, so dyld may inject code into this process or substitute a library the HkdfGuard native library uses; refusing to load it. Unset ${name}.`);
    }
  }
  for (const directory of (getenv('DYLD_LIBRARY_PATH') ?? '').split(':')) {
    if (directory === '') continue;
    const candidate = `${directory.replace(/\/+$/, '')}/${MAC_FILE_NAME}`;
    if (exists(candidate)) {
      throw new UntrustedError(`'${candidate}' is on DYLD_LIBRARY_PATH and would be loaded in place of the verified HkdfGuard native library; refusing to load. Remove it from DYLD_LIBRARY_PATH.`);
    }
  }
}

/** Requires that the file dyld reports having loaded (null: no probe export, or dyld can't say) is the verified one. */
export function macVerifyLoadedImage(expectedPath: string, loadedPath: string | null): void {
  if (loadedPath === null) {
    throw new UntrustedError(`The library loaded for '${expectedPath}' has no '${PROBE_EXPORT}' export, or dyld cannot say where it came from; it is not the HkdfGuard native library and has been unloaded.`);
  }
  if (loadedPath !== expectedPath) {
    throw new UntrustedError(`dyld loaded '${loadedPath}' in place of the verified '${expectedPath}' (DYLD_LIBRARY_PATH, most likely); it has been unloaded and the HkdfGuard native library was not loaded.`);
  }
}

/** Checks the file and every parent directory up to /: not a symbolic link, owned by one of `trustedOwners`, writable by no one else. */
export function macVerifyLocation(path: string, getStatus: (path: string) => FileStatus, trustedOwners: readonly number[]): void {
  const file = getStatus(path);
  if (file.type !== FileType.Regular) {
    throw new UntrustedError(`'${path}' is not a regular file (it is a ${file.type}).`);
  }
  macVerifyComponent(path, file, trustedOwners);

  for (let directory = macParentOf(path); directory !== undefined; directory = macParentOf(directory)) {
    const status = getStatus(directory);
    if (status.type !== FileType.Directory) {
      throw new UntrustedError(`'${directory}' is not a directory (it is a ${status.type}); the library is only loaded through a real path.`);
    }
    macVerifyComponent(directory, status, trustedOwners);
  }
}

function macVerifyComponent(path: string, status: FileStatus, trustedOwners: readonly number[]): void {
  if (status.uid !== 0 && !trustedOwners.includes(status.uid)) {
    const owners = trustedOwners.length === 1 ? 'root' : 'root or the current user';
    throw new UntrustedError(`'${path}' is owned by uid ${status.uid}; the HkdfGuard native library is only loaded from a location owned by ${owners}.`);
  }
  if ((status.perm & PERM_OTHER_WRITE) !== 0) {
    throw new UntrustedError(`'${path}' is writable by every user; the HkdfGuard native library is only loaded from a location only its owner can modify.`);
  }
  if ((status.perm & PERM_GROUP_WRITE) !== 0
    && !(status.uid === 0 && ADMINISTRATIVE_GROUPS.includes(status.gid) && SHARED_SYSTEM_DIRECTORIES.includes(path))) {
    throw new UntrustedError(`'${path}' is writable by group ${status.gid}; the HkdfGuard native library is only loaded from a location only its owner can modify (administrators may also write only to the system directories above an install: ${SHARED_SYSTEM_DIRECTORIES.join(', ')}).`);
  }
}

/** Requires a valid signature satisfying MAC_CODE_REQUIREMENT; `checkSignature` returns 0 or the failing OSStatus. */
export function macVerifySignature(path: string, checkSignature: (path: string, requirement: string) => number): void {
  const status = checkSignature(path, MAC_CODE_REQUIREMENT);
  if (status !== 0) {
    throw new UntrustedError(`'${path}' is not validly signed by the HkdfGuard team (${MAC_TEAM_ID}); code signature check failed with OSStatus ${status}.`);
  }
}

/** `path`'s parent ('/'-separated), or undefined above /. */
export function macParentOf(path: string): string | undefined {
  if (path === '/') return undefined;
  const slash = path.replace(/\/+$/, '').lastIndexOf('/');
  return slash <= 0 ? '/' : path.slice(0, slash);
}

/** A packed Mach-O version as major.minor.patch. */
export function macFormatVersion(version: number): string {
  return `${version >>> 16}.${(version >>> 8) & 0xff}.${version & 0xff}`;
}

/**
 * LC_ID_DYLIB's current_version, read from the start of a Mach-O file: a thin arm64 image, or the
 * arm64 slice of a fat one. `data` is at most the first MAC_VERSION_READ_LIMIT bytes. Throws an
 * Error describing what is wrong for anything malformed, truncated or not arm64.
 */
export function macDylibCurrentVersion(data: Uint8Array): number {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (data.length < 4) throw new Error('too short to be a Mach-O file');
  const magic = view.getUint32(0, false);
  if (magic === FAT_MAGIC || magic === FAT_MAGIC_64) return fatArm64Version(data, view, magic === FAT_MAGIC_64);
  return thinArm64Version(data);
}

function fatArm64Version(data: Uint8Array, view: DataView, wide: boolean): number {
  if (data.length < 8) throw new Error('truncated fat header');
  const count = view.getUint32(4, false);
  const entrySize = wide ? 32 : 20;
  if (count * entrySize + 8 > data.length) throw new Error(`fat header lists ${count} architectures, more than were read`);
  for (let i = 0; i < count; i++) {
    const entry = 8 + i * entrySize;
    if (view.getUint32(entry, false) !== CPU_TYPE_ARM64) continue;
    const offset = wide ? Number(view.getBigUint64(entry + 8, false)) : view.getUint32(entry + 8, false);
    if (offset >= data.length) throw new Error(`the arm64 slice starts at ${offset}, beyond the ${data.length} bytes read`);
    return thinArm64Version(data.subarray(offset));
  }
  throw new Error('no arm64 slice');
}

function thinArm64Version(data: Uint8Array): number {
  const headerSize = 32; // mach_header_64
  if (data.length < headerSize) throw new Error('truncated Mach-O header');
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (view.getUint32(0, true) !== MH_MAGIC_64) throw new Error('not a 64-bit Mach-O file');
  if (view.getUint32(4, true) !== CPU_TYPE_ARM64) throw new Error('not an arm64 image');
  const ncmds = view.getUint32(16, true);
  const end = headerSize + view.getUint32(20, true);
  if (end > data.length) throw new Error('load commands run past the bytes read');
  let at = headerSize;
  for (let i = 0; i < ncmds; i++) {
    if (at + 8 > end) throw new Error(`load command ${i} runs past the load commands`);
    const cmd = view.getUint32(at, true);
    const size = view.getUint32(at + 4, true);
    if (size < 8 || size % 8 !== 0 || at + size > end) throw new Error(`load command ${i} has an invalid size ${size}`);
    if (cmd === LC_ID_DYLIB) {
      // cmd, cmdsize, name offset, timestamp, current_version, compatibility_version
      if (size < 24) throw new Error('LC_ID_DYLIB is too short');
      return view.getUint32(at + 16, true);
    }
    at += size;
  }
  throw new Error('no LC_ID_DYLIB load command');
}

/**
 * Refuses a library whose version, read from `data` (the start of the verified file at `path`), is
 * missing, unreadable or below MAC_MINIMUM_LIBRARY_VERSION.
 */
export function macRequireMinimumVersion(path: string, data: Uint8Array): void {
  let version: number;
  try {
    version = macDylibCurrentVersion(data);
  } catch (error) {
    throw new UntrustedError(`Could not read the version of the HkdfGuard native library '${path}' (${(error as Error).message}); refusing to load it.`);
  }
  if (version < MAC_MINIMUM_LIBRARY_VERSION) {
    throw new UntrustedError(`'${path}' is HkdfGuard native library version ${macFormatVersion(version)}, older than the minimum this package accepts (${macFormatVersion(MAC_MINIMUM_LIBRARY_VERSION)}); install a current release.`);
  }
}

/**
 * The per-user install's base: the home folder the account database gives this process's effective
 * user, or '' - no per-user install - if the lookup failed or gave anything but an absolute path.
 */
export function macHomeFromAccount(home: string | null | undefined): string {
  return typeof home === 'string' && home.startsWith('/') ? home : '';
}


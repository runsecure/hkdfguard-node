import { NotInstalledError, UnsupportedPlatformError, UntrustedError } from './errors.js';
import { PROBE_EXPORT } from './macpolicy.js';
import { ENOENT, ENOTDIR, FileType, PERM_GROUP_WRITE, PERM_OTHER_WRITE, type FileStatus } from './unixpath.js';

/*
 * The Linux loader's decisions, kept free of system calls (they are passed in) so they can be
 * checked against simulated filesystems on any platform. The library receives every plaintext DEK,
 * and the tpm2-tss library it loads every ECDH shared secret, so loading an impostor of either
 * would hand over every key:
 *
 *  1. Location. The file the libhkdfguard1 package installs: the Debian multiarch directory if it is
 *     there, otherwise /usr/lib64. Only "nothing is there" moves on; a path that can't be examined
 *     is refused.
 *  2. Path integrity. Every directory walked through, every symbolic link followed, and the file
 *     itself must be owned by root, and no directory or file may be writable by group or others.
 *  3. Environment. Every location LD_LIBRARY_PATH, LD_PRELOAD or LD_AUDIT names must pass the same
 *     path checks, in both the environment the process started with and the current one.
 *  4. What was loaded. After dlopen, dladdr must place the export in the verified file, and every
 *     object in its dependency closure must be bound to a file that passes the path checks.
 *
 * The library is not content-pinned: a release's authenticity is verified with Sigstore/cosign when
 * the package is installed, so path integrity is what the loader enforces.
 */

export const LINUX_FILE_NAME = 'libhkdfguard.so.1';
export const LINUX_LIB64_DIRECTORY = '/usr/lib64';
export const LINUX_MAX_SYMBOLIC_LINKS = 40;

/** The dynamic-linker variables that decide where, or what, it loads. */
export const ENV_LIBRARY_PATH = 'LD_LIBRARY_PATH';
export const ENV_PRELOAD = 'LD_PRELOAD';
export const ENV_AUDIT = 'LD_AUDIT';

/** Where the package may have installed the library for a process of `arch`, in the order tried. */
export function linuxCandidatePaths(arch: string): string[] {
  const triplet = arch === 'x64' ? 'x86_64-linux-gnu' : arch === 'arm64' ? 'aarch64-linux-gnu' : undefined;
  if (triplet === undefined) {
    throw new UnsupportedPlatformError(`The HkdfGuard native KMS library is built for x64 and arm64 Linux only; this process is ${arch}.`);
  }
  return [`/usr/lib/${triplet}/${LINUX_FILE_NAME}`, `${LINUX_LIB64_DIRECTORY}/${LINUX_FILE_NAME}`];
}

/** The first candidate that exists; `probe` is statx's errno (0 if present). */
export function linuxChoosePath(candidates: readonly string[], probe: (path: string) => number): string {
  for (const candidate of candidates) {
    const errno = probe(candidate);
    if (errno === 0) return candidate;
    if (errno !== ENOENT && errno !== ENOTDIR) {
      throw new UntrustedError(`Could not tell whether the HkdfGuard native library '${candidate}' exists (statx failed with errno ${errno}); refusing to guess or to fall back to another location.`);
    }
  }
  throw new NotInstalledError(`The HkdfGuard native KMS library is not installed. Install the libhkdfguard1 package (hkdfguard-libs on RPM distributions); it is loaded only from ${candidates.map((c) => `'${c}'`).join(' or ')}.`);
}

/** lstat-style status of a path, or undefined when nothing is there; throws for any other failure. */
export type StatusFunction = (path: string) => FileStatus | undefined;
/** A symbolic link's stored target, or undefined if it can't be read. */
export type ReadLinkFunction = (path: string) => string | undefined;

function requireRootControlled(path: string, status: FileStatus): void {
  if (status.uid !== 0) {
    throw new UntrustedError(`'${path}' is owned by uid ${status.uid}; the HkdfGuard native library and its dependencies are only trusted in locations owned by root.`);
  }
  if ((status.perm & (PERM_GROUP_WRITE | PERM_OTHER_WRITE)) !== 0) {
    throw new UntrustedError(`'${path}' is writable by its group or by every user; the HkdfGuard native library and its dependencies are only trusted in locations only root can modify.`);
  }
}

export function linuxParentOf(path: string): string {
  const slash = path.lastIndexOf('/');
  return slash <= 0 ? '/' : path.slice(0, slash);
}

/**
 * Resolves `path` the way the kernel would, checking everything it passes through: every directory
 * and the final object must be root-owned and writable by neither group nor others, and every
 * symbolic link root-owned (its target is then resolved and checked in turn). Returns the resolved
 * path, free of symbolic links - or undefined, when `allowMissing` and a component is missing
 * (everything up to it was checked, so only root could create what is missing).
 */
export function linuxResolveTrusted(path: string, expected: FileType, getStatus: StatusFunction, readLink: ReadLinkFunction, allowMissing = false): string | undefined {
  if (!path.startsWith('/')) {
    throw new UntrustedError(`'${path}' is not an absolute path; the HkdfGuard native library and its dependencies are only trusted at absolute paths.`);
  }
  const root = getStatus('/');
  if (root === undefined) {
    throw new UntrustedError("'/' could not be examined.");
  }
  requireRootControlled('/', root);

  const pending = path.split('/').reverse(); // a stack: the next component is last
  let resolved = '/';
  let resolvedType = FileType.Directory;
  let linksFollowed = 0;

  while (pending.length > 0) {
    const name = pending.pop()!;
    if (name === '' || name === '.') continue;
    if (resolvedType !== FileType.Directory) {
      throw new UntrustedError(`'${path}' runs through '${resolved}', which is not a directory.`);
    }
    if (name === '..') {
      resolved = linuxParentOf(resolved); // resolved has no symbolic links, so its parent is lexical
      continue;
    }

    const candidate = resolved === '/' ? `/${name}` : `${resolved}/${name}`;
    const status = getStatus(candidate);
    if (status === undefined) {
      if (allowMissing) return undefined;
      throw new UntrustedError(`'${candidate}' does not exist (resolving '${path}').`);
    }

    if (status.type === FileType.Symlink) {
      if (status.uid !== 0) {
        throw new UntrustedError(`'${candidate}' is a symbolic link owned by uid ${status.uid}; only links owned by root are followed (resolving '${path}').`);
      }
      if (++linksFollowed > LINUX_MAX_SYMBOLIC_LINKS) {
        throw new UntrustedError(`'${path}' follows more than ${LINUX_MAX_SYMBOLIC_LINKS} symbolic links.`);
      }
      const target = readLink(candidate);
      if (target === undefined) {
        throw new UntrustedError(`'${candidate}' could not be read as a symbolic link.`);
      }
      if (target.startsWith('/')) resolved = '/';
      pending.push(...target.split('/').reverse());
      continue;
    }

    requireRootControlled(candidate, status);
    resolved = candidate;
    resolvedType = status.type;
  }

  if (resolvedType !== expected) {
    throw new UntrustedError(`'${path}' resolves to '${resolved}', which is a ${resolvedType}, not a ${expected}.`);
  }
  return resolved;
}

/**
 * Every value each dynamic-linker variable has had: in the environment the process started with
 * (`initialEnvironment`, /proc/self/environ's NUL-separated block, or undefined if unreadable) and
 * in the current one.
 */
export function linuxReadEnvironment(current: Readonly<Record<string, string | undefined>>, initialEnvironment: Uint8Array | undefined): Map<string, string[]> {
  const names = [ENV_LIBRARY_PATH, ENV_PRELOAD, ENV_AUDIT];
  const values = new Map(names.map((n) => [n, [] as string[]]));
  if (initialEnvironment !== undefined) {
    for (const entry of new TextDecoder().decode(initialEnvironment).split('\0')) {
      const equals = entry.indexOf('=');
      if (equals > 0) values.get(entry.slice(0, equals))?.push(entry.slice(equals + 1));
    }
  }
  for (const name of names) {
    const value = current[name];
    if (value !== undefined && !values.get(name)!.includes(value)) values.get(name)!.push(value);
  }
  return values;
}

function untrustedVariable(variable: string, value: string, what: string): UntrustedError {
  return new UntrustedError(`${variable} ('${value}') contains ${what}; the dynamic linker could load the HkdfGuard native library's dependencies from there. Refusing to load it.`);
}

function verifyVariableLocation(variable: string, value: string, entry: string, expected: FileType, resolveTrusted: (path: string, expected: FileType) => void): void {
  if (entry.includes('$')) {
    throw untrustedVariable(variable, value, `'${entry}', which uses a dynamic string token ($ORIGIN, $LIB or $PLATFORM) that can't be checked in advance`);
  }
  if (!entry.startsWith('/')) {
    throw untrustedVariable(variable, value, `'${entry}', which is relative to the working directory`);
  }
  try {
    resolveTrusted(entry, expected);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new UntrustedError(`${variable} ('${value}') names '${entry}', which the dynamic linker could load the HkdfGuard native library's dependencies from: ${reason} Remove it from ${variable}, or make it a location only root can modify.`, { cause: error });
  }
}

/** Requires every location the dynamic-linker variables could make it load from to pass the path checks. */
export function linuxVerifyEnvironment(environment: ReadonlyMap<string, readonly string[]>, resolveTrusted: (path: string, expected: FileType) => void): void {
  // An empty LD_LIBRARY_PATH is ignored; an empty entry within one is the working directory.
  for (const value of environment.get(ENV_LIBRARY_PATH) ?? []) {
    if (value === '') continue;
    for (const entry of value.split(/[:;]/)) {
      if (entry === '') throw untrustedVariable(ENV_LIBRARY_PATH, value, 'an empty entry, which means the working directory');
      verifyVariableLocation(ENV_LIBRARY_PATH, value, entry, FileType.Directory, resolveTrusted);
    }
  }
  // Objects to preload or audit: separated by spaces or colons (LD_PRELOAD), or colons (LD_AUDIT). A
  // bare name is found by the same search as any dependency, which the check above covers.
  for (const [variable, separators] of [[ENV_PRELOAD, /[ :]/], [ENV_AUDIT, /:/]] as const) {
    for (const value of environment.get(variable) ?? []) {
      for (const entry of value.split(separators)) {
        if (entry !== '' && (entry.includes('/') || entry.includes('$'))) {
          verifyVariableLocation(variable, value, entry, FileType.Regular, resolveTrusted);
        }
      }
    }
  }
}

/** Requires that the (resolved) file the dynamic linker reports having loaded is the verified one. */
export function linuxVerifyLoadedImage(expectedPath: string, loadedPath: string | null): void {
  if (loadedPath === null) {
    throw new UntrustedError(`The library loaded for '${expectedPath}' has no '${PROBE_EXPORT}' export, or the dynamic linker cannot say where it came from; it is not the HkdfGuard native library and has been unloaded.`);
  }
  if (loadedPath !== expectedPath) {
    throw new UntrustedError(`The dynamic linker bound '${expectedPath}' to '${loadedPath}', a different file; it has been unloaded and the HkdfGuard native library was not loaded.`);
  }
}

/**
 * Walks the library's dependency closure - each file's DT_NEEDED names, then theirs - requiring
 * every one to be bound to a trusted file.
 */
export function linuxVerifyDependencies(libraryPath: string, readNeeded: (file: string) => string[],
  loadedPathOf: (soname: string) => string | null, resolveTrusted: (path: string) => string): void {
  const visited = new Set([libraryPath]);
  const queue = [libraryPath];
  while (queue.length > 0) {
    const file = queue.shift()!;
    for (const name of readNeeded(file)) {
      const loaded = loadedPathOf(name);
      if (loaded === null) {
        throw new UntrustedError(`'${file}' depends on '${name}', but no loaded object answers to that name; cannot tell where it came from.`);
      }
      let resolved: string;
      try {
        resolved = resolveTrusted(loaded);
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        throw new UntrustedError(`The HkdfGuard native library's dependency '${name}' (needed by '${file}') was loaded from '${loaded}', which is not trusted: ${reason}`, { cause: error });
      }
      if (!visited.has(resolved)) {
        visited.add(resolved);
        queue.push(resolved);
      }
    }
  }
}

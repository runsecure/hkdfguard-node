import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readlinkSync } from 'node:fs';
import { errnoOf, unixProbe } from './darwin.js';
import { elfReadNeededFile } from './elf.js';
import { UntrustedError } from './errors.js';
import { NativeKmsLibrary } from './library.js';
import {
  linuxCandidatePaths, linuxChoosePath, linuxKnownReleases, linuxReadEnvironment, linuxResolveTrusted, linuxVerifyContent,
  linuxVerifyDependencies, linuxVerifyEnvironment, linuxVerifyLoadedImage,
} from './linuxpolicy.js';
import { PROBE_EXPORT } from './macpolicy.js';
import { nativeAddon } from './native.js';
import { linuxStatusDescriptions } from './status.js';
import { ENOENT, ENOTDIR, FileType, statusFromMode, type FileStatus } from './unixpath.js';

/** lstat without following links; undefined when nothing is there, an error for anything else (EACCES). */
export function linuxStatus(path: string): FileStatus | undefined {
  try {
    const stat = lstatSync(path);
    return statusFromMode(stat.uid, stat.gid, stat.mode);
  } catch (error) {
    const errno = errnoOf(error);
    if (errno === ENOENT || errno === ENOTDIR) return undefined;
    throw new UntrustedError(`lstat('${path}') failed with errno ${errno}.`, { cause: error });
  }
}

export function linuxReadLink(path: string): string | undefined {
  try {
    return readlinkSync(path);
  } catch {
    return undefined;
  }
}

/** Resolves `path` to a regular file, failing unless it passes the path checks. */
export function linuxTrustedFile(path: string): string {
  return linuxResolveTrusted(path, FileType.Regular, linuxStatus, linuxReadLink)!;
}

function sha256File(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

/** Verifies and loads the Linux native KMS library (see linuxpolicy.ts). */
export function loadLinuxLibrary(): NativeKmsLibrary {
  const native = nativeAddon();
  const path = linuxTrustedFile(linuxChoosePath(linuxCandidatePaths(process.arch), unixProbe));
  linuxVerifyContent(path, sha256File, linuxKnownReleases);

  let initial: Uint8Array | undefined;
  try {
    initial = readFileSync('/proc/self/environ');
  } catch {
    initial = undefined;
  }
  linuxVerifyEnvironment(linuxReadEnvironment(process.env, initial), (p, expected) => {
    linuxResolveTrusted(p, expected, linuxStatus, linuxReadLink, true);
  });

  let handle;
  try {
    handle = native.load(path);
  } catch (error) {
    throw new UntrustedError(`'${path}' passed verification but could not be loaded: ${(error as Error).message}`, { cause: error });
  }
  try {
    const loaded = native.symbolImagePath!(handle, PROBE_EXPORT);
    linuxVerifyLoadedImage(path, loaded === null ? null : linuxTrustedFile(loaded));
    linuxVerifyDependencies(path, elfReadNeededFile, (soname) => native.loadedPath!(soname), linuxTrustedFile);
    return NativeKmsLibrary.bind(native, handle, path, 'hkdfguard_harden_process', linuxStatusDescriptions);
  } catch (error) {
    native.unload(handle);
    throw error;
  }
}

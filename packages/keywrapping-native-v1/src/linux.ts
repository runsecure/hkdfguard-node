import { spawnSync } from 'node:child_process';
import { lstatSync, readFileSync, readlinkSync } from 'node:fs';
import { errnoOf, unixProbe } from './darwin.js';
import { elfReadInterpreterFile, elfReadNeededFile } from './elf.js';
import { UntrustedError } from './errors.js';
import { NativeKmsLibrary } from './library.js';
import {
  linuxCandidatePaths, linuxChoosePath, linuxListingEnvironment, linuxParseListing, linuxReadEnvironment, linuxResolveTrusted,
  linuxVerifyDependencies, linuxVerifyEnvironment, linuxVerifyListing, linuxVerifyLoadedImage,
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

/** Bounds the dynamic linker's list run, in milliseconds: it only maps files and reads headers. */
const LINUX_LISTING_TIMEOUT_MS = 30_000;
/** Bounds what the list run may print; a real listing is a few kilobytes. */
const LINUX_LISTING_MAX_BYTES = 1 << 20;

/**
 * Runs `interpreter --list library` - never through a shell - with exactly `environment`, and
 * returns what it printed. A run that fails, is killed or times out refuses the load.
 */
export function linuxListDependencies(interpreter: string, library: string, environment: Readonly<Record<string, string>>): string {
  const result = spawnSync(interpreter, ['--list', library], {
    env: { ...environment }, // never undefined, which would mean "inherit this process's environment"
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    encoding: 'utf8',
    timeout: LINUX_LISTING_TIMEOUT_MS,
    killSignal: 'SIGKILL',
    maxBuffer: LINUX_LISTING_MAX_BYTES,
    windowsHide: true,
  });
  if ((result.error as NodeJS.ErrnoException | undefined)?.code === 'ETIMEDOUT') {
    throw new UntrustedError(`The dynamic linker did not say within ${LINUX_LISTING_TIMEOUT_MS / 1000} s what '${library}' would load; refusing to load it.`, { cause: result.error });
  }
  if (result.error !== undefined || result.status !== 0) {
    const how = result.error !== undefined ? result.error.message : result.signal !== null ? `killed by ${result.signal}` : `exit status ${result.status}`;
    throw new UntrustedError(`The dynamic linker could not say what '${library}' would load (${how}: ${(result.stderr ?? '').trim()}); refusing to load it.`, { cause: result.error });
  }
  return result.stdout;
}

/**
 * Asks this process's own dynamic linker, in list mode, where it would find everything `library`
 * pulls in, and requires each of those files to pass the path checks - before dlopen, so nothing
 * that would fail them ever runs here (see linuxpolicy.ts, check 4). `initialEnvironment` is
 * /proc/self/environ's block.
 */
export function linuxVerifyBeforeLoading(library: string, initialEnvironment: Uint8Array | undefined): void {
  let interpreter: string | undefined;
  try {
    interpreter = elfReadInterpreterFile('/proc/self/exe');
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new UntrustedError(`Could not read which dynamic linker this process runs under: ${reason}`, { cause: error });
  }
  if (interpreter === undefined) {
    throw new UntrustedError(`This process has no dynamic linker (a statically linked executable), so it can't be asked what '${library}' would load; refusing to load it.`);
  }
  let trustedInterpreter: string;
  try {
    trustedInterpreter = linuxTrustedFile(interpreter);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new UntrustedError(`This process's dynamic linker '${interpreter}' is not trusted, so it can't be asked what '${library}' would load: ${reason}`, { cause: error });
  }

  const output = linuxListDependencies(trustedInterpreter, library, linuxListingEnvironment(initialEnvironment));
  linuxVerifyListing(library, linuxParseListing(library, output), linuxTrustedFile);
}

/** Verifies and loads the Linux native KMS library (see linuxpolicy.ts). */
export function loadLinuxLibrary(): NativeKmsLibrary {
  const native = nativeAddon();
  const path = linuxTrustedFile(linuxChoosePath(linuxCandidatePaths(process.arch), unixProbe));

  let initial: Uint8Array | undefined;
  try {
    initial = readFileSync('/proc/self/environ');
  } catch {
    initial = undefined;
  }
  linuxVerifyEnvironment(linuxReadEnvironment(process.env, initial), (p, expected) => {
    linuxResolveTrusted(p, expected, linuxStatus, linuxReadLink, true);
  });
  linuxVerifyBeforeLoading(path, initial);

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
    return NativeKmsLibrary.bind(native, handle, path, linuxStatusDescriptions);
  } catch (error) {
    native.unload(handle);
    throw error;
  }
}

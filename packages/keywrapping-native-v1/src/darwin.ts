import { existsSync, lstatSync } from 'node:fs';
import { constants, homedir } from 'node:os';
import { UntrustedError } from './errors.js';
import { NativeKmsLibrary } from './library.js';
import {
  macChoosePath, macRefuseShadowing, macRequireSupportedPlatform, macVerifyLoadedImage, macVerifyLocation, macVerifySignature, PROBE_EXPORT,
} from './macpolicy.js';
import { nativeAddon } from './native.js';
import { macStatusDescriptions } from './status.js';
import { statusFromMode, type FileStatus } from './unixpath.js';

/** lstat's errno for a path whose existence is only being probed; 0 if it exists. */
export function unixProbe(path: string): number {
  try {
    lstatSync(path);
    return 0;
  } catch (error) {
    return errnoOf(error);
  }
}

/** The positive errno a failed fs call reported, or -1 when it carries none. */
export function errnoOf(error: unknown): number {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  return (code !== undefined ? (constants.errno as Record<string, number>)[code] : undefined) ?? -1;
}

function lstatStatus(path: string): FileStatus {
  try {
    const stat = lstatSync(path);
    return statusFromMode(stat.uid, stat.gid, stat.mode);
  } catch (error) {
    throw new UntrustedError(`lstat('${path}') failed with errno ${errnoOf(error)}.`, { cause: error });
  }
}

/** Verifies and loads the macOS native KMS library (see macpolicy.ts). */
export function loadDarwinLibrary(): NativeKmsLibrary {
  const native = nativeAddon();
  macRequireSupportedPlatform(process.arch, native.productVersion!());

  const { path, isSystem } = macChoosePath(unixProbe, homedir());
  macVerifyLocation(path, lstatStatus, isSystem ? [0] : [0, process.geteuid!()]);
  macVerifySignature(path, native.checkCodeSignature!);
  macRefuseShadowing((name) => process.env[name], existsSync);

  // dyld may still map a different file than the path asks for, so the loaded image is checked and,
  // if it isn't the verified file, unloaded. The library's own dependencies are absolute system paths.
  let handle;
  try {
    handle = native.load(path);
  } catch (error) {
    throw new UntrustedError(`'${path}' passed verification but could not be loaded: ${(error as Error).message}`, { cause: error });
  }
  try {
    macVerifyLoadedImage(path, native.symbolImagePath!(handle, PROBE_EXPORT));
    return NativeKmsLibrary.bind(native, handle, path, macStatusDescriptions);
  } catch (error) {
    native.unload(handle);
    throw error;
  }
}

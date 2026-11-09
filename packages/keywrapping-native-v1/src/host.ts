import { HkdfGuardError } from '@runsecure/hkdfguard-abstractions';
import { classify, UnsupportedPlatformError } from './errors.js';
import type { KmsLibrary } from './library.js';

function loadPlatformLibrary(): KmsLibrary {
  // Each loader is required only on its own platform.
  /* eslint-disable @typescript-eslint/no-require-imports */
  switch (process.platform) {
    case 'darwin': return (require('./darwin.js') as typeof import('./darwin.js')).loadDarwinLibrary(userInstallAllowed);
    case 'linux': return (require('./linux.js') as typeof import('./linux.js')).loadLinuxLibrary();
    case 'win32': return (require('./windows.js') as typeof import('./windows.js')).loadWindowsLibrary();
    default: throw new UnsupportedPlatformError(`There is no HkdfGuard native KMS library for ${process.platform}/${process.arch}.`);
  }
  /* eslint-enable @typescript-eslint/no-require-imports */
}

let loaded: KmsLibrary | undefined;
let loader: () => KmsLibrary = loadPlatformLibrary;
let userInstallAllowed = false;

/**
 * Lets the macOS loader use the per-user install, ~/.hkdfguard/v1, when there is no system-wide
 * one - see the package's allowMacUserInstall. Once the library is loaded, which install it came
 * from is settled: a call then that would have changed nothing does nothing, and one that would
 * have is refused, rather than looking as if it took effect.
 * @throws HkdfGuardError (ERR_HKDFGUARD_INVALID_STATE) the library is already loaded, and the per-user install wasn't allowed
 */
export function allowMacUserInstall(): void {
  if (userInstallAllowed) return;
  if (loaded !== undefined) {
    throw new HkdfGuardError('ERR_HKDFGUARD_INVALID_STATE', 'The HkdfGuard native library is already loaded: call allowMacUserInstall() '
      + 'before the first NativeKeyWrapperV1.create or hardenProcess.');
  }
  userInstallAllowed = true;
}

/**
 * Verifies and loads the current OS's native KMS library once per process, returning the same
 * binding every later call. A failure isn't cached, so a fixed installation is picked up next time.
 */
export function hostLibrary(): KmsLibrary {
  if (loaded === undefined) {
    try {
      loaded = loader();
    } catch (error) {
      throw classify(error);
    }
  }
  return loaded;
}

/** @internal Replaces the platform loader, starting from nothing loaded; returns a function restoring it. */
export function swapLoaderForTesting(replacement: () => KmsLibrary): () => void {
  const previous = { loaded, loader, userInstallAllowed };
  loaded = undefined;
  loader = replacement;
  userInstallAllowed = false;
  return () => {
    loaded = previous.loaded;
    loader = previous.loader;
    userInstallAllowed = previous.userInstallAllowed;
  };
}

/** @internal Whether the per-user install is allowed, for the tests. */
export function isMacUserInstallAllowedForTesting(): boolean {
  return userInstallAllowed;
}

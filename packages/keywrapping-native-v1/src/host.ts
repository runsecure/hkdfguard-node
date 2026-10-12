import { classify, UnsupportedPlatformError } from './errors.js';
import type { KmsLibrary } from './library.js';

function loadPlatformLibrary(): KmsLibrary {
  // Each loader is required only on its own platform.
  /* eslint-disable @typescript-eslint/no-require-imports */
  switch (process.platform) {
    case 'darwin': return (require('./darwin.js') as typeof import('./darwin.js')).loadDarwinLibrary();
    case 'linux': return (require('./linux.js') as typeof import('./linux.js')).loadLinuxLibrary();
    case 'win32': return (require('./windows.js') as typeof import('./windows.js')).loadWindowsLibrary();
    default: throw new UnsupportedPlatformError(`There is no HkdfGuard native KMS library for ${process.platform}/${process.arch}.`);
  }
  /* eslint-enable @typescript-eslint/no-require-imports */
}

let loaded: KmsLibrary | undefined;
let loader: () => KmsLibrary = loadPlatformLibrary;

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
  const previous = { loaded, loader };
  loaded = undefined;
  loader = replacement;
  return () => {
    loaded = previous.loaded;
    loader = previous.loader;
  };
}

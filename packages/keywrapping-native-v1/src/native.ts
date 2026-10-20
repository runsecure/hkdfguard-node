import { UnsupportedPlatformError } from './errors.js';

/** An opaque handle to a library the add-on mapped. */
export type LibraryHandle = { readonly __brand: 'hkdfguard-native-library' };

/** What native/hkdfguard_native.c exports; the platform-specific members exist only on their platform. */
export interface NativeAddon {
  load(path: string): LibraryHandle;
  unload(library: LibraryHandle): void;
  /** Resolves the KMS exports (every one required, on every platform), returning the names of any that are missing. */
  bind(library: LibraryHandle): string[];
  wrapDek(library: LibraryHandle, service: string, input: Uint8Array, output: Uint8Array): Promise<[number, number]>;
  unwrapDek(library: LibraryHandle, service: string, input: Uint8Array, output: Uint8Array): Promise<[number, number]>;
  generateAndWrapDek(library: LibraryHandle, service: string, output: Uint8Array): Promise<[number, number]>;
  openFile(library: LibraryHandle, path: string, output: Uint8Array): Promise<[number, number]>;
  /** hkdfguard_harden_process_with_flags(flags): its status. */
  hardenProcess(library: LibraryHandle, flags: number): number;
  kekExists(library: LibraryHandle, service: string): [number, boolean] | null;
  symbolImagePath?(library: LibraryHandle, symbol: string): string | null;
  loadedPath?(soname: string): string | null;
  checkCodeSignature?(path: string, requirement: string): number;
  productVersion?(): string;
  programFilesPath?(): string;
  fileAttributes?(path: string): number;
  securityDescriptor?(path: string): { owner: string; daclAbsent: boolean; aces: { type: number; flags: number; mask: number; sid: string }[] };
  describeSid?(sid: string): string;
  verifiedSigner?(path: string): { subject: string; ekus: string[]; rootCertificate: Uint8Array } | { status: number } | { error: string };
}

let addon: NativeAddon | undefined;

/**
 * The compiled add-on, loaded on first use. It is built from this package's own C source by
 * node-gyp at install time; a build that failed (no C toolchain) is reported here.
 */
export function nativeAddon(): NativeAddon {
  if (addon === undefined) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      addon = require('../build/Release/hkdfguard_native.node') as NativeAddon;
    } catch (error) {
      throw new UnsupportedPlatformError(
        'The native add-on of @runsecure/hkdfguard-keywrapping-native-v1 is not built. It is compiled at install by node-gyp, which needs Python 3 and a C compiler (Visual Studio Build Tools on Windows); install them and run "npm rebuild @runsecure/hkdfguard-keywrapping-native-v1".',
        { cause: error });
    }
  }
  return addon;
}

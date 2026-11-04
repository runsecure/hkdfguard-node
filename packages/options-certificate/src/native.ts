import { UnsupportedCertificateError } from './errors.js';

/** An opaque handle the add-on holds an operating system object behind. */
export type NativeHandle = { readonly __brand: 'hkdfguard-certificate-handle' };

/** A store call's failure: a JS Error with the call's status. */
export interface NativeStatusError extends Error {
  status?: number;
}

/** What native/hkdfguard_certificate.c exports; the platform-specific members exist only on their platform. */
export interface CertificateAddon {
  releaseKey(key: NativeHandle): void;
  windowsReadStore?(location: 1 | 2, name: string): { der: Buffer; hasPrivateKey: boolean; handle: NativeHandle }[] | null;
  windowsFreeCertificate?(handle: NativeHandle): void;
  windowsOpenKey?(handle: NativeHandle): NativeHandle | { error: 'acquire'; status: number } | { error: 'not-cng' };
  windowsSign?(key: NativeHandle, digest: Uint8Array, hash: number, padding: 0 | 1 | 2, saltLength: number): Promise<Buffer>;
  windowsDecrypt?(key: NativeHandle, ciphertext: Uint8Array, padding: 1 | 2, hash: number, label: Uint8Array): Promise<Buffer>;
  macReadKeychain?(location: 1 | 2): { identities: { der: Buffer; handle: NativeHandle }[]; certificates: Buffer[] } | null;
  macReleaseIdentity?(identity: NativeHandle): void;
  macOpenKey?(identity: NativeHandle): NativeHandle | { error: 'copy'; status: number; message: string };
  macSign?(key: NativeHandle, digest: Uint8Array, algorithm: number): Promise<Buffer>;
  macDecrypt?(key: NativeHandle, ciphertext: Uint8Array, algorithm: number): Promise<Buffer>;
}

let addon: CertificateAddon | undefined;

/**
 * The compiled add-on, loaded on first use of a store. It is built from this package's own C source
 * by node-gyp at install time on Windows and macOS; a build that failed (no C toolchain) is reported here.
 */
export function certificateAddon(): CertificateAddon {
  if (addon === undefined) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      addon = require('../build/Release/hkdfguard_certificate.node') as CertificateAddon;
    } catch (error) {
      throw new UnsupportedCertificateError(
        'The native add-on of @runsecure/hkdfguard-options-certificate, which reads the Windows certificate store and the macOS keychains, '
        + 'is not built. It is compiled at install by node-gyp, which needs Python 3 and a C compiler (Visual Studio Build Tools on Windows, '
        + 'the Xcode command line tools on macOS); install them and run "npm rebuild @runsecure/hkdfguard-options-certificate".',
        { cause: error });
    }
  }
  return addon;
}

/** Whether `value` is a handle the add-on returned, rather than one of its { error } results. */
export function isHandle(value: unknown): value is NativeHandle {
  return typeof value === 'object' && value !== null && !('error' in value);
}

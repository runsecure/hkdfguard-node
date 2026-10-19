import { InvalidArgumentError, MAX_WRAPPED_KEY_BYTES } from '@runsecure/hkdfguard-abstractions';
import { KeyFileRefusedError, UnsupportedPlatformError, UntrustedError } from './errors.js';
import type { LibraryHandle, NativeAddon } from './native.js';
import { Status } from './status.js';

/**
 * One platform's native HkdfGuard KMS library: hkdfguard_wrap_dek, hkdfguard_unwrap_dek,
 * hkdfguard_generate_and_wrap_dek and hkdfguard_open_file, identical in shape across platforms, as
 * are their status codes (see Status). Each call resolves to [status, written]; on a
 * buffer-too-small failure, written is the capacity needed.
 */
export interface KmsLibrary {
  wrapDek(service: string, dek: Uint8Array, output: Uint8Array): Promise<[number, number]>;
  unwrapDek(service: string, wrapped: Uint8Array, output: Uint8Array): Promise<[number, number]>;
  generateAndWrapDek(service: string, output: Uint8Array): Promise<[number, number]>;
  /**
   * hkdfguard_open_file: reads the key file at `path` into `output` still wrapped - it never unwraps
   * or touches a KEK - after the library's checks on the file's path, owner, permissions, size and
   * contents. Resolves to [status, bytes read]. Use {@link openKeyFile} rather than calling it directly.
   */
  openFile(path: string, output: Uint8Array): Promise<[number, number]>;
  /** What a non-zero status means on this platform, or undefined if unknown. */
  describeStatus(status: number): string | undefined;
  /** The process-hardening status. @throws UnsupportedPlatformError off Linux. */
  hardenProcess(): number;
}

/**
 * Reads a key file through the library's hkdfguard_open_file, returning exactly the bytes read -
 * still wrapped, ready for unwrap. The library refuses a file whose path, owner or permissions mean
 * another account could have replaced it, and one holding what looks like an unwrapped key - checks
 * only the platform can make - as well as one of the wrong size or format.
 *
 * @throws InvalidArgumentError for an empty path, before any native call.
 * @throws KeyFileRefusedError for any refusal: its `code` is 'ENOENT', 'EACCES', 'EIO',
 *   ERR_HKDFGUARD_INVALID_KEY_FILE or ERR_HKDFGUARD_INVALID_ARGUMENT, and its message names the
 *   path, the native status and what it means.
 */
export async function openKeyFile(library: KmsLibrary, path: string): Promise<Uint8Array> {
  if (typeof path !== 'string' || path === '') throw new InvalidArgumentError('A key file path is required.');
  // Every platform's wrapped DEK (Windows 132, Linux 276, macOS 125 bytes) fits in
  // MAX_WRAPPED_KEY_BYTES, so one buffer never needs the size probe.
  const buffer = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
  const [status, read] = await library.openFile(path, buffer);
  if (status !== Status.ok) throw new KeyFileRefusedError(path, status, library.describeStatus(status));
  if (!Number.isInteger(read) || read <= 0 || read > buffer.length) {
    throw new InvalidArgumentError(`Native KMS open-file for '${path}' reported ${read} bytes read into a ${buffer.length}-byte buffer.`);
  }
  return buffer.slice(0, read);
}

export const NO_HARDENING = 'The HkdfGuard native KMS library on this platform has no process hardening call; it is available on Linux only.';

/** A verified, loaded library, called through the add-on. */
export class NativeKmsLibrary implements KmsLibrary {
  private constructor(
    private readonly native: NativeAddon,
    private readonly handle: LibraryHandle,
    private readonly descriptions: ReadonlyMap<number, string>,
  ) {}

  /**
   * Binds the KMS exports of a loaded, verified library - every platform's has the three DEK calls;
   * `hardenSymbol` is null where there is no hardening call.
   */
  static bind(native: NativeAddon, handle: LibraryHandle, path: string, hardenSymbol: string | null, descriptions: ReadonlyMap<number, string>): NativeKmsLibrary {
    const missing = native.bind(handle, hardenSymbol);
    if (missing.length > 0) {
      throw new UntrustedError(`'${path}' has no '${missing[0]}' export; it is not the HkdfGuard native library.`);
    }
    return new NativeKmsLibrary(native, handle, descriptions);
  }

  wrapDek(service: string, dek: Uint8Array, output: Uint8Array): Promise<[number, number]> {
    return this.native.wrapDek(this.handle, service, dek, output);
  }

  unwrapDek(service: string, wrapped: Uint8Array, output: Uint8Array): Promise<[number, number]> {
    return this.native.unwrapDek(this.handle, service, wrapped, output);
  }

  generateAndWrapDek(service: string, output: Uint8Array): Promise<[number, number]> {
    return this.native.generateAndWrapDek(this.handle, service, output);
  }

  openFile(path: string, output: Uint8Array): Promise<[number, number]> {
    return this.native.openFile(this.handle, path, output);
  }

  describeStatus(status: number): string | undefined {
    return this.descriptions.get(status);
  }

  hardenProcess(): number {
    const status = this.native.hardenProcess(this.handle);
    if (status === null) throw new UnsupportedPlatformError(NO_HARDENING);
    return status;
  }

  /** hkdfguard_kek_exists: [status, exists], or undefined when the library has no such export. @internal For the tests. */
  kekExists(service: string): [number, boolean] | undefined {
    return this.native.kekExists(this.handle, service) ?? undefined;
  }
}

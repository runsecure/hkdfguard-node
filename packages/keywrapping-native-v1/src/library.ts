import { UnsupportedPlatformError, UntrustedError } from './errors.js';
import type { LibraryHandle, NativeAddon } from './native.js';

/**
 * One platform's native HkdfGuard KMS library: hkdfguard_wrap_dek, hkdfguard_unwrap_dek and
 * hkdfguard_generate_and_wrap_dek, identical in shape across platforms, though each library's
 * negative status codes mean different things. Each call resolves to [status, written]; on a
 * buffer-too-small failure, written is the capacity needed.
 */
export interface KmsLibrary {
  wrapDek(service: string, dek: Uint8Array, output: Uint8Array): Promise<[number, number]>;
  unwrapDek(service: string, wrapped: Uint8Array, output: Uint8Array): Promise<[number, number]>;
  generateAndWrapDek(service: string, output: Uint8Array): Promise<[number, number]>;
  /** What a non-zero status means on this platform, or undefined if unknown. */
  describeStatus(status: number): string | undefined;
  /** The process-hardening status. @throws UnsupportedPlatformError off Linux. */
  hardenProcess(): number;
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

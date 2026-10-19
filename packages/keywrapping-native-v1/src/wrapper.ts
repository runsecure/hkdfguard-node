import { InvalidArgumentError, validateServiceName, wipe, type KeyWrapper } from '@runsecure/hkdfguard-abstractions';
import { StatusError } from './errors.js';
import { hostLibrary } from './host.js';
import { openKeyFile, type KmsLibrary } from './library.js';

/** The length, in bytes, of every DEK the native library wraps and unwraps. */
export const DEK_LENGTH = 32;

const INT32_MAX = 2 ** 31 - 1;

/**
 * A {@link KeyWrapper} over the current OS's native HkdfGuard KMS library, under the KEK its service
 * name identifies - a TPM2, Secure Enclave or Platform Crypto Provider key held entirely outside
 * this process. Since unwrap takes its payload as an argument, one wrapper handles both directions
 * and any number of payloads sharing the same service. The native ABI has no AAD.
 *
 * Native calls run on libuv's thread pool, so the event loop is never blocked by a TPM. The signal
 * is checked before each call; a call that has started runs to completion. The native library works
 * on the add-on's own copies of both buffers, zeroed afterwards, and the result is copied into
 * `result` on the main thread as the call settles - so no other thread ever holds a pointer into a
 * JavaScript buffer. A result buffer detached or shrunk meanwhile fails the call.
 */
export class NativeKeyWrapperV1 implements KeyWrapper {
  private constructor(
    /** The service name identifying this wrapper's KEK. */
    readonly serviceName: string,
    private readonly library: KmsLibrary,
  ) {}

  /**
   * A wrapper for the KEK `serviceName` identifies - 1 to 128 ASCII letters, digits or '.', not
   * starting with '.' and without "..". The name is checked first, so a bad one never reaches native
   * code. The first call in a process verifies and loads the native library; a failure
   * (NotInstalledError, UntrustedError or UnsupportedPlatformError) isn't cached, so a fixed
   * installation is picked up by the next call.
   */
  static create(serviceName: string): NativeKeyWrapperV1 {
    validateServiceName(serviceName);
    return new NativeKeyWrapperV1(serviceName, hostLibrary());
  }

  /** @internal A wrapper over a given library binding - the tests' fakes. */
  static withLibrary(serviceName: string, library: KmsLibrary): NativeKeyWrapperV1 {
    validateServiceName(serviceName);
    return new NativeKeyWrapperV1(serviceName, library);
  }

  /** Wraps a DEK_LENGTH-byte key under this service's KEK; MAX_WRAPPED_KEY_BYTES is always room enough. */
  async wrap(plaintext: Uint8Array, result: Uint8Array, signal?: AbortSignal): Promise<number> {
    checkCall(signal, plaintext, result);
    const [status, written] = await this.library.wrapDek(this.serviceName, plaintext, result);
    return this.complete('wrap', status, written, result);
  }

  /** Reveals the DEK in `wrapped`, which must have been wrapped under this service. On any failure `result` is zeroed. */
  async unwrap(wrapped: Uint8Array, result: Uint8Array, signal?: AbortSignal): Promise<number> {
    checkCall(signal, wrapped, result);
    try {
      const [status, written] = await this.library.unwrapDek(this.serviceName, wrapped, result);
      return this.complete('unwrap', status, written, result);
    } catch (error) {
      wipe(result);
      throw error;
    }
  }

  /** Generates a fresh DEK inside the native library and wraps it; the plaintext DEK never reaches this process. */
  async generateAndWrap(result: Uint8Array, signal?: AbortSignal): Promise<number> {
    checkCall(signal, undefined, result);
    const [status, written] = await this.library.generateAndWrapDek(this.serviceName, result);
    return this.complete('generate-and-wrap', status, written, result);
  }

  /**
   * Reads a key file through the native library's hkdfguard_open_file rather than Node's file I/O,
   * resolving to its bytes still wrapped, ready for unwrap - buildKeyRing reads every key file this
   * way. Besides the size and format checks, the native library refuses a file another account could
   * have written or replaced - its path, owner and permissions are checked the way only the platform
   * can - and one holding what looks like an unwrapped key.
   *
   * @throws InvalidArgumentError for an empty path, before any native call.
   * @throws KeyFileRefusedError when the library refuses the file: `code` is 'ENOENT' (the file or a
   *   folder in its path does not exist), 'EACCES' (this account may not read it, or its path is not
   *   trusted), ERR_HKDFGUARD_INVALID_KEY_FILE (the wrong size, what looks like an unwrapped key, or
   *   not a wrapped DEK) or 'EIO'; `status` is the native status.
   */
  async readKeyFile(path: string, signal?: AbortSignal): Promise<Uint8Array> {
    signal?.throwIfAborted();
    return openKeyFile(this.library, path);
  }

  /** A native status as a byte count or a StatusError; a success claiming more than `result` holds is refused. */
  private complete(operation: string, status: number, written: number, result: Uint8Array): number {
    if (status !== 0) {
      throw new StatusError(operation, this.serviceName, status, this.library.describeStatus(status));
    }
    if (!Number.isInteger(written) || written < 0 || written > result.length) {
      throw new InvalidArgumentError(`Native KMS ${operation} for service '${this.serviceName}' reported ${written} bytes written into a ${result.length}-byte buffer.`);
    }
    return written;
  }
}

function checkCall(signal: AbortSignal | undefined, input: Uint8Array | undefined, result: Uint8Array): void {
  signal?.throwIfAborted();
  if ((input?.length ?? 0) > INT32_MAX || result.length > INT32_MAX) {
    throw new InvalidArgumentError(`A buffer is longer than ${INT32_MAX} bytes.`);
  }
}

/**
 * Hardens the whole process through the native library, loading it if needed. DEKs pass through
 * this process's memory, so a core dump, or another process of the same user attaching a debugger,
 * could recover them. On Linux it sets the core-dump limit to zero and clears the dumpable flag.
 *
 * Opt-in because it is process-wide: debuggers and crash dumps stop working. Call it once, early,
 * after any privilege drop. It does not stop root or CAP_SYS_PTRACE, nor keep memory out of swap.
 *
 * @throws UnsupportedPlatformError off Linux.
 * @throws StatusError if the hardening failed - treat that as a reason not to start.
 */
export function hardenProcess(library: KmsLibrary = hostLibrary()): void {
  const status = library.hardenProcess();
  if (status !== 0) {
    throw new StatusError('process hardening', undefined, status, library.describeStatus(status));
  }
}

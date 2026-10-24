import { InvalidArgumentError, validateServiceName, wipe, type KeyWrapper } from '@runsecure/hkdfguard-abstractions';
import { StatusError } from './errors.js';
import { hostLibrary } from './host.js';
import { HARDEN_REQUIRE_PROTECTED_SIGNATURE, openKeyFile, type KmsLibrary } from './library.js';

/** The length, in bytes, of every DEK the native library wraps and unwraps. */
export const DEK_LENGTH = 32;

const INT32_MAX = 2 ** 31 - 1;

// Set by NativeKeyWrapperV1's static block.
let withLibrary: (serviceName: string, library: KmsLibrary) => NativeKeyWrapperV1;

/**
 * Tests only: a wrapper over a given library binding - the tests' fakes, never a verified load.
 * Exported from this module for the package's own tests, never from the package index - the
 * exports map keeps it out of reach.
 */
export function wrapperForTests(serviceName: string, library: KmsLibrary): NativeKeyWrapperV1 {
  return withLibrary(serviceName, library);
}

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

  static {
    withLibrary = (serviceName, library) => {
      validateServiceName(serviceName);
      return new NativeKeyWrapperV1(serviceName, library);
    };
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

/** How strict {@link hardenProcess} is. */
export interface ProcessHardeningOptions {
  /**
   * Fail unless no other process of the same user can attach a debugger to, or inject code into,
   * this process - what the native command-line tools themselves require. On Windows it also closes
   * everything the process creates afterwards (threads, child processes, named pipes and other
   * named objects) to its own user, so use it in a service that shares no objects with other
   * processes by name. On macOS it fails unless the host executable is signed with the Hardened
   * Runtime and without the get-task-allow or DYLD_* entitlements, so unsigned hosts (node itself)
   * can't use it. On Linux it adds nothing: the plain call already guarantees it. Default false:
   * harden as far as this process allows; on macOS a weak code signature is only logged.
   */
  readonly requireProtectedSignature?: boolean;
}

const HARDENING_OPTIONS: ReadonlySet<string> = new Set(['requireProtectedSignature']);

/**
 * Opt-in hardening of the whole process, through the native KMS library's
 * hkdfguard_harden_process_with_flags, loading the library if needed. DEKs pass through this
 * process's memory, so a crash dump, or another process of the same user attaching a debugger or
 * reading its memory, could recover them. The native library never does this on its own: it
 * changes process-wide state the application owns. What it does:
 *
 * - Windows: crash reports leave out the heap (WerSetFlags NOHEAP), and the process's and its
 *   existing threads' access lists are replaced so that only SYSTEM may read or write its memory,
 *   inject threads or duplicate its handles - the account it runs as keeps only query, synchronize
 *   and terminate. Threads started later keep the default access unless `requireProtectedSignature`
 *   is set; call it early, before starting worker threads (libuv starts its thread pool at the
 *   first asynchronous fs, crypto, dns or zlib call, or the first KMS call).
 * - Linux: the core dump limit is set to zero (hard limit included) and the process's dumpable flag
 *   is cleared, which also stops ptrace and /proc/<pid>/mem access by other processes of the same
 *   user.
 * - macOS: core dumps are disabled and debugger attachment is denied; the host executable's code
 *   signature decides whether code injection is possible, which the library can check but not
 *   change.
 *
 * It is opt-in because it is process-wide: debuggers, inspectors and crash dumps stop working for
 * the application. Call it once, early, and after any privilege drop (on Linux the kernel resets
 * the dumpable flag when a process's credentials change). It is a same-user barrier: it does not
 * stop administrators, root, SYSTEM, a process with CAP_SYS_PTRACE or SeDebugPrivilege, or the
 * kernel, and it does not keep memory out of swap, the page file or hibernation files; those are
 * host settings.
 *
 * @throws InvalidArgumentError if `options` is not an object, has an option this library doesn't
 *   define, or a value that isn't a boolean - before the native library is loaded or called.
 * @throws StatusError if the hardening failed, or the process can't meet
 *   `requireProtectedSignature` - treat that as a reason not to start.
 */
export function hardenProcess(options: ProcessHardeningOptions = {}): void {
  hardenProcessWith(options, hostLibrary);
}

/**
 * Tests only: {@link hardenProcess} through a given library binding - the tests' fakes. Exported
 * from this module for the package's own tests, never from the package index - the exports map
 * keeps it out of reach.
 */
export function hardenProcessForTests(options: ProcessHardeningOptions | undefined, library: KmsLibrary): void {
  hardenProcessWith(options === undefined ? {} : options, () => library);
}

// The library is fetched only after the options are checked, so a bad option never loads it.
function hardenProcessWith(options: ProcessHardeningOptions, library: () => KmsLibrary): void {
  // Checked here so an unknown option never reaches native code, which would refuse it anyway.
  if (typeof options !== 'object' || options === null || Array.isArray(options)) {
    throw new InvalidArgumentError('Process hardening options must be an object.');
  }
  for (const [name, value] of Object.entries(options)) {
    if (!HARDENING_OPTIONS.has(name)) throw new InvalidArgumentError(`Unknown process hardening option '${name}'.`);
    if (value !== undefined && typeof value !== 'boolean') {
      throw new InvalidArgumentError(`Process hardening option '${name}' must be a boolean.`);
    }
  }
  const flags = options.requireProtectedSignature === true ? HARDEN_REQUIRE_PROTECTED_SIGNATURE : 0;

  const kms = library();
  const status = kms.hardenProcess(flags);
  if (status !== 0) {
    throw new StatusError('process hardening', undefined, status, kms.describeStatus(status));
  }
}

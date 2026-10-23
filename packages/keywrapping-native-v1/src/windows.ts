import { createHash } from 'node:crypto';
import { closeSync, openSync, readSync, statSync } from 'node:fs';
import { win32 } from 'node:path';
import { NotInstalledError, UntrustedError } from './errors.js';
import { NativeKmsLibrary } from './library.js';
import { nativeAddon, type NativeAddon } from './native.js';
import { windowsStatusDescriptions } from './status.js';
import {
  WIN_EXPECTED_PUBLISHER, WIN_FILE_NAME, WIN_GUARDED_RIGHTS, WIN_GUARDED_ROOT_RIGHTS, winReadPeHeader, winVerifyImageKind,
  winRevocationDecision, winVerifySignerIdentity, winVerifyTrustedOnly, type WinSecurity,
} from './windowspolicy.js';

// The steps of loadWindowsLibrary are exported for the tests against the real system
// (windows.test.ts); the package's index exports none of them.

const FILE_ATTRIBUTE_REPARSE_POINT = 0x400;

function untrustedCause(error: unknown, message: string): UntrustedError {
  return new UntrustedError(`${message}: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
}

/** The one location the library is loaded from: %ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll. */
export function winInstalledPath(native: NativeAddon = nativeAddon()): string {
  return win32.join(native.programFilesPath!(), 'HkdfGuard', 'v1', WIN_FILE_NAME);
}

/** Refuses a symbolic link or junction: the library is only loaded through a real path. */
export function winVerifyNotReparsePoint(native: NativeAddon, item: string): void {
  let attributes: number;
  try {
    attributes = native.fileAttributes!(item);
  } catch (error) {
    throw untrustedCause(error, `Could not read the attributes of '${item}'`);
  }
  if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) !== 0) {
    throw new UntrustedError(`'${item}' is a symbolic link or junction; the HkdfGuard native library is only loaded through a real path.`);
  }
}

/** Checks the file and each folder below the drive root, then the drive root itself (see windowspolicy.ts). */
export function winVerifyLocation(native: NativeAddon, path: string): void {
  const describe = (sid: string) => native.describeSid!(sid);
  let item = win32.resolve(path);
  for (;;) {
    const parent = win32.dirname(item);
    let security: WinSecurity;
    try {
      security = native.securityDescriptor!(item);
    } catch (error) {
      throw untrustedCause(error, `Could not read the security descriptor of '${item}'`);
    }

    if (parent === item) {
      winVerifyTrustedOnly(security, item, WIN_GUARDED_ROOT_RIGHTS, describe);
      return;
    }

    winVerifyNotReparsePoint(native, item);
    winVerifyTrustedOnly(security, item, WIN_GUARDED_RIGHTS, describe);
    item = parent;
  }
}

/** Requires a valid Authenticode signature from `expectedPublisher`, under the pinned root and profile. */
export function winVerifySignature(native: NativeAddon, path: string, expectedPublisher: string): void {
  const signer = native.verifiedSigner!(path);
  if ('status' in signer) {
    throw new UntrustedError(`'${path}' does not carry a valid, trusted Authenticode signature (WinVerifyTrust status 0x${(signer.status >>> 0).toString(16).toUpperCase().padStart(8, '0')}).`);
  }
  if ('error' in signer) {
    throw new UntrustedError(`Could not read the Authenticode signer of '${path}' (${signer.error}); refusing to load it.`);
  }
  const rootSha256 = createHash('sha256').update(signer.rootCertificate).digest('hex').toUpperCase();
  winVerifySignerIdentity(path, signer.subject, signer.ekus, rootSha256, expectedPublisher);
}

/** Requires a DLL for this process's architecture. */
export function winVerifyImageKindOf(path: string): void {
  const fd = openSync(path, 'r');
  try {
    const head = new Uint8Array(64 * 1024);
    const length = readSync(fd, head, 0, head.length, 0);
    const { machine, characteristics } = winReadPeHeader(path, head.subarray(0, length));
    winVerifyImageKind(path, characteristics, machine, process.arch);
  } finally {
    closeSync(fd);
  }
}

/** Verifies and loads the library at `path`, signed by `expectedPublisher`; the loader passes only the installed path. */
export function winLoadFrom(native: NativeAddon, path: string, expectedPublisher: string): NativeKmsLibrary {
  let isFile = false;
  try {
    isFile = statSync(path).isFile();
  } catch {
    isFile = false;
  }
  if (!isFile) {
    throw new NotInstalledError(`The HkdfGuard native KMS library is not installed at '${path}'. Install it there; it is never loaded from anywhere else.`);
  }

  winVerifyLocation(native, path);
  winVerifySignature(native, path, expectedPublisher);
  winVerifyImageKindOf(path);
  // A second, separate pass, now checking revocation (network allowed); only a definite revocation refuses.
  winRevocationDecision(path, native.revocationStatus!(path));

  // Absolute path, so no probing for the library itself; its own imports come from System32 only.
  let handle;
  try {
    handle = native.load(path);
  } catch (error) {
    throw untrustedCause(error, `'${path}' passed verification but could not be loaded`);
  }
  try {
    return NativeKmsLibrary.bind(native, handle, path, windowsStatusDescriptions);
  } catch (error) {
    native.unload(handle);
    throw error;
  }
}

/** Verifies and loads the Windows native KMS library from %ProgramFiles%\HkdfGuard\v1. */
export function loadWindowsLibrary(): NativeKmsLibrary {
  const native = nativeAddon();
  return winLoadFrom(native, winInstalledPath(native), WIN_EXPECTED_PUBLISHER);
}

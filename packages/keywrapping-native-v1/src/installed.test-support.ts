import { execFileSync } from 'node:child_process';
import { randomFillSync } from 'node:crypto';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import type { TestContext } from 'node:test';
import { MAX_WRAPPED_KEY_BYTES } from '@runsecure/hkdfguard-abstractions';
import { NotInstalledError, UnsupportedPlatformError } from './errors.js';
import { hostLibrary } from './host.js';
import { NativeKmsLibrary, type KmsLibrary } from './library.js';
import { linuxCandidatePaths } from './linuxpolicy.js';
import { macChoosePath } from './macpolicy.js';
import { Status } from './status.js';
import { DEK_LENGTH, NativeKeyWrapperV1 } from './wrapper.js';
import { DEFAULT_TEST_SERVICES, TEST_OTHER_SERVICE_VARIABLE, TEST_SERVICE_VARIABLE, UNPROVISIONED_SERVICE_NAME } from './testservices.test-support.js';

/*
 * How the tests against this platform's installed native KMS library are gated - shared by
 * native.test.ts, linux.test.ts and windows.test.ts. Not part of the package.
 *
 * - Without the library installed, a test needing it is skipped.
 * - The round trips run against a provisioned service: HKDFGUARD_TEST_SERVICE when set, otherwise
 *   the default test service the platform's script under scripts/ provisions - found by the tests
 *   themselves on Windows (the library's hkdfguard_kek_exists) and macOS (the provisioning tool),
 *   and named by the variables the Linux script prints. Without one they are skipped.
 * - A library that is installed but fails verification fails the run, never skips it.
 *
 * macOS: in the library's legacy keychain mode the KEK's access list names the binary that created
 * it, so the first call from another binary - node - is answered with a keychain dialog in a
 * logged-in session (click "Always Allow"), or KEK access denied (-18) without one.
 */

const NATIVE_CALL_TIMEOUT_MS = 60_000;

/** The installed library, verified and loaded; skips the test (returning undefined) when there is none here. */
export function installedLibrary(t: TestContext): KmsLibrary | undefined {
  try {
    return hostLibrary();
  } catch (error) {
    if (error instanceof NotInstalledError || error instanceof UnsupportedPlatformError) {
      t.skip(`the native library is not installed: ${error.message}`);
      return undefined;
    }
    throw error;
  }
}

/** Where the libhkdfguard1 package installed the Linux library, or undefined when it isn't installed (or not on Linux). */
export function installedLinuxLibraryPath(): string | undefined {
  if (process.platform !== 'linux') return undefined;
  try {
    return linuxCandidatePaths(process.arch).find((path) => existsSync(path));
  } catch {
    return undefined; // no package for this architecture
  }
}

/** The hkdfguard-v1-initialize installed beside the library the macOS loader would choose. */
export function macProvisioningTool(): string | undefined {
  try {
    const { path } = macChoosePath((p) => (existsSync(p) ? 0 : 2), homedir());
    const tool = join(dirname(path), 'hkdfguard-v1-initialize');
    return existsSync(tool) ? tool : undefined;
  } catch {
    return undefined;
  }
}

/** Whether the platform default test service is provisioned, without prompting; undefined when it can't tell. */
export function defaultServiceProvisioned(library: KmsLibrary, service: string): { provisioned: boolean; reason?: string } | undefined {
  if (process.platform === 'darwin') {
    // The tool created the KEK, so it is on the keychain item's access list and never prompts.
    const tool = macProvisioningTool();
    if (tool === undefined) return undefined;
    try {
      const status = execFileSync(tool, ['status', '--service-name', service], { encoding: 'utf8' });
      if (status.includes('kek: present')) return { provisioned: true };
      if (status.includes('kek: absent')) return { provisioned: false, reason: `The test KEK '${service}' is not provisioned. Run scripts/provision-macos-test-key.sh, or set ${TEST_SERVICE_VARIABLE} to a provisioned service.` };
    } catch {
      return undefined;
    }
    return undefined;
  }
  if (process.platform === 'win32' && library instanceof NativeKmsLibrary) {
    const answer = library.kekExists(service);
    if (answer === undefined) return undefined;
    const [status, exists] = answer;
    if (status === Status.ok) return exists ? { provisioned: true } : { provisioned: false, reason: `The test KEK '${service}' is not provisioned. Run scripts/provision-windows-test-key.ps1 from an elevated PowerShell, or set ${TEST_SERVICE_VARIABLE} to a provisioned service.` };
    if (status === Status.kekNotFound) return { provisioned: false, reason: `The test KEK '${service}' is not provisioned. Run scripts/provision-windows-test-key.ps1 from an elevated PowerShell.` };
    if (status === Status.kekAccessDenied) return { provisioned: false, reason: `The test KEK '${service}' exists, but this account may not use it. Add it to the HkdfGuardUsers group (then sign out and in), or run the tests elevated.` };
    return undefined;
  }
  return { provisioned: false, reason: `Set ${TEST_SERVICE_VARIABLE} (scripts/provision-linux-test-key.sh prints the command) to run the native round trips.` };
}

let resolved: { service?: string; skipReason?: string } | undefined;
let accessChecked: Promise<void> | undefined;

/** The test service, chosen once per process (see defaultServiceProvisioned), or undefined with the reason why not. */
export function testService(library: KmsLibrary): { service?: string; skipReason?: string } {
  resolved ??= (() => {
    const named = process.env[TEST_SERVICE_VARIABLE];
    if (named) return { service: named };
    const service = DEFAULT_TEST_SERVICES[process.platform]!;
    const answer = defaultServiceProvisioned(library, service);
    // Can't tell: run the tests, so a real failure is reported rather than hidden.
    return answer === undefined || answer.provisioned ? { service } : { skipReason: answer.reason };
  })();
  return resolved;
}

/** A wrapper for the test service; skips the test when there is no library or no service. */
export async function provisionedWrapper(t: TestContext): Promise<NativeKeyWrapperV1 | undefined> {
  const library = installedLibrary(t);
  if (library === undefined) return undefined;
  const { service, skipReason } = testService(library);
  if (service === undefined) {
    t.skip(skipReason);
    return undefined;
  }

  const wrapper = NativeKeyWrapperV1.create(service);
  // The first call under the service, with a deadline, so a keychain dialog nobody answers fails
  // the run with a message saying what to do rather than hanging it.
  accessChecked ??= new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`The first native call under service '${service}' has not returned after ${NATIVE_CALL_TIMEOUT_MS / 1000}s. On macOS the KEK's keychain item is asking for access in a dialog: click "Always Allow". Without a UI session the library reports KEK access denied (-18); run the tests from a logged-in session.`)), NATIVE_CALL_TIMEOUT_MS);
    wrapper.generateAndWrap(new Uint8Array(MAX_WRAPPED_KEY_BYTES)).then(() => resolve(), () => resolve()).finally(() => clearTimeout(timer));
  });
  await accessChecked;
  return wrapper;
}

export const randomDek = (): Uint8Array => randomFillSync(new Uint8Array(DEK_LENGTH));

/** A second provisioned service, or one no KEK exists for. */
export const otherServiceName = (): string => process.env[TEST_OTHER_SERVICE_VARIABLE] || UNPROVISIONED_SERVICE_NAME;

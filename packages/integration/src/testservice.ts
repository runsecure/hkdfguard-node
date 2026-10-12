import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { TestContext } from 'node:test';
import { MAX_WRAPPED_KEY_BYTES } from '@runsecure/hkdfguard-abstractions';
import {
  NativeKeyWrapperV1, NotInstalledError, StatusError, UnsupportedPlatformError,
} from '@runsecure/hkdfguard-keywrapping-native-v1';

// Which native service the end-to-end tests run against - the same rules as the
// keywrapping-native-v1 package's own native tests, through the public API: HKDFGUARD_TEST_SERVICE
// if set; otherwise the default test service each platform's provisioning script creates, when the
// platform can confirm it is provisioned without prompting (macOS asks the provisioning tool, Windows
// asks the library); otherwise skipped.

const TEST_SERVICE_VARIABLE = 'HKDFGUARD_TEST_SERVICE';
const TEST_OTHER_SERVICE_VARIABLE = 'HKDFGUARD_TEST_SERVICE_OTHER';
const UNPROVISIONED_SERVICE_NAME = 'hkdfguard.integrationtest.unprovisioned';

/** The test KEK each platform's provisioning script (packages/keywrapping-native-v1/scripts) creates. */
const DEFAULT_TEST_SERVICES: Record<string, string> = {
  win32: 'com.hkdfguard.native.windows.test',
  darwin: 'com.hkdfguard.native.macos.test',
  linux: 'com.hkdfguard.native.linux.test',
};

// Windows status codes the probe tells "not provisioned" by (see keywrapping-native-v1's status tables).
const WINDOWS_KEK_NOT_FOUND = -12;
const WINDOWS_ACCESS_DENIED = -13;

// Bounds the first native call: on macOS each node executable is answered with a keychain dialog.
const NATIVE_CALL_TIMEOUT_MS = 60_000;

const SCRIPTS = 'packages/keywrapping-native-v1/scripts';

interface TestEnvironment {
  service?: string;
  skipReason?: string;
  /** Set when the tests must fail rather than skip. */
  failReason?: string;
}

let resolved: Promise<TestEnvironment> | undefined;

/** The service to run against; skips the test (returning undefined) when there is none, or fails it. */
export async function testServiceName(t: TestContext): Promise<string | undefined> {
  const environment = await (resolved ??= resolveTestEnvironment());
  if (environment.failReason !== undefined) throw new Error(environment.failReason);
  if (environment.service === undefined) t.skip(environment.skipReason);
  return environment.service;
}

/** A second provisioned service, or one no KEK exists for. */
export const otherServiceName = (): string => process.env[TEST_OTHER_SERVICE_VARIABLE] || UNPROVISIONED_SERVICE_NAME;

async function resolveTestEnvironment(): Promise<TestEnvironment> {
  const named = process.env[TEST_SERVICE_VARIABLE];
  const explicit = named !== undefined && named !== '';
  const service = explicit ? named : DEFAULT_TEST_SERVICES[process.platform];
  if (service === undefined) return { skipReason: `There is no HkdfGuard native library for ${process.platform}.` };

  let wrapper: NativeKeyWrapperV1;
  try {
    wrapper = NativeKeyWrapperV1.create(service);
  } catch (error) {
    if (error instanceof NotInstalledError || error instanceof UnsupportedPlatformError) {
      return { skipReason: `the native library can't be used here: ${error.message}` };
    }
    return { failReason: `the installed native library failed to load: ${(error as Error).message}` };
  }

  if (!explicit) {
    if (process.platform === 'darwin' && darwinServiceProvisioned(service) === false) {
      return { skipReason: `The test KEK '${service}' is not provisioned. Run ${SCRIPTS}/provision-macos-test-key.sh, or set ${TEST_SERVICE_VARIABLE} to a provisioned service.` };
    }
    if (process.platform === 'linux') {
      return { skipReason: `Set ${TEST_SERVICE_VARIABLE} to a service provisioned with hkdfguard-v1-initialize. On a Linux TPM host, sudo ${SCRIPTS}/provision-linux-test-key.sh provisions ${service}.` };
    }
  }

  // The first native call, with a deadline (the macOS keychain dialog); on Windows its status also
  // says whether the default service is provisioned.
  const outcome = await probe(wrapper);
  if (outcome === 'timed out') {
    return { failReason: `The first native call under service '${service}' has not returned after ${NATIVE_CALL_TIMEOUT_MS / 1000}s. On macOS the KEK's keychain item is asking for access in a dialog: click "Always Allow" (each node executable asks once). In a session with no UI the library reports keychainAccessDenied (-17) instead.` };
  }
  if (!explicit && process.platform === 'win32' && outcome instanceof StatusError) {
    if (outcome.status === WINDOWS_KEK_NOT_FOUND) {
      return { skipReason: `The test KEK '${service}' is not provisioned. Run ${SCRIPTS}/provision-windows-test-key.ps1 from an elevated PowerShell, or set ${TEST_SERVICE_VARIABLE} to a provisioned service.` };
    }
    if (outcome.status === WINDOWS_ACCESS_DENIED) {
      return { skipReason: `The test KEK '${service}' exists, but this account may not use it. Add it to the HkdfGuardUsers group (then sign out and in), or run the tests elevated.` };
    }
  }
  return { service };
}

/** One generateAndWrap under the wrapper's service: its error (undefined on success), or 'timed out'. */
async function probe(wrapper: NativeKeyWrapperV1): Promise<unknown> {
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<'timed out'>((resolve) => { timer = setTimeout(() => resolve('timed out'), NATIVE_CALL_TIMEOUT_MS); });
  try {
    return await Promise.race([wrapper.generateAndWrap(new Uint8Array(MAX_WRAPPED_KEY_BYTES)).then(() => undefined, (error: unknown) => error), deadline]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Asks the installed hkdfguard-v1-initialize - beside the library the loader uses: the system install
 * when there is one, else the per-user one - whether the service's KEK exists. The tool created the
 * KEK, so it never prompts. Undefined when the tool can't say.
 */
function darwinServiceProvisioned(service: string): boolean | undefined {
  const directory = ['/Library/Application Support/HkdfGuard/v1', join(homedir(), '.hkdfguard', 'v1')]
    .find((d) => existsSync(join(d, 'libhkdfguard_v1.dylib')));
  if (directory === undefined) return undefined;
  try {
    const status = execFileSync(join(directory, 'hkdfguard-v1-initialize'), ['status', '--service-name', service], { encoding: 'utf8' });
    if (status.includes('kek: present')) return true;
    if (status.includes('kek: absent')) return false;
  } catch {
    // Can't tell: run the tests, so a real failure is reported rather than hidden.
  }
  return undefined;
}

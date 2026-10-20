import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { TestContext } from 'node:test';
import { MAX_WRAPPED_KEY_BYTES } from '@runsecure/hkdfguard-abstractions';
import { awaitNativeAccess, NATIVE_ACCESS_TIMEOUT_MS } from '@runsecure/hkdfguard-test-support';
import {
  NativeKeyWrapperV1, NotInstalledError, Status, StatusError, UnsupportedPlatformError,
} from '@runsecure/hkdfguard-keywrapping-native-v1';

// Which native service the end-to-end tests run against - the same rules as the
// keywrapping-native-v1 package's own native tests, through the public API: HKDFGUARD_TEST_SERVICE
// if set; otherwise DEFAULT_TEST_SERVICE, which every platform's provisioning script creates, when
// the platform can confirm it is provisioned without prompting (macOS asks the provisioning tool,
// Windows asks the library); otherwise skipped.

const TEST_SERVICE_VARIABLE = 'HKDFGUARD_TEST_SERVICE';
const TEST_OTHER_SERVICE_VARIABLE = 'HKDFGUARD_TEST_SERVICE_OTHER';
const UNPROVISIONED_SERVICE_NAME = 'hkdfguard.integrationtest.unprovisioned';

/** The test KEK every platform's provisioning script (packages/keywrapping-native-v1/scripts) creates. */
const DEFAULT_TEST_SERVICE = 'com.hkdfguard.integration.test.221';

// The status codes the Windows probe tells "not provisioned" by.
const { kekNotFound: KEK_NOT_FOUND, kekAccessDenied: KEK_ACCESS_DENIED } = Status;

// The package's main module, which awaitNativeAccess's child process loads.
const PACKAGE_ENTRY = require.resolve('@runsecure/hkdfguard-keywrapping-native-v1');

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

/**
 * A second provisioned service, or one no KEK exists for - once its first native call has returned
 * within the deadline (awaitNativeAccess: on macOS it may be provisioned, and ask in a dialog too).
 */
export async function otherServiceName(): Promise<string> {
  const service = process.env[TEST_OTHER_SERVICE_VARIABLE] || UNPROVISIONED_SERVICE_NAME;
  await awaitNativeAccess(service, PACKAGE_ENTRY);
  return service;
}

async function resolveTestEnvironment(): Promise<TestEnvironment> {
  const named = process.env[TEST_SERVICE_VARIABLE];
  const explicit = named !== undefined && named !== '';
  const service = explicit ? named : DEFAULT_TEST_SERVICE;
  if (!['win32', 'darwin', 'linux'].includes(process.platform)) return { skipReason: `There is no HkdfGuard native library for ${process.platform}.` };

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
      return { skipReason: `Set ${TEST_SERVICE_VARIABLE} to a service provisioned with hkdfguard. On a Linux TPM host, sudo ${SCRIPTS}/provision-linux-test-key.sh provisions ${service}.` };
    }
  }

  // macOS: the first native call, with a deadline, in a child process - a keychain dialog nobody
  // answers fails the run, saying so, rather than hanging it (see awaitNativeAccess).
  try {
    await awaitNativeAccess(service, PACKAGE_ENTRY);
  } catch (error) {
    return { failReason: (error as Error).message };
  }

  // Windows: the first native call's status says whether the default service is provisioned.
  const outcome = !explicit && process.platform === 'win32' ? await probe(wrapper) : undefined;
  if (outcome instanceof StatusError) {
    if (outcome.status === KEK_NOT_FOUND) {
      return { skipReason: `The test KEK '${service}' is not provisioned. Run ${SCRIPTS}/provision-windows-test-key.ps1 from an elevated PowerShell, or set ${TEST_SERVICE_VARIABLE} to a provisioned service.` };
    }
    if (outcome.status === KEK_ACCESS_DENIED) {
      return { skipReason: `The test KEK '${service}' exists, but this account may not use it. Add it to the HkdfGuardUsers group (then sign out and in), or run the tests elevated.` };
    }
  }
  return { service };
}

/** One generateAndWrap under the wrapper's service: its error, or undefined on success. */
function probe(wrapper: NativeKeyWrapperV1): Promise<unknown> {
  return wrapper.generateAndWrap(new Uint8Array(MAX_WRAPPED_KEY_BYTES)).then(() => undefined, (error: unknown) => error);
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
    const status = execFileSync(join(directory, 'hkdfguard-v1-initialize'), ['status', '--service-name', service], { encoding: 'utf8', timeout: NATIVE_ACCESS_TIMEOUT_MS });
    if (status.includes('kek: present')) return true;
    if (status.includes('kek: absent')) return false;
  } catch {
    // Can't tell: run the tests, so a real failure is reported rather than hidden.
  }
  return undefined;
}

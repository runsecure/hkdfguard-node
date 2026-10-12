import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import { randomFillSync } from 'node:crypto';
import { existsSync, lstatSync, mkdtempSync, realpathSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, it, type TestContext } from 'node:test';
import { isZero, MAX_WRAPPED_KEY_BYTES } from '@runsecure/hkdfguard-abstractions';
import { NotInstalledError, StatusError, UnsupportedPlatformError, UntrustedError } from './errors.js';
import { hostLibrary } from './host.js';
import { NativeKmsLibrary, type KmsLibrary } from './library.js';
import { MAC_SYSTEM_DIRECTORY, MAC_TEAM_ID, macChoosePath, macVerifyLocation, macVerifySignature } from './macpolicy.js';
import { nativeAddon } from './native.js';
import { Status } from './status.js';
import { statusFromMode } from './unixpath.js';
import { DEK_LENGTH, NativeKeyWrapperV1 } from './wrapper.js';
import { DEFAULT_TEST_SERVICES, TEST_OTHER_SERVICE_VARIABLE, TEST_SERVICE_VARIABLE, UNPROVISIONED_SERVICE_NAME } from './testservices.test-support.js';

/*
 * Real wrapping and unwrapping against this platform's installed native KMS library. No native
 * library creates a KEK during wrap/unwrap, so the round trips run against a provisioned service:
 * HKDFGUARD_TEST_SERVICE when set, otherwise the default test service the platform's script under
 * scripts/ provisions - found by the tests themselves on Windows and macOS, and named by the
 * variables the Linux script prints. Without the library installed every test here is skipped;
 * without a service the round trips are - reported as skipped, never as passed. A library that is
 * installed but fails verification fails the run. The tests never create or delete a KEK.
 *
 * macOS: in the library's legacy keychain mode the KEK's access list names the binary that created
 * it, so the first call from another binary - node - is answered with a keychain dialog in a
 * logged-in session (click "Always Allow"), or keychainAccessDenied (-17) without one.
 */

const NATIVE_CALL_TIMEOUT_MS = 60_000;

function installedLibrary(t: TestContext): KmsLibrary | undefined {
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

/** The hkdfguard-v1-initialize installed beside the library the macOS loader would choose. */
function macProvisioningTool(): string | undefined {
  try {
    const { path } = macChoosePath((p) => (existsSync(p) ? 0 : 2), homedir());
    const tool = join(dirname(path), 'hkdfguard-v1-initialize');
    return existsSync(tool) ? tool : undefined;
  } catch {
    return undefined;
  }
}

/** Whether the platform default test service is provisioned, without prompting; undefined when it can't tell. */
function defaultServiceProvisioned(library: KmsLibrary, service: string): { provisioned: boolean; reason?: string } | undefined {
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
    if (status === Status.windowsKekNotFound) return { provisioned: false, reason: `The test KEK '${service}' is not provisioned. Run scripts/provision-windows-test-key.ps1 from an elevated PowerShell.` };
    if (status === Status.windowsAccessDenied) return { provisioned: false, reason: `The test KEK '${service}' exists, but this account may not use it. Add it to the HkdfGuardUsers group (then sign out and in), or run the tests elevated.` };
    return undefined;
  }
  return { provisioned: false, reason: `Set ${TEST_SERVICE_VARIABLE} (scripts/provision-linux-test-key.sh prints the command) to run the native round trips.` };
}

let resolved: { service?: string; skipReason?: string } | undefined;
let accessChecked: Promise<void> | undefined;

/** A wrapper for the test service, chosen once per process; skips the test when there is none. */
async function provisionedWrapper(t: TestContext): Promise<NativeKeyWrapperV1 | undefined> {
  const library = installedLibrary(t);
  if (library === undefined) return undefined;
  resolved ??= (() => {
    const named = process.env[TEST_SERVICE_VARIABLE];
    if (named) return { service: named };
    const service = DEFAULT_TEST_SERVICES[process.platform]!;
    const answer = defaultServiceProvisioned(library, service);
    // Can't tell: run the tests, so a real failure is reported rather than hidden.
    return answer === undefined || answer.provisioned ? { service } : { skipReason: answer.reason };
  })();
  if (resolved.service === undefined) {
    t.skip(resolved.skipReason);
    return undefined;
  }

  const wrapper = NativeKeyWrapperV1.create(resolved.service);
  // The first call under the service, with a deadline, so a keychain dialog nobody answers fails
  // the run with a message saying what to do rather than hanging it.
  accessChecked ??= new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`The first native call under service '${resolved!.service}' has not returned after ${NATIVE_CALL_TIMEOUT_MS / 1000}s. On macOS the KEK's keychain item is asking for access in a dialog: click "Always Allow". Without a UI session the library reports keychainAccessDenied (-17); run the tests from a logged-in session.`)), NATIVE_CALL_TIMEOUT_MS);
    wrapper.generateAndWrap(new Uint8Array(MAX_WRAPPED_KEY_BYTES)).then(() => resolve(), () => resolve()).finally(() => clearTimeout(timer));
  });
  await accessChecked;
  return wrapper;
}

const randomDek = () => randomFillSync(new Uint8Array(DEK_LENGTH));
const otherServiceName = () => process.env[TEST_OTHER_SERVICE_VARIABLE] || UNPROVISIONED_SERVICE_NAME;

describe('the installed native library', () => {
  it('loads once and answers calls', async (t) => {
    const library = installedLibrary(t);
    if (library === undefined) return;
    assert.equal(hostLibrary(), library);
    // No KEK is provisioned under this name, so the library answers with an error status - which
    // proves it loaded and ran.
    const [status] = await library.wrapDek(UNPROVISIONED_SERVICE_NAME, new Uint8Array(DEK_LENGTH), new Uint8Array(MAX_WRAPPED_KEY_BYTES));
    assert.ok(status < 0, `wrap under an unprovisioned service returned ${status}`);
  });

  it('round-trips a 32-byte DEK', async (t) => {
    const w = await provisionedWrapper(t);
    if (w === undefined) return;
    const dek = randomDek();
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const n = await w.wrap(Uint8Array.from(dek), wrapped);
    assert.ok(n > 0);
    const unwrapped = new Uint8Array(DEK_LENGTH);
    assert.equal(await w.unwrap(wrapped.subarray(0, n), unwrapped), DEK_LENGTH);
    assert.deepEqual(unwrapped, dek);
  });

  it('generates a stable, non-zero DEK, and keeps several keys independent', async (t) => {
    const w = await provisionedWrapper(t);
    if (w === undefined) return;
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const n = await w.generateAndWrap(wrapped);
    const first = new Uint8Array(DEK_LENGTH), second = new Uint8Array(DEK_LENGTH);
    await w.unwrap(wrapped.subarray(0, n), first);
    await w.unwrap(wrapped.subarray(0, n), second);
    assert.ok(!isZero(first));
    assert.deepEqual(first, second);

    const [a, b] = [randomDek(), randomDek()];
    const wa = new Uint8Array(MAX_WRAPPED_KEY_BYTES), wb = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const na = await w.wrap(Uint8Array.from(a), wa), nb = await w.wrap(Uint8Array.from(b), wb);
    const ra = new Uint8Array(DEK_LENGTH), rb = new Uint8Array(DEK_LENGTH);
    await w.unwrap(wb.subarray(0, nb), rb);
    await w.unwrap(wa.subarray(0, na), ra);
    assert.deepEqual([ra, rb], [a, b]);
  });

  it('reveals nothing from a payload wrapped under another service', async (t) => {
    const w = await provisionedWrapper(t);
    if (w === undefined) return;
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const n = await w.wrap(randomDek(), wrapped);
    const destination = new Uint8Array(DEK_LENGTH);
    await assert.rejects(NativeKeyWrapperV1.create(otherServiceName()).unwrap(wrapped.subarray(0, n), destination), StatusError);
    assert.ok(isZero(destination));
  });

  it('fails on too-small buffers and corrupt payloads', async (t) => {
    const w = await provisionedWrapper(t);
    if (w === undefined) return;
    await assert.rejects(w.wrap(randomDek(), new Uint8Array(8)), StatusError);
    await assert.rejects(w.generateAndWrap(new Uint8Array(8)), StatusError);
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const n = await w.generateAndWrap(wrapped);
    await assert.rejects(w.unwrap(wrapped.subarray(0, n), new Uint8Array(8)), StatusError);
    wrapped[Math.floor(n / 2)]! ^= 0xff;
    const destination = new Uint8Array(DEK_LENGTH);
    await assert.rejects(w.unwrap(wrapped.subarray(0, n), destination), StatusError);
    assert.ok(isZero(destination));
  });
});

describe('the macOS loader against the real system', { skip: process.platform !== 'darwin' }, () => {
  it('passes every check for the installed library', (t) => {
    let chosen;
    try {
      chosen = macChoosePath((p) => (existsSync(p) ? 0 : 2), homedir());
    } catch {
      t.skip('the native library is not installed');
      return;
    }
    macVerifyLocation(chosen.path, (p) => { const s = lstatSync(p); return statusFromMode(s.uid, s.gid, s.mode); },
      chosen.isSystem ? [0] : [0, process.geteuid!()]);
    macVerifySignature(chosen.path, nativeAddon().checkCodeSignature!);
  });

  it('refuses the provisioning tool - signed by the team, but not the library', (t) => {
    const tool = join(MAC_SYSTEM_DIRECTORY, 'hkdfguard-v1-initialize');
    if (!existsSync(tool)) { t.skip(`${tool} is not installed`); return; }
    assert.throws(() => macVerifySignature(tool, nativeAddon().checkCodeSignature!), (e: unknown) => e instanceof UntrustedError && e.message.includes(MAC_TEAM_ID));
  });

  it('refuses an unsigned file', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'hkdfguard-')), 'libhkdfguard_v1.dylib');
    writeFileSync(path, new Uint8Array([0xcf, 0xfa, 0xed, 0xfe]));
    assert.throws(() => macVerifySignature(realpathSync(path), nativeAddon().checkCodeSignature!), UntrustedError);
  });

  it('reports an unprovisioned service as absent through the provisioning tool', (t) => {
    const tool = macProvisioningTool();
    if (tool === undefined) { t.skip('the provisioning tool is not installed'); return; }
    assert.ok(execFileSync(tool, ['status', '--service-name', UNPROVISIONED_SERVICE_NAME], { encoding: 'utf8' }).includes('kek: absent'));
  });
});

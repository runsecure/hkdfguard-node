import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import { randomBytes, randomFillSync } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, it, type TestContext } from 'node:test';
import { isZero, MAX_WRAPPED_KEY_BYTES } from '@runsecure/hkdfguard-abstractions';
import { KeyFileRefusedError, NotInstalledError, StatusError, UnsupportedPlatformError, UntrustedError } from './errors.js';
import { hostLibrary } from './host.js';
import { NativeKmsLibrary, type KmsLibrary } from './library.js';
import { MAC_SYSTEM_DIRECTORY, MAC_TEAM_ID, macChoosePath, macVerifyLocation, macVerifySignature } from './macpolicy.js';
import { nativeAddon } from './native.js';
import { Status, WRAPPED_DEK_LENGTHS } from './status.js';
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
 * logged-in session (click "Always Allow"), or KEK access denied (-18) without one.
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
    if (status === Status.kekNotFound) return { provisioned: false, reason: `The test KEK '${service}' is not provisioned. Run scripts/provision-windows-test-key.ps1 from an elevated PowerShell.` };
    if (status === Status.kekAccessDenied) return { provisioned: false, reason: `The test KEK '${service}' exists, but this account may not use it. Add it to the HkdfGuardUsers group (then sign out and in), or run the tests elevated.` };
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
    const timer = setTimeout(() => reject(new Error(`The first native call under service '${resolved!.service}' has not returned after ${NATIVE_CALL_TIMEOUT_MS / 1000}s. On macOS the KEK's keychain item is asking for access in a dialog: click "Always Allow". Without a UI session the library reports KEK access denied (-18); run the tests from a logged-in session.`)), NATIVE_CALL_TIMEOUT_MS);
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
    // Another provisioned KEK: a fingerprint mismatch (or, on macOS, an authentication failure); none at all: KEK not found.
    const refusals: number[] = [Status.kekFingerprintMismatch, Status.payloadAuthFailed, Status.kekNotFound];
    await assert.rejects(NativeKeyWrapperV1.create(otherServiceName()).unwrap(wrapped.subarray(0, n), destination),
      (e: unknown) => e instanceof StatusError && refusals.includes(e.status));
    assert.ok(isZero(destination));
  });

  it('fails on too-small buffers and corrupt payloads', async (t) => {
    const w = await provisionedWrapper(t);
    if (w === undefined) return;
    const failsWith = (...statuses: number[]) => (e: unknown) => e instanceof StatusError && statuses.includes(e.status);
    await assert.rejects(w.wrap(randomDek(), new Uint8Array(8)), failsWith(Status.bufferTooSmall));
    await assert.rejects(w.generateAndWrap(new Uint8Array(8)), failsWith(Status.bufferTooSmall));
    const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const n = await w.generateAndWrap(wrapped);
    await assert.rejects(w.unwrap(wrapped.subarray(0, n), new Uint8Array(8)), failsWith(Status.bufferTooSmall, Status.invalidArgument));
    // A truncated payload is malformed; an altered one fails as malformed, unauthenticated,
    // unsupported or under another KEK, depending on which field the change lands in.
    const destination = new Uint8Array(DEK_LENGTH);
    await assert.rejects(w.unwrap(wrapped.subarray(0, n - 1), destination), failsWith(Status.payloadMalformed));
    assert.ok(isZero(destination));
    const tampered = (e: unknown) => failsWith(Status.payloadMalformed, Status.payloadAuthFailed, Status.payloadUnsupported, Status.kekFingerprintMismatch)(e);
    for (const at of [0, Math.floor(n / 2), n - 1]) {
      const altered = Uint8Array.from(wrapped.subarray(0, n));
      altered[at]! ^= 0xff;
      await assert.rejects(w.unwrap(altered, destination), tampered, `byte ${at}`);
      assert.ok(isZero(destination));
    }
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

/*
 * Key files read through the real library's hkdfguard_open_file. Refusals of a file's size,
 * contents or location need no KEK, so they run wherever the Windows library is installed; reading
 * back a real wrapped key needs the provisioned test service. Windows only: elsewhere the library
 * refuses a key file under the sticky, world-writable /tmp, so these temporary files would only
 * ever be untrusted. (The key-ring halves of these tests are in packages/integration.)
 */
describe('key files read through the installed native library', { skip: process.platform !== 'win32' }, () => {
  const directories: string[] = [];
  after(() => {
    for (const directory of directories) rmSync(directory, { recursive: true, force: true });
  });

  /**
   * A fresh folder under the temp folder, by its long path: hkdfguard_open_file refuses an 8.3 short
   * name anywhere in a path, and Windows can hand out %TEMP% in short form (C:\Users\RUNNER~1\...
   * on GitHub-hosted runners). realpathSync.native expands it; realpathSync would not.
   */
  function temporaryFolder(): string {
    const directory = realpathSync.native(mkdtempSync(join(tmpdir(), 'hkdfguard-keyfile-')));
    directories.push(directory);
    return directory;
  }

  function write(contents: Uint8Array, name = 'key.bin'): string {
    const path = join(temporaryFolder(), name);
    writeFileSync(path, contents);
    return path;
  }

  /** A wrapper only for reading: any valid name, since reading a file never touches a KEK. */
  function reader(t: TestContext): NativeKeyWrapperV1 | undefined {
    return installedLibrary(t) === undefined ? undefined : NativeKeyWrapperV1.create('hkdfguard.keyfile.reader');
  }

  const refused = (status: number, code: string, path?: string) => (e: unknown) =>
    e instanceof KeyFileRefusedError && e.status === status && e.code === code
    && (path === undefined || (e.path === path && e.message.startsWith(`Key file '${path}' was refused by the native library with status ${status} (`)));

  it('expands a short temp folder name to its long form', (t) => {
    if (installedLibrary(t) === undefined) return;
    const directory = temporaryFolder();
    assert.ok(!/~\d/.test(directory), directory);
  });

  it('refuses a missing file, and a file in a missing folder', async (t) => {
    const r = reader(t);
    if (r === undefined) return;
    const missing = join(temporaryFolder(), 'missing.bin');
    await assert.rejects(r.readKeyFile(missing), refused(Status.fileNotFound, 'ENOENT', missing));
    await assert.rejects(r.readKeyFile(join(temporaryFolder(), 'no-such-folder', 'dek.bin')), refused(Status.fileNotFound, 'ENOENT'));
  });

  it('refuses what looks like an unwrapped key as a key exposure', async (t) => {
    const r = reader(t);
    if (r === undefined) return;
    const dek = randomBytes(32);
    const forms: Record<string, Uint8Array> = {
      raw: dek,
      hex: Buffer.from(dek.toString('hex').toUpperCase(), 'ascii'),
      'lower-hex': Buffer.from(dek.toString('hex'), 'ascii'),
      base64: Buffer.from(dek.toString('base64'), 'ascii'),
      'base64-with-newline': Buffer.from(`${dek.toString('base64')}\n`, 'ascii'),
    };
    for (const [form, contents] of Object.entries(forms)) {
      const path = write(contents, `plaintext-${form}.bin`);
      await assert.rejects(r.readKeyFile(path), (e: unknown) =>
        refused(Status.filePlaintextKey, 'ERR_HKDFGUARD_INVALID_KEY_FILE', path)(e) && (e as Error).message.includes('key exposure'), form);
    }
  });

  it('refuses a file of the wrong size', async (t) => {
    const r = reader(t);
    if (r === undefined) return;
    const length = WRAPPED_DEK_LENGTHS.win32;
    for (const [size, status] of [[0, Status.fileTooShort], [100, Status.fileTooShort], [length - 1, Status.fileTooShort],
      [length + 1, Status.fileTooLong], [4096, Status.fileTooLong]] as const) {
      const contents = new Uint8Array(size);
      if (size > 0) contents[0] = 0x7f; // never mistaken for text
      const path = write(contents, `size-${size}.bin`);
      await assert.rejects(r.readKeyFile(path), refused(status, 'ERR_HKDFGUARD_INVALID_KEY_FILE', path), String(size));
    }
  });

  it('refuses a folder', async (t) => {
    const r = reader(t);
    if (r === undefined) return;
    const directory = temporaryFolder();
    await assert.rejects(r.readKeyFile(directory), (e: unknown) => e instanceof KeyFileRefusedError
      && (e.status === Status.fileIo || e.status === Status.fileAccessDenied) && (e.code === 'EIO' || e.code === 'EACCES'));
  });

  it('refuses a file reached through a junction as untrusted', async (t) => {
    const r = reader(t);
    if (r === undefined) return;
    const directory = temporaryFolder();
    const target = join(directory, 'real');
    mkdirSync(target);
    writeFileSync(join(target, 'dek.bin'), new Uint8Array(WRAPPED_DEK_LENGTHS.win32));
    const junction = join(directory, 'junction');
    symlinkSync(target, junction, 'junction'); // a junction needs no elevation, unlike a symbolic link
    try {
      const path = join(junction, 'dek.bin');
      await assert.rejects(r.readKeyFile(path), refused(Status.fileUntrusted, 'EACCES', path));
    } finally {
      rmSync(junction); // the junction itself, not what it points at
    }
    assert.ok(existsSync(join(target, 'dek.bin')));
  });

  it('reads back a key file the wrapper wrote, exactly, and it unwraps to its DEK', async (t) => {
    const w = await provisionedWrapper(t);
    if (w === undefined) return;
    const dek = randomDek();
    const buffer = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const wrapped = buffer.slice(0, await w.wrap(Uint8Array.from(dek), buffer));
    assert.equal(wrapped.length, WRAPPED_DEK_LENGTHS.win32);
    const path = write(wrapped, 'wrapped-dek.bin');

    const read = await w.readKeyFile(path);
    assert.deepEqual(read, wrapped);
    const recovered = new Uint8Array(DEK_LENGTH);
    assert.equal(await w.unwrap(read, recovered), DEK_LENGTH);
    assert.deepEqual(recovered, dek);
  });

  it('refuses a right-size key file with an unknown version as malformed', async (t) => {
    const w = await provisionedWrapper(t);
    if (w === undefined) return;
    const buffer = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
    const wrapped = buffer.slice(0, await w.wrap(randomDek(), buffer));
    wrapped[0]! ^= 0xff; // the version byte
    const path = write(wrapped, 'wrapped-dek.bin');
    await assert.rejects(w.readKeyFile(path), refused(Status.fileMalformed, 'ERR_HKDFGUARD_INVALID_KEY_FILE', path));
  });
});

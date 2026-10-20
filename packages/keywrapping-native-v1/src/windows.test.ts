import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, win32 } from 'node:path';
import { after, describe, it, type TestContext } from 'node:test';
import { NotInstalledError, UntrustedError } from './errors.js';
import { hostLibrary } from './host.js';
import { NativeKmsLibrary } from './library.js';
import { nativeAddon, type NativeAddon } from './native.js';
import { Status } from './status.js';
import { winInstalledPath, winLoadFrom, winVerifyImageKindOf, winVerifyLocation, winVerifyNotReparsePoint, winVerifySignature } from './windows.js';
import { WIN_CODE_SIGNING_EKU, WIN_EXPECTED_PROFILE_EKU, WIN_EXPECTED_PUBLISHER, WIN_EXPECTED_ROOT_SHA256, WIN_FILE_NAME } from './windowspolicy.js';
import { UNPROVISIONED_SERVICE_NAME } from './testservices.test-support.js';

/*
 * Windows only: the Windows loader's checks against this machine's real filesystem, WinVerifyTrust
 * and the installed %ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll (and hkdfguard.exe beside it) where
 * there is one - reported as skipped where it isn't. windowspolicy.test.ts checks the same
 * decisions against plain data on every platform; the key files the installed library reads are in
 * native.test.ts. The ports of the .NET WindowsNativeLibraryLoaderTests that touch the system, and
 * the Go TestWindows_* tests.
 */

const directories: string[] = [];
after(() => {
  for (const directory of directories) rmSync(directory, { recursive: true, force: true });
});

/** A fresh folder under the temp folder, by its long path (see native.test.ts). */
function temporaryFolder(prefix = 'hkdfguard-loader-'): string {
  const directory = realpathSync.native(mkdtempSync(join(tmpdir(), prefix)));
  directories.push(directory);
  return directory;
}

function writeTemporary(name: string, contents: Uint8Array): string {
  const path = join(temporaryFolder(), name);
  writeFileSync(path, contents);
  return path;
}

/** The installed library's path; skips the test when it isn't installed. */
function installedPath(t: TestContext): string | undefined {
  const path = winInstalledPath();
  if (!existsSync(path)) {
    t.skip(`The native KMS library is not installed at ${path}.`);
    return undefined;
  }
  return path;
}

/** The files mapped into this process, from its diagnostic report. */
function mappedModules(): string[] {
  const report = process.report.getReport() as { sharedObjects?: string[] };
  return report.sharedObjects ?? [];
}

const sameFile = (a: string, b: string) => win32.resolve(a).toLowerCase() === win32.resolve(b).toLowerCase();
const untrusted = (...fragments: string[]) => (e: unknown) => e instanceof UntrustedError && fragments.every((f) => e.message.includes(f));
const NOT_PE = new Uint8Array([0x4d, 0x5a, 0x90, 0x00]); // 'MZ', and nothing after it

describe('the Windows loader against the real system', { skip: process.platform !== 'win32' && 'Windows only' }, () => {
  it('loads only from the fixed Program Files location', () => {
    const programFiles = process.env.ProgramFiles;
    assert.ok(programFiles !== undefined, '%ProgramFiles% is not set');
    assert.ok(sameFile(winInstalledPath(), win32.join(programFiles, 'HkdfGuard', 'v1', 'HkdfGuard.dll')), winInstalledPath());
  });

  it('reports a missing file as not installed, naming the only supported path', () => {
    const missing = join(temporaryFolder(), 'missing', WIN_FILE_NAME);
    assert.throws(() => winLoadFrom(nativeAddon(), missing, WIN_EXPECTED_PUBLISHER),
      (e: unknown) => e instanceof NotInstalledError && e.message.includes(missing));
  });

  it('refuses a planted file in a user-writable folder before anything is loaded', () => {
    // The DLL-planting scenario: a correctly named file in a folder the current user controls.
    const planted = writeTemporary(WIN_FILE_NAME, new Uint8Array([0x4d, 0x5a]));
    const native: NativeAddon = { ...nativeAddon(), load: () => assert.fail('the planted file was loaded') };
    assert.throws(() => winLoadFrom(native, planted, WIN_EXPECTED_PUBLISHER), UntrustedError);
  });

  it('refuses a junction', () => {
    // Junctions need no privilege to create, unlike symbolic links.
    const target = temporaryFolder('hkdfguard-target-');
    const junction = join(tmpdir(), `hkdfguard-junction-${process.pid}-${Date.now()}`);
    execFileSync('cmd.exe', ['/c', 'mklink', '/J', junction, target], { stdio: 'ignore' });
    try {
      assert.throws(() => winVerifyNotReparsePoint(nativeAddon(), junction), untrusted('symbolic link or junction'));
      winVerifyNotReparsePoint(nativeAddon(), target);
    } finally {
      rmSync(junction, { recursive: true, force: true }); // the junction itself, not what it points at
    }
    assert.ok(existsSync(target));
  });

  it('refuses an unsigned file', () => {
    assert.throws(() => winVerifySignature(nativeAddon(), writeTemporary('unsigned.dll', NOT_PE), WIN_EXPECTED_PUBLISHER), UntrustedError);
  });

  it('fails closed on a file that is not a PE image', () => {
    assert.throws(() => winVerifyImageKindOf(writeTemporary('not-pe.dll', NOT_PE)), untrusted('PE header'));
  });

  it('passes the location, signature and image checks for the installed library', (t) => {
    const path = installedPath(t);
    if (path === undefined) return;
    winVerifyLocation(nativeAddon(), path);
    winVerifySignature(nativeAddon(), path, WIN_EXPECTED_PUBLISHER);
    winVerifyImageKindOf(path);
  });

  it('finds the installed library chained to the pinned root, with the profile EKU', (t) => {
    // The chain WinVerifyTrust validated, not one built separately.
    const path = installedPath(t);
    if (path === undefined) return;
    const signer = nativeAddon().verifiedSigner!(path);
    assert.ok('subject' in signer, `no verified signer: ${JSON.stringify(signer)}`);
    assert.equal(signer.subject, WIN_EXPECTED_PUBLISHER);
    assert.equal(createHash('sha256').update(signer.rootCertificate).digest('hex').toUpperCase(), WIN_EXPECTED_ROOT_SHA256);
    assert.ok(signer.ekus.includes(WIN_CODE_SIGNING_EKU) && signer.ekus.includes(WIN_EXPECTED_PROFILE_EKU), signer.ekus.join(', '));
  });

  it('refuses the installed library as signed by another publisher', (t) => {
    const path = installedPath(t);
    if (path === undefined) return;
    assert.throws(() => winVerifySignature(nativeAddon(), path, 'CN=Someone Else'), untrusted('not the expected HkdfGuard publisher'));
  });

  it('refuses a tampered copy of the installed library', (t) => {
    const path = installedPath(t);
    if (path === undefined) return;
    const image = readFileSync(path);
    image[image.length >> 1]! ^= 0xff; // inside the signed image, not the signature itself
    assert.throws(() => winVerifySignature(nativeAddon(), writeTemporary(WIN_FILE_NAME, image), WIN_EXPECTED_PUBLISHER), UntrustedError);
  });

  it("passes the provisioning tool's signer checks, but refuses it as not a DLL", (t) => {
    // Installed beside the library and signed under the same profile: only the image check tells
    // them apart.
    const path = installedPath(t);
    if (path === undefined) return;
    const tool = win32.join(win32.dirname(path), 'hkdfguard.exe');
    assert.ok(existsSync(tool), `${tool} is installed with the library`);
    winVerifySignature(nativeAddon(), tool, WIN_EXPECTED_PUBLISHER);
    assert.throws(() => winVerifyImageKindOf(tool), untrusted('not a DLL'));
  });

  it('maps exactly the installed file, once, however often it is loaded', (t) => {
    const path = installedPath(t);
    if (path === undefined) return;
    const library = hostLibrary();
    assert.equal(hostLibrary(), library);

    // A second load of the verified path only takes another reference to the module already mapped.
    const native = nativeAddon();
    native.unload(native.load(path));
    const mapped = mappedModules().filter((m) => win32.basename(m).toLowerCase() === WIN_FILE_NAME.toLowerCase());
    assert.equal(mapped.length, 1, `HkdfGuard.dll is mapped from: ${mapped.join(', ')}`);
    assert.ok(sameFile(mapped[0]!, path), `mapped from ${mapped[0]}, not ${path}`);
  });

  it('answers kekExists for an unprovisioned service', (t) => {
    if (installedPath(t) === undefined) return;
    const library = hostLibrary();
    assert.ok(library instanceof NativeKmsLibrary);
    const answer = library.kekExists(UNPROVISIONED_SERVICE_NAME);
    assert.ok(answer !== undefined, 'the installed library has no hkdfguard_kek_exists export');
    const [status, exists] = answer;
    assert.equal(exists, false);
    assert.ok(status === Status.ok || library.describeStatus(status) !== undefined, `undescribed status ${status}`);
  });
});

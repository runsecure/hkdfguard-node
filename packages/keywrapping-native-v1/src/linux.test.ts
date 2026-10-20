import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, type TestContext } from 'node:test';
import { isValidServiceName, isZero, MAX_SERVICE_NAME_LENGTH, MAX_WRAPPED_KEY_BYTES } from '@runsecure/hkdfguard-abstractions';
import { keyFileDirectory, linuxKeyFileRoot, untrustedDirectoryChain } from '@runsecure/hkdfguard-test-support';
import { unixProbe } from './darwin.js';
import { elfReadNeededFile } from './elf.js';
import { NotInstalledError, StatusError, UntrustedError } from './errors.js';
import { hostLibrary } from './host.js';
import type { KmsLibrary } from './library.js';
import { linuxReadLink, linuxStatus, linuxTrustedFile } from './linux.js';
import {
  ENV_AUDIT, ENV_LIBRARY_PATH, ENV_PRELOAD, linuxKnownReleases, linuxReadEnvironment, linuxResolveTrusted, linuxVerifyContent,
  linuxVerifyDependencies, linuxVerifyEnvironment, linuxVerifyLoadedImage,
} from './linuxpolicy.js';
import { PROBE_EXPORT } from './macpolicy.js';
import { nativeAddon } from './native.js';
import { Status } from './status.js';
import { ENOENT, FileType } from './unixpath.js';
import { DEK_LENGTH, NativeKeyWrapperV1 } from './wrapper.js';
import { installedLinuxLibraryPath, provisionedWrapper, randomDek } from './installed.test-support.js';
import { TEST_OTHER_SERVICE_VARIABLE, UNPROVISIONED_SERVICE_NAME } from './testservices.test-support.js';

/*
 * Linux only: the Linux loader against this machine's real filesystem and dynamic linker, and the
 * Linux native library's contract against the real KEK provider - on a TPM host, provisioned by
 * scripts/provision-linux-test-key.sh:
 *
 *   sudo scripts/provision-linux-test-key.sh
 *   HKDFGUARD_TEST_SERVICE=com.hkdfguard.integration.test.221 \
 *   HKDFGUARD_TEST_SERVICE_OTHER=com.hkdfguard.integration.test.221.other \
 *   npm test --workspace packages/keywrapping-native-v1
 *
 * native.test.ts covers what every platform shares; these pin down the exact Linux status codes,
 * the native library's own input checks (which the wrapper's validation normally keeps it from
 * seeing), what a failed unwrap leaves in the caller's buffer, and the deployment path through
 * hkdfguard. The ports of the .NET LinuxNativeLibraryLoaderSystemTests and
 * LinuxNativeIntegrationTests, and the Go TestLinuxSystem_* and TestLinuxNative_* tests.
 *
 * The add-on hands the library its own zeroed output buffer and copies a result back only on
 * success, so the library's own zeroing of a failed unwrap can't be seen from here; what the
 * caller's buffer holds afterwards is checked through NativeKeyWrapperV1.unwrap, which zeroes it.
 */

const POLICY_PATH = '/etc/hkdfguard/policy.toml';
const CLI = '/usr/bin/hkdfguard';
const CLI_TIMEOUT_MS = 60_000;

/** The installed library's path; skips the test when the package isn't installed. */
function installedPath(t: TestContext): string | undefined {
  const path = installedLinuxLibraryPath();
  if (path === undefined) t.skip('The libhkdfguard1 package is not installed.');
  return path;
}

interface Needs {
  /** HKDFGUARD_TEST_SERVICE_OTHER: a second provisioned service, with its own KEK. */
  otherService?: boolean;
  /** The policy's provisioning allowlist (tpm.require_pinned_names), so an unlisted service has no KEK. */
  pinnedNamesAllowlist?: boolean;
  /** The hkdfguard package's /usr/bin/hkdfguard. */
  cli?: boolean;
}

interface Provisioned {
  library: KmsLibrary;
  service: string;
  wrapper: NativeKeyWrapperV1;
}

/**
 * The installed library and the provisioned test service (HKDFGUARD_TEST_SERVICE); skips the test,
 * saying why, without the package, the service, or what `needs` asks for.
 */
async function provisioned(t: TestContext, needs: Needs = {}): Promise<Provisioned | undefined> {
  if (installedPath(t) === undefined) return undefined;
  const wrapper = await provisionedWrapper(t);
  if (wrapper === undefined) return undefined;
  if (needs.otherService && !process.env[TEST_OTHER_SERVICE_VARIABLE]) {
    t.skip(`Set ${TEST_OTHER_SERVICE_VARIABLE} to a second provisioned service.`);
    return undefined;
  }
  if (needs.pinnedNamesAllowlist && !policyRequiresPinnedNames()) {
    t.skip(`${POLICY_PATH} does not set tpm.require_pinned_names = true (scripts/provision-linux-test-key.sh does).`);
    return undefined;
  }
  if (needs.cli && !existsSync(CLI)) {
    t.skip(`${CLI} is not installed (the hkdfguard package).`);
    return undefined;
  }
  return { library: hostLibrary(), service: wrapper.serviceName, wrapper };
}

function policyRequiresPinnedNames(): boolean {
  try {
    return readFileSync(POLICY_PATH, 'utf8').split('\n').some((line) => line.replaceAll(' ', '').trim() === 'require_pinned_names=true');
  } catch {
    return false;
  }
}

/** `actual` is `expected`, and the binding describes it. */
function assertStatus(library: KmsLibrary, expected: number, actual: number, message?: string): void {
  assert.equal(actual, expected, `${message === undefined ? '' : `${message}: `}status ${actual} (${library.describeStatus(actual)}), want ${expected} (${library.describeStatus(expected)})`);
  assert.notEqual(library.describeStatus(actual), undefined, `status ${actual} has no description`);
}

async function wrap(p: Provisioned, dek: Uint8Array): Promise<Uint8Array> {
  const buffer = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
  const [status, written] = await p.library.wrapDek(p.service, dek, buffer);
  assertStatus(p.library, Status.ok, status, 'wrap');
  return buffer.slice(0, written);
}

const filled = (value: number, length: number) => new Uint8Array(length).fill(value);
const resolveReal = (path: string, expected: FileType, allowMissing = false) => linuxResolveTrusted(path, expected, linuxStatus, linuxReadLink, allowMissing);
const sha256File = (path: string) => createHash('sha256').update(readFileSync(path)).digest('hex');

function temporaryDirectory(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

describe('the Linux loader against the real system', { skip: process.platform !== 'linux' && 'Linux only' }, () => {
  it('trusts the root and system library directories', () => {
    for (const directory of ['/', '/usr/lib']) assert.equal(resolveReal(directory, FileType.Directory), directory);
  });

  it("loads this process's libc from a trusted file", () => {
    const libc = nativeAddon().loadedPath!('libc.so.6');
    assert.ok(libc !== null, 'libc.so.6 is not loaded');
    assert.ok(linuxTrustedFile(libc).startsWith('/'));
  });

  it('has no loaded path for a name nothing is loaded under', () => {
    assert.equal(nativeAddon().loadedPath!('libhkdfguard-never-loaded.so.0'), null);
  });

  it('does not trust a directory this user created for the library path', () => {
    // The attack this loader exists to stop: a directory the service's own user (or anyone) can
    // write, put on LD_LIBRARY_PATH so a dependency is found there first.
    const directory = temporaryDirectory('hkdfguard-ldpath-');
    try {
      assert.throws(() => linuxVerifyEnvironment(new Map([[ENV_LIBRARY_PATH, [directory]]]), (p, type) => { resolveReal(p, type, true); }),
        (e: unknown) => e instanceof UntrustedError && e.message.includes(directory));
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("reads the linker's variables from /proc/self/environ", () => {
    // Whatever this process started with, /proc/self/environ must be readable for the loader to
    // see it - and parse to the same three variables.
    const block = readFileSync('/proc/self/environ');
    const values = linuxReadEnvironment({}, block);
    assert.deepEqual([...values.keys()].sort(), [ENV_AUDIT, ENV_LIBRARY_PATH, ENV_PRELOAD]);
  });

  it('probes tell a missing path from a present one', () => {
    assert.equal(unixProbe('/'), 0);
    assert.equal(unixProbe('/definitely/not/here'), ENOENT);
  });

  it("describes this user's files through status and readlink", () => {
    const directory = temporaryDirectory('hkdfguard-status-');
    try {
      const file = join(directory, 'file');
      const link = join(directory, 'link');
      writeFileSync(file, 'x');
      chmodSync(file, 0o640);
      symlinkSync('file', link);

      const status = linuxStatus(file);
      assert.deepEqual([status?.type, status?.uid, (status?.perm ?? 0) & 0o777], [FileType.Regular, process.getuid!(), 0o640]);
      const linkStatus = linuxStatus(link);
      assert.deepEqual([linkStatus?.type, linkStatus?.uid], [FileType.Symlink, process.getuid!()]);
      assert.equal(linuxReadLink(link), 'file');
      assert.equal(linuxStatus(join(directory, 'missing')), undefined);

      // Owned by this user (or, as root, under the world-writable temp directory), so the loader
      // refuses it - however it is reached.
      assert.throws(() => linuxTrustedFile(file), UntrustedError);
      assert.throws(() => linuxTrustedFile(link), UntrustedError);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("passes the post-load checks for this process's libc", () => {
    // The checks the loader runs after mapping the library, against a library every Linux host has:
    // an export of libc is placed in libc's own file, and libc's dependency closure is trusted.
    const native = nativeAddon();
    const libc = native.loadedPath!('libc.so.6');
    assert.ok(libc !== null, 'libc.so.6 is not loaded');
    const trusted = linuxTrustedFile(libc);
    const handle = native.load(trusted); // already mapped: only another reference
    try {
      const mapped = native.symbolImagePath!(handle, 'getpid');
      linuxVerifyLoadedImage(trusted, mapped === null ? null : linuxTrustedFile(mapped));
    } finally {
      native.unload(handle);
    }
    linuxVerifyDependencies(trusted, elfReadNeededFile, (soname) => native.loadedPath!(soname), linuxTrustedFile);
  });

  it('reports the library as not installed, naming libhkdfguard1, without the package', (t) => {
    if (installedLinuxLibraryPath() !== undefined) {
      t.skip('The libhkdfguard1 package is installed.');
      return;
    }
    assert.throws(() => hostLibrary(), (e: unknown) => e instanceof NotInstalledError && e.message.includes('libhkdfguard1'));
  });

  it('finds the installed library needing the TPM stack and libc', (t) => {
    const path = installedPath(t);
    if (path === undefined) return;
    const needed = elfReadNeededFile(linuxTrustedFile(path));
    for (const name of ['libtss2-esys.so.0', 'libc.so.6']) assert.ok(needed.includes(name), `DT_NEEDED is ${needed.join(', ')}`);
  });

  it('finds the installed library a known release in a trusted location', (t) => {
    const path = installedPath(t);
    if (path === undefined) return;
    const resolved = linuxTrustedFile(path);
    linuxVerifyContent(resolved, sha256File, linuxKnownReleases);
  });

  it('loads the installed library through the verified loader, its dependencies trusted', async (t) => {
    const path = installedPath(t);
    if (path === undefined) return;
    const library = hostLibrary(); // installed: a failure here fails the test
    assert.equal(hostLibrary(), library); // once per process

    // Through the binding: a wrap for a service nobody provisioned. Whatever this host's providers
    // say, the answer is a status code the binding can describe.
    const [status] = await library.wrapDek('hkdfguard.loadertest.unprovisioned', new Uint8Array(DEK_LENGTH), new Uint8Array(MAX_WRAPPED_KEY_BYTES));
    assert.ok(status === Status.ok || library.describeStatus(status) !== undefined, `undescribed status ${status}`);

    // What the dynamic linker mapped is the verified file, and every dependency it pulled in came
    // from a trusted file. Opening the verified path again only takes another reference to it.
    const native = nativeAddon();
    const expected = linuxTrustedFile(path);
    const handle = native.load(expected);
    try {
      const mapped = native.symbolImagePath!(handle, PROBE_EXPORT);
      assert.ok(mapped !== null, `no image for ${PROBE_EXPORT}`);
      assert.equal(linuxTrustedFile(mapped), expected);
    } finally {
      native.unload(handle);
    }
    linuxVerifyDependencies(expected, elfReadNeededFile, (soname) => native.loadedPath!(soname), linuxTrustedFile);
  });
});

describe('the Linux native library against a provisioned service', { skip: process.platform !== 'linux' && 'Linux only' }, () => {
  it('round-trips a wrapped DEK that fits the key-file limit', async (t) => {
    const p = await provisioned(t);
    if (p === undefined) return;
    const dek = randomDek();
    const wrapped = await wrap(p, dek);
    const recovered = new Uint8Array(DEK_LENGTH);
    const [status, written] = await p.library.unwrapDek(p.service, wrapped, recovered);
    assertStatus(p.library, Status.ok, status);
    assert.equal(written, DEK_LENGTH);
    assert.deepEqual(recovered, dek);
    assert.ok(wrapped.length > DEK_LENGTH && wrapped.length <= MAX_WRAPPED_KEY_BYTES, `payload is ${wrapped.length} bytes`);
  });

  it('gives different payloads for the same DEK wrapped twice', async (t) => {
    // A fresh salt per payload: equal DEKs must not be recognizable from their wrapped form.
    const p = await provisioned(t);
    if (p === undefined) return;
    const dek = randomDek();
    assert.notDeepEqual(await wrap(p, dek), await wrap(p, dek));
  });

  it('generates distinct DEKs', async (t) => {
    const p = await provisioned(t);
    if (p === undefined) return;
    const seen = new Set<string>();
    for (let i = 0; i < 4; i++) {
      const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
      const [status, written] = await p.library.generateAndWrapDek(p.service, wrapped);
      assertStatus(p.library, Status.ok, status);
      const dek = new Uint8Array(DEK_LENGTH);
      const [unwrapStatus] = await p.library.unwrapDek(p.service, wrapped.subarray(0, written), dek);
      assertStatus(p.library, Status.ok, unwrapStatus);
      seen.add(Buffer.from(dek).toString('hex'));
    }
    assert.equal(seen.size, 4);
  });

  it('refuses an unwrap under another provisioned service as a fingerprint mismatch, zeroing the whole buffer', async (t) => {
    const p = await provisioned(t, { otherService: true });
    if (p === undefined) return;
    const other = process.env[TEST_OTHER_SERVICE_VARIABLE]!;
    const wrapped = await wrap(p, randomDek());

    const [status] = await p.library.unwrapDek(other, wrapped, filled(0xaa, 64));
    assertStatus(p.library, Status.kekFingerprintMismatch, status);

    const destination = filled(0xaa, 64);
    const otherWrapper = NativeKeyWrapperV1.create(other);
    await assert.rejects(otherWrapper.unwrap(wrapped, destination), (e: unknown) => e instanceof StatusError && e.status === Status.kekFingerprintMismatch);
    assert.ok(isZero(destination), 'the destination was not zeroed');
  });

  it('has no KEK for a service the allowlist does not name', async (t) => {
    const p = await provisioned(t, { pinnedNamesAllowlist: true });
    if (p === undefined) return;
    const [wrapStatus] = await p.library.wrapDek(UNPROVISIONED_SERVICE_NAME, new Uint8Array(DEK_LENGTH), new Uint8Array(MAX_WRAPPED_KEY_BYTES));
    assertStatus(p.library, Status.kekNotFound, wrapStatus);
    const [generateStatus] = await p.library.generateAndWrapDek(UNPROVISIONED_SERVICE_NAME, new Uint8Array(MAX_WRAPPED_KEY_BYTES));
    assertStatus(p.library, Status.kekNotFound, generateStatus);
    assert.ok(p.library.describeStatus(Status.kekNotFound)!.includes('provision'));
  });

  it('refuses a change to any byte of the payload, revealing nothing', async (t) => {
    // Every byte is either ciphertext or bound into the AEAD's associated data and the HKDF info,
    // so no single-byte change may unwrap - to the original DEK or to any other. Each refusal can
    // cost a TPM ECDH, so this changes the first and last eight bytes and every fifth byte
    // between: a spread that lands in every field of the payload.
    const p = await provisioned(t);
    if (p === undefined) return;
    const wrapped = await wrap(p, randomDek());
    // A changed header byte makes the payload malformed or of an unknown version; a changed
    // fingerprint routes it to no KEK; anything else fails authentication.
    const refusals: number[] = [Status.payloadAuthFailed, Status.payloadMalformed, Status.payloadUnsupported, Status.kekFingerprintMismatch];
    for (let i = 0; i < wrapped.length; i++) {
      if (!(i < 8 || i >= wrapped.length - 8 || i % 5 === 0)) continue;
      const tampered = Uint8Array.from(wrapped);
      tampered[i]! ^= 0x01;
      const destination = filled(0xaa, DEK_LENGTH);
      await assert.rejects(p.wrapper.unwrap(tampered, destination), (e: unknown) =>
        e instanceof StatusError && refusals.includes(e.status) && p.library.describeStatus(e.status) !== undefined, `byte ${i} of ${wrapped.length}`);
      assert.ok(isZero(destination), `the destination after changing byte ${i}`);
    }
  });

  it('refuses a truncated or extended payload', async (t) => {
    const p = await provisioned(t);
    if (p === undefined) return;
    const wrapped = await wrap(p, randomDek());
    const extended = new Uint8Array(wrapped.length + 1);
    extended.set(wrapped);
    for (const [what, payload] of [['truncated', wrapped.subarray(0, wrapped.length - 1)], ['extended', extended], ['8 bytes', wrapped.subarray(0, 8)]] as const) {
      const [status] = await p.library.unwrapDek(p.service, payload, new Uint8Array(DEK_LENGTH));
      assertStatus(p.library, Status.payloadMalformed, status, what);
    }
  });

  it('refuses an empty payload', async (t) => {
    const p = await provisioned(t);
    if (p === undefined) return;
    const [status] = await p.library.unwrapDek(p.service, new Uint8Array(0), new Uint8Array(DEK_LENGTH));
    assert.ok(status === Status.invalidArgument || status === Status.payloadMalformed, `status ${status}`);
  });

  it('refuses a DEK of the wrong length as an invalid argument', async (t) => {
    const p = await provisioned(t);
    if (p === undefined) return;
    for (const length of [0, 16, DEK_LENGTH - 1, DEK_LENGTH + 1, 64]) {
      const [status] = await p.library.wrapDek(p.service, new Uint8Array(length), new Uint8Array(MAX_WRAPPED_KEY_BYTES));
      assertStatus(p.library, Status.invalidArgument, status, `${length} bytes`);
    }
  });

  it('checks service names itself', async (t) => {
    // The wrapper's validation normally stops these before the boundary; the library must refuse
    // them on its own too, for every operation.
    const p = await provisioned(t);
    if (p === undefined) return;
    for (const service of ['', '.leading.dot', 'double..dot', 'has space', 'slash/inside', 'dash-inside', `caf${String.fromCharCode(0xe9)}`, 'a'.repeat(129)]) {
      assert.ok(!isValidServiceName(service), `'${service}' is a valid service name`);
      const [wrapStatus] = await p.library.wrapDek(service, new Uint8Array(DEK_LENGTH), new Uint8Array(MAX_WRAPPED_KEY_BYTES));
      assertStatus(p.library, Status.invalidServiceName, wrapStatus, `wrap under '${service}'`);
      const [generateStatus] = await p.library.generateAndWrapDek(service, new Uint8Array(MAX_WRAPPED_KEY_BYTES));
      assertStatus(p.library, Status.invalidServiceName, generateStatus, `generate under '${service}'`);
      const [unwrapStatus] = await p.library.unwrapDek(service, new Uint8Array(100), new Uint8Array(DEK_LENGTH));
      assertStatus(p.library, Status.invalidServiceName, unwrapStatus, `unwrap under '${service}'`);
    }
  });

  it('accepts a service name of the maximum length', async (t) => {
    // 128 characters is valid; with the allowlist it simply has no KEK, without one it may.
    const p = await provisioned(t);
    if (p === undefined) return;
    const [status] = await p.library.wrapDek('a'.repeat(MAX_SERVICE_NAME_LENGTH), new Uint8Array(DEK_LENGTH), new Uint8Array(MAX_WRAPPED_KEY_BYTES));
    assert.notEqual(status, Status.invalidServiceName);
  });

  it('reports a too-small buffer with a capacity that suffices', async (t) => {
    // The reported capacity is an upper bound for any payload, not the exact size of this one; it
    // must fit a key file and be enough.
    const p = await provisioned(t);
    if (p === undefined) return;
    const dek = randomDek();

    const [tooSmall, required] = await p.library.wrapDek(p.service, dek, new Uint8Array(1));
    assertStatus(p.library, Status.bufferTooSmall, tooSmall);
    assert.ok(required > DEK_LENGTH && required <= MAX_WRAPPED_KEY_BYTES, `required capacity ${required}`);

    const buffer = new Uint8Array(required);
    const [status, written] = await p.library.wrapDek(p.service, dek, buffer);
    assertStatus(p.library, Status.ok, status);
    assert.ok(written > DEK_LENGTH && written <= required, `wrote ${written} bytes into ${required}`);
    const exact = buffer.subarray(0, written);

    const [generateTooSmall, generateRequired] = await p.library.generateAndWrapDek(p.service, new Uint8Array(1));
    assertStatus(p.library, Status.bufferTooSmall, generateTooSmall);
    assert.equal(generateRequired, required);

    const [unwrapTooSmall, unwrapRequired] = await p.library.unwrapDek(p.service, exact, filled(0xaa, DEK_LENGTH - 1));
    assertStatus(p.library, Status.bufferTooSmall, unwrapTooSmall);
    assert.equal(unwrapRequired, DEK_LENGTH);
    const short = filled(0xaa, DEK_LENGTH - 1);
    await assert.rejects(p.wrapper.unwrap(exact, short), (e: unknown) => e instanceof StatusError && e.status === Status.bufferTooSmall);
    assert.ok(isZero(short), 'the short destination was not zeroed');
  });

  it('gives concurrent callers each their own DEK back', async (t) => {
    // Every call runs on libuv's thread pool, so these overlap in the native library.
    const p = await provisioned(t);
    if (p === undefined) return;
    const results = await Promise.all(Array.from({ length: 8 }, async () => {
      const dek = randomDek();
      const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
      const [wrapStatus, written] = await p.library.wrapDek(p.service, dek, wrapped);
      const recovered = new Uint8Array(DEK_LENGTH);
      const [unwrapStatus] = wrapStatus === Status.ok ? await p.library.unwrapDek(p.service, wrapped.subarray(0, written), recovered) : [wrapStatus];
      return { wrapStatus, unwrapStatus, same: Buffer.compare(dek, recovered) === 0 };
    }));
    for (const result of results) assert.deepEqual(result, { wrapStatus: Status.ok, unwrapStatus: Status.ok, same: true });
  });

  it('reveals the DEK of a key file wrapped by the provisioning tool through the wrapper', async (t) => {
    // The deployment path: hkdfguard wraps a delivered DEK on the host, in its own process, and the
    // application unwraps the key file through this binding.
    const p = await provisioned(t, { cli: true });
    if (p === undefined) return;
    // Not under /tmp: the library refuses a key file in any group- or other-writable directory chain.
    const directory = keyFileDirectory(t, 'hkdfguard-cli-');
    if (directory === undefined) return;
    const dek = randomDek();
    const dekFile = join(directory, 'dek');
    const keyFile = join(directory, 'key.bin');
    writeFileSync(dekFile, Buffer.from(dek).toString('base64'), { mode: 0o600, flag: 'wx' });

    const { status, output } = runCli('wrap', '--key-file-path', keyFile, '--service-name', p.service, '--dek-file', dekFile);
    assert.equal(status, 0, `hkdfguard wrap exited ${status}: ${output}`);
    assert.equal(statSync(keyFile).mode & 0o777, 0o600);

    // Read back as an application does - through the library's hkdfguard_open_file - and unwrapped.
    const wrapped = await p.wrapper.readKeyFile(keyFile);
    assert.deepEqual(wrapped, new Uint8Array(readFileSync(keyFile)));
    const recovered = new Uint8Array(DEK_LENGTH);
    assert.equal(await p.wrapper.unwrap(wrapped, recovered), DEK_LENGTH);
    assert.deepEqual(recovered, dek);
  });

  it('reports the test service as provisioned through the provisioning tool', async (t) => {
    const p = await provisioned(t, { cli: true });
    if (p === undefined) return;
    const { status, output } = runCli('provision', '--service-name', p.service);
    assert.equal(status, 0, `hkdfguard provision exited ${status}: ${output}`);
  });
});

describe('the private key-file folder the Linux tests use (test support)', { skip: process.platform !== 'linux' && 'Linux only' }, () => {
  // keyFileDirectory: the Linux native library refuses a key file whose directory chain has a group-
  // or other-writable directory, sticky or not, so the tests that write key files use this instead
  // of the temp directory.

  /** The trusted root the folders are made in; skips the test, saying why, without one. */
  function root(t: TestContext): string | undefined {
    const { root: directory, skipReason } = linuxKeyFileRoot();
    if (directory === undefined) t.skip(skipReason);
    return directory;
  }

  it('makes a private folder outside the temp directories, trusted all the way up, and removes it after the test', async (t) => {
    if (root(t) === undefined) return;
    let made: string | undefined;
    await t.test('a test using it', (inner) => {
      made = keyFileDirectory(inner, 'hkdfguard-helper-');
      assert.ok(made !== undefined, 'the test was skipped');
      const status = statSync(made);
      assert.deepEqual([status.isDirectory(), status.uid, status.mode & 0o7777], [true, process.getuid!(), 0o700]);
      assert.equal(untrustedDirectoryChain(made), undefined);
      for (const sticky of ['/tmp/', '/var/tmp/', '/dev/shm/']) assert.ok(!made.startsWith(sticky), made);
      writeFileSync(join(made, 'key.bin'), new Uint8Array(4), { mode: 0o600 });
    });
    assert.ok(made !== undefined && !existsSync(made), `${made} is still there after its test`);
  });

  it('finds the sticky, world-writable temp directories untrusted', () => {
    for (const directory of ['/tmp', '/var/tmp', '/dev/shm']) {
      if (!existsSync(directory)) continue;
      assert.match(untrustedDirectoryChain(directory) ?? 'trusted', /writable by its group or others \(mode 1777\)/, directory);
    }
  });

  it('finds a group-writable or sticky directory untrusted, and every directory under one', (t) => {
    const directory = keyFileDirectory(t, 'hkdfguard-helper-');
    if (directory === undefined) return;
    const shared = join(directory, 'shared');
    const inside = join(shared, 'private');
    mkdirSync(inside, { recursive: true, mode: 0o700 });
    chmodSync(inside, 0o700);
    for (const mode of [0o770, 0o707, 0o1777, 0o1770]) {
      chmodSync(shared, mode);
      assert.match(untrustedDirectoryChain(shared) ?? 'trusted', /writable by its group or others/, mode.toString(8));
      const why = untrustedDirectoryChain(inside) ?? 'trusted';
      assert.ok(why.startsWith(`${shared} is writable by its group or others`), `${mode.toString(8)}: ${why}`);
    }
    chmodSync(shared, 0o755);
    assert.equal(untrustedDirectoryChain(inside), undefined);
  });
});

function runCli(...args: string[]): { status: number | null; output: string } {
  const result = spawnSync(CLI, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: CLI_TIMEOUT_MS });
  if (result.error !== undefined) throw result.error;
  return { status: result.status, output: `${result.stdout}${result.stderr}` };
}


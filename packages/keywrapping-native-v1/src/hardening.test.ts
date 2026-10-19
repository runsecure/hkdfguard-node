import { strict as assert } from 'node:assert';
import { readFileSync, statSync } from 'node:fs';
import { describe, it, type TestContext } from 'node:test';
import { NotInstalledError, UnsupportedPlatformError } from './errors.js';
import { hostLibrary } from './host.js';
import { nativeAddon } from './native.js';
import { hardenProcess } from './wrapper.js';

/*
 * hardenProcess against the real native library, hardening this very test process - so these tests
 * run only when asked for, with HKDFGUARD_TEST_PROCESS_HARDENING=1, on their platform, with the
 * native library installed. node --test runs each test file in its own process, so the rest of the
 * suite is never hardened by them. To run only these:
 *
 *   HKDFGUARD_TEST_PROCESS_HARDENING=1 node --test-name-pattern="<test name>" dist/hardening.test.js
 *
 * The unit tests of the option handling, flags and error messages are in wrapper.test.ts.
 */

const VARIABLE = 'HKDFGUARD_TEST_PROCESS_HARDENING';

// OpenProcess access rights, and the error a refused one fails with.
const PROCESS_VM_READ = 0x0010;
const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
const ERROR_ACCESS_DENIED = 5;

/** Whether to run a self-test on `platform`; skips the test, saying why, when not. */
function shouldRun(t: TestContext, platform: NodeJS.Platform): boolean {
  if (process.env[VARIABLE] !== '1') {
    t.skip(`hardens the test process itself; set ${VARIABLE}=1 to run it`);
    return false;
  }
  if (process.platform !== platform) {
    t.skip(`${platform} only`);
    return false;
  }
  try {
    hostLibrary();
  } catch (error) {
    if (error instanceof NotInstalledError || error instanceof UnsupportedPlatformError) {
      t.skip(`needs the native library installed: ${error.message}`);
      return false;
    }
    throw error;
  }
  return true;
}

describe('hardenProcess, hardening this test process (opt-in)', () => {
  /*
   * Afterwards no debugger can attach to the test process and it writes no core dump. The kernel
   * makes a non-dumpable process's /proc/<pid> files root's, which is how the dumpable flag shows
   * from inside the process without a prctl call.
   */
  it('on Linux, disables core dumps and clears the dumpable flag', (t) => {
    if (!shouldRun(t, 'linux')) return;

    hardenProcess();

    const core = readFileSync('/proc/self/limits', 'utf8').split('\n').find((line) => line.startsWith('Max core file size'));
    assert.ok(core !== undefined, '/proc/self/limits has no core file size line');
    const [soft, hard] = core.slice('Max core file size'.length).trim().split(/\s+/);
    assert.equal(soft, '0');
    assert.equal(hard, '0');

    if (process.getuid?.() === 0) {
      t.diagnostic('running as root: /proc/<pid> is root-owned either way, so the dumpable flag is not checked');
    } else {
      assert.equal(statSync(`/proc/${process.pid}/status`).uid, 0, 'a non-dumpable process\'s /proc/<pid> files belong to root');
    }

    // Idempotent: hardening an already hardened process succeeds.
    hardenProcess();
  });

  /*
   * The process's access list then grants its own account only query, synchronize and terminate -
   * so even this process, asking without SeDebugPrivilege, can no longer open itself to read its
   * memory, though it can still query it. OpenProcess is called by the add-on's test-only
   * testOpenOwnProcess, from inside this process: another process would be a different test.
   */
  it('on Windows, closes the process to its own account', (t) => {
    if (!shouldRun(t, 'win32')) return;
    const openOwnProcess = nativeAddon().testOpenOwnProcess!;

    hardenProcess();

    assert.equal(openOwnProcess(PROCESS_VM_READ), ERROR_ACCESS_DENIED);
    assert.equal(openOwnProcess(PROCESS_QUERY_LIMITED_INFORMATION), 0);

    // Idempotent: hardening an already hardened process succeeds.
    hardenProcess();
  });

  /*
   * The strict form, on Windows: a console process sharing no named objects - this test process -
   * can meet requireProtectedSignature, and threads started afterwards are closed too.
   */
  it('on Windows, with requireProtectedSignature, succeeds', (t) => {
    if (!shouldRun(t, 'win32')) return;
    const openOwnProcess = nativeAddon().testOpenOwnProcess!;

    hardenProcess({ requireProtectedSignature: true });

    assert.equal(openOwnProcess(PROCESS_VM_READ), ERROR_ACCESS_DENIED);
    assert.equal(openOwnProcess(PROCESS_QUERY_LIMITED_INFORMATION), 0);

    // Idempotent, and a later plain call leaves the stricter state in place.
    hardenProcess({ requireProtectedSignature: true });
    hardenProcess();
  });
});

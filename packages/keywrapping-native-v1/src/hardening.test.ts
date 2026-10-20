import { strict as assert } from 'node:assert';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface, type Interface } from 'node:readline';
import { describe, it, type TestContext } from 'node:test';
import { NotInstalledError, UnsupportedPlatformError } from './errors.js';
import { hostLibrary } from './host.js';
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

/*
 * Windows: another process of this same account - the attacker the hardening keeps out: any code
 * running as the service's user - asking OpenProcess for this test process by its pid. Node has no
 * FFI, and the production add-on carries no test-only exports, so the call is made by Windows
 * PowerShell, through a P/Invoke declaration compiled when it starts. It runs with this process's own
 * token (inherited, never elevated beyond it), and without SeDebugPrivilege enabled, so it meets the
 * same access check on this process's DACL that this process asking for itself would. It is started
 * before the hardening, so nothing the hardening does to process creation can stand in its way, and
 * answers one access mask per line: 0 if OpenProcess succeeded (the handle is closed at once), else
 * the Windows error.
 */
const OPENER_SCRIPT = `
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class HkdfGuardOpenProcessProbe {
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, uint processId);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
    public static int Open(uint processId, uint access) {
        IntPtr handle = OpenProcess(access, false, processId);
        if (handle == IntPtr.Zero) return Marshal.GetLastWin32Error();
        CloseHandle(handle);
        return 0;
    }
}
'@
$target = [uint32]$args[0]
[Console]::Out.WriteLine('ready')
[Console]::Out.Flush()
while ($null -ne ($line = [Console]::In.ReadLine())) {
    [Console]::Out.WriteLine([HkdfGuardOpenProcessProbe]::Open($target, [uint32]$line))
    [Console]::Out.Flush()
}
`;

const OPENER_TIMEOUT_MS = 60_000;

/** The second, same-account process that opens this one; see OPENER_SCRIPT. */
class SameAccountOpener {
  private readonly lines: AsyncIterator<string>;

  private constructor(private readonly child: ChildProcessWithoutNullStreams, private readonly reader: Interface) {
    this.lines = reader[Symbol.asyncIterator]();
  }

  /** Starts the opener, once it is ready to answer. */
  static async start(): Promise<SameAccountOpener> {
    const powershell = join(process.env['SystemRoot'] ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    // The script takes this process's pid as its argument: -Command's script block, by -EncodedCommand
    // so nothing in it needs quoting.
    const command = `& { ${OPENER_SCRIPT} } ${process.pid}`;
    const child = spawn(powershell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', Buffer.from(command, 'utf16le').toString('base64')],
      { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    let errors = '';
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => { errors += chunk; });
    const opener = new SameAccountOpener(child, createInterface({ input: child.stdout }));
    const first = await opener.next();
    if (first !== 'ready') {
      opener.close();
      throw new Error(`the PowerShell opener did not start: ${first ?? 'it exited'} ${errors}`.trim());
    }
    return opener;
  }

  /** 0 if the opener may open this process with `access`, else the Windows error. */
  async open(access: number): Promise<number> {
    this.child.stdin.write(`${access}\n`);
    const answer = await this.next();
    assert.ok(answer !== undefined && /^\d+$/.test(answer), `the opener answered ${answer}`);
    return Number(answer);
  }

  close(): void {
    this.reader.close();
    this.child.stdin.end();
    this.child.kill();
  }

  private async next(): Promise<string | undefined> {
    let timer: NodeJS.Timeout | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`the PowerShell opener has not answered after ${OPENER_TIMEOUT_MS / 1000}s`)), OPENER_TIMEOUT_MS);
    });
    try {
      const { value, done } = await Promise.race([this.lines.next(), deadline]);
      return done ? undefined : value.trim();
    } finally {
      clearTimeout(timer);
    }
  }
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
   * so another process of that account, asking without SeDebugPrivilege, can no longer open it to
   * read its memory, though it can still query it. Before the hardening it could do both.
   */
  it('on Windows, closes the process to its own account', async (t) => {
    if (!shouldRun(t, 'win32')) return;
    const opener = await SameAccountOpener.start();
    try {
      assert.equal(await opener.open(PROCESS_VM_READ), 0, 'before hardening, this account may read the process');

      hardenProcess();

      assert.equal(await opener.open(PROCESS_VM_READ), ERROR_ACCESS_DENIED);
      assert.equal(await opener.open(PROCESS_QUERY_LIMITED_INFORMATION), 0);

      // Idempotent: hardening an already hardened process succeeds.
      hardenProcess();
      assert.equal(await opener.open(PROCESS_VM_READ), ERROR_ACCESS_DENIED);
    } finally {
      opener.close();
    }
  });

  /*
   * The strict form, on Windows: a console process sharing no named objects - this test process -
   * can meet requireProtectedSignature, and threads started afterwards are closed too.
   */
  it('on Windows, with requireProtectedSignature, succeeds', async (t) => {
    if (!shouldRun(t, 'win32')) return;
    const opener = await SameAccountOpener.start();
    try {
      assert.equal(await opener.open(PROCESS_VM_READ), 0, 'before hardening, this account may read the process');

      hardenProcess({ requireProtectedSignature: true });

      assert.equal(await opener.open(PROCESS_VM_READ), ERROR_ACCESS_DENIED);
      assert.equal(await opener.open(PROCESS_QUERY_LIMITED_INFORMATION), 0);

      // Idempotent, and a later plain call leaves the stricter state in place.
      hardenProcess({ requireProtectedSignature: true });
      hardenProcess();
      assert.equal(await opener.open(PROCESS_VM_READ), ERROR_ACCESS_DENIED);
    } finally {
      opener.close();
    }
  });
});

import { execFileSync } from 'node:child_process';
import { join } from 'node:path';

/*
 * Windows helpers for the tests that read real key files through the managed checks
 * (@runsecure/hkdfguard-securefile): who the test account is, changing a file's DACL, and a path's
 * 8.3 short form. Each runs a System32 tool by its full path, never one found on PATH.
 */

function system32(tool: string): string {
  return join(process.env['SystemRoot'] ?? 'C:\\Windows', 'System32', tool);
}

let userSid: string | undefined;

/** The SID of the account running the tests, as whoami reports it. Windows only. */
export function windowsCurrentUserSid(): string {
  if (userSid === undefined) {
    const output = execFileSync(system32('whoami.exe'), ['/user', '/fo', 'csv', '/nh'], { encoding: 'utf8' }).trim();
    const sid = output.slice(output.lastIndexOf(',') + 1).replace(/"/g, ''); // "DOMAIN\name","S-1-5-21-..."
    if (!sid.startsWith('S-1-')) throw new Error(`whoami reported no SID: ${output}`);
    userSid = sid;
  }
  return userSid;
}

/** Runs icacls with `args` (for example a path, "/grant", "*S-1-5-32-545:(W)"), failing on any error. Windows only. */
export function icacls(...args: string[]): void {
  execFileSync(system32('icacls.exe'), args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

/**
 * The 8.3 short form of an existing path (Scripting.FileSystemObject's ShortPath), or the path
 * itself when the volume has short names turned off. Windows only.
 */
export function windowsShortPath(path: string): string {
  const command = '$item = Get-Item -LiteralPath $env:HKDFGUARD_SHORT_PATH; $fso = New-Object -ComObject Scripting.FileSystemObject; '
    + 'if ($item.PSIsContainer) { $fso.GetFolder($item.FullName).ShortPath } else { $fso.GetFile($item.FullName).ShortPath }';
  const output = execFileSync(system32(join('WindowsPowerShell', 'v1.0', 'powershell.exe')), ['-NoProfile', '-NonInteractive', '-Command', command],
    { encoding: 'utf8', env: { ...process.env, HKDFGUARD_SHORT_PATH: path } }).trim();
  return output === '' ? path : output;
}

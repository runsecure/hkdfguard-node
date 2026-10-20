import { strict as assert } from 'node:assert';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { awaitNativeAccess, probeNativeAccess } from '@runsecure/hkdfguard-test-support';

/*
 * The deadline on the first native call under a service (awaitNativeAccess, in the test-support
 * package), which turns a macOS keychain dialog nobody answers into a failure rather than a hang. It
 * makes the call in a child process; here that child loads a stand-in for this package, so the
 * probe's own behaviour is checked on every platform, with no native library.
 */

const directory = mkdtempSync(join(tmpdir(), 'hkdfguard-access-'));
after(() => rmSync(directory, { recursive: true, force: true }));

/** A stand-in entry module whose generateAndWrap runs `body`. */
function standIn(name: string, body: string): string {
  const path = join(directory, `${name}.js`);
  writeFileSync(path, `exports.NativeKeyWrapperV1 = { create: (service) => ({ generateAndWrap: (output) => { ${body} } }) };\n`);
  return path;
}

describe('the deadline on the first native call (test support)', () => {
  it('resolves once the call returns, whatever it answers', async () => {
    await probeNativeAccess('service.answers', standIn('answers', 'return Promise.resolve(output.length);'), 30_000);
    await probeNativeAccess('service.refuses', standIn('refuses', 'return Promise.reject(new Error("KEK access denied"));'), 30_000);
  });

  it('fails, explaining the keychain dialog, when the call never returns - and does not hang', async () => {
    // Blocks as an unanswered dialog would: the process stays alive and the promise never settles.
    const blocked = standIn('blocked', 'setInterval(() => {}, 1000); return new Promise(() => {});');
    const started = Date.now();
    await assert.rejects(probeNativeAccess('service.blocked', blocked, 1_500), (e: unknown) =>
      e instanceof Error && e.message.includes("'service.blocked'") && e.message.includes('Always Allow') && e.message.includes('-18'));
    assert.ok(Date.now() - started < 20_000, 'the probe outlived its deadline');
  });

  it('only probes on macOS', { skip: process.platform === 'darwin' && 'macOS probes' }, async () => {
    // Off macOS there is no dialog to wait for: it resolves without starting anything.
    await awaitNativeAccess('service.blocked', join(directory, 'no-such-module.js'), 1);
  });
});

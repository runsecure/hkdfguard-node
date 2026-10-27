import { strict as assert } from 'node:assert';
import { closeSync, openSync, readSync } from 'node:fs';
import { describe, it } from 'node:test';
import { NotInstalledError, UntrustedError } from './errors.js';
import {
  MAC_MINIMUM_LIBRARY_VERSION, MAC_SYSTEM_PATH, MAC_VERSION_READ_LIMIT, macChoosePath, macDylibCurrentVersion, macFormatVersion,
  macHomeFromAccount, macPackVersion, macRequireMinimumVersion,
} from './macpolicy.js';
import { ENOENT } from './unixpath.js';

// Mach-O images built in memory for the version check, which runs on every platform.

const ARM64 = 0x0100000c, X86_64 = 0x01000007;
const version = macPackVersion;

function idDylib(v: number): Uint8Array {
  const cmd = new Uint8Array(32); // cmd, cmdsize, name offset, timestamp, current, compatibility, "x\0" + padding
  const view = new DataView(cmd.buffer);
  view.setUint32(0, 0xd, true);
  view.setUint32(4, 32, true);
  view.setUint32(8, 24, true);
  view.setUint32(16, v, true);
  view.setUint32(20, version(1, 0, 0), true);
  cmd[24] = 0x78;
  return cmd;
}

function otherCommand(): Uint8Array { // LC_UUID
  const cmd = new Uint8Array(24);
  const view = new DataView(cmd.buffer);
  view.setUint32(0, 0x1b, true);
  view.setUint32(4, 24, true);
  return cmd;
}

function thinImage(cputype: number, ...commands: Uint8Array[]): Uint8Array {
  const body = commands.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(32 + body);
  const view = new DataView(out.buffer);
  view.setUint32(0, 0xfeedfacf, true);
  view.setUint32(4, cputype, true);
  view.setUint32(12, 6, true); // MH_DYLIB
  view.setUint32(16, commands.length, true);
  view.setUint32(20, body, true);
  let at = 32;
  for (const c of commands) { out.set(c, at); at += c.length; }
  return out;
}

/** A 32-bit fat image with each slice at a 4 KiB boundary. */
function fatImage(slices: [number, Uint8Array][]): Uint8Array {
  const out = new Uint8Array(4096 * (slices.length + 1));
  const view = new DataView(out.buffer);
  view.setUint32(0, 0xcafebabe, false);
  view.setUint32(4, slices.length, false);
  slices.forEach(([cpu, image], i) => {
    view.setUint32(8 + 20 * i, cpu, false);
    view.setUint32(8 + 20 * i + 8, 4096 * (i + 1), false);
    view.setUint32(8 + 20 * i + 12, image.length, false);
    out.set(image, 4096 * (i + 1));
  });
  return out;
}

function patched(image: Uint8Array, offset: number, value: number): Uint8Array {
  const copy = image.slice();
  new DataView(copy.buffer).setUint32(offset, value, true);
  return copy;
}

const untrusted = (fn: () => void, ...fragments: string[]) => assert.throws(fn, (e: unknown) =>
  e instanceof UntrustedError && fragments.every((f) => e.message.includes(f)));

describe('macOS library version', () => {
  it('reads LC_ID_DYLIB from a thin arm64 image', () => {
    assert.equal(macDylibCurrentVersion(thinImage(ARM64, otherCommand(), idDylib(version(0, 9, 0)))), version(0, 9, 0));
  });

  it('accepts the minimum and above, and refuses below it', () => {
    assert.equal(MAC_MINIMUM_LIBRARY_VERSION, version(0, 9, 0));
    for (const v of [version(0, 9, 0), version(0, 9, 1), version(0, 10, 0), version(1, 0, 0)]) {
      macRequireMinimumVersion('/lib.dylib', thinImage(ARM64, idDylib(v)));
    }
    untrusted(() => macRequireMinimumVersion('/lib.dylib', thinImage(ARM64, idDylib(version(0, 8, 0)))), '0.8.0', '0.9.0', '/lib.dylib');
  });

  it('refuses what is not a well-formed arm64 dylib', () => {
    const good = thinImage(ARM64, otherCommand(), idDylib(version(0, 9, 0)));
    const cases: Record<string, Uint8Array> = {
      'empty': new Uint8Array(0),
      'truncated header': good.subarray(0, 20),
      'truncated load commands': good.subarray(0, good.length - 8),
      'cmdsize overflow': patched(good, 36, 0xfffffff8),
      'cmdsize not 8-aligned': patched(good, 36, 20),
      'cmdsize below 8': patched(good, 36, 4),
      'ncmds beyond sizeofcmds': patched(thinImage(ARM64, otherCommand()), 16, 5),
      'sizeofcmds past the read': patched(thinImage(ARM64, idDylib(version(0, 9, 0))), 20, 1 << 20),
      'wrong magic': patched(good, 0, 0xfeedface),
      'no LC_ID_DYLIB': thinImage(ARM64, otherCommand()),
      'x86_64-only thin file': thinImage(X86_64, idDylib(version(0, 9, 0))),
      'fat without arm64': fatImage([[X86_64, thinImage(X86_64, idDylib(version(0, 9, 0)))]]),
    };
    for (const [name, data] of Object.entries(cases)) {
      assert.throws(() => macDylibCurrentVersion(data), Error, name);
      untrusted(() => macRequireMinimumVersion('/lib.dylib', data), '/lib.dylib');
    }
  });

  it('reads the arm64 slice of a fat image, and refuses one beyond the bytes read', () => {
    const data = fatImage([[X86_64, thinImage(X86_64, idDylib(version(1, 0, 0)))], [ARM64, thinImage(ARM64, idDylib(version(0, 10, 0)))]]);
    assert.equal(macDylibCurrentVersion(data), version(0, 10, 0));
    assert.throws(() => macDylibCurrentVersion(data.subarray(0, 2 * 4096 + 16)));
    assert.throws(() => macDylibCurrentVersion(data.subarray(0, 2 * 4096)));
    assert.equal(macFormatVersion(version(0, 10, 0)), '0.10.0');
  });

  it('accepts the release installed on this machine, when there is one', (t) => {
    let fd: number;
    try {
      fd = openSync(MAC_SYSTEM_PATH, 'r');
    } catch {
      t.skip(`no system install at ${MAC_SYSTEM_PATH}`);
      return;
    }
    const buffer = new Uint8Array(MAC_VERSION_READ_LIMIT);
    let total = 0;
    try {
      while (total < buffer.length) {
        const read = readSync(fd, buffer, total, buffer.length - total, null);
        if (read === 0) break;
        total += read;
      }
    } finally {
      closeSync(fd);
    }
    assert.doesNotThrow(() => macRequireMinimumVersion(MAC_SYSTEM_PATH, buffer.subarray(0, total)));
  });
});

describe('macOS home folder', () => {
  it('uses only an absolute home from a successful account lookup', () => {
    assert.equal(macHomeFromAccount('/Users/dev'), '/Users/dev');
    for (const home of [null, undefined, '', 'Users/dev', '~/dev']) assert.equal(macHomeFromAccount(home), '', String(home));
  });

  it('with no usable home, considers only the system install', () => {
    const probed: string[] = [];
    assert.throws(() => macChoosePath((path) => { probed.push(path); return ENOENT; }, macHomeFromAccount(null)), NotInstalledError);
    assert.deepEqual(probed, [MAC_SYSTEM_PATH]);
  });
});

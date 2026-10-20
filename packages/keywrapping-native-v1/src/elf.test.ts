import { strict as assert } from 'node:assert';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { elfReadNeeded, elfReadNeededFile } from './elf.js';
import { UntrustedError } from './errors.js';

const LOAD_ADDRESS = 0x40_0000n;

interface Options {
  withoutDynamic?: boolean;
  withoutStringTable?: boolean;
  withoutStringTableSize?: boolean;
  stringTableAddress?: bigint;
  neededOffset?: bigint;
  stringTableSizeAdjustment?: number;
}

/** A minimal 64-bit little-endian ELF image: one PT_LOAD over the whole file, one PT_DYNAMIC, and a string table. */
function syntheticElf(needed: string[], o: Options = {}): Uint8Array {
  const header = 64, phdrs = 2 * 56;
  const strings: number[] = [0];
  const offsets: bigint[] = [];
  for (const name of needed) {
    offsets.push(o.neededOffset ?? BigInt(strings.length));
    strings.push(...new TextEncoder().encode(name), 0);
  }
  const dynamic: [bigint, bigint][] = offsets.map((offset) => [1n, offset]);
  const stringTableOffset = header + phdrs + (needed.length + 3) * 16;
  if (!o.withoutStringTable) {
    dynamic.push([5n, o.stringTableAddress ?? LOAD_ADDRESS + BigInt(stringTableOffset)]);
    if (!o.withoutStringTableSize) dynamic.push([10n, BigInt(strings.length + (o.stringTableSizeAdjustment ?? 0))]);
  }
  dynamic.push([0n, 0n]);

  const image = new Uint8Array(stringTableOffset + strings.length);
  const view = new DataView(image.buffer);
  image.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  view.setBigUint64(32, BigInt(header), true);
  view.setUint16(54, 56, true);
  view.setUint16(56, 2, true);
  const programHeader = (index: number, type: number, offset: bigint, address: bigint, size: bigint) => {
    const at = header + index * 56;
    view.setUint32(at, type, true);
    view.setBigUint64(at + 8, offset, true);
    view.setBigUint64(at + 16, address, true);
    view.setBigUint64(at + 32, size, true);
  };
  const dynamicOffset = header + phdrs;
  programHeader(0, 1, 0n, LOAD_ADDRESS, BigInt(image.length));
  programHeader(1, o.withoutDynamic ? 4 : 2, BigInt(dynamicOffset), LOAD_ADDRESS + BigInt(dynamicOffset), BigInt(dynamic.length * 16));
  dynamic.forEach(([tag, value], i) => {
    view.setBigInt64(dynamicOffset + i * 16, tag, true);
    view.setBigUint64(dynamicOffset + i * 16 + 8, value, true);
  });
  image.set(strings, stringTableOffset);
  return image;
}

const parse = (image: Uint8Array) => elfReadNeeded('test.so', (offset, count) => (offset + count <= image.length ? image.slice(offset, offset + count) : undefined));

describe('ELF DT_NEEDED', () => {
  it('reads every needed name in order', () => {
    assert.deepEqual(parse(syntheticElf(['libtss2-esys.so.0', 'libc.so.6'])), ['libtss2-esys.so.0', 'libc.so.6']);
  });

  it('finds no dependencies where there are none', () => {
    assert.deepEqual(parse(syntheticElf([])), []);
    assert.deepEqual(parse(syntheticElf([], { withoutStringTable: true })), []);
    assert.deepEqual(parse(syntheticElf(['ignored.so'], { withoutDynamic: true })), []);
  });

  it('refuses malformed images', () => {
    const base = () => syntheticElf(['x.so']);
    const edit = (f: (view: DataView, image: Uint8Array) => void) => { const image = base(); f(new DataView(image.buffer), image); return image; };
    const cases: [string, Uint8Array][] = [
      ['not an ELF file', edit((_, i) => { i[1] = 0x58; })],
      ['not a 64-bit little-endian', edit((_, i) => { i[4] = 1; })],
      ['not a 64-bit little-endian', edit((_, i) => { i[5] = 2; })],
      ['program header table is malformed', edit((v) => v.setUint16(56, 0, true))],
      ['out of range', edit((v) => v.setBigUint64(32, 0xffffffffffffffffn, true))],
      ['implausibly large', edit((v) => v.setBigUint64(64 + 56 + 32, 2n << 20n, true))],
      ['runs past the end', base().slice(0, 40)],
      ['runs past the end', base().slice(0, base().length - 3)],
      ['no string table', syntheticElf(['x.so'], { withoutStringTable: true })],
      ['no string table', syntheticElf(['x.so'], { withoutStringTableSize: true })],
      ['outside every loaded segment', syntheticElf(['x.so'], { stringTableAddress: 0x10n })],
      ['runs past its string table', syntheticElf(['x.so'], { neededOffset: 4096n })],
      ['runs past its string table', syntheticElf(['x.so'], { stringTableSizeAdjustment: -1 })],
    ];
    for (const [reason, image] of cases) {
      assert.throws(() => parse(image), (e: unknown) => e instanceof UntrustedError && e.message.includes('test.so') && e.message.includes(reason), reason);
    }
  });

  it('reads from a file', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'hkdfguard-elf-')), 'lib.so');
    writeFileSync(path, syntheticElf(['libc.so.6']));
    assert.deepEqual(elfReadNeededFile(path), ['libc.so.6']);
    writeFileSync(path, syntheticElf(['libc.so.6']).slice(0, 100));
    assert.throws(() => elfReadNeededFile(path), UntrustedError);
  });
});

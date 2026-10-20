import { closeSync, openSync, readSync } from 'node:fs';
import { UntrustedError } from './errors.js';

/*
 * Reads the DT_NEEDED entries - the shared libraries an ELF object asks the dynamic linker to load -
 * from a 64-bit little-endian ELF file (x64 and arm64 Linux). Only the ELF header, the program
 * headers, the dynamic segment and its string table are read, each bounded. Anything malformed is
 * refused: the caller is deciding whether to trust what the file pulled into the process.
 */

const HEADER_SIZE = 64;
const PROGRAM_HEADER_SIZE = 56;
const DYNAMIC_ENTRY_SIZE = 16;
const MAX_PROGRAM_HEADERS = 4096;
const MAX_SEGMENT_BYTES = 1 << 20;
const PT_LOAD = 1;
const PT_DYNAMIC = 2;
const DT_NULL = 0n;
const DT_NEEDED = 1n;
const DT_STRTAB = 5n;
const DT_STRSZ = 10n;

/** Reads exactly `count` bytes at `offset`, or undefined if the file is shorter. */
export type ReadAt = (offset: number, count: number) => Uint8Array | undefined;

function malformed(path: string, reason: string): UntrustedError {
  return new UntrustedError(`'${path}' is not a well-formed ELF shared object: ${reason}.`);
}

function read(path: string, readAt: ReadAt, offset: number, count: number, what: string): DataView {
  const bytes = readAt(offset, count);
  if (bytes === undefined || bytes.length !== count) {
    throw malformed(path, `its ${what} runs past the end of the file`);
  }
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function offsetOf(path: string, value: bigint): number {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw malformed(path, 'a file offset is out of range');
  return Number(value);
}

function sizeOf(path: string, value: bigint, what: string): number {
  if (value > BigInt(MAX_SEGMENT_BYTES)) throw malformed(path, `its ${what} is implausibly large`);
  return Number(value);
}

/** The DT_NEEDED names of an ELF image read through `readAt`, in file order. `path` names it in errors. */
export function elfReadNeeded(path: string, readAt: ReadAt): string[] {
  const header = read(path, readAt, 0, HEADER_SIZE, 'ELF header');
  if (header.getUint32(0) !== 0x7f454c46) throw malformed(path, 'it is not an ELF file');
  if (header.getUint8(4) !== 2 || header.getUint8(5) !== 1) throw malformed(path, 'it is not a 64-bit little-endian ELF file');

  const programHeaderOffset = offsetOf(path, header.getBigUint64(32, true));
  const programHeaderSize = header.getUint16(54, true);
  const programHeaderCount = header.getUint16(56, true);
  if (programHeaderSize < PROGRAM_HEADER_SIZE || programHeaderCount === 0 || programHeaderCount > MAX_PROGRAM_HEADERS) {
    throw malformed(path, 'its program header table is malformed');
  }

  const headers = read(path, readAt, programHeaderOffset, programHeaderSize * programHeaderCount, 'program headers');
  const loads: { virtualAddress: bigint; fileSize: bigint; offset: number }[] = [];
  let dynamic: { offset: number; size: number } | undefined;
  for (let i = 0; i < programHeaderCount; i++) {
    const at = i * programHeaderSize;
    const type = headers.getUint32(at, true);
    const offset = offsetOf(path, headers.getBigUint64(at + 8, true));
    const virtualAddress = headers.getBigUint64(at + 16, true);
    const fileSize = headers.getBigUint64(at + 32, true);
    if (type === PT_LOAD) loads.push({ virtualAddress, fileSize, offset });
    else if (type === PT_DYNAMIC) dynamic = { offset, size: sizeOf(path, fileSize, 'dynamic segment') };
  }
  if (dynamic === undefined) return [];

  const entries = read(path, readAt, dynamic.offset, dynamic.size - (dynamic.size % DYNAMIC_ENTRY_SIZE), 'dynamic segment');
  const neededOffsets: bigint[] = [];
  let stringTableAddress: bigint | undefined;
  let stringTableSize: bigint | undefined;
  for (let at = 0; at + DYNAMIC_ENTRY_SIZE <= entries.byteLength; at += DYNAMIC_ENTRY_SIZE) {
    const tag = entries.getBigInt64(at, true);
    const value = entries.getBigUint64(at + 8, true);
    if (tag === DT_NULL) break;
    if (tag === DT_NEEDED) neededOffsets.push(value);
    else if (tag === DT_STRTAB) stringTableAddress = value;
    else if (tag === DT_STRSZ) stringTableSize = value;
  }
  if (neededOffsets.length === 0) return [];
  if (stringTableAddress === undefined || stringTableSize === undefined) {
    throw malformed(path, 'it names dependencies but has no string table');
  }

  // DT_STRTAB is a virtual address; the PT_LOAD segment containing it maps it to the file.
  const address = stringTableAddress;
  const containing = loads.find((l) => address >= l.virtualAddress && address - l.virtualAddress < l.fileSize);
  if (containing === undefined) throw malformed(path, 'its string table lies outside every loaded segment');

  const tableOffset = offsetOf(path, BigInt(containing.offset) + (address - containing.virtualAddress));
  const table = read(path, readAt, tableOffset, sizeOf(path, stringTableSize, 'string table'), 'string table');
  const bytes = new Uint8Array(table.buffer, table.byteOffset, table.byteLength);
  return neededOffsets.map((offset) => {
    const start = offset < BigInt(bytes.length) ? Number(offset) : -1;
    const end = start < 0 ? -1 : bytes.indexOf(0, start);
    if (end < 0) throw malformed(path, 'a dependency name runs past its string table');
    return new TextDecoder().decode(bytes.subarray(start, end));
  });
}

/** The DT_NEEDED names of the ELF file at `path`. */
export function elfReadNeededFile(path: string): string[] {
  const fd = openSync(path, 'r');
  try {
    return elfReadNeeded(path, (offset, count) => {
      const buffer = new Uint8Array(count);
      let total = 0;
      while (total < count) {
        const n = readSync(fd, buffer, total, count - total, offset + total);
        if (n === 0) return undefined;
        total += n;
      }
      return buffer;
    });
  } finally {
    closeSync(fd);
  }
}

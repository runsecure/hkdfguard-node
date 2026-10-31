import { readFileSync } from 'node:fs';

/*
 * Reads a built Windows add-on's PE headers, for the tests that check how Windows resolves the DLLs
 * it imports. Node loads an add-on with LOAD_WITH_ALTERED_SEARCH_PATH, so without a
 * DependentLoadFlags of its own an add-on's static imports are searched for in its own folder
 * first - where a planted wintrust.dll or crypt32.dll (not KnownDLLs) would be loaded in place of
 * System32's. The ports of the .NET NativeImportSearchPathTests.
 */

/** LOAD_LIBRARY_SEARCH_SYSTEM32: the DependentLoadFlags value that resolves imports from System32 only. */
export const LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800;

const IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;
const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;
// IMAGE_LOAD_CONFIG_DIRECTORY64.DependentLoadFlags: a WORD at this offset, in a directory at least this long.
const DEPENDENT_LOAD_FLAGS_OFFSET = 0x4e;

/**
 * The DependentLoadFlags of the PE32+ image at path - the linker's /DEPENDENTLOADFLAG - or 0 when
 * it has no load configuration directory, or one too short to hold the field. Throws for a file
 * that isn't a PE32+ image (Node on Windows is x64 or arm64 only).
 */
export function peDependentLoadFlags(path: string): number {
  const image = readFileSync(path);
  if (image.readUInt16LE(0) !== 0x5a4d) throw new Error(`${path} isn't a PE image: no MZ header.`);
  const pe = image.readUInt32LE(0x3c);
  if (image.readUInt32LE(pe) !== 0x4550) throw new Error(`${path} isn't a PE image: no PE signature.`);

  const sectionCount = image.readUInt16LE(pe + 6);
  const optionalHeaderSize = image.readUInt16LE(pe + 20);
  const optional = pe + 24;
  if (image.readUInt16LE(optional) !== IMAGE_NT_OPTIONAL_HDR64_MAGIC) throw new Error(`${path} isn't a PE32+ image.`);

  // The data directories follow the 112-byte PE32+ optional header fields; each is an RVA and a size.
  const directoryCount = image.readUInt32LE(optional + 108);
  if (directoryCount <= IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) return 0;
  const entry = optional + 112 + IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG * 8;
  const rva = image.readUInt32LE(entry);
  const size = image.readUInt32LE(entry + 4);
  if (rva === 0 || size === 0) return 0;

  // The load configuration's own Size field, not the directory entry's, says which fields it has.
  const offset = fileOffset(image, optional + optionalHeaderSize, sectionCount, rva);
  if (image.readUInt32LE(offset) < DEPENDENT_LOAD_FLAGS_OFFSET + 2) return 0;
  return image.readUInt16LE(offset + DEPENDENT_LOAD_FLAGS_OFFSET);
}

/** The file offset of rva, through the section table at sections. */
function fileOffset(image: Buffer, sections: number, count: number, rva: number): number {
  for (let i = 0; i < count; i++) {
    const header = sections + i * 40;
    const virtualAddress = image.readUInt32LE(header + 12);
    const extent = Math.max(image.readUInt32LE(header + 8), image.readUInt32LE(header + 16));
    if (rva >= virtualAddress && rva < virtualAddress + extent) return image.readUInt32LE(header + 20) + (rva - virtualAddress);
  }
  throw new Error(`RVA 0x${rva.toString(16)} is in no section.`);
}

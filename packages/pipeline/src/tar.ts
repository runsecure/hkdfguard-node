// A minimal PAX tar writer (POSIX.1-2001 pax interchange format over ustar headers) - just enough
// to hand a remote tar a folder of regular files, since Node's standard library has none. Readable
// by GNU tar, bsdtar (macOS, and Windows' tar.exe) and .NET's TarReader.

const BLOCK = 512;
const encoder = new TextEncoder();

/** One regular file in an archive. */
export interface TarFile {
  /** Its name: a plain file name, no folder - ASCII, as SecretPipelineWriter's file names are. */
  readonly name: string;
  /** Its contents. */
  readonly data: Uint8Array;
  /** Its permission bits, e.g. 0o644. */
  readonly mode: number;
  /** When it was last modified, in whole seconds since the Unix epoch. */
  readonly mtime: number;
}

/**
 * Each block of a PAX archive of `files`, in order: for every file, an extended header ('x')
 * carrying its path and mtime - so a name past ustar's 100 bytes survives - then its ustar header
 * (type '0') and its data, padded to a whole block; then the two zero blocks that end an archive.
 * One Uint8Array per file, and one for the end, so a caller can write them one at a time.
 */
export function* tarArchive(files: Iterable<TarFile>): Generator<Uint8Array> {
  for (const file of files) {
    const pax = paxRecords([['path', file.name], ['mtime', String(file.mtime)]]);
    const paxHeader = ustarHeader(`PaxHeaders/${file.name}`, pax.length, 0o644, file.mtime, 'x');
    const header = ustarHeader(file.name, file.data.length, file.mode, file.mtime, '0');

    const entry = new Uint8Array(BLOCK + padded(pax.length) + BLOCK + padded(file.data.length));
    let offset = 0;
    entry.set(paxHeader, offset);
    entry.set(pax, offset += BLOCK);
    entry.set(header, offset += padded(pax.length));
    entry.set(file.data, offset + BLOCK);
    yield entry;
  }
  yield new Uint8Array(2 * BLOCK);
}

/** `length` rounded up to a whole number of blocks. */
function padded(length: number): number {
  return Math.ceil(length / BLOCK) * BLOCK;
}

/**
 * The extended header's data: one "<length> <key>=<value>\n" record per attribute, the length
 * counting the whole record, its own digits included.
 */
function paxRecords(attributes: readonly (readonly [string, string])[]): Uint8Array {
  let text = '';
  for (const [key, value] of attributes) {
    const body = ` ${key}=${value}\n`;
    const bodyLength = encoder.encode(body).length;
    let length = bodyLength + String(bodyLength).length;
    if (String(length).length + bodyLength !== length) length = bodyLength + String(length).length;
    text += `${length}${body}`;
  }
  return encoder.encode(text);
}

/** A ustar header block: owned by uid and gid 0, with no owner names - unpacked with --no-same-owner, they belong to whoever unpacks them. */
function ustarHeader(name: string, size: number, mode: number, mtime: number, type: string): Uint8Array {
  const header = new Uint8Array(BLOCK);
  const field = (offset: number, length: number, text: string) => {
    const bytes = encoder.encode(text);
    header.set(bytes.subarray(0, length), offset);
  };
  // Octal, zero-padded to the field's length less one, then a NUL.
  const octal = (offset: number, length: number, value: number) => field(offset, length, `${value.toString(8).padStart(length - 1, '0')}\0`);

  field(0, 100, name); //       name: the whole of a short one; the 'x' header's path holds a long one
  octal(100, 8, mode); //       mode
  octal(108, 8, 0); //          uid
  octal(116, 8, 0); //          gid
  octal(124, 12, size); //      size
  octal(136, 12, mtime); //     mtime
  field(148, 8, ' '.repeat(8)); // chksum: spaces while it is summed
  field(156, 1, type); //       typeflag
  field(257, 6, 'ustar\0'); //  magic
  field(263, 2, '00'); //       version
  octal(329, 8, 0); //          devmajor
  octal(337, 8, 0); //          devminor

  let sum = 0;
  for (const b of header) sum += b;
  field(148, 8, `${sum.toString(8).padStart(6, '0')}\0 `);
  return header;
}

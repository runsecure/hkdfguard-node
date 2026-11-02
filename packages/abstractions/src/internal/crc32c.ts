// CRC32C (Castagnoli, reflected polynomial 0x82F63B78), as Cloud KMS checksums requests and responses
// and Secret Manager checksums payloads. Computed here: Node has none built in (zlib.crc32 is
// CRC-32), and what is checksummed - a key, the context, a wrapped key, a payload of at most 64 KiB -
// is small.
const TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index++) {
    let crc = index;
    for (let bit = 0; bit < 8; bit++) crc = crc & 1 ? (crc >>> 1) ^ 0x82f63b78 : crc >>> 1;
    table[index] = crc;
  }
  return table;
})();

/** The CRC32C of `data`, as an unsigned 32-bit number. */
export function crc32c(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of data) crc = TABLE[(crc ^ byte) & 0xff]! ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

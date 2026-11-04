// PEM, Buffer to Buffer: blocks found and base64 decoded and encoded byte by byte, so a key file's
// contents never become a JavaScript string - which can't be wiped - on the way in or out. Never
// exported from the package index.
import { wipe } from '@runsecure/hkdfguard-abstractions';

/** One PEM block: its label, whether it has RFC 1421 headers (a legacy encrypted key's Proc-Type), and its base64 body - a view of the data. */
export interface PemBlock {
  readonly label: string;
  readonly headers: ReadonlySet<string>;
  readonly body: Buffer;
}

const BEGIN = '-----BEGIN ';
const DASHES = '-----';

/** Every PEM block in `data`, in order; the bodies are views of `data`, not copies. */
export function pemBlocks(data: Buffer, fail: (problem: string) => Error): PemBlock[] {
  const blocks: PemBlock[] = [];
  let position = 0;
  for (;;) {
    const begin = data.indexOf(BEGIN, position, 'latin1');
    if (begin < 0) return blocks;
    const labelStart = begin + BEGIN.length;
    const labelEnd = data.indexOf(DASHES, labelStart, 'latin1');
    if (labelEnd < 0 || labelEnd - labelStart > 64) throw fail('A PEM BEGIN line is malformed.');
    const labelBytes = data.subarray(labelStart, labelEnd);
    if (!labelBytes.every((c) => (c >= 0x41 && c <= 0x5a) || (c >= 0x30 && c <= 0x39) || c === 0x20 || c === 0x23)) {
      throw fail('A PEM BEGIN line is malformed.');
    }
    const label = labelBytes.toString('latin1'); // the label is ASCII, and not secret
    const endMarker = `-----END ${label}-----`;
    const start = labelEnd + DASHES.length;
    const end = data.indexOf(endMarker, start, 'latin1');
    if (end < 0) throw fail(`A PEM ${label} block has no END line.`);
    let bodyStart = start;
    const headers = new Set<string>();
    // RFC 1421 headers, as legacy OpenSSL-encrypted keys carry: "Name: value" lines, then a blank
    // line. Base64 has no ':', so a ':' in the block means headers.
    const colon = data.indexOf(':', start, 'latin1');
    if (colon >= 0 && colon < end) {
      let blank = data.indexOf('\n\n', start, 'latin1');
      const crlf = data.indexOf('\r\n\r\n', start, 'latin1');
      if (crlf >= 0 && (blank < 0 || crlf < blank)) blank = crlf;
      if (blank < 0 || blank > end) throw fail(`A PEM ${label} block has headers but no blank line after them.`);
      for (const line of data.subarray(start, blank).toString('latin1').split(/\r?\n/)) {
        const separator = line.indexOf(':');
        if (separator > 0) headers.add(line.slice(0, separator).trim());
      }
      bodyStart = blank;
    }
    blocks.push({ label, headers, body: data.subarray(bodyStart, end) });
    position = end + endMarker.length;
  }
}

const ALPHABET = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', 'latin1');
const VALUES = (() => {
  const values = new Int16Array(256).fill(-1);
  ALPHABET.forEach((c, i) => {
    values[c] = i;
  });
  return values;
})();

/**
 * A PEM body, base64-decoded into a new buffer the caller wipes, sized once: whitespace is skipped,
 * padding is accepted only at the end, and anything else is refused.
 */
export function decodeBase64(body: Buffer, fail: (problem: string) => Error): Buffer {
  let symbols = 0;
  let padding = 0;
  for (const c of body) {
    if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) continue;
    if (c === 0x3d) {
      padding++;
      continue;
    }
    if (padding > 0 || VALUES[c]! < 0) throw fail('A PEM block isn\'t base64.');
    symbols++;
  }
  if (padding > 2 || (symbols + padding) % 4 !== 0 || symbols % 4 === 1) throw fail('A PEM block isn\'t base64.');
  const out = Buffer.alloc(Math.floor((symbols * 6) / 8));
  let accumulator = 0;
  let bits = 0;
  let written = 0;
  for (const c of body) {
    const value = VALUES[c]!;
    if (value < 0) continue;
    accumulator = ((accumulator << 6) | value) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[written++] = (accumulator >> bits) & 0xff;
    }
  }
  accumulator = 0;
  return out;
}

/**
 * `der` as a PEM block with `label`, in a new buffer the caller wipes - base64 in lines of 64, sized
 * once, never through a string.
 */
export function encodePem(label: string, der: Uint8Array): Buffer {
  const head = Buffer.from(`-----BEGIN ${label}-----\n`, 'latin1');
  const tail = Buffer.from(`-----END ${label}-----\n`, 'latin1');
  const symbols = Math.ceil(der.length / 3) * 4;
  const lines = Math.ceil(symbols / 64);
  const out = Buffer.alloc(head.length + symbols + lines + tail.length);
  let written = head.copy(out, 0);
  let column = 0;
  const put = (c: number) => {
    out[written++] = c;
    if (++column === 64) {
      out[written++] = 0x0a;
      column = 0;
    }
  };
  for (let i = 0; i < der.length; i += 3) {
    const a = der[i]!;
    const b = i + 1 < der.length ? der[i + 1]! : 0;
    const c = i + 2 < der.length ? der[i + 2]! : 0;
    put(ALPHABET[a >> 2]!);
    put(ALPHABET[((a & 0x03) << 4) | (b >> 4)]!);
    put(i + 1 < der.length ? ALPHABET[((b & 0x0f) << 2) | (c >> 6)]! : 0x3d);
    put(i + 2 < der.length ? ALPHABET[c & 0x3f]! : 0x3d);
  }
  if (column !== 0) out[written++] = 0x0a;
  written += tail.copy(out, written);
  if (written !== out.length) {
    wipe(out);
    throw new Error('encodePem: the length was miscounted');
  }
  return out;
}

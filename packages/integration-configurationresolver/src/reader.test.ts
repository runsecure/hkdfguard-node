// The port of the Python suite's test_reader.py, itself the port of .NET's
// ReaderAndTokenScenarioTests, with tests of what .NET's decoding gives a key: a byte order mark
// selecting a stream's encoding, invalid UTF-8 replaced per maximal subpart, and trimming of exactly
// .NET's whitespace.
import { strict as assert } from 'node:assert';
import { Readable } from 'node:stream';
import { describe, it } from 'node:test';
import { InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';
import { CAFE, CustomToken, DictValueProvider, ReadingResolver, REPLACEMENT, resolveToString, utf8 } from './core.test-support.js';
import { ConfigurationItemReader } from './reader.js';
import { ConfigurationItemTokenBase, DefaultToken } from './tokens.js';

const TEXT = 'this is my ${ value 1 }, and this is ${value2} and lastly this is ${value3}';

const newReader = () => new ConfigurationItemReader(new DefaultToken());

const bytes = (...values: number[]) => new Uint8Array(values);

function concat(...parts: Uint8Array[]): Uint8Array {
  return new Uint8Array(Buffer.concat(parts));
}

/** `s` as UTF-16, in either byte order. */
function utf16(s: string, littleEndian: boolean): Uint8Array {
  const out = new Uint8Array(s.length * 2);
  const view = new DataView(out.buffer);
  for (let i = 0; i < s.length; i++) view.setUint16(i * 2, s.charCodeAt(i), littleEndian);
  return out;
}

/** `s` as UTF-32, in either byte order. */
function utf32(s: string, littleEndian: boolean): Uint8Array {
  const codePoints = Array.from(s, (c) => c.codePointAt(0)!);
  const out = new Uint8Array(codePoints.length * 4);
  const view = new DataView(out.buffer);
  codePoints.forEach((c, i) => view.setUint32(i * 4, c, littleEndian));
  return out;
}

/** `s` as Latin-1: each code unit as one byte. */
const latin1 = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));

const BOM_UTF8 = bytes(0xef, 0xbb, 0xbf);
const BOM_UTF16_LE = bytes(0xff, 0xfe);
const BOM_UTF16_BE = bytes(0xfe, 0xff);
const BOM_UTF32_LE = bytes(0xff, 0xfe, 0x00, 0x00);
const BOM_UTF32_BE = bytes(0x00, 0x00, 0xfe, 0xff);

/** A stream over `data`, as a Node Readable of Uint8Array chunks. */
const streamOf = (...chunks: Uint8Array[]) => Readable.from(chunks.map((chunk) => Buffer.from(chunk)), { objectMode: false });

const GRINNING_FACE = String.fromCodePoint(0x1f600);
const BOM_TEXT = `\${ ${CAFE} ${GRINNING_FACE} }`;
const BOM_KEY = `${CAFE} ${GRINNING_FACE}`;

const ch = (c: number) => String.fromCodePoint(c);

describe('ConfigurationItemReader', () => {
  it('readKeys from a string, bytes and a stream return the same keys', async () => {
    const reader = newReader();
    const expected = ['value 1', 'value2', 'value3'];
    const encoded = utf8(TEXT);

    assert.deepEqual(reader.readKeys(TEXT), expected);
    assert.deepEqual(reader.readKeys(encoded), expected);
    assert.deepEqual(reader.readKeys(Buffer.from(encoded)), expected);
    // A view into a larger buffer, as Python's memoryview test.
    const padded = concat(utf8('xx'), encoded, utf8('yy'));
    assert.deepEqual(reader.readKeys(padded.subarray(2, 2 + encoded.length)), expected);
    assert.deepEqual(await reader.readKeysFrom(streamOf(encoded)), expected);
    // The stream split mid-item, and as a plain iterable of chunks.
    assert.deepEqual(await reader.readKeysFrom([encoded.subarray(0, 15), encoded.subarray(15)]), expected);
  });

  it('readKeysFrom a stream with an explicit encoding decodes with it', async () => {
    const data = latin1(`\${ ${CAFE} }`);

    assert.deepEqual(await newReader().readKeysFrom(streamOf(data), 'latin1'), [CAFE]);
  });

  it('readKeysFrom a stream reads from its position and leaves it open', async () => {
    // Python seeks a BytesIO; here the iterator has already yielded its first chunk.
    let returned = false;
    const chunks = [utf8('${skipped} '), utf8('${read}')];
    let index = 0;
    const iterator: Iterator<Uint8Array> & Iterable<Uint8Array> = {
      next: () => (index < chunks.length ? { value: chunks[index++]!, done: false } : { value: undefined, done: true }),
      return: () => {
        returned = true;
        return { value: undefined, done: true };
      },
      [Symbol.iterator]() {
        return this;
      },
    };
    iterator.next();

    assert.deepEqual(await newReader().readKeysFrom(iterator), ['read']);
    assert.equal(returned, false);
  });

  describe('readKeysFrom: a byte order mark selects the encoding', () => {
    // .NET's StreamReader defaults to UTF-8 and lets a byte order mark select the encoding.
    const cases: [string, Uint8Array, string | undefined, string[]][] = [
      ['no BOM', utf8(BOM_TEXT), undefined, [BOM_KEY]],
      ['UTF-8', concat(BOM_UTF8, utf8(BOM_TEXT)), undefined, [BOM_KEY]],
      ['UTF-16LE', concat(BOM_UTF16_LE, utf16(BOM_TEXT, true)), undefined, [BOM_KEY]],
      ['UTF-16BE', concat(BOM_UTF16_BE, utf16(BOM_TEXT, false)), undefined, [BOM_KEY]],
      ['UTF-32LE', concat(BOM_UTF32_LE, utf32(BOM_TEXT, true)), undefined, [BOM_KEY]],
      ['UTF-32BE', concat(BOM_UTF32_BE, utf32(BOM_TEXT, false)), undefined, [BOM_KEY]],
      ['BOM over explicit encoding', concat(BOM_UTF8, utf8(BOM_TEXT)), 'latin1', [BOM_KEY]],
      ['only BOM', BOM_UTF8, undefined, []],
      ['empty', new Uint8Array(0), undefined, []],
      // Not UTF-8 and no BOM: read as UTF-8, so the e with acute (0xE9) becomes U+FFFD.
      ['latin-1 without encoding', concat(utf8('${ caf'), bytes(0xe9), utf8(' }')), undefined, ['caf' + REPLACEMENT]],
      ['short BOM', bytes(0xef, 0xbb), undefined, []],
    ];
    for (const [name, data, encoding, expected] of cases) {
      it(name, async () => {
        assert.deepEqual(await newReader().readKeysFrom(streamOf(data), encoding), expected);
      });
    }
  });

  describe('readKeys: invalid UTF-8 is replaced per maximal subpart', () => {
    // As .NET's UTF-8 decoder does: each maximal ill-formed subsequence becomes one U+FFFD.
    const item = (...inner: number[]) => concat(utf8('${'), bytes(...inner), utf8('}'));
    const a = 0x61;
    const b = 0x62;
    const cases: [string, Uint8Array, string][] = [
      ['a lone FF', item(a, 0xff, b), `a${REPLACEMENT}b`],
      ['E0 must be followed by A0-BF', item(a, 0xe0, 0x80, b), `a${REPLACEMENT}${REPLACEMENT}b`],
      ['a truncated four-byte sequence', item(a, 0xf0, 0x9f, 0x98, b), `a${REPLACEMENT}b`],
      ['an encoded surrogate', item(0xed, 0xa0, 0x80), REPLACEMENT.repeat(3)],
      ['an overlong encoding', item(a, 0xc0, 0xaf, b), `a${REPLACEMENT}${REPLACEMENT}b`],
      ['truncated at the end of the item', item(a, 0xe2, 0x82), `a${REPLACEMENT}`],
    ];
    for (const [name, text, key] of cases) {
      it(name, () => {
        assert.deepEqual(newReader().readKeys(text), [key]);
      });
    }
  });

  it("resolve: an invalid UTF-8 key is the reader's key", async () => {
    const resolver = new ReadingResolver(new DefaultToken(), [new DictValueProvider({ [`a${REPLACEMENT}b`]: 'value' })]);

    assert.equal(await resolveToString(resolver, concat(utf8('[${ a'), bytes(0xff), utf8('b }]'))), '[value]');
  });

  describe("readKeys trims exactly .NET's whitespace", () => {
    const cases: [string, string, string[]][] = [
      ['no-break and ideographic space', `\${${ch(0x00a0)}Name${ch(0x3000)}}`, ['Name']],
      ['next line and separators', `\${${ch(0x0085)}${ch(0x2028)}Name${ch(0x2029)}\v\f\r}`, ['Name']],
      ['Zs spaces', `\${${ch(0x1680)}${ch(0x2000)}${ch(0x200a)}${ch(0x202f)}${ch(0x205f)}Name}`, ['Name']],
      ['zero width space is not whitespace', `\${${ch(0x200b)}Name}`, [ch(0x200b) + 'Name']],
      ['only whitespace', `\${${ch(0x00a0)}${ch(0x2003)}}`, []],
      // .NET's Trim keeps the information separators U+001C-U+001F.
      ['information separators are kept', `\${${ch(0x001c)}Name${ch(0x001f)}}`, [ch(0x001c) + 'Name' + ch(0x001f)]],
    ];
    for (const [name, text, keys] of cases) {
      it(name, () => {
        assert.deepEqual(newReader().readKeys(text), keys);
      });
    }
  });

  describe('readKeys skips empty, unterminated and escaped items', () => {
    const cases: [string, string[]][] = [
      ['', []],
      ['no items', []],
      ['${} ${ } ${a}', ['a']],
      ['${a} ${unterminated', ['a']],
      ['${a}${b}', ['a', 'b']],
      ['$${a} ${b} $${', ['b']],
      ['$$${a} $${b ${c}}', ['c']],
    ];
    for (const [text, expected] of cases) {
      it(JSON.stringify(text), () => {
        assert.deepEqual(newReader().readKeys(text), expected);
      });
    }
  });

  it('keys returns the most recent read', () => {
    const reader = newReader();
    assert.deepEqual(reader.keys(), []);

    reader.readKeys('${first}');
    reader.readKeys('${second}');

    assert.deepEqual(reader.keys(), ['second']);
  });

  it("readKeys with a custom token uses its sequences", () => {
    const reader = new ConfigurationItemReader(new CustomToken('{{', '}}'));

    assert.deepEqual(reader.readKeys('{{a}} ${b}'), ['a']);
  });

  it('readKeys with a custom escape sequence skips only its escaped items', () => {
    const withEscape = new ConfigurationItemReader(new CustomToken('{{', '}}', '\\'));
    const withoutEscape = new ConfigurationItemReader(new CustomToken('{{', '}}'));

    assert.deepEqual(withEscape.readKeys('\\{{a}} ${{b}}'), ['b']);
    assert.deepEqual(withoutEscape.readKeys('\\{{a}} ${{b}}'), ['a', 'b']);
  });

  it('readKeysAll keeps the keys of all the texts', () => {
    const reader = newReader();
    reader.readKeys('${old}');

    const keys = reader.readKeysAll(['${a} ${b}', '', '${c', '}${d}', '${a}']);

    assert.deepEqual(keys, ['a', 'b', 'd', 'a']);
    assert.deepEqual(reader.keys(), keys);
  });

  it('readKeysAll with undefined arguments throws', () => {
    const reader = newReader();

    assert.throws(() => reader.readKeysAll(undefined as never), TypeError);
    // .NET throws ArgumentException for a null text; Node reports it with TypeError.
    assert.throws(() => reader.readKeysAll(['${a}', undefined as never]), TypeError);
    // A single string is iterable, but is not several texts.
    assert.throws(() => reader.readKeysAll('${a}'), TypeError);
  });

  it('reader with undefined arguments throws', async () => {
    assert.throws(() => new ConfigurationItemReader(undefined as never), TypeError);
    await assert.rejects(newReader().readKeysFrom(undefined as never), TypeError);
    assert.throws(() => newReader().readKeys(undefined as never), TypeError);
  });

  it('token defaults and overrides', () => {
    const defaults = new DefaultToken();
    const custom = new CustomToken('<%', '%>');

    assert.equal(defaults.startSequence, ConfigurationItemTokenBase.DEFAULT_START_SEQUENCE);
    assert.equal(defaults.startSequence, '${');
    assert.equal(defaults.endSequence, ConfigurationItemTokenBase.DEFAULT_END_SEQUENCE);
    assert.equal(defaults.endSequence, '}');
    assert.equal(defaults.escapeSequence, ConfigurationItemTokenBase.DEFAULT_ESCAPE_SEQUENCE);
    assert.equal(defaults.escapeSequence, '$');
    assert.equal(custom.startSequence, '<%');
    assert.equal(custom.endSequence, '%>');
    assert.equal(custom.escapeSequence, undefined);
  });

  it('token with an empty escape sequence throws', () => {
    assert.throws(
      () => new CustomToken('${', '}', ''),
      (error) => error instanceof InvalidArgumentError && /escapeSequence/.test(error.message),
    );
  });

  describe('token with a null or empty sequence throws', () => {
    // null, not undefined: an undefined sequence takes the default.
    const cases: [string | null, string | null, 'TypeError' | 'InvalidArgumentError'][] = [
      [null, '}', 'TypeError'],
      ['', '}', 'InvalidArgumentError'],
      ['${', null, 'TypeError'],
      ['${', '', 'InvalidArgumentError'],
    ];
    for (const [start, end, expected] of cases) {
      it(`${JSON.stringify(start)}, ${JSON.stringify(end)}`, () => {
        assert.throws(
          () => new CustomToken(start as string, end as string),
          expected === 'TypeError' ? TypeError : InvalidArgumentError,
        );
      });
    }
  });
});

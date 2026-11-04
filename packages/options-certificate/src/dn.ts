// Distinguished names, decoded: parsed from configuration, read from a certificate's DER, compared
// whole ignoring case, and rendered as .NET and Windows render them. A port of the Python port's _dn.
import * as der from './der.js';
import { DerError, type Element } from './der.js';

// The attribute keywords a configured subject may use, as Windows' CertStrToName and .NET accept them,
// upper-cased; and the one each type is written with.
const KEYWORDS: Record<string, string> = {
  CN: '2.5.4.3',
  SN: '2.5.4.4',
  SERIALNUMBER: '2.5.4.5',
  C: '2.5.4.6',
  L: '2.5.4.7',
  S: '2.5.4.8',
  ST: '2.5.4.8',
  STREET: '2.5.4.9',
  O: '2.5.4.10',
  OU: '2.5.4.11',
  T: '2.5.4.12',
  TITLE: '2.5.4.12',
  DESCRIPTION: '2.5.4.13',
  POSTALCODE: '2.5.4.17',
  G: '2.5.4.42',
  GN: '2.5.4.42',
  GIVENNAME: '2.5.4.42',
  I: '2.5.4.43',
  INITIALS: '2.5.4.43',
  DNQUALIFIER: '2.5.4.46',
  DC: '0.9.2342.19200300.100.1.25',
  UID: '0.9.2342.19200300.100.1.1',
  E: '1.2.840.113549.1.9.1',
  EMAIL: '1.2.840.113549.1.9.1',
  EMAILADDRESS: '1.2.840.113549.1.9.1',
  UNSTRUCTUREDNAME: '1.2.840.113549.1.9.2',
  UNSTRUCTUREDADDRESS: '1.2.840.113549.1.9.8',
};
const NAMES: Record<string, string> = {
  '2.5.4.3': 'CN', '2.5.4.4': 'SN', '2.5.4.5': 'SERIALNUMBER', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'S', '2.5.4.9': 'STREET',
  '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.12': 'T', '2.5.4.13': 'DESCRIPTION', '2.5.4.17': 'PostalCode', '2.5.4.42': 'G', '2.5.4.43': 'I',
  '2.5.4.46': 'DNQualifier', '0.9.2342.19200300.100.1.25': 'DC', '0.9.2342.19200300.100.1.1': 'UID', '1.2.840.113549.1.9.1': 'E',
  '1.2.840.113549.1.9.2': 'unstructuredName',
};
const HEX = /^[0-9a-fA-F]$/;

/** One attribute: its type, and its value - decoded text, or the bytes of a value that isn't a string type, which no configured value matches. */
interface Attribute {
  readonly oid: string;
  readonly value: string | Buffer;
}

function attributesMatch(a: Attribute, b: Attribute): boolean {
  if (a.oid !== b.oid) return false;
  if (typeof a.value === 'string' && typeof b.value === 'string') return fold(a.value) === fold(b.value);
  return Buffer.isBuffer(a.value) && Buffer.isBuffer(b.value) && a.value.equals(b.value);
}

// Ignoring case as .NET's OrdinalIgnoreCase does: character by character, one for one, so "ß" doesn't become "SS".
function fold(text: string): string {
  let out = '';
  for (const c of text) {
    const upper = c.toUpperCase();
    out += [...upper].length === 1 ? upper : c;
  }
  return out;
}

/**
 * A distinguished name: its relative distinguished names in the order it is written - most specific
 * first, "CN=api.example.com, O=Contoso" - each one or more attributes. A certificate's subject is
 * encoded the other way round, so it is reversed as it is read, as .NET's X500DistinguishedName.Name
 * and Windows render it.
 */
export class DistinguishedName {
  private constructor(private readonly rdns: readonly (readonly Attribute[])[]) {}

  /**
   * Parses a distinguished name as configuration writes it: "CN=api.example.com, O=Contoso". Relative
   * names are separated by "," or ";", attributes within one by "+"; a type is a keyword (CN, O, OU,
   * L, S, C, E, DC, ...) or a dotted OID, optionally "OID."-prefixed; a value may be double-quoted, and
   * "\" escapes the next character or two hex digits. Space around types and values is ignored.
   * @throws TypeError the text isn't a distinguished name
   */
  static parse(text: string): DistinguishedName {
    const rdns: Attribute[][] = [];
    let current: Attribute[] = [];
    let rest = text;
    for (;;) {
      const { attribute, after, separator } = parseAttribute(rest);
      current.push(attribute);
      if (separator !== '+') {
        rdns.push(current);
        current = [];
      }
      if (separator === '') return new DistinguishedName(rdns);
      rest = after;
    }
  }

  /** A Name, as a certificate encodes its subject or issuer, most specific relative name first. */
  static fromDer(name: Element): DistinguishedName {
    const rdns: Attribute[][] = [];
    for (const set of der.children(der.expect(name, der.SEQUENCE, 'A name'))) {
      const rdn: Attribute[] = [];
      for (const pair of der.children(der.expect(set, der.SET, 'A relative distinguished name'))) {
        const [type, value] = der.sequence(pair, 'An attribute', 2, 2);
        rdn.push({ oid: der.oid(type), value: decodeValue(value!) });
      }
      rdns.push(rdn);
    }
    return new DistinguishedName(rdns.reverse());
  }

  /**
   * Whether the two are the same name: the same relative names in the same order, each with the same
   * attributes - in any order within it, as a SET OF is - each value compared decoded and ignoring
   * case. Never a substring: "CN=api" doesn't match "CN=api.example.com".
   */
  matches(other: DistinguishedName): boolean {
    if (this.rdns.length !== other.rdns.length) return false;
    for (let i = 0; i < this.rdns.length; i++) {
      const mine = this.rdns[i]!;
      const unmatched = [...other.rdns[i]!];
      if (mine.length !== unmatched.length) return false;
      for (const attribute of mine) {
        const index = unmatched.findIndex((candidate) => attributesMatch(attribute, candidate));
        if (index < 0) return false;
        unmatched.splice(index, 1);
      }
    }
    return true;
  }

  /** The name as .NET and Windows render it: "CN=api.example.com, O=Contoso", a value quoted when it holds a separator, a quote or surrounding space. */
  toString(): string {
    return this.rdns.map((rdn) => rdn.map((a) => `${NAMES[a.oid] ?? `OID.${a.oid}`}=${quote(a.value)}`).join(' + ')).join(', ');
  }
}

function quote(value: string | Buffer): string {
  if (Buffer.isBuffer(value)) return `#${value.toString('hex').toUpperCase()}`;
  if (value !== value.trim() || /[,;+="\\<>#\n]/.test(value)) return `"${value.replace(/"/g, '""')}"`;
  return value;
}

function decodeValue(value: Element): string | Buffer {
  const contents = value.contents;
  switch (value.tag) {
    case 0x0c: // UTF8String
      return contents.toString('utf8');
    case 0x12: // NumericString
    case 0x13: // PrintableString
    case 0x14: // TeletexString, read as Latin-1, as Windows and .NET read it
    case 0x16: // IA5String
    case 0x1a: // VisibleString
      return contents.toString('latin1');
    case 0x1e: { // BMPString
      if (contents.length % 2 !== 0) throw new DerError('A BMPString has an odd length.');
      const swapped = Buffer.from(contents);
      swapped.swap16();
      return swapped.toString('utf16le');
    }
    case 0x1c: { // UniversalString
      if (contents.length % 4 !== 0) throw new DerError("A UniversalString isn't whole characters.");
      let text = '';
      for (let i = 0; i < contents.length; i += 4) text += String.fromCodePoint(contents.readUInt32BE(i));
      return text;
    }
    default:
      return Buffer.from(value.encoding);
  }
}

/** One type=value from the start of `text`: the attribute, what follows its separator, and the separator ("," ";" "+"), or "" at the end. */
function parseAttribute(text: string): { attribute: Attribute; after: string; separator: string } {
  const equals = text.indexOf('=');
  if (equals < 0) throw new TypeError("Not a distinguished name: an attribute has no '='.");
  const oid = attributeType(text.slice(0, equals).trim());
  const rest = text.slice(equals + 1).replace(/^ +/, '');
  const quoted = rest.startsWith('"');
  const value: string[] = [];
  // trailing is the length of value up to its last non-space, unescaped character: unquoted values
  // lose trailing spaces, but not escaped ones.
  let trailing = 0;
  for (let i = quoted ? 1 : 0; i < rest.length; i++) {
    const c = rest[i]!;
    if (c === '\\') {
      if (i + 1 >= rest.length) throw new TypeError('Not a distinguished name: it ends in an escape.');
      if (i + 2 < rest.length && HEX.test(rest[i + 1]!) && HEX.test(rest[i + 2]!)) {
        value.push(`\0${rest.slice(i + 1, i + 3)}`);
        i += 2;
      } else {
        value.push(rest[i + 1]!);
        i += 1;
      }
      trailing = value.length;
    } else if (quoted && c === '"') {
      if (rest[i + 1] === '"') { // "" is a quote, as Windows writes one
        value.push('"');
        i += 1;
        trailing = value.length;
        continue;
      }
      const after = rest.slice(i + 1).replace(/^ +/, '');
      if (after === '') return { attribute: { oid, value: join(value) }, after: '', separator: '' };
      if (!',;+'.includes(after[0]!)) throw new TypeError('Not a distinguished name: text follows a quoted value.');
      return { attribute: { oid, value: join(value) }, after: after.slice(1), separator: after[0]! };
    } else if (!quoted && ',;+'.includes(c)) {
      return { attribute: { oid, value: join(value.slice(0, trailing)) }, after: rest.slice(i + 1), separator: c };
    } else {
      value.push(c);
      if (c !== ' ' || quoted) trailing = value.length;
    }
  }
  if (quoted) throw new TypeError('Not a distinguished name: a quoted value has no closing quote.');
  return { attribute: { oid, value: join(value.slice(0, trailing)) }, after: '', separator: '' };
}

// Hex escapes are carried as "\0XX" and decoded together, as UTF-8 (Latin-1 for bytes that aren't),
// so "\C3\A9" is "é".
function join(parts: string[]): string {
  let out = '';
  let pending: number[] = [];
  const flush = () => {
    if (pending.length === 0) return;
    const bytes = Buffer.from(pending);
    const utf8 = bytes.toString('utf8');
    out += Buffer.from(utf8, 'utf8').equals(bytes) ? utf8 : bytes.toString('latin1');
    pending = [];
  };
  for (const part of parts) {
    if (part.length === 3 && part[0] === '\0') {
      pending.push(Number.parseInt(part.slice(1), 16));
      continue;
    }
    flush();
    out += part;
  }
  flush();
  return out;
}

function attributeType(keyword: string): string {
  const known = KEYWORDS[keyword.toUpperCase()];
  if (known !== undefined) return known;
  const dotted = keyword.length > 4 && keyword.slice(0, 4).toUpperCase() === 'OID.' ? keyword.slice(4) : keyword;
  const parts = dotted.split('.');
  if (parts.length < 2 || !parts.every((part) => /^[0-9]+$/.test(part))) throw new TypeError(`Not a distinguished name: '${keyword}' isn't an attribute type.`);
  return parts.map((part) => String(Number(part))).join('.');
}

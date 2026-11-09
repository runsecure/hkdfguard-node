// What the loader reads from a certificate beyond node:crypto's X509Certificate: its subject as a
// structured name, compared attribute by attribute, and its validity period as dates (X509Certificate's
// validFromDate and validToDate arrived only in Node 22.10). Never exported from the package index.
import { X509Certificate, type KeyObject } from 'node:crypto';
import * as der from './der.js';
import { DerError, type Element } from './der.js';
import { DistinguishedName } from './dn.js';
import { InvalidCertificateFileError, UnsupportedCertificateError } from './errors.js';

/** One certificate, parsed. */
export interface ParsedCertificate {
  readonly x509: X509Certificate;
  readonly der: Buffer;
  readonly subject: DistinguishedName;
  readonly notBefore: Date;
  readonly notAfter: Date;
}

/**
 * `data` - one DER certificate - parsed by node:crypto and by this module's reader.
 * @throws InvalidCertificateFileError it isn't a certificate
 */
export function parseCertificate(data: Uint8Array, what: string): ParsedCertificate {
  const copy = Buffer.from(data);
  let x509: X509Certificate;
  try {
    x509 = new X509Certificate(copy);
  } catch (error) {
    throw new InvalidCertificateFileError(`${what} isn't a certificate: ${(error as Error).message}`, { cause: error });
  }
  try {
    const [tbs] = der.sequence(der.read(copy), 'A certificate', 3, 3);
    const fields = der.sequence(tbs, 'A TBSCertificate', 6);
    const offset = fields[0]?.tag === der.CONTEXT_0 ? 1 : 0; // [0] version, absent for v1
    const validity = der.sequence(fields[offset + 3], 'The validity', 2, 2);
    return {
      x509,
      der: copy,
      subject: DistinguishedName.fromDer(fields[offset + 4]!),
      notBefore: time(validity[0]!),
      notAfter: time(validity[1]!),
    };
  } catch (error) {
    if (error instanceof DerError) throw new InvalidCertificateFileError(`${what} isn't a certificate: ${error.message}`);
    throw error;
  }
}

function time(element: Element): Date {
  const text = element.contents.toString('latin1');
  let match: RegExpMatchArray | null;
  let year: number;
  if (element.tag === 0x17) { // UTCTime: YYMMDDHHMMSSZ, a year below 50 being 20YY
    match = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
    if (match === null) throw new DerError('A UTCTime is malformed.');
    const yy = Number(match[1]);
    year = yy < 50 ? 2000 + yy : 1900 + yy;
  } else if (element.tag === 0x18) { // GeneralizedTime: YYYYMMDDHHMMSS[.fff]Z
    match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$/.exec(text);
    if (match === null) throw new DerError('A GeneralizedTime is malformed.');
    year = Number(match[1]);
  } else {
    throw new DerError("A validity time isn't a UTCTime or GeneralizedTime.");
  }
  const [month, day, hour, minute, second] = [2, 3, 4, 5, 6].map((i) => Number(match![i]));
  const date = new Date(Date.UTC(year, month! - 1, day!, hour!, minute!, second!));
  // Date.UTC rolls a field out of range into the next (month 13 is January); a certificate's time is
  // what it says, so one that doesn't come back field for field isn't a time. A leap second (:60) is
  // refused too, as X.509 profiles forbid it.
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month! - 1 || date.getUTCDate() !== day! || date.getUTCHours() !== hour!
    || date.getUTCMinutes() !== minute! || date.getUTCSeconds() !== second!) {
    throw new DerError(`A validity time, ${text}, names a date or time that doesn't exist.`);
  }
  return date;
}

/** The DER of a public key's SubjectPublicKeyInfo, to compare two keys by. */
export function spki(key: KeyObject): Buffer {
  return key.export({ format: 'der', type: 'spki' });
}

/** The certificate's key type: 'rsa' or 'ec' (RSA-PSS keys sign as RSA keys do). */
export function keyType(certificate: ParsedCertificate): 'rsa' | 'ec' {
  const type = certificate.x509.publicKey.asymmetricKeyType;
  if (type === 'rsa' || type === 'rsa-pss') return 'rsa';
  if (type === 'ec') return 'ec';
  throw new UnsupportedCertificateError(`The certificate's key is ${type ?? 'of an unknown type'}, not RSA or ECDSA.`);
}

/** `certificates` with the first whose public key is `publicKey` first - as .NET chooses the certificate - and the rest after it in order; undefined if none is its. */
export function leafFirst(certificates: readonly ParsedCertificate[], publicKey: KeyObject): ParsedCertificate[] | undefined {
  const wanted = spki(publicKey);
  const index = certificates.findIndex((certificate) => spki(certificate.x509.publicKey).equals(wanted));
  if (index < 0) return undefined;
  return [certificates[index]!, ...certificates.slice(0, index), ...certificates.slice(index + 1)];
}

/** A certificate's subject as messages name it. */
export function describe(certificate: ParsedCertificate): string {
  return certificate.subject.toString();
}

/** .NET's "u" format, as its messages give a validity period. */
export function universal(moment: Date): string {
  return moment.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, 'Z');
}

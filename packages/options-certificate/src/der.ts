// The BER/DER reader and DER writer this package parses certificates, names and keys with: the one
// HkdfGuard's packages share, @runsecure/hkdfguard-abstractions/internal's `der`, re-exported here by
// name so the rest of the package imports it as before. Never exported from the package index.
import { der } from '@runsecure/hkdfguard-abstractions/internal';

export const {
  INTEGER, BIT_STRING, OCTET_STRING, NULL, OBJECT_IDENTIFIER, UTF8_STRING, VISIBLE_STRING, SEQUENCE, SET, CONTEXT_0,
  read, children, expect, sequence, only, oid, integer, octets, algorithm, encode, encodeOid, encodeInteger,
} = der;
/** The bytes aren't the ASN.1 they were read as. */
export const DerError = der.DerError;
export type DerError = der.DerError;
export type Element = der.Element;

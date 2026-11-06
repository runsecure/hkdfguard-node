import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { certificate, nameDer, rsaKey } from './certificates.test-support.js';
import * as der from './der.js';
import { DistinguishedName } from './dn.js';
import { parseCertificate } from './x509.js';

function subjectOf(name: Buffer): DistinguishedName {
  return parseCertificate(certificate(rsaKey(), { subject: name }), 'test').subject;
}

describe('DistinguishedName', () => {
  it("matches a certificate's whole subject, ignoring case, never a part of it", () => {
    const subject = subjectOf(nameDer('CN=api.example.com, O=Contoso'));
    assert.ok(subject.matches(DistinguishedName.parse('CN=api.example.com, O=Contoso')));
    assert.ok(subject.matches(DistinguishedName.parse('cn=API.EXAMPLE.COM;o=contoso')));
    assert.ok(!subject.matches(DistinguishedName.parse('CN=api.example.com')));
    assert.ok(!subject.matches(DistinguishedName.parse('CN=api, O=Contoso')));
    assert.ok(!subject.matches(DistinguishedName.parse('O=Contoso, CN=api.example.com')));
    assert.ok(!subject.matches(DistinguishedName.parse('CN=api.example.com, O=Contoso, C=US')));
  });

  it('compares a value decoded, whatever its string type', () => {
    for (const tag of [der.UTF8_STRING, 0x13, 0x1e]) {
      assert.ok(subjectOf(nameDer('CN=api.example.com, O=Contoso', tag)).matches(DistinguishedName.parse('CN=api.example.com, O=Contoso')), `tag ${tag}`);
    }
    assert.ok(subjectOf(nameDer('CN=Zürich')).matches(DistinguishedName.parse('CN=ZÜRICH')));
  });

  it('ignores case character for character, as OrdinalIgnoreCase does', () => {
    assert.ok(subjectOf(nameDer('CN=straße')).matches(DistinguishedName.parse('CN=STRAßE')));
    assert.ok(!subjectOf(nameDer('CN=straße')).matches(DistinguishedName.parse('CN=STRASSE')));
  });

  it('reads a quoted or escaped value', () => {
    const subject = subjectOf(nameDer('CN=a, O=Contoso'));
    for (const text of ['CN="a", O="Contoso"', 'CN=\\61, O=Contoso', 'CN = a ,  O = Contoso ']) {
      assert.ok(subject.matches(DistinguishedName.parse(text)), text);
    }
    assert.equal(DistinguishedName.parse('CN="a, ""b"""').toString(), 'CN="a, ""b"""');
    assert.equal(DistinguishedName.parse('CN=\\C3\\A9t\\E9').toString(), 'CN=été');
    assert.equal(DistinguishedName.parse('CN=a\\ ').toString(), 'CN="a "');
  });

  it('matches a multi-valued relative name in any order', () => {
    const name = der.encode(der.SEQUENCE, der.encode(der.SET,
      der.encode(der.SEQUENCE, der.encodeOid('2.5.4.3'), der.encode(der.UTF8_STRING, Buffer.from('a'))),
      der.encode(der.SEQUENCE, der.encodeOid('2.5.4.11'), der.encode(der.UTF8_STRING, Buffer.from('b')))));
    const subject = subjectOf(name);
    assert.ok(subject.matches(DistinguishedName.parse('CN=a + OU=b')));
    assert.ok(subject.matches(DistinguishedName.parse('OU=b + CN=a')));
    assert.ok(!subject.matches(DistinguishedName.parse('CN=a, OU=b')));
  });

  it("refuses what isn't a distinguished name", () => {
    for (const text of ['', 'api.example.com', 'XX=a', 'CN="a', 'CN="a" b', 'CN=a\\', '1=a']) {
      assert.throws(() => DistinguishedName.parse(text), TypeError, text);
    }
  });

  it('renders a name as .NET does', () => {
    assert.equal(subjectOf(nameDer('CN=api.example.com, OU=Web, O=Contoso, C=US')).toString(), 'CN=api.example.com, OU=Web, O=Contoso, C=US');
    assert.equal(DistinguishedName.parse('E=a@b.c, DC=example, OID.1.2.3.4=x').toString(), 'E=a@b.c, DC=example, OID.1.2.3.4=x');
  });
});

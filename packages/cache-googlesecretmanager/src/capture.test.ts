import { strict as assert } from 'node:assert';
import { inspect } from 'node:util';
import { describe, it, type TestContext } from 'node:test';
import { protos } from '@google-cloud/secret-manager';
import { isZero } from '@runsecure/hkdfguard-abstractions';
import { crc32c } from '@runsecure/hkdfguard-abstractions/internal';
import { AccessedSecretVersion, MalformedResponseError, parseAccessResponse, ResponseCapture } from './capture.js';

/*
 * The AccessSecretVersion response parser and the per-fetch capture, driven directly with the bytes
 * gRPC would hand the deserializer - the counterpart of hkdfguard-python's capture tests and
 * hkdfguard-java's ReceiveBufferScrubberTest.
 */

const v1 = protos.google.cloud.secretmanager.v1;
const utf8 = (s: string) => new TextEncoder().encode(s);

const payloadOf = (length: number) => Uint8Array.from({ length }, (_, i) => (i % 251) + 1);

function serialized(name = 'projects/1/secrets/s/versions/1', data: Uint8Array = new Uint8Array(0), crc?: number): Buffer {
  const payload: protos.google.cloud.secretmanager.v1.ISecretPayload = { data };
  if (crc !== undefined) payload.dataCrc32c = crc;
  return Buffer.from(v1.AccessSecretVersionResponse.encode({ name, payload }).finish());
}

function varint(value: number): number[] {
  const out: number[] = [];
  for (;;) {
    const byte = value & 0x7f;
    value = Math.floor(value / 128);
    if (value === 0) {
      out.push(byte);
      return out;
    }
    out.push(byte | 0x80);
  }
}

const bytes = (...parts: (number[] | Uint8Array)[]) => Buffer.concat(parts.map((p) => Buffer.from(p)));

function field(number: number, wireType: number, body: number[] | Uint8Array): Buffer {
  const tag = varint((number << 3) | wireType);
  return wireType === 2 ? bytes(tag, varint(body.length), body) : bytes(tag, body);
}

/** Records the payload buffer every AccessedSecretVersion.zero erases, for the rest of the test. */
function recordZeroed(t: TestContext): Uint8Array[] {
  const zeroed: Uint8Array[] = [];
  const zero = AccessedSecretVersion.prototype.zero;
  t.mock.method(AccessedSecretVersion.prototype, 'zero', function (this: AccessedSecretVersion) {
    zeroed.push(this.data);
    zero.call(this);
  });
  return zeroed;
}

describe('parseAccessResponse', () => {
  for (const length of [0, 1, 100, 127, 128, 20_000, 64 * 1024]) {
    it(`parses a ${length}-byte payload as protobuf does`, () => {
      const data = payloadOf(length);
      const version = parseAccessResponse(serialized(undefined, data, crc32c(data)));
      assert.equal(version.name, 'projects/1/secrets/s/versions/1');
      assert.deepEqual(version.data, data);
      assert.equal(version.dataCrc32c, BigInt(crc32c(data)));
    });
  }

  it('copies the payload into a Uint8Array of its own, untouched by zeroing the message', () => {
    const raw = serialized(undefined, utf8('value'));
    const version = parseAccessResponse(raw);
    raw.fill(0);
    assert.equal(Object.getPrototypeOf(version.data), Uint8Array.prototype);
    assert.deepEqual(version.data, utf8('value'));
  });

  it('erases the payload on zero', () => {
    const version = parseAccessResponse(serialized(undefined, utf8('value')));
    version.zero();
    assert.equal(version.data.length, 5);
    assert.ok(isZero(version.data));
  });

  it('parses an empty message as the default instance', () => {
    const version = parseAccessResponse(new Uint8Array(0));
    assert.deepEqual([version.name, version.data, version.dataCrc32c], ['', new Uint8Array(0), undefined]);
  });

  it('gives a response without a payload no data and no checksum', () => {
    const version = parseAccessResponse(v1.AccessSecretVersionResponse.encode({ name: 'n' }).finish());
    assert.deepEqual([version.name, version.data, version.dataCrc32c], ['n', new Uint8Array(0), undefined]);
  });

  it('reads a checksum of zero as present, not absent', () => {
    assert.equal(parseAccessResponse(serialized(undefined, utf8('x'), 0)).dataCrc32c, 0n);
  });

  it('reads a negative int64 checksum as signed', () => {
    assert.equal(parseAccessResponse(serialized(undefined, utf8('x'), -1)).dataCrc32c, -1n);
  });

  it('skips unknown fields of every wire type, at both levels', () => {
    const unknown = bytes(field(9, 0, varint(300)), field(10, 1, new Uint8Array(8)), field(11, 2, utf8('skipped')), field(12, 5, new Uint8Array(4)));
    const payload = bytes(unknown, field(1, 2, utf8('value')), unknown, field(2, 0, varint(7)));
    const version = parseAccessResponse(bytes(unknown, field(1, 2, utf8('name')), field(2, 2, payload), unknown));
    assert.deepEqual([version.name, version.data, version.dataCrc32c], ['name', utf8('value'), 7n]);
  });

  it('reads fields in any order', () => {
    const version = parseAccessResponse(bytes(field(2, 2, bytes(field(2, 0, varint(5)), field(1, 2, utf8('value')))), field(1, 2, utf8('name'))));
    assert.deepEqual([version.name, version.data, version.dataCrc32c], ['name', utf8('value'), 5n]);
  });

  it('merges a repeated payload, zeroing the data it replaces', (t) => {
    const zeroed = recordZeroed(t);
    const raw = bytes(field(2, 2, bytes(field(1, 2, utf8('first')), field(2, 0, varint(9)))), field(2, 2, field(1, 2, utf8('second'))));

    const version = parseAccessResponse(raw);

    // The second occurrence's data replaces the first's; its absent checksum leaves the first's.
    assert.deepEqual([version.data, version.dataCrc32c], [utf8('second'), 9n]);
    const first = zeroed.filter((data) => data.length === 5);
    assert.equal(first.length, 1);
    assert.ok(isZero(first[0]!));
  });

  it('keeps the last name', () => {
    assert.equal(parseAccessResponse(bytes(field(1, 2, utf8('a')), field(1, 2, utf8('b')))).name, 'b');
  });

  const malformed: [string, number[]][] = [
    ['name\'s length past the end', [0x0a, 0x7f, 1, 2, 3]],
    ['the message ending before name\'s length', [0x0a]],
    ['the message ending inside a tag', [0x80]],
    ['name as a varint', [0x08, 0x01]],
    ['data as a varint', [0x12, 0x02, 0x08, 0x01]],
    ['data_crc32c length-delimited', [0x12, 0x02, 0x12, 0x00]],
    ['data_crc32c ending inside its varint', [0x12, 0x02, 0x10, 0x80]],
    ['field number 0', [0x00, 0x00]],
    ['a group (wire type 3)', [0x1b]],
    ['wire type 6', [0x1e]],
    ['a fixed64 ending early', [0x19, 0, 0]],
    ['a fixed32 ending early', [0x1d, 0]],
    ['a varint over 10 bytes', [0x18, ...new Array<number>(10).fill(0xff), 1]],
    ['a varint over 64 bits', [0x18, ...new Array<number>(9).fill(0xff), 0x7f]],
    ['a name that isn\'t UTF-8', [0x0a, 0x02, 0xc3, 0x28]],
    ['data running past its payload', [0x12, 0x03, 0x0a, 0x05, 0x61]],
  ];
  for (const [what, raw] of malformed) {
    it(`refuses ${what}`, () => {
      assert.throws(() => parseAccessResponse(Uint8Array.from(raw)), MalformedResponseError);
    });
  }

  it('zeroes the payload it had already copied when the parse fails', (t) => {
    const zeroed = recordZeroed(t);
    assert.throws(() => parseAccessResponse(bytes(field(2, 2, field(1, 2, utf8('secret'))), [0x0a, 0x7f])), MalformedResponseError);
    const copied = zeroed.filter((data) => data.length === 6);
    assert.equal(copied.length, 1);
    assert.ok(isZero(copied[0]!));
  });

  it('says nothing of the message\'s contents when it is malformed', () => {
    assert.throws(() => parseAccessResponse(bytes(field(2, 2, field(1, 2, utf8('s3cret'))), [0x0a, 0x02, 0xc3, 0x28])), (e: unknown) => {
      assert.ok(e instanceof MalformedResponseError);
      assert.ok(!e.message.includes('s3cret'));
      assert.equal(e.cause, undefined);
      return true;
    });
  });

  it('never shows the payload when inspected or serialized', () => {
    const version = parseAccessResponse(serialized(undefined, utf8('s3cret'), 1));
    assert.ok(!inspect(version).includes('s3cret'));
    assert.ok(inspect(version).includes('6 bytes'));
    assert.ok(!JSON.stringify(version).includes('s3cret'));
  });
});

describe('ResponseCapture', () => {
  it('keeps every response it parsed, and close zeroes them all', () => {
    const capture = new ResponseCapture();
    const first = capture.deserialize(serialized(undefined, utf8('first')));
    const second = capture.deserialize(serialized(undefined, utf8('second')));

    capture.close();

    assert.deepEqual([first.data.length, second.data.length], [5, 6]);
    assert.ok(isZero(first.data));
    assert.ok(isZero(second.data));
  });

  it('zeroes the message gRPC received once it is read', () => {
    const raw = serialized(undefined, utf8('value'));
    const version = new ResponseCapture().deserialize(raw);
    assert.ok(isZero(raw));
    assert.deepEqual(version.data, utf8('value'));
  });

  it('parses nothing once closed, and zeroes the message unread', () => {
    const capture = new ResponseCapture();
    capture.close();
    const raw = serialized(undefined, utf8('late'));

    const late = capture.deserialize(raw);

    assert.deepEqual([late.name, late.data], ['', new Uint8Array(0)]);
    assert.ok(isZero(raw));
  });

  it('throws for a malformed message, zeroing it and keeping nothing', () => {
    const capture = new ResponseCapture();
    const raw = bytes(field(2, 2, field(1, 2, utf8('secret'))), [0x0a, 0x7f]);
    assert.throws(() => capture.deserialize(raw), MalformedResponseError);
    assert.ok(isZero(raw));
    capture.close();
  });
});

describe('crc32c', () => {
  it('matches the Castagnoli check value', () => {
    assert.equal(crc32c(utf8('123456789')), 0xe3069283);
    assert.equal(crc32c(new Uint8Array(0)), 0);
    assert.equal(crc32c(Buffer.from('123456789')), 0xe3069283);
  });
});

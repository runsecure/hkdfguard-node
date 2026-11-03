import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { SecureBuffer } from './body.js';
import { VaultJsonError } from './client-errors.js';
import { formatGoDuration, parseGoDuration } from './duration.js';
import { decrypt, makeProtector } from './fake-vault.test-support.js';
import { AliCloudLoginRequest, KvV2ReadResponse } from './generated/schema.js';
import { JsonKind, JsonValue, JsonWriter } from './json.js';
import { readResponse } from './response.js';

function written(write: (writer: JsonWriter) => void): string {
  const buffer = new SecureBuffer();
  try {
    write(new JsonWriter(buffer));
    return buffer.view().toString('utf8');
  } finally {
    buffer.close();
  }
}

describe('Go durations', () => {
  for (const [text, ms] of [['0', 0], ['1h30m', 5_400_000], ['300ms', 300], ['2.5s', 2500], ['-1m', -60_000], ['+5s', 5000], ['1500us', 1.5],
    ['1µs', 0.001], ['10ns', 0.00001], ['.5s', 500], ['1h1m1s1ms', 3_661_001]] as const) {
    it(`parses ${text}`, () => assert.equal(parseGoDuration(text), ms));
  }

  for (const text of ['', '5', 's', '1.2.3s', '1d', '-', '1h-1m', '..5s', '9999999999h']) {
    it(`refuses '${text}'`, () => assert.throws(() => parseGoDuration(text), RangeError));
  }

  for (const [ms, text] of [[0, '0s'], [300_000, '5m0s'], [3_723_500, '1h2m3.5s'], [0.0015, '1.5µs'], [1.5e-5, '15ns'], [2.25, '2.25ms'], [-1000, '-1s'],
    [90_000, '1m30s']] as const) {
    it(`formats ${ms} ms as ${text}`, () => assert.equal(formatGoDuration(ms), text));
  }
});

describe('JsonValue', () => {
  it('reads a string property from whatever JSON stands in its place, as text', () => {
    const json = JsonValue.parse('{"s":"x","n":1.50,"b":true,"o":{"a":[1]},"z":null}');
    assert.deepEqual(['s', 'n', 'b', 'o', 'z'].map((m) => json.member(m).readString()), ['x', '1.50', 'true', '{"a":[1]}', undefined]);
  });

  it('reads numbers leniently, but refuses what isn\'t one', () => {
    const json = JsonValue.parse('{"i":12,"f":"4.0","e":1e3,"s":" 7 ","h":4.5,"x":"abc"}');
    assert.deepEqual(['i', 'f', 'e', 's'].map((m) => json.member(m).readInteger()), [12, 4, 1000, 7]);
    assert.throws(() => json.member('h').readInteger(), VaultJsonError);
    assert.throws(() => json.member('x').readNumber(), VaultJsonError);
    assert.equal(json.member('h').readNumber(), 4.5);
    assert.equal(JsonValue.parse('123456789012345678901').asBigInt(), 123456789012345678901n);
  });

  it('has strict readers that refuse another kind', () => {
    const json = JsonValue.parse('{"s":"x"}');
    assert.throws(() => json.member('s').asNumber(), /Expected a JSON number, not a string/);
    assert.throws(() => json.asArray(), VaultJsonError);
    assert.throws(() => json.member('s').readBoolean(), VaultJsonError);
    assert.equal(json.member('missing').isNull, true);
    assert.equal(json.kind, JsonKind.object);
  });

  it('reads a date-time as Go writes it, and without an offset as UTC', () => {
    const read = (text: string) => JsonValue.of(text).readDate()?.toISOString();
    assert.equal(read('2024-01-02T03:04:05.123456789Z'), '2024-01-02T03:04:05.123Z');
    assert.equal(read('2024-01-02T03:04:05+02:00'), '2024-01-02T01:04:05.000Z');
    assert.equal(read('2024-01-02T03:04:05'), '2024-01-02T03:04:05.000Z');
    assert.equal(read(''), undefined);
    assert.throws(() => read('yesterday'), VaultJsonError);
  });

  it('reads plain JavaScript, a big integer as a bigint', () => {
    assert.deepEqual(JsonValue.parse('{"a":[1,"x",null,true],"b":{"c":1.5},"d":9007199254740993}').readUnknown(),
      { a: [1, 'x', null, true], b: { c: 1.5 }, d: 9007199254740993n });
  });

  it('keeps members in order, the last of a repeated name winning in the first one\'s place', () => {
    assert.deepEqual(Object.keys(JsonValue.parse('{"b":1,"a":2,"b":3}').asRecord()), ['b', 'a']);
    assert.equal(JsonValue.parse('{"b":1,"a":2,"b":3}').member('b').asNumber(), 3);
  });

  it('is compact JSON as a string, and equal structurally', () => {
    const json = JsonValue.parse(' { "a" : [ 1 , "\\u00e9\\n" ] } ');
    assert.equal(json.toString(), '{"a":[1,"é\\n"]}');
    assert.ok(json.equals(JsonValue.parse('{"a":[1,"é\\n"]}')));
    assert.ok(!json.equals(JsonValue.parse('{"a":[1]}')));
  });

  it('passes null through readModel and readJson', () => {
    assert.equal(JsonValue.NULL.readModel(() => 'never'), undefined);
    assert.equal(JsonValue.NULL.readJson(), undefined);
  });

  it('refuses a null in an array or record of typed values', () => {
    assert.throws(() => JsonValue.parse('[1,null]').readArray((v) => v.readInteger()), VaultJsonError);
    assert.throws(() => JsonValue.parse('{"a":null}').readRecord((v) => v.readString()), VaultJsonError);
  });

  it("refuses what isn't one JSON value", () => {
    for (const text of ['', '{', '{} {}', '[1,]', 'nul']) assert.throws(() => JsonValue.parse(text), VaultJsonError, text);
  });

  it("reads a generated model leniently, and refuses what isn't an object", () => {
    const model = KvV2ReadResponse.read(JsonValue.parse('{"data":{"k":"v"},"metadata":{"version":3},"extra":1}'));
    assert.equal(model.data?.k?.asString(), 'v');
    assert.equal(model.metadata?.version?.asNumber(), 3);
    assert.throws(() => KvV2ReadResponse.read(JsonValue.parse('[]')), /Expected a JSON object for KvV2ReadResponse/);
  });
});

describe('JsonWriter', () => {
  it('escapes what JSON must and writes the rest as UTF-8', () => {
    assert.equal(written((w) => w.value('q"b\\\n\t\u0001é\u{1f600}')), '"q\\"b\\\\\\n\\t\\u0001é\u{1f600}"');
  });

  it("refuses an unpaired surrogate and bytes that aren't UTF-8", () => {
    assert.throws(() => written((w) => w.value('\ud800')), RangeError);
    assert.throws(() => written((w) => w.value(Uint8Array.of(0xc0, 0x80))), RangeError);
    assert.throws(() => written((w) => w.value(Uint8Array.of(0xe2, 0x82))), RangeError);
  });

  it('writes bytes as a string', () => {
    assert.equal(written((w) => w.value(Buffer.from('sé"cret'))), '"sé\\"cret"');
  });

  it('writes every kind of value', () => {
    const value = { s: 'x', n: 1.5, i: -2, big: 10n, t: true, z: null, u: undefined, d: new Date(Date.UTC(2024, 0, 2)), a: [1, [2]], m: new Map([['k', 'v']]),
      j: JsonValue.parse('{"x":1}'), o: Object.assign(Object.create(null), { p: 1 }) };
    assert.equal(written((w) => w.value(value)),
      '{"s":"x","n":1.5,"i":-2,"big":10,"t":true,"z":null,"d":"2024-01-02T00:00:00.000Z","a":[1,[2]],"m":{"k":"v"},"j":{"x":1},"o":{"p":1}}');
  });

  it("refuses what JSON can't hold", () => {
    for (const value of [Number.NaN, Infinity, Symbol('s'), () => 1, new Date(Number.NaN), new (class Thing {})()]) {
      assert.throws(() => written((w) => w.value(value)), (error: Error) => error instanceof TypeError || error instanceof RangeError);
    }
  });

  it('refuses nesting deeper than 64', () => {
    let deep: unknown = 1;
    for (let i = 0; i < 64; i++) deep = [deep];
    assert.doesNotThrow(() => written((w) => w.value(deep)));
    assert.throws(() => written((w) => w.value([deep])), RangeError);
  });

  it('keeps to the grammar', () => {
    assert.throws(() => written((w) => w.beginObject().value(1)), /needs a name/);
    assert.throws(() => written((w) => w.name('a')), /only inside an object/);
    assert.throws(() => written((w) => w.beginArray().endObject()), /No open object/);
  });

  it('fails the write of a model missing a required member', () => {
    assert.throws(() => written((w) => AliCloudLoginRequest.write(w, {} as never)), /AliCloudLoginRequest needs its role/);
    assert.match(written((w) => AliCloudLoginRequest.write(w, { role: 'r' })), /"role":"r"/);
  });

  it('grows a secure buffer, zeroing the old bytes as it grows and all on close', () => {
    const buffer = new SecureBuffer(1);
    buffer.write(Buffer.alloc(256, 7));
    const first = buffer.view();
    buffer.writeByte(8);
    assert.ok(first.every((b) => b === 0));
    assert.equal(buffer.length, 257);
    const last = buffer.view();
    buffer.close();
    assert.ok(last.every((b) => b === 0));
    assert.equal(buffer.length, 0);
  });
});

describe('readResponse', () => {
  const protector = makeProtector();

  it('protects the tokens in a response straight from its bytes, and they appear nowhere else', async () => {
    const body = Buffer.from('{"auth":{"client_token":"hvs.abc","accessor":"a"},"wrap_info":{"token":"hvs.wrap","ttl":5}}');
    const response = readResponse(body, protector, (j) => j.readJsonRecord());
    assert.equal(await decrypt(protector, response?.auth?.clientToken), 'hvs.abc');
    assert.equal(await decrypt(protector, response?.wrapInfo?.token), 'hvs.wrap');
    assert.ok(!JSON.stringify({ ...response?.auth, clientToken: undefined }).includes('hvs.abc'));
  });

  it('reads a body without an envelope member whole as data', () => {
    assert.equal(readResponse(Buffer.from('{"sealed":true}'), protector, (j) => j.readJsonRecord())?.data?.sealed?.asBoolean(), true);
  });

  it('is undefined for an empty body', () => {
    assert.equal(readResponse(new Uint8Array(0), protector, (j) => j), undefined);
  });

  for (const body of ['{"data":{},"auth":"x"}', '{"wrap_info":[1]}', '{"data":{}} 1', '{"data":', '{"auth":{"client_token":5}}']) {
    it(`fails a response of the wrong shape: ${body}`, () => {
      assert.throws(() => readResponse(Buffer.from(body), protector, (j) => j.readJsonRecord()), VaultJsonError);
    });
  }
});

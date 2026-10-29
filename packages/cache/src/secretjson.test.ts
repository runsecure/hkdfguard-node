import { strict as assert } from 'node:assert';
import { Readable } from 'node:stream';
import { describe, it } from 'node:test';
import { InvalidArgumentError, isZero } from '@runsecure/hkdfguard-abstractions';
import { KeyRing } from '@runsecure/hkdfguard-dek';
import { RecordingKey } from '@runsecure/hkdfguard-test-support';
import type { ResponseBody } from './body.js';
import { ErrorResponseBody } from './errorbody.js';
import { InvalidSecretDataError } from './errors.js';
import { JsonReader, JsonToken, MalformedJsonError } from './json.js';
import { RemoteSecretCache, SecretNameMatching, type SecretValueSink } from './remote.js';
import { SecretJsonBody, type SecretJsonCaptureOptions } from './secretjson.js';

const utf8 = (s: string) => new TextEncoder().encode(s);
const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

/** A RemoteSecretCache whose every fetch is onFetch, as a provider's capture would be. */
class SinkCache extends RemoteSecretCache {
  onFetch: ((name: string, sink: SecretValueSink) => void | Promise<void>) | undefined;

  constructor() {
    const ring = new KeyRing();
    ring.add(1, new RecordingKey());
    super(ring, SecretNameMatching.exact);
  }

  protected override isValidName(name: string): boolean {
    return name.length > 0;
  }

  protected override async fetch(name: string, sink: SecretValueSink): Promise<void> {
    await this.onFetch?.(name, sink);
  }
}

async function decryptString(cache: RemoteSecretCache, name: string): Promise<string> {
  const result = new Uint8Array(256);
  return text(result.subarray(0, await cache.decrypt(name, result)));
}

const missing = async (cache: RemoteSecretCache, name: string) => assert.equal(await cache.decrypt(name, new Uint8Array(16)), 0);

/** The forms a body can come in: whole, a Node Readable, a web ReadableStream, and an array of small chunks. */
const bodyForms: [string, (json: Uint8Array) => ResponseBody][] = [
  ['buffer', (json) => json],
  ['Readable', (json) => Readable.from([json.slice(0, 5), json.slice(5)])],
  ['ReadableStream', (json) => new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(json.slice());
      controller.close();
    },
  })],
  ['chunks', (json) => Array.from({ length: Math.ceil(json.length / 3) }, (_, i) => json.slice(i * 3, i * 3 + 3))],
];

/** A stream whose read fails, as a reset connection's does. */
const failingStream = () => new Readable({ read() { this.destroy(new Error('connection reset')); } });

function tokens(json: string): (JsonToken | undefined)[] {
  const reader = new JsonReader(utf8(json));
  const found: (JsonToken | undefined)[] = [];
  while (reader.read()) found.push(reader.token());
  return found;
}

describe('JsonReader', () => {
  it('reads every kind of token', () => {
    assert.deepEqual(tokens(' {"a" : [ "s", -0.5e+10, true, false, null, {}, [] ] }\r\n\t'), [
      JsonToken.StartObject, JsonToken.PropertyName, JsonToken.StartArray, JsonToken.String, JsonToken.Number, JsonToken.True,
      JsonToken.False, JsonToken.Null, JsonToken.StartObject, JsonToken.EndObject, JsonToken.StartArray, JsonToken.EndArray,
      JsonToken.EndArray, JsonToken.EndObject]);
  });

  for (const json of ['0', '-0', '12', '1.25', '1e5', '1E-5', '-12.5e+3', '"text"', 'true', 'null', '[]', '{}']) {
    it(`reads ${json} as the root`, () => {
      assert.equal(tokens(json).length, json[0] === '[' || json[0] === '{' ? 2 : 1);
    });
  }

  it('finds no tokens in empty or whitespace input', () => {
    assert.deepEqual(tokens(''), []);
    assert.deepEqual(tokens(' \n '), []);
  });

  for (const json of [
    '01', '-', '1.', '1.e5', '1e', '1e+', '.5', '+1', '1x', 'tru', 'trUe', 'nul', 'falsy',
    '{', '[', '{"a"', '{"a":', '{"a" 1}', '{"a":1,}', '[1,]', '[1 2]', '{"a":1 "b":2}', '{1:2}', '{,}', '[,1]',
    '"unterminated', '"bad \\x escape"', '"\\u12"', '"\\u12G4"', '"\\udc00"', '"\\ud800"', '"\\ud800\\u0041"',
    '"\\ud800x"', '"tab\there"', '1 2', '{} {}', ']', '}', '/* comment */ 1', '{"a":1}/',
  ]) {
    it(`refuses ${JSON.stringify(json)}`, () => {
      assert.throws(() => tokens(json), MalformedJsonError);
    });
  }

  it('refuses nesting deeper than the limit, but not to it', () => {
    const depth = JsonReader.MAX_DEPTH;
    assert.equal(tokens('['.repeat(depth) + ']'.repeat(depth)).length, 2 * depth);
    assert.throws(() => tokens('['.repeat(depth + 1) + ']'.repeat(depth + 1)), MalformedJsonError);
  });

  it('places an error by its line and its position in it, never quoting it', () => {
    assert.throws(() => tokens('{\n"a":\n  x}'), (error: MalformedJsonError) =>
      error.line === 2 && error.position === 2 && !error.message.includes('x'));
  });

  it("skips a container's children, and nothing else", () => {
    const reader = new JsonReader(utf8('{"a":{"b":[1,{"c":2}]},"d":3}'));
    reader.read();
    reader.read();
    reader.read();
    assert.equal(reader.token(), JsonToken.StartObject);
    reader.skip();
    assert.equal(reader.token(), JsonToken.EndObject);
    reader.read();
    assert.equal(reader.getString(), 'd');
    reader.read();
    reader.skip();
    assert.equal(reader.token(), JsonToken.Number);
  });

  it('unescapes with copyString, and compares the unescaped text with valueTextEquals', () => {
    const reader = new JsonReader(utf8('{"k\\u0065y":"\\u00e9\\u4e2d\\ud83d\\ude00\\""}'));
    reader.read();
    reader.read();
    assert.ok(reader.valueTextEquals('key'));
    assert.ok(!reader.valueTextEquals('kex'));
    assert.equal(reader.getString(), 'key');
    reader.read();
    const destination = new Uint8Array(reader.valueLength);
    assert.equal(text(destination.subarray(0, reader.copyString(destination))), 'é中😀"');
  });

  it("bounds a string's token by its quotes", () => {
    const reader = new JsonReader(utf8('{"a": "xyz"}'));
    reader.read();
    reader.read();
    reader.read();
    assert.deepEqual([reader.tokenStart, reader.bytesConsumed, reader.valueLength], [6, 11, 3]);
  });

  it('replaces invalid UTF-8 in getString', () => {
    const reader = new JsonReader(Uint8Array.of(0x22, 0xff, 0x22));
    reader.read();
    assert.equal(reader.getString(), '�');
  });

  it('reads only the part of a buffer it is given', () => {
    const reader = new JsonReader(utf8('{"a":1} garbage'), 7);
    const found: (JsonToken | undefined)[] = [];
    while (reader.read()) found.push(reader.token());
    assert.deepEqual(found, [JsonToken.StartObject, JsonToken.PropertyName, JsonToken.Number, JsonToken.EndObject]);
  });
});

/** Runs captureAsync inside a fetch, as a provider's pipeline does; resolves to the redacted body and the value cached. */
async function captured(
  body: string, textProperty = 'value', options: SecretJsonCaptureOptions = {}, form: (json: Uint8Array) => ResponseBody = (json) => json,
): Promise<[string, string]> {
  const cache = new SinkCache();
  const redacted: Uint8Array[] = [];
  cache.onFetch = async (_name, sink) => { redacted.push(await SecretJsonBody.captureAsync(form(utf8(body)), sink, textProperty, options)); };
  const value = await decryptString(cache, 'item');
  return [text(redacted[0]!), value];
}

/** Expects a fetch capturing `body` to fail with InvalidSecretDataError, caching nothing. */
async function refused(capture: (sink: SecretValueSink) => unknown, message?: RegExp): Promise<void> {
  const cache = new SinkCache();
  cache.onFetch = async (_name, sink) => { await capture(sink); };
  await assert.rejects(cache.decrypt('item', new Uint8Array(16)), (error: Error) =>
    error instanceof InvalidSecretDataError && error.cause === undefined && (message === undefined || message.test(error.message)));
  cache.onFetch = undefined;
  await missing(cache, 'item');
}

describe('SecretJsonBody', () => {
  for (const [form, make] of bodyForms) {
    it(`hands the text value over and blanks it in the body: ${form}`, async () => {
      const [redacted, value] = await captured('{"id":"x","value":"s3cret","n":1}', 'value', {}, make);
      assert.equal(value, 's3cret');
      assert.equal(redacted, '{"id":"x","value":"","n":1}');
    });
  }

  it('captures synchronously from a whole body, reading it in place and leaving it as it is', async () => {
    const cache = new SinkCache();
    const body = utf8('{"value":"s3cret"}');
    const redacted: Uint8Array[] = [];
    cache.onFetch = (_name, sink) => { redacted.push(SecretJsonBody.capture(body, sink, 'value')); };
    assert.equal(await decryptString(cache, 'item'), 's3cret');
    assert.equal(text(redacted[0]!), '{"value":""}');
    assert.equal(text(body), '{"value":"s3cret"}');
  });

  it("zeroes a stream's chunks once copied", async () => {
    const cache = new SinkCache();
    const chunks = [utf8('{"value":'), utf8('"s3cret"}')];
    cache.onFetch = async (_name, sink) => { await SecretJsonBody.captureAsync(chunks, sink, 'value'); };
    assert.equal(await decryptString(cache, 'item'), 's3cret');
    assert.ok(chunks.every(isZero));
  });

  it('hands the base64 value over decoded', async () => {
    const cache = new SinkCache();
    const redacted: Uint8Array[] = [];
    cache.onFetch = (_name, sink) => {
      redacted.push(SecretJsonBody.capture(utf8('{"SecretString":null,"SecretBinary":"AAH+/w=="}'), sink, 'SecretString', { base64Property: 'SecretBinary' }));
    };
    const result = new Uint8Array(16);
    assert.deepEqual(result.subarray(0, await cache.decrypt('item', result)), Uint8Array.of(0, 1, 254, 255));
    assert.equal(text(redacted[0]!), '{"SecretString":null,"SecretBinary":""}');
  });

  for (let length = 1; length < 10; length++) {
    it(`decodes base64 of ${length} bytes, padded or not`, async () => {
      const data = Uint8Array.from({ length }, (_, i) => 250 - i);
      const encoded = Buffer.from(data).toString('base64');
      for (const form of [encoded, encoded.replace(/=+$/, '')]) {
        const cache = new SinkCache();
        cache.onFetch = (_name, sink) => { SecretJsonBody.capture(utf8(`{"b":"${form}"}`), sink, 't', { base64Property: 'b' }); };
        const result = new Uint8Array(16);
        assert.deepEqual(result.subarray(0, await cache.decrypt('item', result)), data);
      }
    });
  }

  it('unescapes escapes', async () => {
    const [, value] = await captured('{"value":"a\\"b\\\\c\\u00e9\\n\\/\\b\\f\\r\\t\\ud83d\\ude00é"}');
    assert.equal(value, 'a"b\\cé\n/\b\f\r\t😀é');
  });

  it('leaves a nested property of the same name alone', async () => {
    const [redacted, value] = await captured('{"tags":{"value":"tag"},"list":[{"value":"x"}],"value":"top"}');
    assert.equal(value, 'top');
    assert.equal(redacted, '{"tags":{"value":"tag"},"list":[{"value":"x"}],"value":""}');
  });

  it('matches an escaped property name unescaped', async () => {
    const [redacted, value] = await captured('{"val\\u0075e":"s3cret"}');
    assert.equal(value, 's3cret');
    assert.equal(redacted, '{"val\\u0075e":""}');
  });

  for (const body of ['{"other":"x"}', '{"value":null}', '{"value":42}', '{"value":""}', '{}']) {
    it(`hands nothing over for ${body}`, async () => {
      const [redacted, value] = await captured(body);
      assert.equal(value, '');
      assert.equal(redacted, body);
    });
  }

  it('blanks empty duplicates alongside the value', async () => {
    const [redacted, value] = await captured('{"value":"","value":"s","value":""}');
    assert.equal(value, 's');
    assert.equal(redacted, '{"value":"","value":"","value":""}');
  });

  for (const [body, textProperty, base64Property] of [
    ['{"value":"a","value":"b"}', 'value', undefined],
    ['{"SecretString":"a","SecretBinary":"Yg=="}', 'SecretString', 'SecretBinary'],
    ['{"SecretBinary":"not base64!"}', 'SecretString', 'SecretBinary'],
    ['{"SecretBinary":"Yg="}', 'SecretString', 'SecretBinary'],
    ['{"SecretBinary":"Y"}', 'SecretString', 'SecretBinary'],
    ['{"SecretBinary":"Yg==Yg=="}', 'SecretString', 'SecretBinary'],
    ['["value"]', 'value', undefined],
    ['{"value":"unterminated', 'value', undefined],
    ['"value"', 'value', undefined],
    ['', 'value', undefined],
  ] as const) {
    it(`refuses ${JSON.stringify(body)}, caching nothing`, async () => {
      await refused((sink) => SecretJsonBody.captureAsync(Readable.from([utf8(body)]), sink, textProperty, { base64Property }));
      if (body.length > 0) await refused((sink) => SecretJsonBody.capture(utf8(body), sink, textProperty, { base64Property }));
    });
  }

  for (const [body, position] of [['{"value":"s3cr\\qt"}', 15], ['{"value":"s3cr\x01t"}', 14]] as const) {
    it(`reports a malformed secret by position only, never the byte rejected: ${position}`, async () => {
      await refused((sink) => SecretJsonBody.capture(utf8(body), sink, 'value'),
        new RegExp(`^The response body isn't valid JSON \\(at byte ${position} of line 0\\)\\.$`));
    });
  }

  it('reports a malformed secret by its position in its own line', async () => {
    await refused((sink) => SecretJsonBody.capture(utf8('{\n  "value":"s3cr\\qt"}'), sink, 'value'),
      /^The response body isn't valid JSON \(at byte 16 of line 1\)\.$/);
  });

  it('reads a body larger than the first buffer whole', async () => {
    const padding = 'x'.repeat(100_000);
    const [redacted, value] = await captured(`{"pad":"${padding}","value":"s3cret"}`, 'value', {}, bodyForms[1]![1]);
    assert.equal(value, 's3cret');
    assert.equal(redacted, `{"pad":"${padding}","value":""}`);
  });

  for (const [form, make] of bodyForms) {
    it(`refuses a body at the limit: ${form}`, async () => {
      const body = new Uint8Array(SecretJsonBody.MAX_BODY_LENGTH);
      await refused((sink) => SecretJsonBody.captureAsync(make(body), sink, 'value'), /bytes or more/);
    });
  }

  it('refuses a body at the limit synchronously, and reads one just under it', async () => {
    await refused((sink) => SecretJsonBody.capture(new Uint8Array(SecretJsonBody.MAX_BODY_LENGTH), sink, 'value'), /bytes or more/);
    const json = utf8(`{"value":"s3cret","pad":"${'x'.repeat(SecretJsonBody.MAX_BODY_LENGTH - 28)}"}`);
    assert.equal(json.length, SecretJsonBody.MAX_BODY_LENGTH - 1);
    const cache = new SinkCache();
    cache.onFetch = async (_name, sink) => { await SecretJsonBody.captureAsync(Readable.from([json]), sink, 'value'); };
    assert.equal(await decryptString(cache, 'item'), 's3cret');
  });

  it('fails with the read error when the body cannot be read', async () => {
    const cache = new SinkCache();
    cache.onFetch = async (_name, sink) => { await SecretJsonBody.captureAsync(failingStream(), sink, 'value'); };
    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), /connection reset/);
  });

  it('refuses a stream yielding strings', async () => {
    const cache = new SinkCache();
    cache.onFetch = async (_name, sink) => { await SecretJsonBody.captureAsync(Readable.from(['{"value":"s"}']), sink, 'value'); };
    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), TypeError);
  });

  it('stops reading once its signal is aborted', async () => {
    const cache = new SinkCache();
    const reason = new Error('gave up');
    cache.onFetch = async (_name, sink) => {
      await SecretJsonBody.captureAsync([utf8('{"value":"s"}')], sink, 'value', { signal: AbortSignal.abort(reason) });
    };
    await assert.rejects(cache.decrypt('item', new Uint8Array(16)), (error) => error === reason);
  });

  it('hands a nested value over, blanking only it', async () => {
    const body = '{"value":"top","data":{"value":"middle","data":{"other":1,"value":"s3cret"},"metadata":{"value":"m"}}}';
    const [redacted, value] = await captured(body, 'value', { objectPath: ['data', 'data'] });
    assert.equal(value, 's3cret');
    assert.equal(redacted, '{"value":"top","data":{"value":"middle","data":{"other":1,"value":""},"metadata":{"value":"m"}}}');
  });

  for (const body of ['{"data":null}', '{"data":"value"}', '{"data":[{"value":"x"}]}', '{"other":{"value":"x"}}']) {
    it(`hands nothing over when the path leads to no object: ${body}`, async () => {
      const [, value] = await captured(body, 'value', { objectPath: ['data'] });
      assert.equal(value, '');
    });
  }

  it('refuses values under duplicate parents', async () => {
    await refused((sink) => SecretJsonBody.capture(utf8('{"data":{"value":"a"},"data":{"value":"b"}}'), sink, 'value', { objectPath: ['data'] }));
  });

  it('hands a text value holding a JSON object over whole and by key, but a base64 one only whole', async () => {
    const cache = new SinkCache();
    const json = '{"user":"app","pass":"s3cret"}';
    const body = utf8(JSON.stringify({ SecretString: json }));
    cache.onFetch = (_name, sink) => { SecretJsonBody.capture(body, sink, 'SecretString', { base64Property: 'SecretBinary' }); };
    assert.equal(await decryptString(cache, 'item#pass'), 's3cret');
    assert.equal(await decryptString(cache, 'item#user'), 'app');
    assert.equal(await decryptString(cache, 'item'), json);

    const binary = utf8(JSON.stringify({ SecretBinary: Buffer.from(json).toString('base64') }));
    cache.onFetch = (_name, sink) => { SecretJsonBody.capture(binary, sink, 'SecretString', { base64Property: 'SecretBinary' }); };
    assert.equal(await decryptString(cache, 'binary'), json);
    await missing(cache, 'binary#pass');
  });

  for (const [form, make] of bodyForms) {
    it(`captureKeys hands over every member of the object at the path: ${form}`, async () => {
      const cache = new SinkCache();
      const body = utf8('{"data":{"data":{"username":"app","password":"s3cret","port":5432},"metadata":{"version":3}},"value":"top"}');
      cache.onFetch = async (_name, sink) => { await SecretJsonBody.captureKeysAsync(make(body), sink, ['data', 'data']); };
      assert.equal(await decryptString(cache, 'item#password'), 's3cret');
      assert.equal(await decryptString(cache, 'item#username'), 'app');
      assert.equal(await decryptString(cache, 'item#port'), '5432');
      for (const name of ['item', 'item#version', 'item#value']) await missing(cache, name);
    });
  }

  it('captureKeys reads a whole body synchronously', async () => {
    const cache = new SinkCache();
    cache.onFetch = (_name, sink) => SecretJsonBody.captureKeys(utf8('{"k":"v"}'), sink, []);
    assert.equal(await decryptString(cache, 'item#k'), 'v');
  });

  for (const body of ['{"data":{"data":null}}', '{"data":{"other":{"k":"v"}}}', '{"data":{"data":{}}}']) {
    it(`captureKeys hands nothing over with no keys at the path: ${body}`, async () => {
      const cache = new SinkCache();
      cache.onFetch = (_name, sink) => SecretJsonBody.captureKeys(utf8(body), sink, ['data', 'data']);
      await missing(cache, 'item#k');
    });
  }

  for (const body of ['{"data":{"k":"a"},"data":{"k":"b"}}', '{"data":{"k":"a","k":"b"}}', '{"data":{"k":"a",}}', '["data"]']) {
    it(`captureKeys refuses ${body}, caching nothing`, async () => {
      await refused((sink) => SecretJsonBody.captureKeysAsync(Readable.from([utf8(body)]), sink, ['data']));
    });
  }

  it('checks its arguments', async () => {
    const cache = new SinkCache();
    cache.onFetch = async (_name, sink) => {
      const body = utf8('{}');
      assert.throws(() => SecretJsonBody.capture(undefined as unknown as Uint8Array, sink, 'value'), TypeError);
      assert.throws(() => SecretJsonBody.capture(body, undefined as unknown as SecretValueSink, 'value'), TypeError);
      assert.throws(() => SecretJsonBody.capture(body, {} as SecretValueSink, 'value'), TypeError);
      assert.throws(() => SecretJsonBody.capture(Readable.from([body]) as unknown as Uint8Array, sink, 'value'), TypeError);
      assert.throws(() => SecretJsonBody.capture(body, sink, ''), (error: Error) => error instanceof InvalidArgumentError && /text property/.test(error.message));
      assert.throws(() => SecretJsonBody.capture(body, sink, undefined as unknown as string), /text property/);
      assert.throws(() => SecretJsonBody.capture(body, sink, 'value', { objectPath: ['data', ''] }), /path/);
      assert.throws(() => SecretJsonBody.capture(body, sink, 'value', { objectPath: [undefined as unknown as string] }), /path/);
      assert.throws(() => SecretJsonBody.capture(body, sink, 'value', { objectPath: 'data' as unknown as string[] }), TypeError);
      assert.throws(() => SecretJsonBody.captureKeys(undefined as unknown as Uint8Array, sink, ['data']), TypeError);
      assert.throws(() => SecretJsonBody.captureKeys(body, undefined as unknown as SecretValueSink, ['data']), TypeError);
      assert.throws(() => SecretJsonBody.captureKeys(body, sink, ['']), /path/);
      await assert.rejects(SecretJsonBody.captureAsync(undefined as unknown as Uint8Array, sink, 'value'), TypeError);
      await assert.rejects(SecretJsonBody.captureAsync(42 as unknown as Uint8Array, sink, 'value'), TypeError);
      await assert.rejects(SecretJsonBody.captureAsync(body, sink, ''), /text property/);
      await assert.rejects(SecretJsonBody.captureKeysAsync(body, sink, undefined as unknown as string[]), TypeError);
    };
    await missing(cache, 'item');
  });
});

describe('ErrorResponseBody', () => {
  const readErrors = (body: string, form: (json: Uint8Array) => ResponseBody = (json) => json) =>
    ErrorResponseBody.readStringsAsync(form(utf8(body)), 'errors');

  for (const [form, make] of bodyForms) {
    it(`returns the array's elements, strings as their text and anything else as JSON: ${form}`, async () => {
      const body = '{"warnings":["w"],"errors":["permission denied","a \\"quoted\\" \\u00e9",42,{"a":[1]},null],"n":{}}';
      assert.deepEqual(await readErrors(body, make), ['permission denied', 'a "quoted" é', '42', '{"a":[1]}', 'null']);
    });
  }

  it('reads a whole body synchronously', () => {
    assert.deepEqual(ErrorResponseBody.readStrings(utf8('{"errors":["denied"]}'), 'errors'), ['denied']);
  });

  it('finds no errors in an object without the property', async () => {
    assert.deepEqual(await readErrors('{"data":{"k":"v"}}'), []);
    assert.deepEqual(await readErrors('{"errors":[]}'), []);
  });

  for (const body of ['', '<html>Bad Gateway</html>', '["errors"]', '{"errors":"denied"}', '{"errors":["x"]} trailing', '{"errors":["x"']) {
    it(`reads ${JSON.stringify(body)}, which isn't an object with an array, as undefined`, async () => {
      assert.equal(await readErrors(body), undefined);
      assert.equal(ErrorResponseBody.readStrings(utf8(body), 'errors'), undefined);
    });
  }

  for (const [form, make] of bodyForms) {
    it(`reads a body beyond the limit only that far, so it isn't JSON: ${form}`, async () => {
      assert.equal(await readErrors(`{"errors":["${'x'.repeat(ErrorResponseBody.MAX_BODY_LENGTH)}"]}`, make), undefined);
    });
  }

  it('propagates a read failure, and refuses missing arguments', async () => {
    await assert.rejects(ErrorResponseBody.readStringsAsync(failingStream(), 'errors'), /connection reset/);
    await assert.rejects(ErrorResponseBody.readStringsAsync(undefined as unknown as Uint8Array, 'errors'), TypeError);
    assert.throws(() => ErrorResponseBody.readStrings(undefined as unknown as Uint8Array, 'errors'), TypeError);
    assert.throws(() => ErrorResponseBody.readStrings(new Uint8Array(0), undefined as unknown as string), TypeError);
  });
});

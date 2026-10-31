import { wipe } from '@runsecure/hkdfguard-abstractions';

/*
 * Reads an AccessSecretVersion response straight from the bytes gRPC received, so the secret payload
 * lands only in a Uint8Array HkdfGuard zeroes - never in a protobufjs message - and zeroes gRPC's
 * received bytes once read. Internal to the package; the counterpart of hkdfguard-python's _capture
 * and of the .NET and Java ReceiveBufferScrubber.
 */

// Protobuf wire types.
const VARINT = 0;
const FIXED64 = 1;
const LENGTH_DELIMITED = 2;
const FIXED32 = 5;

// AccessSecretVersionResponse: string name = 1; SecretPayload payload = 2.
const RESPONSE_NAME = 1;
const RESPONSE_PAYLOAD = 2;
// SecretPayload: bytes data = 1; optional int64 data_crc32c = 2.
const PAYLOAD_DATA = 1;
const PAYLOAD_DATA_CRC32C = 2;

const MAX_FIELD_NUMBER = 0x1fffffff;
const utf8 = new TextDecoder('utf-8', { fatal: true });

/**
 * The bytes gRPC received aren't an AccessSecretVersionResponse. Says where, never what: no part of
 * the message is quoted. Thrown inside gRPC's response deserializer, which turns it into an INTERNAL
 * status ("Response message parsing error: ..."), as a malformed message is for any gRPC client.
 */
export class MalformedResponseError extends Error {
  override readonly name = 'MalformedResponseError';
}

/**
 * What an AccessSecretVersion response holds, as the cache needs it: the version's resource name, its
 * payload's `data` in a Uint8Array of the cache's own, and `dataCrc32c` (undefined when the response
 * has none) as the signed 64-bit integer the field is. {@link zero} erases the payload; neither
 * inspecting nor JSON-serializing it shows the payload.
 */
export class AccessedSecretVersion {
  name = '';
  data: Uint8Array = new Uint8Array(0);
  dataCrc32c: bigint | undefined;

  /** Zeroes the payload. */
  zero(): void {
    wipe(this.data);
  }

  toJSON(): Record<string, unknown> {
    return { name: this.name, data: `<${this.data.length} bytes>`, dataCrc32c: this.dataCrc32c?.toString() };
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return `AccessedSecretVersion { name: ${JSON.stringify(this.name)}, data: <${this.data.length} bytes>, dataCrc32c: ${String(this.dataCrc32c)} }`;
  }
}

/**
 * Parses a serialized AccessSecretVersionResponse as protobuf does - fields in any order, a repeated
 * message merged, a repeated scalar's last value kept, unknown fields skipped - copying the payload
 * out of `raw` into a Uint8Array of its own. A payload left behind by a later occurrence, or by a
 * failure, is zeroed. `raw` itself is left as it is (see {@link ResponseCapture}).
 * @throws MalformedResponseError raw isn't a well-formed AccessSecretVersionResponse
 */
export function parseAccessResponse(raw: Uint8Array): AccessedSecretVersion {
  const version = new AccessedSecretVersion();
  try {
    parseResponse(new Reader(raw, 0, raw.length), version);
  } catch (error) {
    version.zero();
    throw error;
  }
  return version;
}

function parseResponse(reader: Reader, version: AccessedSecretVersion): void {
  while (!reader.done) {
    const [field, wireType] = reader.tag();
    if (field === RESPONSE_NAME) {
      const name = reader.lengthDelimited(wireType, 'name');
      try {
        version.name = utf8.decode(name);
      } catch {
        throw new MalformedResponseError('The response\'s name isn\'t UTF-8.');
      }
    } else if (field === RESPONSE_PAYLOAD) {
      const payload = reader.lengthDelimited(wireType, 'payload');
      parsePayload(new Reader(payload, 0, payload.length), version);
    } else {
      reader.skip(wireType);
    }
  }
}

function parsePayload(reader: Reader, version: AccessedSecretVersion): void {
  while (!reader.done) {
    const [field, wireType] = reader.tag();
    if (field === PAYLOAD_DATA) {
      const data = reader.lengthDelimited(wireType, 'payload data');
      // A later occurrence replaces the earlier one, which is erased first.
      version.zero();
      version.data = Uint8Array.from(data);
    } else if (field === PAYLOAD_DATA_CRC32C) {
      if (wireType !== VARINT) throw new MalformedResponseError('The payload\'s data_crc32c isn\'t a varint.');
      version.dataCrc32c = BigInt.asIntN(64, reader.varint());
    } else {
      reader.skip(wireType);
    }
  }
}

/** Reads protobuf's wire format from bytes[position, end). */
class Reader {
  constructor(private readonly bytes: Uint8Array, private position: number, private readonly end: number) {}

  get done(): boolean {
    return this.position >= this.end;
  }

  /** A field's number and wire type. */
  tag(): [number, number] {
    const tag = this.varint();
    const field = tag >> 3n;
    if (field === 0n || field > BigInt(MAX_FIELD_NUMBER)) throw new MalformedResponseError('The response holds an invalid field number.');
    return [Number(field), Number(tag & 7n)];
  }

  varint(): bigint {
    let value = 0n;
    for (let shift = 0n; shift < 70n; shift += 7n) {
      if (this.position >= this.end) throw new MalformedResponseError('The response ends inside a varint.');
      const byte = this.bytes[this.position++]!;
      value |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) {
        if (value >= 1n << 64n) throw new MalformedResponseError('The response holds a varint over 64 bits.');
        return value;
      }
    }
    throw new MalformedResponseError('The response holds a varint over 10 bytes.');
  }

  /** A length-delimited field's bytes: a view of the message, not a copy. */
  lengthDelimited(wireType: number, what: string): Uint8Array {
    if (wireType !== LENGTH_DELIMITED) throw new MalformedResponseError(`The response's ${what} isn't length-delimited.`);
    const length = this.varint();
    if (length > BigInt(this.end - this.position)) throw new MalformedResponseError(`The response's ${what} runs past the end of its message.`);
    const start = this.position;
    this.position += Number(length);
    return this.bytes.subarray(start, this.position);
  }

  skip(wireType: number): void {
    let size: number;
    if (wireType === VARINT) {
      this.varint();
      return;
    } else if (wireType === LENGTH_DELIMITED) {
      this.lengthDelimited(wireType, 'unknown field');
      return;
    } else if (wireType === FIXED64) {
      size = 8;
    } else if (wireType === FIXED32) {
      size = 4;
    } else {
      // Groups (3, 4) are proto2 only; 6 and 7 aren't wire types.
      throw new MalformedResponseError(`The response holds a field of wire type ${wireType}.`);
    }
    if (size > this.end - this.position) throw new MalformedResponseError('The response ends inside a fixed-size field.');
    this.position += size;
  }
}

/**
 * The response deserializer for one fetch's AccessSecretVersion calls, and the place every response
 * it parsed is kept until {@link close} zeroes them - a retry's, or one that arrived after the fetch
 * was aborted, included. Every message gRPC hands it is zeroed once read, parsed or not: gRPC
 * reassembles each received message into a buffer of its own (or a slice of its shared pool) that
 * nothing else reads afterwards. Once closed it parses nothing: a message gRPC delivers later is
 * zeroed unread.
 */
export class ResponseCapture {
  readonly #versions: AccessedSecretVersion[] = [];
  #closed = false;

  /**
   * gRPC's response deserializer.
   * @throws MalformedResponseError raw isn't an AccessSecretVersionResponse
   */
  deserialize(raw: Uint8Array): AccessedSecretVersion {
    try {
      if (this.#closed) return new AccessedSecretVersion();
      const version = parseAccessResponse(raw);
      this.#versions.push(version);
      return version;
    } finally {
      wipe(raw);
    }
  }

  /** Zeroes every payload parsed, and parses nothing more. */
  close(): void {
    this.#closed = true;
    for (const version of this.#versions) version.zero();
  }
}

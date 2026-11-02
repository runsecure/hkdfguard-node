// Hands a JSON object's members to a SecretValueSink as keys, never as strings: each value is
// unescaped (or, for a number, true or false, copied) into a buffer of its own, handed over, and
// zeroed. Internal to this package.
import { wipe } from '@runsecure/hkdfguard-abstractions';
import { JsonReader, JsonToken, MalformedJsonError } from '@runsecure/hkdfguard-abstractions/internal';
import { InvalidSecretDataError } from './errors.js';
import type { SecretValueSink } from './remote.js';
import { isValidKey } from './secretnames.js';

/**
 * When `json` is exactly one JSON object, hands each of its members over as a key; anything else -
 * plain text that merely starts like JSON included - hands nothing over. The whole value is checked
 * first, so malformed JSON never hands over part of its members.
 */
export function trySetKeys(json: Uint8Array, sink: SecretValueSink): void {
  if (!isObject(json)) return;

  const reader = new JsonReader(json);
  reader.read();
  setKeys(reader, sink, new Set());
}

/**
 * Hands each member of the object `reader` is at the start of over as a key, leaving `reader` at its
 * end. A string is handed over as its UTF-8 bytes; a number, true or false as its JSON text; null, an
 * object, an array, an empty string, or a member whose name isn't a key a name can hold, isn't
 * handed over. `seen` collects the member names, across every object handed over for one secret.
 * @throws InvalidSecretDataError a member name is in `seen` already
 */
export function setKeys(reader: JsonReader, sink: SecretValueSink, seen: Set<string>): void {
  while (reader.read() && reader.token() === JsonToken.PropertyName) {
    const key = reader.getString();
    // Not named: a key is part of a lookup name, logged only with sensitive logging on.
    if (seen.has(key)) throw new InvalidSecretDataError('The secret holds a key more than once.');
    seen.add(key);

    reader.read();
    const token = reader.token();
    if (isValidKey(key) && (token === JsonToken.String || token === JsonToken.Number || token === JsonToken.True || token === JsonToken.False)) {
      setKey(reader, key, sink);
    } else {
      reader.skip();
    }
  }
}

function setKey(reader: JsonReader, key: string, sink: SecretValueSink): void {
  // Unescaped, a string is never longer than it is escaped; anything else is copied as it is.
  const buffer = new Uint8Array(reader.valueLength);
  try {
    const length = reader.token() === JsonToken.String ? reader.copyString(buffer) : reader.copyRaw(buffer);
    sink.setKeyBytes(key, buffer.subarray(0, length));
  } finally {
    wipe(buffer);
  }
}

// One JSON object and nothing after it but whitespace.
function isObject(json: Uint8Array): boolean {
  const reader = new JsonReader(json);
  try {
    if (!reader.read() || reader.token() !== JsonToken.StartObject) return false;
    reader.skip();
    return !reader.read();
  } catch (error) {
    if (error instanceof MalformedJsonError) return false;
    throw error;
  }
}

import { wipe } from '@runsecure/hkdfguard-abstractions';
import { decodeStreamText, endsWith, indexOf, itemKey, readAll, utf8Of, utf8Sequence } from './text.js';
import type { ConfigurationItemTokenBase } from './tokens.js';

/**
 * What a resolver needs of a reader: the keys it may resolve - the Keys member of .NET's
 * IConfigurationItemReader. {@link ConfigurationItemReader} implements it.
 */
export interface KeyReader {
  /** The keys of the most recent read. */
  keys(): readonly string[];
}

/**
 * Reads text and extracts the keys of the configuration items delimited by a token's start and end
 * sequences - the port of ConfigurationItemReader.
 *
 * Keys are trimmed of surrounding whitespace, and empty keys are skipped. A start sequence with no
 * matching end sequence is ignored, and so is a start sequence preceded by the token's escape
 * sequence. Each read replaces the keys {@link keys} returns.
 */
export class ConfigurationItemReader implements KeyReader {
  readonly #start: Uint8Array;
  readonly #end: Uint8Array;
  readonly #escape: Uint8Array;
  #keys: readonly string[] = [];

  /** @throws TypeError token is undefined or null */
  constructor(token: ConfigurationItemTokenBase) {
    if (token === undefined || token === null) throw new TypeError('token must not be undefined.');
    this.#start = utf8Sequence(token.startSequence);
    this.#end = utf8Sequence(token.endSequence);
    this.#escape = utf8Sequence(token.escapeSequence);
  }

  /** The keys extracted by the most recent read, or none if nothing has been read. */
  keys(): string[] {
    return [...this.#keys];
  }

  /**
   * Extracts the keys of the configuration items in `text`: a string, or UTF-8 bytes.
   * @returns the trimmed keys, in the order they appear
   * @throws TypeError text is neither a string nor a Uint8Array
   */
  readKeys(text: string | Uint8Array): string[] {
    const keys: string[] = [];
    this.#addKeys(text, keys);
    this.#keys = Object.freeze([...keys]);
    return keys;
  }

  /**
   * Reads `stream` to its end as text and extracts the keys of the configuration items it holds. A
   * Node Readable works, read without an encoding, and so does any iterable of Uint8Array chunks. It
   * is read from its current position and is not closed.
   * @param encoding the stream's encoding - a WHATWG label such as "utf-16le", or "utf-32le" or
   *   "utf-32be" - UTF-8 by default; a UTF-8, UTF-16 or UTF-32 byte order mark in the stream takes
   *   precedence
   * @returns the trimmed keys, in the order they appear
   * @throws TypeError (rejecting) stream is undefined or null, or yields something other than a Uint8Array
   */
  async readKeysFrom(stream: AsyncIterable<Uint8Array> | Iterable<Uint8Array>, encoding?: string): Promise<string[]> {
    if (stream === undefined || stream === null) throw new TypeError('stream must not be undefined.');
    const data = await readAll(stream);
    try {
      return this.readKeys(decodeStreamText(data, encoding));
    } finally {
      wipe(data);
    }
  }

  /**
   * Extracts the keys of the configuration items in each of several texts, such as the values of a
   * configuration, and keeps the keys from all of them. Each text is read on its own, so an item
   * can't start in one text and end in the next.
   * @returns the trimmed keys, in the order they appear, text by text
   * @throws TypeError texts is undefined, null or a single string, or holds something other than a string
   */
  readKeysAll(texts: Iterable<string>): string[] {
    if (texts === undefined || texts === null) throw new TypeError('texts must not be undefined.');
    if (typeof texts === 'string') throw new TypeError('texts must be several texts, not one string: use readKeys for one.');
    const keys: string[] = [];
    for (const text of texts) {
      if (typeof text !== 'string') throw new TypeError('The texts must all be strings.');
      this.#addKeys(text, keys);
    }
    this.#keys = Object.freeze([...keys]);
    return keys;
  }

  #addKeys(text: string | Uint8Array, keys: string[]): void {
    const { bytes, owned } = utf8Of(text, 'text');
    try {
      const start = this.#start;
      const end = this.#end;
      const escape = this.#escape;
      let position = 0;
      for (;;) {
        const startIndex = indexOf(bytes, start, position);
        if (startIndex < 0) return;

        const escaped = escape.length > 0 && endsWith(bytes, escape, position, startIndex);
        position = startIndex + start.length;
        if (escaped) continue;

        const endIndex = indexOf(bytes, end, position);
        if (endIndex < 0) return;

        const key = itemKey(bytes, position, endIndex);
        if (key.length > 0) keys.push(key);
        position = endIndex + end.length;
      }
    } finally {
      if (owned) wipe(bytes);
    }
  }
}

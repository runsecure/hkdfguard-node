// How every HkdfGuard Vault integration reads Vault's answers: the whole body, into a buffer that is
// zeroed, and - for a refusal - the errors Vault listed and the message they make.
import { STATUS_CODES } from 'node:http';
import { wipe } from '@runsecure/hkdfguard-abstractions';
import { VaultRequestError } from './errors.js';

/** The largest refusal the transit key wrapper and the KV secret cache read, in bytes; Vault's are far smaller. */
export const MAX_ERROR_BODY_LENGTH = 64 * 1024;

/**
 * A growable buffer that zeroes what it held: each smaller buffer as it grows, and the last on
 * {@link close}. What request bodies are written into and response bodies read into.
 */
export class SecureBuffer {
  static readonly #MINIMUM_CAPACITY = 256;
  static readonly #MAXIMUM_INITIAL_CAPACITY = 1 << 20;

  // Buffer.alloc, never the shared pool allocUnsafe draws from, so zeroing it reaches every copy.
  #buffer: Buffer;
  #length = 0;

  /** @param expectedLength room to make at first (within limits); 0 if unknown */
  constructor(expectedLength = 0) {
    this.#buffer = Buffer.alloc(Math.min(Math.max(expectedLength, SecureBuffer.#MINIMUM_CAPACITY), SecureBuffer.#MAXIMUM_INITIAL_CAPACITY));
  }

  get length(): number {
    return this.#length;
  }

  /** The bytes written, in place: valid until the buffer next grows or is closed. */
  view(): Buffer {
    return this.#buffer.subarray(0, this.#length);
  }

  writeByte(b: number): void {
    this.#reserve(1);
    this.#buffer[this.#length++] = b;
  }

  write(data: Uint8Array | string): void {
    const bytes = typeof data === 'string' ? Buffer.from(data, 'latin1') : data;
    this.#reserve(bytes.length);
    this.#buffer.set(bytes, this.#length);
    this.#length += bytes.length;
  }

  /** Zeroes what the buffer holds. Safe to call more than once. */
  close(): void {
    wipe(this.#buffer);
    this.#length = 0;
  }

  #reserve(count: number): void {
    if (this.#buffer.length - this.#length >= count) return;
    const larger = Buffer.alloc(Math.max(this.#buffer.length * 2, this.#length + count));
    larger.set(this.#buffer.subarray(0, this.#length));
    wipe(this.#buffer);
    this.#buffer = larger;
  }
}

/**
 * The whole of `body` - a response's chunks, chunksOf(response) - in a {@link SecureBuffer} the
 * caller closes; undefined, with nothing kept, once it is over `maxLength` bytes (the rest isn't
 * read). Each chunk is zeroed once copied: it may hold a secret. Rejects with the body's own failure
 * (a lost connection), having zeroed what it read.
 * @param expectedLength room to make at first: the response's Content-Length, if known
 */
export async function readBody(body: AsyncIterable<Uint8Array>, maxLength = Number.POSITIVE_INFINITY, expectedLength = 0): Promise<SecureBuffer | undefined> {
  const buffer = new SecureBuffer(Math.min(expectedLength, maxLength));
  try {
    for await (const chunk of body) {
      const over = buffer.length + chunk.length > maxLength;
      if (!over) buffer.write(chunk);
      wipe(chunk);
      if (over) {
        buffer.close();
        return undefined;
      }
    }
    return buffer;
  } catch (error) {
    buffer.close();
    throw error;
  }
}

/**
 * The errors a refusal's body lists: `{"errors":[...]}` (each one that isn't a string as its JSON
 * text), or failing that `{"error":"..."}`; an empty list for a JSON object listing none; undefined
 * for a body that isn't a JSON object, or whose "errors" isn't an array. A refusal holds no secret,
 * so is read as a string.
 */
export function readVaultErrors(body: Uint8Array): string[] | undefined {
  let root: unknown;
  try {
    root = JSON.parse(Buffer.from(body.buffer, body.byteOffset, body.length).toString('utf8'));
  } catch {
    return undefined;
  }
  if (typeof root !== 'object' || root === null || Array.isArray(root)) return undefined;
  const { errors, error } = root as { errors?: unknown; error?: unknown };
  if (errors !== undefined && !Array.isArray(errors)) return undefined;
  const listed = (errors ?? []).map((e: unknown) => (typeof e === 'string' ? e : JSON.stringify(e)));
  if (listed.length === 0 && typeof error === 'string' && error !== '') return [error];
  return listed;
}

/**
 * Vault's answer as the transit key wrapper and the KV secret cache describe it: its status, the
 * status's name as .NET's HttpStatusCode spells it, and the errors it listed - "400 BadRequest:
 * cipher: message authentication failed".
 */
export function describeAnswer(status: number, errors: readonly string[] | undefined): string {
  const name = STATUS_CODES[status]?.replace(/[^A-Za-z0-9]/g, '');
  const detail = errors !== undefined && errors.length > 0 ? `: ${errors.join('; ')}` : '';
  return `${status}${name ? ` ${name}` : ''}${detail}`;
}

/**
 * Vault's refusal - `status`, and the `errors` its body listed ({@link readVaultErrors}) - as the
 * {@link VaultRequestError} the transit key wrapper and the KV secret cache report: "Vault answered
 * 403 Forbidden: permission denied", after `what` if given ("Couldn't read 'myapp/db': Vault
 * answered ..."). Transient (429, or a 5xx other than 501) as its status says.
 */
export function vaultRefusal(status: number, errors: readonly string[] | undefined, what?: string): VaultRequestError {
  const answered = `Vault answered ${describeAnswer(status, errors)}`;
  return new VaultRequestError(what === undefined ? answered : `${what}: ${answered}`, { statusCode: status });
}

// What the generated API calls: the client's one way of sending a request, and how paths and
// queries are built. Its own module, so the generated classes and the client don't import each other.
import type { VaultRequestOptions } from './client-options.js';
import type { JsonValue, JsonWriter } from './json.js';
import type { VaultResponse } from './response.js';

/** A request's query parameters, in the order they were added. */
export type Query = [string, string][];

/** The key of the method a {@link VaultSender} sends with: not a name, so it stays off the client's public surface. */
export const SEND: unique symbol = Symbol('VaultSender.send');

/** Sends requests for the generated API: a VaultClient. */
export interface VaultSender {
  /**
   * Sends a request - with the body `body` writes, if any - and reads Vault's response into a
   * {@link VaultResponse}, its data read with `reader`; undefined if it has no body.
   */
  [SEND]<T>(
    method: string, path: string, body: ((writer: JsonWriter) => void) | undefined, query: Query, options: VaultRequestOptions | undefined,
    reader: (json: JsonValue) => T | undefined,
  ): Promise<VaultResponse<T> | undefined>;
}

const UNRESERVED = /[A-Za-z0-9\-_.~]/;
const encoder = new TextEncoder();

/** `options`' mount path, leading and trailing '/' trimmed, or `defaultMountPath`. */
export function mountPathOr(options: VaultRequestOptions | undefined, defaultMountPath: string): string {
  const mountPath = options?.mountPath;
  if (mountPath === undefined || mountPath === null) return defaultMountPath;
  if (typeof mountPath !== 'string') throw new TypeError('mountPath must be a string.');
  let start = 0;
  let end = mountPath.length;
  while (start < end && mountPath[start] === '/') start++;
  while (end > start && mountPath[end - 1] === '/') end--;
  return mountPath.slice(start, end) || defaultMountPath;
}

/**
 * `value` as one path segment: everything but A-Z, a-z, 0-9, '-', '_', '.' and '~' percent-encoded
 * as UTF-8, '/' included.
 * @throws TypeError value isn't a string, number or boolean
 */
export function escapePathSegment(value: string | number | boolean): string {
  if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean') throw new TypeError('A path parameter must be a string.');
  let escaped = '';
  for (const b of encoder.encode(String(value))) {
    const c = String.fromCharCode(b);
    escaped += b < 0x80 && UNRESERVED.test(c) ? c : `%${b.toString(16).toUpperCase().padStart(2, '0')}`;
  }
  return escaped;
}

/** `options`' query parameters, in a fresh array to add the endpoint's own to. */
export function queryParameters(options: VaultRequestOptions | undefined): Query {
  const parameters = options?.queryParameters;
  if (parameters === undefined || parameters === null) return [];
  if (!Array.isArray(parameters)) throw new TypeError('queryParameters must be an array of [name, value] pairs.');
  return parameters.map(([name, value]) => [String(name), String(value)]);
}

/** `value` as a query parameter: a boolean as true or false. */
export function formatQueryValue(value: string | number | boolean): string {
  return String(value);
}

/** `query`, sorted by name (values of one name keep their order) as Go's url.Values.Encode sorts it; "" for none. */
export function queryString(query: Query | undefined): string {
  if (query === undefined || query.length === 0) return '';
  const ordered = [...query].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return `?${ordered.map(([name, value]) => `${escapePathSegment(name)}=${escapePathSegment(value)}`).join('&')}`;
}

/** `path` under /v1/, whether or not it starts with "/", "v1/" or "/v1/" already. */
export function v1Path(path: string): string {
  if (typeof path !== 'string') throw new TypeError('path must be a string.');
  if (path.startsWith('/v1/')) return path;
  if (path.startsWith('v1/')) return `/${path}`;
  if (path.startsWith('/')) return `/v1${path}`;
  return `/v1/${path}`;
}

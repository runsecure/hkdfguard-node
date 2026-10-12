import { cacheMatchKey, HkdfGuardError, InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';
import type { Lookup } from './reader.js';

/** Two configuration keys that differ only in ASCII case, which would make a lookup ambiguous. */
export class DuplicateKeyError extends HkdfGuardError {
  constructor(message: string) {
    super('ERR_HKDFGUARD_DUPLICATE_CONFIGURATION_KEY', message);
  }
}

// Upper-cases a-z only - the rule configurationPurpose applies - so a lookup matches exactly the
// keys a value authenticates under.
const matchKey = cacheMatchKey;

/**
 * A Lookup over `values` that matches keys ignoring ASCII case, as .NET configuration does for ASCII
 * keys.
 *
 * @throws DuplicateKeyError two keys differ only in ASCII case.
 */
export function mapLookup(values: Readonly<Record<string, string>> | ReadonlyMap<string, string>): Lookup {
  const byKey = new Map<string, string>();
  for (const [key, value] of values instanceof Map ? values : Object.entries(values)) {
    const upper = matchKey(key);
    if (byKey.has(upper)) throw new DuplicateKeyError(`'${key}' differs from another key only in case.`);
    byKey.set(upper, value);
  }
  return (key) => byKey.get(matchKey(key));
}

/**
 * Reads keys from environment variables the way .NET's environment configuration does: each ':' in
 * the key becomes "__", after `prefix` - so with prefix "APP_", "ConnectionStrings:Admin" reads
 * APP_ConnectionStrings__Admin. Variable names are matched exactly, as the environment does on Linux
 * and macOS.
 */
export function envLookup(prefix = '', env: Readonly<Record<string, string | undefined>> = process.env): Lookup {
  return (key) => env[prefix + key.replaceAll(':', '__')];
}

/**
 * Flattens a JSON document into configuration keys the way .NET's JSON configuration does: nested
 * object members join with ':' ("ConnectionStrings:Admin") and array elements use their index
 * ("Hosts:0"). Strings are taken as they are, numbers exactly as written ("1.50" stays "1.50"),
 * booleans as "true" or "false", and null as "". Pass the result to mapLookup.
 *
 * @throws InvalidArgumentError the document is not a JSON object.
 * @throws DuplicateKeyError two keys differ only in ASCII case.
 */
export function flattenJson(document: string): Record<string, string> {
  let root: unknown;
  try {
    // Node 22's reviver context carries each primitive's source text, so numbers keep their form.
    root = JSON.parse(document, function (this: unknown, _key: string, value: unknown, context?: { source?: string }) {
      return typeof value === 'number' && context?.source !== undefined ? new RawNumber(context.source) : value;
    } as (this: unknown, key: string, value: unknown) => unknown);
  } catch (error) {
    throw new InvalidArgumentError(`Invalid JSON: ${(error as Error).message}`, 'ERR_HKDFGUARD_INVALID_JSON');
  }
  if (root === null || typeof root !== 'object' || Array.isArray(root)) {
    throw new InvalidArgumentError('Invalid JSON: the document must be an object.', 'ERR_HKDFGUARD_INVALID_JSON');
  }

  const values: Record<string, string> = {};
  const seen = new Map<string, string>();
  const walk = (prefix: string, node: unknown): void => {
    if (Array.isArray(node)) {
      node.forEach((child, i) => walk(`${prefix}:${i}`, child));
      return;
    }
    if (node !== null && typeof node === 'object' && !(node instanceof RawNumber)) {
      for (const [name, child] of Object.entries(node)) walk(prefix === '' ? name : `${prefix}:${name}`, child);
      return;
    }
    const other = seen.get(matchKey(prefix));
    if (other !== undefined) throw new DuplicateKeyError(`'${prefix}' and '${other}' differ only in case.`);
    seen.set(matchKey(prefix), prefix);
    values[prefix] = node === null ? '' : node instanceof RawNumber ? node.source : String(node);
  };
  walk('', root);
  return values;
}

/** A JSON number, kept as it was written. */
class RawNumber {
  constructor(readonly source: string) {}
}

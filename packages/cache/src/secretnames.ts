// The rules for a key within a secret's name ("app-config#api-key"), and the case-escaped spelling
// names and keys are stored under. Internal: RemoteSecretCache publishes the constants and isValidKey.

/** Separates a secret's name from a key it holds: "app-config#api-key". */
export const KEY_SEPARATOR = '#';

/** The longest key a name can hold. */
export const MAX_KEY_LENGTH = 256;

/** Marks an upper-case letter in an entry name. */
export const UPPER_CASE_MARKER = '!';

/**
 * Whether `key` can follow {@link KEY_SEPARATOR} in a name: 1-{@link MAX_KEY_LENGTH} printable ASCII
 * characters other than space, '!' and '#'.
 */
export function isValidKey(key: string | undefined | null): boolean {
  if (typeof key !== 'string' || key.length === 0 || key.length > MAX_KEY_LENGTH) return false;
  for (let i = 0; i < key.length; i++) {
    const c = key.charCodeAt(i);
    if (c <= 0x20 || c > 0x7e || c === 0x21 || c === 0x23) return false;
  }
  return true;
}

/**
 * The case-escaped spelling of a name or key: each upper-case ASCII letter becomes '!' and its
 * lower-case form, so the result holds no upper-case letters and matching it ignoring ASCII case is
 * matching it exactly. "prod/Db" is "prod/!db"; "prod/db" stays as it is.
 */
export function entryName(secretName: string): string {
  return secretName.replace(/[A-Z]/g, (c) => UPPER_CASE_MARKER + c.toLowerCase());
}

/** The name {@link entryName} made `escaped` from. */
export function secretName(escaped: string): string {
  return escaped.replace(/!([a-z])/g, (_, c: string) => c.toUpperCase());
}

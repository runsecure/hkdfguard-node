// What both HashiCorp Vault packages - the KV secret cache and the transit key wrapper - check about
// Vault's address and the paths under it.
import { isIPv4 } from 'node:net';
import { InvalidArgumentError } from '../errors.js';

const PATH_SEGMENT = /^[A-Za-z0-9._-]+$/;

/** Where Vault's API is: whether over https, its host and port, and the path of /v1/ under the address. */
export interface VaultApiBase {
  readonly https: boolean;
  readonly hostname: string;
  readonly port: number | undefined;
  readonly base: string;
}

/**
 * Vault's API under `address`, refusing an address that would send what every request `carries` in
 * the clear (http anywhere but loopback) or that holds credentials, a query or a fragment.
 * @throws InvalidArgumentError ERR_HKDFGUARD_INVALID_VAULT_ADDRESS
 */
export function vaultApiBase(address: string, carries: string): VaultApiBase {
  const invalid = (problem: string) => new InvalidArgumentError(`Vault's address '${address}' ${problem}`, 'ERR_HKDFGUARD_INVALID_VAULT_ADDRESS');

  // A scheme and a host, checked on the text: the URL parser would read "https:///host" as "https://host".
  let url: URL | undefined;
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#\\]/.test(address)) {
    try {
      url = new URL(address);
    } catch {
      url = undefined;
    }
  }
  if (url === undefined || url.hostname === '') throw invalid("isn't absolute, e.g. https://vault.example.com:8200.");

  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback(url.hostname))) {
    throw invalid(`must be https; http is allowed only on a loopback address (a local Vault Agent or dev server), since every request carries ${carries}.`);
  }
  const authority = address.slice(address.indexOf('//') + 2).split(/[/?#]/, 1)[0]!;
  if (authority.includes('@') || url.username !== '' || url.password !== '' || address.includes('?') || address.includes('#')) {
    throw invalid('must not hold credentials, a query or a fragment.');
  }

  let prefix = url.pathname;
  while (prefix.endsWith('/')) prefix = prefix.slice(0, -1);
  return {
    https: url.protocol === 'https:',
    hostname: url.hostname.startsWith('[') ? url.hostname.slice(1, -1) : url.hostname,
    port: url.port === '' ? undefined : Number(url.port),
    base: `${prefix}/v1/`,
  };
}

/** '/'-separated segments, none empty, "." or "..": a path that stays where it's put. */
export function isValidVaultPath(path: unknown): boolean {
  return typeof path === 'string' && path.split('/').every((segment) => PATH_SEGMENT.test(segment) && segment !== '.' && segment !== '..');
}

// localhost, or an IP literal on the loopback network - as the URL parser normalized it, so no name
// is ever resolved.
function isLoopback(hostname: string): boolean {
  return hostname === 'localhost' || (isIPv4(hostname) && hostname.startsWith('127.')) || hostname === '[::1]';
}

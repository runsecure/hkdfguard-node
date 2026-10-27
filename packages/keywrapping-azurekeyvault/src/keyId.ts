import { InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';

// Parsed by hand rather than with URL: the WHATWG parser reads a backslash as a slash, resolves "."
// and ".." segments and percent-decodes nothing, so it would accept, and quietly rewrite, identifiers
// the other ports refuse. Key Vault's own rules: names are 1-127 letters, digits and dashes; versions
// are 32 hex digits in Key Vault and Managed HSM alike, but only their characters are checked here: a
// version recorded in a wrapped DEK must be exactly 32 (see envelope.ts). The scheme ignores case, as in
// the other ports, but "keys" doesn't; the host is letters, digits, dots and dashes, with no user info
// or IPv6 literal.
const KEY_ID = /^[Hh][Tt][Tt][Pp][Ss]:\/\/([0-9A-Za-z](?:[0-9A-Za-z.-]*[0-9A-Za-z])?)(?::([0-9]{1,5}))?\/keys\/([0-9A-Za-z-]{1,127})(?:\/([0-9A-Za-z]{1,64}))?\/?$/;

/**
 * A Key Vault key identifier, `https://{vault}/keys/{name}[/{version}]`, parsed strictly: the SDK's
 * own parseKeyVaultKeyIdentifier accepts any two- or three-segment path (a secret's, say), and this
 * one decides which keys a wrapper is pinned to.
 */
export class KeyVaultKeyId {
  private constructor(
    /** The vault's URL - scheme, host and any port - without a trailing slash; the host in lower case. */
    readonly vault: string,
    /** The key's name. */
    readonly name: string,
    /** The key's version, or undefined for its current one. */
    readonly version: string | undefined,
  ) {}

  /**
   * Parses a key identifier.
   *
   * @throws InvalidArgumentError it isn't a Key Vault key's.
   */
  static parse(keyId: string): KeyVaultKeyId {
    const match = typeof keyId === 'string' ? KEY_ID.exec(keyId) : null;
    if (match === null) {
      throw new InvalidArgumentError(`${JSON.stringify(keyId) ?? String(keyId)} isn't a Key Vault key identifier: `
        + 'https://{vault}.vault.azure.net/keys/{name}, optionally followed by /{version}.');
    }
    const [, host, port, name, version] = match;
    if (port !== undefined && Number(port) > 65535) {
      throw new InvalidArgumentError(`${JSON.stringify(keyId)} isn't a Key Vault key identifier: port ${port} is out of range.`);
    }
    const vault = `https://${host!.toLowerCase()}${port === undefined ? '' : `:${Number(port)}`}`;
    return new KeyVaultKeyId(vault, name!, version);
  }

  /** The same key, at `version`. */
  withVersion(version: string): KeyVaultKeyId {
    return new KeyVaultKeyId(this.vault, this.name, version);
  }

  /** Whether `other` names the same key, in any version: Key Vault's host and key names ignore case. */
  sameKey(other: KeyVaultKeyId): boolean {
    return this.vault === other.vault && this.name.toLowerCase() === other.name.toLowerCase();
  }

  /** The identifier, as the Key Vault clients are given it. */
  toString(): string {
    return `${this.vault}/keys/${this.name}${this.version === undefined ? '' : `/${this.version}`}`;
  }
}

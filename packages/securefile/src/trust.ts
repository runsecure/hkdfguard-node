import { InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';

/** The largest uid or gid: both are unsigned 32-bit integers. */
const MAX_ID = 0xffff_ffff;

/** Who {@link KeyFileTrust} trusts besides the operating system's administrators. Every list is optional. */
export interface KeyFileTrustOptions {
  /**
   * Windows security identifiers (SIDs, such as a deployers group's "S-1-5-21-...-1005") that may
   * also own, and hold write rights on, a key file and the folders above it. Checked when a key file
   * is read: Everyone, Authenticated Users, Users, Interactive and Anonymous are refused then.
   */
  readonly windowsPrincipals?: Iterable<string>;
  /** Linux and macOS user ids that may also own a key file, the directories above it, and the symbolic links on its path. */
  readonly unixUserIds?: Iterable<number>;
  /**
   * Linux and macOS group ids whose members may write a key file or a directory above it: a
   * group-writable file or directory is refused unless its group is listed. Writable by others is
   * refused whatever is listed.
   */
  readonly unixGroupIds?: Iterable<number>;
}

/**
 * Who, besides the operating system's administrators, {@link readTrustedKeyFile} trusts to have
 * written a key file it reads. A key file and every folder above it must be owned by a trusted
 * principal, and no one else may write, replace, rename or re-permission any of them: whoever can
 * replace a key file - and can also wrap under the KEK, as anyone allowed to encrypt with a network
 * KMS key can - chooses the DEK new data is encrypted under.
 *
 * Always trusted: SYSTEM, Administrators and TrustedInstaller on Windows; root on Linux and macOS.
 * {@link KeyFileTrust.administratorsOnly} trusts no one else, which is the default. Add the account
 * or group your deployment writes key files as - never the account the application runs as, unless
 * it is a developer machine: an application that can rewrite its own key files can be made to roll
 * back to an older one.
 *
 * Immutable, and every list is copied, so a list changed afterwards doesn't change what is trusted:
 *
 * ```ts
 * const trust = new KeyFileTrust({
 *   windowsPrincipals: ['S-1-5-21-1111111111-2222222222-3333333333-1005'],
 *   unixUserIds: [1001],
 *   unixGroupIds: [2001],
 * });
 * ```
 */
export class KeyFileTrust {
  /** Trusts only the operating system's administrators. The default. */
  static readonly administratorsOnly: KeyFileTrust = new KeyFileTrust();

  /** See {@link KeyFileTrustOptions.windowsPrincipals}. */
  readonly windowsPrincipals: readonly string[];
  /** See {@link KeyFileTrustOptions.unixUserIds}. */
  readonly unixUserIds: readonly number[];
  /** See {@link KeyFileTrustOptions.unixGroupIds}. */
  readonly unixGroupIds: readonly number[];

  /**
   * @throws InvalidArgumentError a list is not iterable (or is a single string), a SID is not a
   *   string, or an id is not an integer from 0 to 4294967295.
   */
  constructor(options: KeyFileTrustOptions = {}) {
    if (typeof options !== 'object' || options === null) {
      throw new InvalidArgumentError('KeyFileTrust options must be an object.');
    }
    this.windowsPrincipals = Object.freeze(requireSids(options.windowsPrincipals ?? []));
    this.unixUserIds = Object.freeze(requireIds(options.unixUserIds ?? [], 'unixUserIds'));
    this.unixGroupIds = Object.freeze(requireIds(options.unixGroupIds ?? [], 'unixGroupIds'));
    Object.freeze(this);
  }
}

function requireSids(sids: Iterable<string>): string[] {
  if (typeof sids === 'string' || !isIterable(sids)) {
    throw new InvalidArgumentError('windowsPrincipals must be a list of SID strings.');
  }
  const copy = [...sids];
  for (const sid of copy) {
    if (typeof sid !== 'string') throw new InvalidArgumentError(`windowsPrincipals holds ${String(sid)}, which is not a SID string.`);
  }
  return copy;
}

function requireIds(ids: Iterable<number>, name: string): number[] {
  if (typeof ids === 'string' || !isIterable(ids)) {
    throw new InvalidArgumentError(`${name} must be a list of ids.`);
  }
  const copy = [...ids];
  for (const value of copy) {
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > MAX_ID) {
      throw new InvalidArgumentError(`${name} holds ${String(value)}, which is not a valid id (an integer from 0 to ${MAX_ID}).`);
    }
  }
  return copy;
}

function isIterable(value: unknown): value is Iterable<unknown> {
  return typeof value === 'object' && value !== null && typeof (value as Iterable<unknown>)[Symbol.iterator] === 'function';
}

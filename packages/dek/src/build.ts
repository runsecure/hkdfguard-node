import { stat } from 'node:fs/promises';
import {
  HkdfGuardError, InvalidArgumentError, MAX_WRAPPED_KEY_BYTES, RefreshFailurePolicy, validateServiceName,
  type CryptoProvider, type CryptoProviderFactory, type EncryptedFormatProvider, type KeyWrapper,
} from '@runsecure/hkdfguard-abstractions';
import { HkdfGuardLog, type Logger } from '@runsecure/hkdfguard-diagnostics';
import { DataEncryptionKey, type EncryptionDeadline } from './key.js';
import { KeyRing, MAX_TIMER_DELAY_MS, Rotation } from './keyring.js';

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

/** How often a ring with ephemeral keys rotates them, unless configured otherwise. */
export const DEFAULT_EPHEMERAL_KEY_ROTATION_HOURS = 24;
/** The shortest rotation accepted - rotating faster loads the KMS for no security. */
export const MIN_EPHEMERAL_KEY_ROTATION_HOURS = 1;
/**
 * The longest rotation accepted: 596 hours, the most whole hours a Node.js timer can wait. A delay
 * over 2^31-1 ms (about 596.5 hours) is not an error in Node - it is silently clamped to 1 ms, which
 * would rotate keys back to back without end. The .NET port accepts up to 1193; a shared
 * configuration above 596 is refused here rather than misbehaving.
 */
export const MAX_EPHEMERAL_KEY_ROTATION_HOURS = Math.floor(MAX_TIMER_DELAY_MS / HOUR_MS);
/** How long a superseded ephemeral key stays registered, unless configured otherwise. */
export const DEFAULT_EPHEMERAL_KEY_RETENTION_HOURS = 24;
/** The shortest retention accepted, in minutes. */
export const MIN_EPHEMERAL_KEY_RETENTION_MINUTES = 1;
/**
 * How many days after it was last written a key file stops encrypting, unless configured otherwise.
 * AES-GCM with random nonces is safe for about 2^32 encryptions under one key in total, and a key
 * file outlives the process that counts them, so it is bounded by age instead: rotate key files by
 * deploying a new one at a higher version. Decryption under an old key file never stops.
 */
export const DEFAULT_KEY_FILE_MAX_AGE_DAYS = 365;
/** The longest key-file age accepted, in days. */
export const MAX_KEY_FILE_MAX_AGE_DAYS = 3650;
/** The fraction of the maximum age after which a warning is logged: 90%, about five weeks of a year. */
export const KEY_FILE_AGE_WARNING_FRACTION = 0.9;

/**
 * A key file that is not a wrapped key, or that the key wrapper does not trust - for a custom key
 * wrapper's readKeyFile to throw. The native key wrapper reports its own KeyFileRefusedError, with
 * the same code.
 */
export class InvalidKeyFileError extends HkdfGuardError {
  constructor(message: string) {
    super('ERR_HKDFGUARD_INVALID_KEY_FILE', message);
  }
}

/**
 * What {@link buildKeyRing} assembles. One key wrapper is shared by every key - it is bound to a
 * KEK, not to a payload. For each key file the crypto provider factory creates a provider for that
 * file's wrapped bytes; for each ephemeral version, one around a DEK generated at build time.
 *
 * Key files are rotated by deployment. Ephemeral keys are rotated by the ring: one with any
 * ephemeral key adds a fresh one as its current version every ephemeralKeyRotationHours. A rotating
 * ring must have its highest ephemeral version above every key file, or the first rotation would
 * replace a key file as current with a key that doesn't survive a restart; buildKeyRing refuses it.
 */
export interface KeyRingConfig {
  /** Reveals every key's DEK. */
  keyWrapper: KeyWrapper;
  /** Creates each key's provider - the cipher. */
  cryptoProviderFactory: CryptoProviderFactory;
  /**
   * How often, in seconds (1-300), each key is re-revealed to confirm the KEK is still available.
   * With the refresh-failure policy it sets how fast a revoked KEK stops a running process: about
   * maxFailures × keyRefreshInterval.
   */
  keyRefreshInterval: number;
  /** Handed to every provider; fails closed after 3 failures unless set. */
  refreshFailurePolicy?: RefreshFailurePolicy;
  /** Versions whose wrapped DEK is read from a file. */
  keyFiles?: Readonly<Record<number, string>> | ReadonlyMap<number, string>;
  /**
   * Versions whose DEK is generated at build time and never written to disk. The highest version
   * overall becomes current. Unless rotation is disabled, the highest must be above every key file.
   */
  ephemeralKeys?: readonly number[];
  /** Formats protected values; a DefaultFormatProvider when omitted. */
  formatProvider?: EncryptedFormatProvider;
  /** This ring's KEK identity, for callers to read back; validated when set. */
  serviceName?: string;
  /** Hours between ephemeral-key rotations (1-596); 24 when omitted. A ring of key files never rotates. */
  ephemeralKeyRotationHours?: number;
  /**
   * Keeps the ephemeral key built at startup current until the process restarts. Required when a key
   * file's version is above every ephemeral version, so that key file stays current.
   */
  disableEphemeralKeyRotation?: boolean;
  /** Minutes (at least 1) a superseded ephemeral key stays registered for decryption; 24 hours when omitted. */
  ephemeralKeyRetentionMinutes?: number;
  /**
   * Days (1-3650) after a key file was last written that it stops encrypting; 365 when omitted. Its
   * age is its modification time, so copy key files with their timestamps preserved (cp -p, rsync
   * -t). A warning is logged at 90% of the age; past it, encrypt throws EncryptionLimitReachedError
   * and decryption still works. Only the current version ever encrypts, so only it is reported.
   */
  keyFileMaxAgeDays?: number;
  /** Receives an entry for every rotation, failed rotation and retirement, and for a current key file nearing or past its age. */
  logger?: Logger;
  /** Cancels reading key files and revealing keys; anything already created is closed. */
  signal?: AbortSignal;
}

/** Test hooks, reached only through {@link buildKeyRingForTests}. */
export interface BuildInternals {
  manualRotation?: boolean;
}

function invalid(message: string): InvalidArgumentError {
  return new InvalidArgumentError(message, 'ERR_HKDFGUARD_INVALID_CONFIG');
}

function validate(config: KeyRingConfig): void {
  if (!config.keyWrapper) throw invalid('A keyWrapper is required.');
  if (!config.cryptoProviderFactory) throw invalid('A cryptoProviderFactory is required.');
  const keyFiles = entries(config.keyFiles);
  if (keyFiles.length === 0 && (config.ephemeralKeys?.length ?? 0) === 0) throw invalid('At least one key file or ephemeral key is required.');
  if (!Number.isInteger(config.keyRefreshInterval) || config.keyRefreshInterval < 1 || config.keyRefreshInterval > 300) {
    throw invalid('keyRefreshInterval must be between 1 and 300 seconds.');
  }
  const hours = config.ephemeralKeyRotationHours;
  if (hours !== undefined && !(Number.isInteger(hours) && hours >= MIN_EPHEMERAL_KEY_ROTATION_HOURS && hours <= MAX_EPHEMERAL_KEY_ROTATION_HOURS)) {
    throw invalid(`ephemeralKeyRotationHours must be between ${MIN_EPHEMERAL_KEY_ROTATION_HOURS} and ${MAX_EPHEMERAL_KEY_ROTATION_HOURS}.`);
  }
  if (hours !== undefined && config.disableEphemeralKeyRotation) {
    throw invalid("disableEphemeralKeyRotation and ephemeralKeyRotationHours can't both be set: one turns rotation off, the other schedules it.");
  }
  const days = config.keyFileMaxAgeDays;
  if (days !== undefined && !(Number.isInteger(days) && days >= 1 && days <= MAX_KEY_FILE_MAX_AGE_DAYS)) {
    throw invalid(`keyFileMaxAgeDays must be between 1 and ${MAX_KEY_FILE_MAX_AGE_DAYS}.`);
  }
  const minutes = config.ephemeralKeyRetentionMinutes;
  if (minutes !== undefined && !(Number.isFinite(minutes) && minutes >= MIN_EPHEMERAL_KEY_RETENTION_MINUTES)) {
    throw invalid(`ephemeralKeyRetentionMinutes must be at least ${MIN_EPHEMERAL_KEY_RETENTION_MINUTES}.`);
  }
  for (const [version, path] of keyFiles) {
    if (path.trim() === '') throw invalid(`Key file version ${version} is missing a path.`);
  }
  const superseded = keyFileSupersededProblem(keyFiles.map(([version]) => version), config.ephemeralKeys ?? [], config.disableEphemeralKeyRotation, 'disableEphemeralKeyRotation');
  if (superseded !== undefined) throw invalid(superseded);
  if (config.serviceName !== undefined) validateServiceName(config.serviceName);
}

/**
 * Why a rotating ring's first rotation would supersede a key file, or undefined when it can't: a
 * rotation adds its key at currentVersion + 1, so a key file above every ephemeral version would
 * stop being current. `disableSetting` names the setting that turns rotation off.
 * @internal Shared with validateKeyRingOptions.
 */
export function keyFileSupersededProblem(keyFileVersions: readonly number[], ephemeralVersions: readonly number[], rotationDisabled: boolean | undefined, disableSetting: string): string | undefined {
  if (ephemeralVersions.length === 0 || rotationDisabled) return undefined;
  const highestKeyFile = Math.max(...keyFileVersions);
  if (!(highestKeyFile > Math.max(...ephemeralVersions))) return undefined;
  return `Key file version ${highestKeyFile} is above every ephemeral version, so the first scheduled rotation would replace it as the current version and new values would be encrypted under a key that does not survive a restart. Configure the ephemeral key at a version above every key file, or set ${disableSetting}.`;
}

function entries(keyFiles: KeyRingConfig['keyFiles']): [number, string][] {
  if (keyFiles === undefined) return [];
  const list = keyFiles instanceof Map ? [...keyFiles] : Object.entries(keyFiles).map(([v, p]) => [Number(v), p] as [number, string]);
  return list.sort(([a], [b]) => a - b); // version order, so a failure is reported for the same file every time
}

/**
 * A key file's wrapped DEK, read through the key wrapper - whose own checks decide whether anyone but
 * a trusted account could have written or replaced it - and its modification time, the key file's age.
 */
async function readKeyFileFor(wrapper: KeyWrapper, path: string, signal: AbortSignal | undefined): Promise<{ wrapped: Uint8Array; modifiedMs: number }> {
  const wrapped = await wrapper.readKeyFile(path, signal);
  // Whatever the key wrapper, a wrapped key is never empty and never over the limit.
  if (wrapped.length === 0) throw new InvalidKeyFileError(`Key file '${path}' is empty.`);
  if (wrapped.length > MAX_WRAPPED_KEY_BYTES) {
    throw new InvalidKeyFileError(`Key file '${path}' is larger than ${MAX_WRAPPED_KEY_BYTES} bytes (MAX_WRAPPED_KEY_BYTES); a wrapped key never is.`);
  }
  return { wrapped, modifiedMs: (await stat(path)).mtimeMs };
}

async function addOwned(ring: KeyRing, version: number, provider: CryptoProvider, deadline?: EncryptionDeadline): Promise<void> {
  const key = new DataEncryptionKey(provider, deadline);
  try {
    ring.add(version, key);
  } catch (error) {
    await key.close();
    throw error;
  }
}

/** When the key file at `path`, last written at `modifiedMs`, stops encrypting, and who hears about it. */
function keyFileDeadline(version: number, path: string, modifiedMs: number, maxAgeDays: number, logger: Logger | undefined): EncryptionDeadline {
  const refuseAt = modifiedMs + maxAgeDays * DAY_MS;
  return {
    warnAt: modifiedMs + maxAgeDays * DAY_MS * KEY_FILE_AGE_WARNING_FRACTION,
    refuseAt,
    reason: `Key file '${path}' (version ${version}) was last written ${new Date(modifiedMs).toISOString()}, more than ${maxAgeDays} days ago (keyFileMaxAgeDays), so it no longer encrypts: AES-GCM is only safe for a bounded number of encryptions under one key. Deploy a new key file at a higher version; values under this one still decrypt.`,
    onWarning: () => HkdfGuardLog.keyFileAgeWarning(logger, version, path, new Date(refuseAt)),
    onExpired: () => HkdfGuardLog.keyFileExpired(logger, version, path),
  };
}

/**
 * Reads each key file, creates each ephemeral key, and returns the populated key ring. A ring with
 * ephemeral keys rotates them unless disableEphemeralKeyRotation is set; such a ring with a key file
 * above every ephemeral version is refused, with the rest of the config, before anything is read or
 * created. If anything fails partway - an unreadable file, an unwrap failure, a version registered
 * twice, the signal aborted - every key created so far is closed and the error rethrown.
 */
export function buildKeyRing(config: KeyRingConfig): Promise<KeyRing> {
  return build(config, {});
}

/**
 * Tests only: {@link buildKeyRing} with test hooks, such as rotation the test drives itself.
 * Exported from this module for the package's own tests, never from the package index - the
 * exports map keeps it out of reach.
 */
export function buildKeyRingForTests(config: KeyRingConfig, internals: BuildInternals): Promise<KeyRing> {
  return build(config, internals);
}

async function build(config: KeyRingConfig, internals: BuildInternals): Promise<KeyRing> {
  validate(config);
  const { keyWrapper, cryptoProviderFactory: factory, signal } = config;
  const providerOptions = { expirySeconds: config.keyRefreshInterval, refreshFailurePolicy: config.refreshFailurePolicy ?? RefreshFailurePolicy.default, signal };
  const ring = new KeyRing(config.formatProvider);

  try {
    const maxAgeDays = config.keyFileMaxAgeDays ?? DEFAULT_KEY_FILE_MAX_AGE_DAYS;
    for (const [version, path] of entries(config.keyFiles)) {
      signal?.throwIfAborted();
      const { wrapped, modifiedMs } = await readKeyFileFor(keyWrapper, path, signal);
      await addOwned(ring, version, await factory.create(keyWrapper, wrapped, providerOptions),
        keyFileDeadline(version, path, modifiedMs, maxAgeDays, config.logger));
    }
    for (const version of config.ephemeralKeys ?? []) {
      signal?.throwIfAborted();
      await addOwned(ring, version, await factory.createEphemeral(keyWrapper, providerOptions));
    }
  } catch (error) {
    await ring.close().catch(() => undefined);
    throw error;
  }

  // Report a current key file already nearing or past its age now, not at its first encrypt.
  const current = ring.tryGet(ring.currentVersion);
  if (current instanceof DataEncryptionKey) current.checkDeadline();

  const ephemeral = config.ephemeralKeys ?? [];
  if (ephemeral.length > 0 && !config.disableEphemeralKeyRotation) {
    // Each rotation creates its key exactly as an ephemeral version was created at build time.
    const rotationOptions = { ...providerOptions, signal: undefined };
    ring.rotation = new Rotation(ring,
      (config.ephemeralKeyRotationHours ?? DEFAULT_EPHEMERAL_KEY_ROTATION_HOURS) * HOUR_MS,
      (config.ephemeralKeyRetentionMinutes ?? DEFAULT_EPHEMERAL_KEY_RETENTION_HOURS * 60) * 60 * 1000,
      ephemeral,
      async (rotationSignal) => new DataEncryptionKey(await factory.createEphemeral(keyWrapper, { ...rotationOptions, signal: rotationSignal })),
      config.logger,
      internals.manualRotation);
  }
  return ring;
}

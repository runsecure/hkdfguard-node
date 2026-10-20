import { constants as fsConstants } from 'node:fs';
import { lstat, open, realpath, stat } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import {
  HkdfGuardError, InvalidArgumentError, MAX_WRAPPED_KEY_BYTES, RefreshFailurePolicy, validateServiceName,
  type CryptoProvider, type CryptoProviderFactory, type EncryptedFormatProvider, type KeyWrapper,
} from '@runsecure/hkdfguard-abstractions';
import { HkdfGuardLog, type Logger } from '@runsecure/hkdfguard-diagnostics';
import { DataEncryptionKey, type EncryptionDeadline } from './key.js';
import { KeyRing, Rotation } from './keyring.js';

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

// Group- and other-write: anyone with either could choose the key new data is encrypted under.
const KEY_FILE_FORBIDDEN_MODE = 0o022;
// A sticky directory (/tmp) lets others create entries, but not rename or delete anyone else's.
const STICKY_BIT = 0o1000;

/** How often a ring with ephemeral keys rotates them, unless configured otherwise. */
export const DEFAULT_EPHEMERAL_KEY_ROTATION_HOURS = 24;
/** The shortest rotation accepted - rotating faster loads the KMS for no security. */
export const MIN_EPHEMERAL_KEY_ROTATION_HOURS = 1;
/** The longest rotation accepted - the .NET port's timer limit, kept so one configuration suits every port. */
export const MAX_EPHEMERAL_KEY_ROTATION_HOURS = 1193;
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

/** A key file that is empty, larger than MAX_WRAPPED_KEY_BYTES, or in a location someone else could replace it in. */
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
 * ephemeral key adds a fresh one as its current version every ephemeralKeyRotationHours.
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
  /** Versions whose DEK is generated at build time and never written to disk. The highest version overall becomes current. */
  ephemeralKeys?: readonly number[];
  /** Formats protected values; a DefaultFormatProvider when omitted. */
  formatProvider?: EncryptedFormatProvider;
  /** This ring's KEK identity, for callers to read back; validated when set. */
  serviceName?: string;
  /** Hours between ephemeral-key rotations (1-1193); 24 when omitted. A ring of key files never rotates. */
  ephemeralKeyRotationHours?: number;
  /** Keeps the ephemeral key built at startup current until the process restarts. */
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

/** @internal Test hooks. */
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
  if (config.serviceName !== undefined) validateServiceName(config.serviceName);
}

function entries(keyFiles: KeyRingConfig['keyFiles']): [number, string][] {
  if (keyFiles === undefined) return [];
  const list = keyFiles instanceof Map ? [...keyFiles] : Object.entries(keyFiles).map(([v, p]) => [Number(v), p] as [number, string]);
  return list.sort(([a], [b]) => a - b); // version order, so a failure is reported for the same file every time
}

/**
 * Reads a wrapped DEK with Node's own file I/O - how buildKeyRing reads key files for a key wrapper
 * with no readKeyFile of its own (a remote KMS, say, or a test double). A wrapper backed by the
 * native KMS library reads through that library instead, which makes its own checks.
 *
 * Refuses anything that isn't a regular file, one its group or other users can
 * write, or - outside Windows, whose ACLs the native tool sets - one in a location anyone but root
 * or this process's user could replace it in (see {@link verifyKeyFileLocation}), an empty file, or one over
 * MAX_WRAPPED_KEY_BYTES - never reading more than one byte past the limit, so a wrong path (a log, a
 * device) can't make startup read without bound. The checks are made on the opened file, so they
 * describe what is read, not a path that may have changed in between.
 */
export async function readKeyFile(path: string): Promise<Uint8Array> {
  return (await readKeyFileWithTime(path)).wrapped;
}

/** The parts of lstat and realpath the location check uses; replaced in tests. @internal */
export interface KeyFileSystem {
  lstat(path: string): Promise<{ uid: number; mode: number; isDirectory(): boolean; isSymbolicLink(): boolean; isFile(): boolean }>;
  realpath(path: string): Promise<string>;
}

const nodeFileSystem: KeyFileSystem = { lstat, realpath };

function ownerProblem(uid: number, euid: number): string | undefined {
  return uid === 0 || uid === euid ? undefined : `is owned by uid ${uid}; only root or this process's user (uid ${euid}) may own a key file and the folders above it`;
}

/**
 * Checks where a key file lives, outside Windows, and returns its real path. Anyone who can replace
 * a key file chooses the key new data is encrypted under, so the file and every folder above it, up
 * to /, must be owned by root or by this process's user, and no folder may be writable by its
 * group or by others unless it is sticky (as /tmp is). A symbolic link is followed - Kubernetes
 * mounts secrets through them - but must itself be owned by root or this user, and the folders
 * holding it are held to the same rule. Only reads: nothing about the file is changed.
 * @internal Exported for tests.
 */
export async function verifyKeyFileLocation(path: string, euid: number, fs: KeyFileSystem = nodeFileSystem): Promise<string> {
  const absolute = resolve(path);
  const link = await fs.lstat(absolute);
  if (link.isSymbolicLink()) {
    const problem = ownerProblem(link.uid, euid);
    if (problem !== undefined) throw new InvalidKeyFileError(`Key file '${path}' is a symbolic link that ${problem}.`);
  }
  const real = await fs.realpath(absolute);
  const target = real === absolute ? link : await fs.lstat(real);
  const problem = ownerProblem(target.uid, euid);
  if (problem !== undefined) throw new InvalidKeyFileError(`Key file '${path}' ${problem}.`);

  await verifyFolders(dirname(real), path, euid, fs);
  if (link.isSymbolicLink()) await verifyFolders(await fs.realpath(dirname(absolute)), path, euid, fs);
  return real;
}

async function verifyFolders(directory: string, path: string, euid: number, fs: KeyFileSystem): Promise<void> {
  for (let folder = directory; ; folder = dirname(folder)) {
    const status = await fs.lstat(folder);
    if (!status.isDirectory()) throw new InvalidKeyFileError(`Key file '${path}' is under '${folder}', which is not a folder.`);
    const problem = ownerProblem(status.uid, euid);
    if (problem !== undefined) throw new InvalidKeyFileError(`Key file '${path}' is under '${folder}', which ${problem}.`);
    if ((status.mode & KEY_FILE_FORBIDDEN_MODE) !== 0 && (status.mode & STICKY_BIT) === 0) {
      const mode = (status.mode & 0o7777).toString(8).padStart(4, '0');
      throw new InvalidKeyFileError(`Key file '${path}' is under '${folder}', which its group or others can write (mode ${mode}), so they could replace the key file.`);
    }
    if (dirname(folder) === folder) return;
  }
}

/**
 * A key file's wrapped DEK and its modification time - the key file's age. Read through the key
 * wrapper when it has readKeyFile (its own checks on who could have written the file), otherwise
 * with {@link readKeyFile}.
 */
async function readKeyFileFor(wrapper: KeyWrapper, path: string, signal: AbortSignal | undefined): Promise<{ wrapped: Uint8Array; modifiedMs: number }> {
  if (wrapper.readKeyFile === undefined) return readKeyFileWithTime(path);
  const wrapped = await wrapper.readKeyFile(path, signal);
  return { wrapped, modifiedMs: (await stat(path)).mtimeMs };
}

/** {@link readKeyFile}, with the opened file's modification time - the key file's age. */
async function readKeyFileWithTime(path: string): Promise<{ wrapped: Uint8Array; modifiedMs: number }> {
  const unix = process.platform !== 'win32';
  // Outside Windows the real path is checked, then opened without following a link, so what is read
  // is the file that was checked. Windows ACLs are not checked here (see the getting-started guide).
  const file = unix
    ? await open(await verifyKeyFileLocation(path, process.geteuid!()), fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW)
    : await open(path, 'r');
  try {
    const stats = await file.stat();
    if (!stats.isFile()) throw new InvalidKeyFileError(`Key file '${path}' is not a regular file.`);
    if (unix && (stats.mode & KEY_FILE_FORBIDDEN_MODE) !== 0) {
      const mode = (stats.mode & 0o777).toString(8).padStart(4, '0');
      throw new InvalidKeyFileError(`Key file '${path}' is writable by its group or by others (mode ${mode}); only its owner may write it.`);
    }
    const owner = unix ? ownerProblem(stats.uid, process.geteuid!()) : undefined;
    if (owner !== undefined) throw new InvalidKeyFileError(`Key file '${path}' ${owner}.`);
    const buffer = new Uint8Array(MAX_WRAPPED_KEY_BYTES + 1);
    let total = 0;
    for (;;) {
      const { bytesRead } = await file.read(buffer, total, buffer.length - total, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total === buffer.length) break;
    }
    if (total === 0) throw new InvalidKeyFileError(`Key file '${path}' is empty.`);
    if (total > MAX_WRAPPED_KEY_BYTES) {
      throw new InvalidKeyFileError(`Key file '${path}' is larger than ${MAX_WRAPPED_KEY_BYTES} bytes (MAX_WRAPPED_KEY_BYTES); a wrapped key never is.`);
    }
    return { wrapped: buffer.slice(0, total), modifiedMs: stats.mtimeMs };
  } finally {
    await file.close();
  }
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
 * Reads each key file, creates each ephemeral key, and returns the populated key ring. If anything
 * fails partway - an unreadable file, an unwrap failure, a version registered twice, the signal
 * aborted - every key created so far is closed and the error rethrown.
 */
export async function buildKeyRing(config: KeyRingConfig, internals: BuildInternals = {}): Promise<KeyRing> {
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

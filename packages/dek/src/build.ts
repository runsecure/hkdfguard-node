import { open } from 'node:fs/promises';
import {
  HkdfGuardError, InvalidArgumentError, MAX_WRAPPED_KEY_BYTES, RefreshFailurePolicy, validateServiceName,
  type CryptoProvider, type CryptoProviderFactory, type EncryptedFormatProvider, type KeyWrapper,
} from '@runsecure/hkdfguard-abstractions';
import type { Logger } from '@runsecure/hkdfguard-diagnostics';
import { DataEncryptionKey } from './key.js';
import { KeyRing, Rotation } from './keyring.js';

const HOUR_MS = 60 * 60 * 1000;

// Group- and other-write: anyone with either could choose the key new data is encrypted under.
const KEY_FILE_FORBIDDEN_MODE = 0o022;

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

/** A key file that is empty, or larger than MAX_WRAPPED_KEY_BYTES. */
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
  /** Receives an entry for every rotation, failed rotation and retirement. */
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
 * Reads a wrapped DEK, refusing anything that isn't a regular file, one its group or other users can
 * write (outside Windows, whose ACLs are the owner's to set), an empty file, or one over
 * MAX_WRAPPED_KEY_BYTES - never reading more than one byte past the limit, so a wrong path (a log, a
 * device) can't make startup read without bound. The checks are made on the opened file, so they
 * describe what is read, not a path that may have changed in between.
 */
export async function readKeyFile(path: string): Promise<Uint8Array> {
  const file = await open(path, 'r');
  try {
    const stats = await file.stat();
    if (!stats.isFile()) throw new InvalidKeyFileError(`Key file '${path}' is not a regular file.`);
    if (process.platform !== 'win32' && (stats.mode & KEY_FILE_FORBIDDEN_MODE) !== 0) {
      const mode = (stats.mode & 0o777).toString(8).padStart(4, '0');
      throw new InvalidKeyFileError(`Key file '${path}' is writable by its group or by others (mode ${mode}); only its owner may write it.`);
    }
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
    return buffer.slice(0, total);
  } finally {
    await file.close();
  }
}

async function addOwned(ring: KeyRing, version: number, provider: CryptoProvider): Promise<void> {
  const key = new DataEncryptionKey(provider);
  try {
    ring.add(version, key);
  } catch (error) {
    await key.close();
    throw error;
  }
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
    for (const [version, path] of entries(config.keyFiles)) {
      signal?.throwIfAborted();
      const wrapped = await readKeyFile(path);
      await addOwned(ring, version, await factory.create(keyWrapper, wrapped, providerOptions));
    }
    for (const version of config.ephemeralKeys ?? []) {
      signal?.throwIfAborted();
      await addOwned(ring, version, await factory.createEphemeral(keyWrapper, providerOptions));
    }
  } catch (error) {
    await ring.close().catch(() => undefined);
    throw error;
  }

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

import {
  HkdfGuardError, InvalidArgumentError, jsonErrorLocation, jsonKind, MAX_ALLOWED_REFRESH_FAILURES, RefreshFailurePolicy, serviceNameProblem,
  type CryptoProviderFactory, type KeyWrapper,
} from '@runsecure/hkdfguard-abstractions';
import { keyFileSupersededProblem, MAX_EPHEMERAL_KEY_ROTATION_HOURS, MAX_KEY_FILE_MAX_AGE_DAYS, type KeyRingConfig } from './build.js';

/** Options that break one or more rules; the message lists every rule broken. */
export class InvalidOptionsError extends HkdfGuardError {
  constructor(readonly failures: readonly string[]) {
    super('ERR_HKDFGUARD_INVALID_OPTIONS', `Invalid HkdfGuard options:\n  ${failures.join('\n  ')}`);
  }
}

/** One key file: a version paired with the path of its wrapped DEK. */
export interface KeyFileOptions {
  Version: number;
  Path: string;
}

/**
 * The file-loadable form of {@link KeyRingConfig}: plain data with the field names and units of the
 * .NET port's HkdfGuardOptions, so one "HkdfGuard" section of an appsettings.json configures every
 * port. It carries no behavior - the key wrapper and crypto provider factory a ring needs are given
 * to {@link keyRingConfigFromOptions}.
 */
export interface KeyRingOptions {
  /** Identifies this ring's KEK to the native KMS library. Required. */
  ServiceName?: string;
  /**
   * Seconds (1-300) between re-reveals of each key through the KEK, and each reveal's deadline (see
   * KeyRingConfig.keyRefreshInterval: 10 or more for TPM-backed keys).
   */
  KeyRefreshInterval?: number;
  /** Consecutive failed refreshes before a key fails closed; 1-100. Can't be combined with FailOpenOnRefreshFailure. */
  MaxRefreshFailures?: number;
  /** Keeps the last good key in use however many refreshes fail. */
  FailOpenOnRefreshFailure?: boolean;
  /** Hours (1-596) between ephemeral key rotations. Can't be combined with DisableEphemeralKeyRotation. */
  EphemeralKeyRotationHours?: number;
  /** Keeps the ephemeral key built at startup current. Required when a KeyFiles version is above every EphemeralKeys version. */
  DisableEphemeralKeyRotation?: boolean;
  /** Hours (at least 1) a superseded ephemeral key stays registered for decryption. */
  EphemeralKeyRetentionHours?: number;
  /** Days (1-3650) after a key file was last written that it stops encrypting; 365 when unset. Node port only so far. */
  KeyFileMaxAgeDays?: number;
  /** Versions whose wrapped DEK is read from a file. */
  KeyFiles?: KeyFileOptions[];
  /** Versions whose DEK is generated at startup and never written to disk. */
  EphemeralKeys?: number[];
}

const FIELDS: (keyof KeyRingOptions)[] = [
  'ServiceName', 'KeyRefreshInterval', 'MaxRefreshFailures', 'FailOpenOnRefreshFailure', 'EphemeralKeyRotationHours',
  'DisableEphemeralKeyRotation', 'EphemeralKeyRetentionHours', 'KeyFileMaxAgeDays', 'KeyFiles', 'EphemeralKeys',
];

/**
 * Every rule {@link keyRingConfigFromOptions} enforces, as the .NET port's validator words them - a
 * valid ServiceName, every range, no contradictory settings, at least one key, a path for every key
 * file, no version registered twice, and, unless rotation is disabled, no key file above every
 * ephemeral version. Empty when the options are valid.
 */
export function validateKeyRingOptions(options: KeyRingOptions): string[] {
  const failures: string[] = [];
  const problem = serviceNameProblem(options.ServiceName?.trim() === '' ? undefined : options.ServiceName);
  if (problem !== undefined) failures.push(`ServiceName is invalid: ${problem}`);

  const outside = (value: number | undefined, min: number, max = Infinity) => value !== undefined && !(Number.isInteger(value) && value >= min && value <= max);
  if (outside(options.KeyRefreshInterval, 1, 300)) failures.push('KeyRefreshInterval must be between 1 and 300 seconds.');
  if (outside(options.MaxRefreshFailures, 1, MAX_ALLOWED_REFRESH_FAILURES)) failures.push(`MaxRefreshFailures must be between 1 and ${MAX_ALLOWED_REFRESH_FAILURES}.`);
  if (outside(options.EphemeralKeyRotationHours, 1, MAX_EPHEMERAL_KEY_ROTATION_HOURS)) failures.push(`EphemeralKeyRotationHours must be between 1 and ${MAX_EPHEMERAL_KEY_ROTATION_HOURS}.`);
  if (outside(options.EphemeralKeyRetentionHours, 1)) failures.push('EphemeralKeyRetentionHours must be at least 1.');
  if (outside(options.KeyFileMaxAgeDays, 1, MAX_KEY_FILE_MAX_AGE_DAYS)) failures.push(`KeyFileMaxAgeDays must be between 1 and ${MAX_KEY_FILE_MAX_AGE_DAYS}.`);
  if (options.DisableEphemeralKeyRotation && options.EphemeralKeyRotationHours !== undefined) {
    failures.push("DisableEphemeralKeyRotation and EphemeralKeyRotationHours can't both be set: one turns rotation off, the other schedules it.");
  }
  if (options.FailOpenOnRefreshFailure && options.MaxRefreshFailures !== undefined) {
    failures.push("FailOpenOnRefreshFailure and MaxRefreshFailures can't both be set: one fails open, the other fails closed.");
  }

  const keyFiles = options.KeyFiles ?? [];
  const ephemeral = options.EphemeralKeys ?? [];
  if (keyFiles.length === 0 && ephemeral.length === 0) failures.push('At least one key file or ephemeral key is required.');
  for (const keyFile of keyFiles) {
    if ((keyFile.Path ?? '').trim() === '') failures.push(`KeyFiles version ${keyFile.Version} is missing a path.`);
  }
  const seen = new Map<number, number>();
  for (const version of [...keyFiles.map((k) => k.Version), ...ephemeral]) {
    seen.set(version, (seen.get(version) ?? 0) + 1);
    if (seen.get(version) === 2) failures.push(`Version ${version} is registered more than once across KeyFiles/EphemeralKeys.`);
  }
  const superseded = keyFileSupersededProblem(keyFiles.map((k) => k.Version), ephemeral, options.DisableEphemeralKeyRotation, 'DisableEphemeralKeyRotation');
  if (superseded !== undefined) failures.push(superseded);
  return failures;
}

/**
 * Validates `options` and returns the {@link KeyRingConfig} they describe, with the behavior options
 * can't carry as data. Settings left unset keep buildKeyRing's defaults; further fields
 * (formatProvider, logger, signal) can be set on the result.
 *
 * @throws InvalidOptionsError listing every rule broken.
 */
export function keyRingConfigFromOptions(options: KeyRingOptions, keyWrapper: KeyWrapper, cryptoProviderFactory: CryptoProviderFactory): KeyRingConfig {
  const failures = validateKeyRingOptions(options);
  if (failures.length > 0) throw new InvalidOptionsError(failures);

  const config: KeyRingConfig = {
    keyWrapper,
    cryptoProviderFactory,
    // Unset, buildKeyRing reports it as missing - the same as the other ports.
    keyRefreshInterval: options.KeyRefreshInterval ?? Number.NaN,
    serviceName: options.ServiceName,
    keyFiles: Object.fromEntries((options.KeyFiles ?? []).map((k) => [k.Version, k.Path])),
    ephemeralKeys: [...(options.EphemeralKeys ?? [])],
  };
  if (options.FailOpenOnRefreshFailure) config.refreshFailurePolicy = RefreshFailurePolicy.failOpen();
  else if (options.MaxRefreshFailures !== undefined) config.refreshFailurePolicy = RefreshFailurePolicy.failClosedAfter(options.MaxRefreshFailures);
  if (options.DisableEphemeralKeyRotation) config.disableEphemeralKeyRotation = true;
  if (options.EphemeralKeyRotationHours !== undefined) config.ephemeralKeyRotationHours = options.EphemeralKeyRotationHours;
  if (options.EphemeralKeyRetentionHours !== undefined) config.ephemeralKeyRetentionMinutes = options.EphemeralKeyRetentionHours * 60;
  if (options.KeyFileMaxAgeDays !== undefined) config.keyFileMaxAgeDays = options.KeyFileMaxAgeDays;
  return config;
}

/**
 * Reads {@link KeyRingOptions} from `section` of a JSON document - the "HkdfGuard" section of an
 * appsettings.json, or a nested path such as "Security:HkdfGuard"; "" reads the whole document. As
 * .NET's configuration binder does, section and field names match ignoring case, unknown fields are
 * ignored, and numbers and booleans may be given as strings ("60", "true") - which is how
 * environment-variable overrides arrive. The result is not validated; keyRingConfigFromOptions does that.
 *
 * @throws InvalidArgumentError bad JSON, a missing section, or a value of the wrong type. Messages
 * name the field and the kind of value found, never the value or any of the document.
 */
export function keyRingOptionsFromJson(document: string, section = 'HkdfGuard'): KeyRingOptions {
  const fail = (message: string) => new InvalidArgumentError(message, 'ERR_HKDFGUARD_INVALID_OPTIONS_JSON');
  let node: unknown;
  try {
    node = JSON.parse(document);
  } catch (error) {
    throw fail(`Reading options section '${section}': invalid JSON${jsonErrorLocation(error)}.`);
  }
  for (const name of section === '' ? [] : section.split(':')) {
    const child = isObject(node) ? memberIgnoringCase(node, name) : undefined;
    if (child === undefined) throw fail(`The JSON document has no '${section}' section.`);
    node = child;
  }
  if (!isObject(node)) throw fail(`The '${section}' section is not an object.`);

  const at = (field: string) => `${section === '' ? '' : `${section}:`}${field}`;
  const integer = (value: unknown, field: string): number => {
    const n = typeof value === 'string' && /^\s*-?\d+\s*$/.test(value) ? Number(value) : value;
    if (typeof n !== 'number' || !Number.isInteger(n)) throw fail(`'${at(field)}' must be an integer, got ${jsonKind(value)}.`);
    return n;
  };
  const boolean = (value: unknown, field: string): boolean => {
    if (typeof value === 'boolean') return value;
    if (typeof value === 'string' && /^(true|false)$/i.test(value.trim())) return value.trim().toLowerCase() === 'true';
    throw fail(`'${at(field)}' must be true or false, got ${jsonKind(value)}.`);
  };
  const array = (value: unknown, field: string): unknown[] => {
    if (Array.isArray(value)) return value;
    // .NET configuration has no arrays: they arrive as objects keyed "0", "1", ... - accept those too.
    if (isObject(value) && Object.keys(value).every((k) => /^\d+$/.test(k))) {
      return Object.entries(value).sort(([a], [b]) => Number(a) - Number(b)).map(([, v]) => v);
    }
    throw fail(`'${at(field)}' must be a list.`);
  };

  const options: KeyRingOptions = {};
  for (const field of FIELDS) {
    const value = memberIgnoringCase(node, field);
    if (value === undefined || value === null) continue;
    switch (field) {
      case 'ServiceName':
        if (typeof value !== 'string') throw fail(`'${at(field)}' must be a string.`);
        options.ServiceName = value;
        break;
      case 'FailOpenOnRefreshFailure':
      case 'DisableEphemeralKeyRotation':
        options[field] = boolean(value, field);
        break;
      case 'KeyFiles':
        options.KeyFiles = array(value, field).map((entry, i) => {
          if (!isObject(entry)) throw fail(`'${at(`${field}:${i}`)}' must be an object with Version and Path.`);
          const path = memberIgnoringCase(entry, 'Path');
          return { Version: integer(memberIgnoringCase(entry, 'Version'), `${field}:${i}:Version`), Path: typeof path === 'string' ? path : '' };
        });
        break;
      case 'EphemeralKeys':
        options.EphemeralKeys = array(value, field).map((v, i) => integer(v, `${field}:${i}`));
        break;
      default:
        options[field] = integer(value, field);
    }
  }
  return options;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function memberIgnoringCase(object: Record<string, unknown>, name: string): unknown {
  const lower = name.toLowerCase();
  const key = Object.keys(object).find((k) => k.toLowerCase() === lower);
  return key === undefined ? undefined : object[key];
}

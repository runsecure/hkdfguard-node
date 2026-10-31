import {
  cacheMatchKey, HkdfGuardError, InvalidArgumentError, wipe, type KeyRing, type KeyTrackingValue, type ProtectedReadOnlyCache,
} from '@runsecure/hkdfguard-abstractions';
import { AttributeNames, CacheMetrics, HkdfGuardLog, HkdfGuardTelemetry, Results, SpanNames, type Logger } from '@runsecure/hkdfguard-diagnostics';
import { trySetKeys } from './jsonkeys.js';
import { entryName, isValidKey, KEY_SEPARATOR, MAX_KEY_LENGTH, secretName, UPPER_CASE_MARKER } from './secretnames.js';
import { Store } from './store.js';

/** How a {@link RemoteSecretCache} matches names, which must be how its secret store does. */
export const SecretNameMatching = {
  /** Names differing only in ASCII case are one secret (e.g. Azure Key Vault). */
  ignoreAsciiCase: 'ignore_ascii_case',
  /**
   * Names are matched exactly; names differing in case are different secrets (e.g. AWS Secrets
   * Manager, Google Secret Manager). A name holding '!' is reported missing without a fetch - none of
   * those stores allow it, and it marks case in entry names (see {@link RemoteSecretCache}).
   */
  exact: 'exact',
} as const;

/** A {@link SecretNameMatching} value. */
export type SecretNameMatching = (typeof SecretNameMatching)[keyof typeof SecretNameMatching];

/**
 * The shared plumbing of a ProtectedReadOnlyCache over a remote secret store: nothing is fetched up
 * front; the first decrypt/maxDecryptedLength for a name that isn't cached yet calls {@link fetch}
 * for that one secret, encrypts every value it hands over under the ring's current key, and caches
 * the ciphertext; every later lookup is served from the cache. A subclass supplies only
 * {@link isValidName} and {@link fetch} - one call that reads one secret by name, never a listing.
 *
 * A name is a secret's name, optionally followed by {@link KEY_SEPARATOR} and a key:
 * "app-config#api-key" is the api-key key of the secret app-config, which fetch hands over with
 * {@link SecretValueSink.setKeyBytes} (or, for a secret holding a JSON object,
 * {@link SecretValueSink.setBytesWithJsonKeys}), and "app-config" is the secret's whole value, or
 * its {@link defaultKey} where the store has one. One fetch caches the whole value and every key it
 * hands over, so the first lookup of any of them fetches the secret once and the rest are already
 * cached. A key is 1-{@link MAX_KEY_LENGTH} printable ASCII characters other than space, '!' and '#'
 * (see {@link isValidKey}), and is matched exactly whatever the store's matching.
 *
 * A name whose secret isValidName rejects, or whose key isn't one, is reported missing without a
 * fetch, so a cache can sit in a ProtectedCacheCollection beside sources with other naming rules (as
 * is a name that isn't well-formed UTF-16, which no store can hold). A name the fetch hands no value
 * for, or an empty one, is reported missing - decrypt resolves to 0 - and isn't remembered, so it is
 * fetched again on the next request (a key a cached secret doesn't hold costs a fetch every time).
 * An error from fetch propagates to the caller unchanged, and nothing that fetch handed over is
 * cached. Concurrent lookups of the same uncached secret - of any of its keys or spellings - share
 * one fetch. A cached value is kept for the life of the instance: a later fetch of the same secret
 * adds keys that weren't cached yet, but never replaces one that was.
 *
 * Cancellation, as .NET's: the signal of the lookup that starts a fetch is the one fetch is given,
 * and aborting it cancels that fetch (as far as fetch honours it - a fetch that ignores it runs on,
 * and that lookup waits for it). Every other lookup sharing the fetch waits under its own signal, so
 * aborting one only stops that lookup waiting; and a lookup whose shared fetch failed because the
 * lookup that started it was aborted starts a new fetch under its own signal, rather than failing
 * with someone else's abort. A sink refuses every value once its fetch has settled, so a fetch that
 * runs on past an abort caches nothing.
 *
 * Encryption, name binding and key rotation are the shared Store's, as for every cache here. It
 * matches names ignoring ASCII case, so keys - and, under {@link SecretNameMatching.exact}, secret
 * names - are stored there under a case-escaped spelling: every upper-case ASCII letter becomes '!'
 * and its lower-case form, so "prod/Db" and "prod/db" are different entries, each bound to its own
 * spelling.
 *
 * Telemetry: each fetch is a {@link SpanNames.cache.populate} span on HkdfGuardTelemetry.cache,
 * counted in CacheMetrics.operations as "success", "not_found" or "error"; with sensitive logging on,
 * the secret's name (never a value) is logged. A failed fetch is logged as an error.
 */
export abstract class RemoteSecretCache implements ProtectedReadOnlyCache {
  /** Separates a secret's name from a key it holds: "app-config#api-key". */
  static readonly KEY_SEPARATOR = KEY_SEPARATOR;

  /** The longest key a name can hold. */
  static readonly MAX_KEY_LENGTH = MAX_KEY_LENGTH;

  readonly #store: RemoteStore;
  readonly #matching: SecretNameMatching;
  readonly #logger: Logger | undefined;

  /**
   * @param ring supplies the key every fetched secret is encrypted under; owned by the caller - the
   *   cache never closes keys
   * @param matching how the secret store matches names
   * @param logger receives a debug entry per fetched name while sensitive logging is enabled, and an
   *   error entry per failed fetch
   * @throws TypeError ring is missing, or matching isn't a SecretNameMatching
   */
  constructor(ring: KeyRing, matching: SecretNameMatching, logger?: Logger) {
    if (ring === undefined || ring === null) throw new TypeError('ring must not be undefined.');
    if (matching !== SecretNameMatching.exact && matching !== SecretNameMatching.ignoreAsciiCase) {
      throw new TypeError('matching must be a SecretNameMatching.');
    }
    this.#store = new RemoteStore(ring, (secretEntryName, signal) => this.#populate(secretEntryName, signal));
    this.#matching = matching;
    this.#logger = logger;
  }

  /**
   * Whether `key` can follow {@link KEY_SEPARATOR} in a name: 1-{@link MAX_KEY_LENGTH} printable
   * ASCII characters other than space, '!' and '#'.
   */
  static isValidKey(key: string | undefined | null): boolean {
    return isValidKey(key);
  }

  /**
   * The key a name without one reads, for a store whose secrets are all sets of keys (HashiCorp
   * Vault's KV); undefined - the default - when such a name reads the secret's whole value.
   */
  protected defaultKey(): string | undefined {
    return undefined;
  }

  /** Whether the secret store can hold a secret named `name`; a name it can't is never fetched. */
  protected abstract isValidName(name: string): boolean;

  /**
   * Reads the one secret named `name` and hands its current value, and any keys it holds, to `sink` -
   * or resolves without doing so if it doesn't exist. Any other failure should reject. Called only for
   * a name isValidName accepts, and never while another fetch of the same secret is running. `signal`
   * is the signal of the lookup that started this fetch: pass it on to the store's client. Hand
   * values to the sink before resolving; it refuses them once the fetch has settled.
   */
  protected abstract fetch(name: string, sink: SecretValueSink, signal?: AbortSignal): Promise<void>;

  /**
   * Decrypts `name`'s value into `result`, resolving to the bytes written, or 0 if the store has none.
   * @throws TypeError (rejecting) name isn't a string
   */
  async decrypt(name: string, result: Uint8Array, signal?: AbortSignal): Promise<number> {
    const entry = this.#entryNameFor(name);
    return entry === undefined ? 0 : this.#store.decrypt(entry, result, signal);
  }

  /**
   * An upper bound on how many bytes decrypt writes for `name`, or undefined if the store has none.
   * @throws TypeError (rejecting) name isn't a string
   */
  async maxDecryptedLength(name: string, signal?: AbortSignal): Promise<number | undefined> {
    const entry = this.#entryNameFor(name);
    return entry === undefined ? undefined : this.#store.maxDecryptedLength(entry, signal);
  }

  // The entry a name is stored under - its secret's entry name, then '#' and the case-escaped key,
  // if any - or undefined if the name is missing without a fetch.
  #entryNameFor(name: string): string | undefined {
    if (typeof name !== 'string') throw new TypeError('name must be a string.');

    const separator = name.indexOf(KEY_SEPARATOR);
    const secret = separator < 0 ? name : name.slice(0, separator);
    const key = separator < 0 ? this.defaultKey() : name.slice(separator + 1);
    const exact = this.#matching === SecretNameMatching.exact;
    if ((key !== undefined && !isValidKey(key))
      || !name.isWellFormed()
      || !this.isValidName(secret)
      || (exact && secret.includes(UPPER_CASE_MARKER))) {
      return undefined;
    }

    const secretEntryName = exact ? entryName(secret) : secret;
    return key === undefined ? secretEntryName : secretEntryName + KEY_SEPARATOR + entryName(key);
  }

  // Fetches the secret stored under secretEntryName, caching everything handed over; false if
  // nothing was.
  #populate(secretEntryName: string, signal: AbortSignal | undefined): Promise<boolean> {
    const name = this.#matching === SecretNameMatching.exact ? secretName(secretEntryName) : secretEntryName;
    const telemetry = HkdfGuardTelemetry.cache;
    return telemetry.withSpan(SpanNames.cache.populate, async (span) => {
      if (telemetry.enableSensitiveLogging) {
        telemetry.logSensitiveOperation(span, SpanNames.cache.populate, { [AttributeNames.name]: name });
        HkdfGuardLog.sensitiveOperationLogged(this.#logger, SpanNames.cache.populate, name);
      }

      const sink = createSink(this.#store, secretEntryName);
      try {
        await this.fetch(name, sink, signal);
        const values = closeSink(sink);
        if (values.size === 0) {
          recordOperation(Results.notFound);
          return false;
        }

        // A fetch that began just after another finished may find values already stored; keep those.
        for (const [entry, value] of values) this.#store.putIfAbsent(entry, value);
        recordOperation(Results.success);
        return true;
      } catch (error) {
        closeSink(sink);
        HkdfGuardLog.operationFailed(this.#logger, SpanNames.cache.populate, error);
        recordOperation(Results.error);
        throw error;
      }
    });
  }
}

function recordOperation(result: string): void {
  CacheMetrics.operations.add(1, { [AttributeNames.operationName]: SpanNames.cache.populate, [AttributeNames.result]: result });
}

/** One fetch of a secret, shared by every lookup of it while it runs. */
interface SharedFetch {
  readonly promise: Promise<boolean>;
  /** Whether it failed because the lookup that started it was aborted. */
  cancelled: boolean;
}

/** The entries, keyed by entry name, and the fetches filling them. */
class RemoteStore extends Store {
  // One fetch per uncached secret at a time, whichever of its names was asked for, keyed by the
  // secret's entry name as the Store matches it; removed once it settles, whatever the outcome.
  readonly #fetches = new Map<string, SharedFetch>();
  readonly #run: (secretEntryName: string, signal: AbortSignal | undefined) => Promise<boolean>;

  constructor(ring: KeyRing, run: (secretEntryName: string, signal: AbortSignal | undefined) => Promise<boolean>) {
    super(ring);
    this.#run = run;
  }

  // Runs the fetch of the secret name belongs to, or waits for the one already running; the Store
  // then looks name up again.
  protected override async populate(name: string, signal?: AbortSignal): Promise<boolean> {
    const separator = name.indexOf(KEY_SEPARATOR);
    const secretEntryName = separator < 0 ? name : name.slice(0, separator);
    const key = cacheMatchKey(secretEntryName);

    for (;;) {
      signal?.throwIfAborted();
      const running = this.#fetches.get(key);
      if (running === undefined) return this.#start(key, secretEntryName, signal);

      try {
        return await untilAborted(running.promise, signal);
      } catch (error) {
        // Cancelled by the lookup that started it, not by this one: fetch again.
        if (running.cancelled && signal?.aborted !== true) continue;
        throw error;
      }
    }
  }

  async #start(key: string, secretEntryName: string, signal: AbortSignal | undefined): Promise<boolean> {
    const { promise, resolve, reject } = Promise.withResolvers<boolean>();
    // Observed here, so a failure no other lookup waited on isn't reported as unhandled.
    promise.catch(() => undefined);
    const fetch: SharedFetch = { promise, cancelled: false };
    this.#fetches.set(key, fetch);
    try {
      const populated = await this.#run(secretEntryName, signal);
      resolve(populated);
      return populated;
    } catch (error) {
      fetch.cancelled = signal?.aborted === true;
      reject(error);
      throw error;
    } finally {
      // Before any waiter resumes, so one fetching again starts a fetch of its own.
      if (this.#fetches.get(key) === fetch) this.#fetches.delete(key);
    }
  }
}

/** `promise`, or `signal`'s reason once it is aborted, whichever comes first. */
function untilAborted<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (signal === undefined) return promise;
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (value) => { signal.removeEventListener('abort', onAbort); resolve(value); },
      (error: unknown) => { signal.removeEventListener('abort', onAbort); reject(error); });
  });
}

const encoder = new TextEncoder();

// Set by SecretValueSink's static block: the cache creates and closes sinks, nothing else can.
const SINK_TOKEN = Symbol('SecretValueSink');
let createSink: (store: Store, secretEntryName: string) => SecretValueSink;
let closeSink: (sink: SecretValueSink) => ReadonlyMap<string, KeyTrackingValue>;

/**
 * Receives what {@link RemoteSecretCache.fetch} read, and encrypts each value at once, bound to its
 * own name within the secret being fetched - nothing else can be stored through it, and it refuses
 * every call once that fetch has settled. Set the secret's whole value at most once, and each key at
 * most once; an empty value counts as none. Every Uint8Array handed over is zeroed as a side effect,
 * whether it is stored or refused - so hand over a buffer of your own, or a view of the part of one
 * holding the value, never one something else still needs.
 *
 * Created by the cache for each fetch; it can't be constructed.
 */
export class SecretValueSink {
  readonly #store: Store;
  readonly #secretEntryName: string;
  readonly #values = new Map<string, KeyTrackingValue>();
  #closed = false;

  private constructor(token: symbol, store: Store, secretEntryName: string) {
    if (token !== SINK_TOKEN) throw new TypeError('A SecretValueSink is created by its cache, for each fetch.');
    this.#store = store;
    this.#secretEntryName = secretEntryName;
  }

  /**
   * Encrypts `plaintext` as the secret's whole value. `plaintext` is zeroed as a side effect.
   * @throws TypeError plaintext isn't a Uint8Array
   * @throws HkdfGuardError (ERR_HKDFGUARD_INVALID_STATE) the value was already set, or the fetch has settled
   */
  setBytes(plaintext: Uint8Array): void {
    requireBytes(plaintext);
    this.#set(this.#secretEntryName, plaintext);
  }

  /**
   * Encrypts `text`'s UTF-8 bytes as the secret's whole value. The bytes it is encoded into are
   * zeroed once encrypted; `text` itself is an immutable string and is not - prefer
   * {@link setBytes} for a secret.
   * @throws HkdfGuardError (ERR_HKDFGUARD_INVALID_STATE) the value was already set, or the fetch has settled
   */
  setText(text: string): void {
    this.#ensureUnset(this.#secretEntryName);
    this.#set(this.#secretEntryName, encoder.encode(text));
  }

  /**
   * Encrypts `plaintext` as the value of one key the secret holds - looked up as "name#key".
   * `plaintext` is zeroed as a side effect, even when it is refused.
   * @throws TypeError plaintext isn't a Uint8Array
   * @throws InvalidArgumentError key isn't one a name can hold (see {@link RemoteSecretCache.isValidKey})
   * @throws HkdfGuardError (ERR_HKDFGUARD_INVALID_STATE) that key was already set, or the fetch has settled
   */
  setKeyBytes(key: string, plaintext: Uint8Array): void {
    requireBytes(plaintext);
    try {
      if (!isValidKey(key)) {
        throw new InvalidArgumentError(`'${String(key)}' isn't a key: 1-${MAX_KEY_LENGTH} printable ASCII characters other than space, '!' and '#'.`);
      }
      this.#set(this.#secretEntryName + KEY_SEPARATOR + entryName(key), plaintext);
    } finally {
      wipe(plaintext);
    }
  }

  /**
   * Encrypts `plaintext` as the secret's whole value and, when it is a JSON object - such as an AWS
   * Secrets Manager key/value secret - each of its top-level members as a key: a string as its UTF-8
   * bytes, a number, true or false as its JSON text. A member that is null, an object or an array, or
   * whose name isn't a key a name can hold, is left out. Anything that isn't a JSON object - plain
   * text, an array, malformed JSON - is the whole value only. `plaintext` is zeroed as a side effect,
   * and every buffer a member was unescaped into is zeroed once encrypted. The JSON is read in place,
   * never as a string.
   * @throws TypeError plaintext isn't a Uint8Array
   * @throws InvalidSecretDataError the JSON object holds a member name more than once
   * @throws HkdfGuardError (ERR_HKDFGUARD_INVALID_STATE) the value or a key was already set, or the fetch has settled
   */
  setBytesWithJsonKeys(plaintext: Uint8Array): void {
    requireBytes(plaintext);
    try {
      trySetKeys(plaintext, this);
      this.setBytes(plaintext);
    } finally {
      wipe(plaintext);
    }
  }

  #set(entry: string, plaintext: Uint8Array): void {
    try {
      this.#ensureUnset(entry);
      if (plaintext.length > 0) this.#values.set(entry, this.#store.encrypt(entry, plaintext));
    } finally {
      wipe(plaintext);
    }
  }

  #ensureUnset(entry: string): void {
    if (this.#closed) throw new HkdfGuardError('ERR_HKDFGUARD_INVALID_STATE', 'The fetch this value belongs to has already returned.');
    if (this.#values.has(entry)) throw new HkdfGuardError('ERR_HKDFGUARD_INVALID_STATE', 'A value has already been set for this secret or key.');
  }

  static {
    createSink = (store, secretEntryName) => new SecretValueSink(SINK_TOKEN, store, secretEntryName);
    // Refuses every later call, and returns every value set, by the entry name it was encrypted under.
    closeSink = (sink) => {
      sink.#closed = true;
      return sink.#values;
    };
  }
}

function requireBytes(plaintext: unknown): void {
  if (!(plaintext instanceof Uint8Array)) throw new TypeError('plaintext must be a Uint8Array.');
}

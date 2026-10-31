import { randomInt } from 'node:crypto';
import { stringify } from 'node:querystring';
import { protos, SecretManagerServiceClient } from '@google-cloud/secret-manager';
import { InvalidArgumentError, type KeyRing } from '@runsecure/hkdfguard-abstractions';
import { abortReason, crc32c, delay as sleep, untilAborted } from '@runsecure/hkdfguard-abstractions/internal';
import { InvalidSecretDataError, RemoteSecretCache, SecretNameMatching, type SecretValueSink } from '@runsecure/hkdfguard-cache';
import type { Logger } from '@runsecure/hkdfguard-diagnostics';
import { ResponseCapture, type AccessedSecretVersion } from './capture.js';

/** The options of a {@link GoogleSecretManagerSecretCache}. */
export interface GoogleSecretManagerSecretCacheOptions {
  /** Receives a debug entry per fetched name while sensitive logging is enabled, and an error entry per failed fetch. */
  readonly logger?: Logger;
  /**
   * How long a fetch may take, retries included, in milliseconds; omitted is
   * {@link GoogleSecretManagerSecretCache.DEFAULT_TIMEOUT_MS}.
   */
  readonly timeoutMs?: number;
}

/** The options of {@link GoogleSecretManagerSecretCache.create}. */
export interface GoogleSecretManagerSecretCacheCreateOptions extends GoogleSecretManagerSecretCacheOptions {
  /**
   * The new client's options, e.g. `{ apiEndpoint: 'secretmanager.europe-west1.rep.googleapis.com' }`
   * or `{ keyFilename }`; omitted is the global endpoint, signed in with Application Default
   * Credentials. `fallback` (REST) is refused.
   */
  readonly clientOptions?: SecretManagerClientOptions;
}

/** What SecretManagerServiceClient's constructor takes. */
export type SecretManagerClientOptions = NonNullable<ConstructorParameters<typeof SecretManagerServiceClient>[0]>;

const METHOD = '/google.cloud.secretmanager.v1.SecretManagerService/AccessSecretVersion';

// gRPC status codes.
const NOT_FOUND = 5;
const RESOURCE_EXHAUSTED = 8;
const UNAVAILABLE = 14;

/**
 * How a fetch retries: as the client retries AccessSecretVersion by default (its
 * secret_manager_service_client_config.json) - RESOURCE_EXHAUSTED and UNAVAILABLE, after a random
 * delay of up to 2 s, doubling to 60 s, everything within the timeout. Not part of the package API:
 * the tests shorten the delay.
 */
export const retrySettings = { initialDelayMs: 2_000, delayMultiplier: 2, maxDelayMs: 60_000 };

// A version's resource name, of a global or a regional secret.
const SECRET_VERSION_NAME = /^projects\/[^/]+\/(?:locations\/[^/]+\/)?secrets\/([^/]+)\/versions\/[^/]+$/;

// The client header the client itself sends, as far as it can be known without reaching into it.
const API_CLIENT_HEADER = (() => {
  const parts = [`gl-node/${process.versions.node}`];
  try {
    parts.push(`gapic/${(require('@google-cloud/secret-manager/package.json') as { version: string }).version}`);
  } catch {
    // A future package that hides its package.json: the header names Node only.
  }
  return parts.join(' ');
})();

/** The few members of a @grpc/grpc-js Client - the client's stub - that a fetch uses. */
interface GrpcStub {
  makeUnaryRequest(method: string, serialize: (request: Buffer) => Buffer, deserialize: (raw: Buffer) => AccessedSecretVersion,
    argument: Buffer, options: object, callback: (error: Error | null, response?: AccessedSecretVersion) => void): { cancel(): void };
}

/** A gRPC call as an interceptor sees it: only start, whose metadata the cache adds its headers to. */
interface InterceptedCall {
  start(metadata: { set(key: string, value: string): void }, ...rest: unknown[]): void;
}

/**
 * A ProtectedReadOnlyCache over the secrets in one Google Cloud project's Secret Manager - the Node
 * port of the .NET HkdfGuard.Cache.GoogleSecretManager library. The first lookup of a name that isn't
 * cached yet reads that one secret's latest version with AccessSecretVersion; fetching, encryption,
 * caching and telemetry are RemoteSecretCache's. This class never lists secrets or versions, so the
 * principal needs only `secretmanager.versions.access` on the secrets it reads (the Secret Manager
 * Secret Accessor role), never `secretmanager.secrets.list`.
 *
 * Names are matched exactly, as Secret Manager matches secret IDs: "Db-Password" and "db-password"
 * are two secrets and two entries. A name Secret Manager can't hold - anything but 1-255 ASCII
 * letters, digits, hyphens and underscores, such as the configuration path "ConnectionStrings:Admin"
 * - is reported missing without a call.
 *
 * A payload holding a JSON object, such as {"username":"app","password":"..."}, is cached whole under
 * the secret's ID and each member under "id#key" - "Db-Login#password" - all from one call (see
 * RemoteSecretCache).
 *
 * A secret that doesn't exist, or has no versions (NOT_FOUND), or whose value is empty is reported
 * missing. Any other failure (permission denied, a disabled or destroyed latest version, Google
 * unreachable, the timeout passing) rejects with the gRPC error as @grpc/grpc-js reports it - an Error
 * whose `code` is the numeric gRPC status, with `details` and `metadata` - and a credential that can't
 * get a token, or a client that can't start, with the client's own error. A payload whose CRC32C
 * doesn't match the checksum Google returns, or a response naming a different secret, is refused with
 * InvalidSecretDataError; a response that isn't well-formed protobuf fails as INTERNAL.
 *
 * **The payload never becomes a protobuf message or a string.** The cache makes AccessSecretVersion
 * itself, on the client's own gRPC stub - its channel, endpoint and credentials - with a response
 * deserializer of its own: it reads the few fields it needs straight from the message gRPC received,
 * copies the payload into a Uint8Array, and zeroes the received message; the copy is encrypted and
 * zeroed, refused or not. The client's protobufjs message, which would hold the payload where nothing
 * erases it, is never built, and the client's own debug logging (GOOGLE_SDK_NODE_LOGGING), which
 * would log the whole response, is bypassed. Out of reach, as in every port: the transport's buffers
 * below gRPC's message (HTTP/2 frames, TLS decryption).
 *
 * The client is the application's: it creates it - credentials, endpoint, channel options - and must
 * use gRPC (the default); a REST (`fallback`) client is refused at the first fetch, as its stub can't
 * make the call. Only the client's stub is used, so its per-call settings don't apply: every call
 * carries the routing header the client would add, and is retried as the client retries
 * AccessSecretVersion by default (RESOURCE_EXHAUSTED and UNAVAILABLE, with exponential backoff), all
 * within `timeoutMs`. {@link create} makes a client of its own, which {@link close} closes; a client
 * passed in is never closed.
 *
 * Aborting the signal of the lookup that started a fetch cancels the call (or the wait before a
 * retry), and the lookup rejects with the signal's reason.
 */
export class GoogleSecretManagerSecretCache extends RemoteSecretCache {
  /** The longest ID Secret Manager accepts for a secret. */
  static readonly MAX_SECRET_NAME_LENGTH = 255;

  /** How long a fetch may take by default, retries included, in milliseconds: the client's own default. */
  static readonly DEFAULT_TIMEOUT_MS = 60_000;

  readonly #client: SecretManagerServiceClient;
  readonly #projectId: string;
  readonly #timeoutMs: number;
  #ownsClient = false;

  /**
   * A cache over a client the caller created, and closes. No call is made until a secret is looked up.
   *
   * @param client e.g. `new SecretManagerServiceClient()` - the global endpoint, signed in with
   *   Application Default Credentials. It must use gRPC (the default).
   * @param projectId the project whose secrets are read: its ID or number
   * @param ring supplies the key every fetched secret is encrypted under; owned by the caller - the
   *   cache never closes keys
   * @throws InvalidArgumentError `client` isn't a SecretManagerServiceClient; `projectId` is empty, or
   *   holds anything but ASCII letters, digits, hyphens, dots and colons; or `timeoutMs` isn't a
   *   positive number
   * @throws TypeError ring is missing
   */
  constructor(client: SecretManagerServiceClient, projectId: string, ring: KeyRing, options: GoogleSecretManagerSecretCacheOptions = {}) {
    if (typeof client !== 'object' || client === null || typeof (client as { initialize?: unknown }).initialize !== 'function') {
      throw new InvalidArgumentError('client must be a SecretManagerServiceClient from @google-cloud/secret-manager.');
    }
    checkProjectId(projectId);
    const timeoutMs = checkOptions(options);
    super(ring, SecretNameMatching.exact, options.logger);
    this.#client = client;
    this.#projectId = projectId;
    this.#timeoutMs = timeoutMs;
  }

  /**
   * A cache reading secrets through a new gRPC client, which {@link close} closes: by default to the
   * global endpoint, signed in with Application Default Credentials - looked up at the first fetch,
   * which rejects if there are none.
   *
   * @throws InvalidArgumentError as the constructor - checked before a client is created - or
   *   `clientOptions` asks for REST (`fallback`)
   * @throws TypeError ring is missing
   */
  static create(projectId: string, ring: KeyRing, options: GoogleSecretManagerSecretCacheCreateOptions = {}): GoogleSecretManagerSecretCache {
    checkProjectId(projectId);
    checkOptions(options);
    if (ring === undefined || ring === null) throw new TypeError('ring must not be undefined.');
    if (options.clientOptions?.fallback) {
      throw new InvalidArgumentError('The client must use gRPC, so the cache can take the payload out of the response before the client parses it; '
        + 'remove fallback from clientOptions.');
    }

    const client = new SecretManagerServiceClient(options.clientOptions);
    try {
      const cache = new GoogleSecretManagerSecretCache(client, projectId, ring, options);
      cache.#ownsClient = true;
      return cache;
    } catch (error) {
      void client.close();
      throw error;
    }
  }

  /**
   * Whether Secret Manager accepts `name` as a secret ID: 1-{@link MAX_SECRET_NAME_LENGTH} ASCII
   * letters, digits, hyphens and underscores.
   */
  static isValidSecretName(name: string | undefined | null): boolean {
    return typeof name === 'string' && name.length <= GoogleSecretManagerSecretCache.MAX_SECRET_NAME_LENGTH && /^[A-Za-z0-9_-]+$/.test(name);
  }

  /** Closes the client {@link create} made; a client passed in is left open. */
  async close(): Promise<void> {
    if (this.#ownsClient) await this.#client.close();
  }

  protected override isValidName(name: string): boolean {
    return GoogleSecretManagerSecretCache.isValidSecretName(name);
  }

  protected override async fetch(name: string, sink: SecretValueSink, signal?: AbortSignal): Promise<void> {
    const deadline = Date.now() + this.#timeoutMs;
    const stub = await this.#stub(signal);
    const resourceName = `projects/${this.#projectId}/secrets/${name}/versions/latest`;
    const capture = new ResponseCapture();
    try {
      let version: AccessedSecretVersion;
      try {
        version = await callWithRetries(stub, resourceName, capture, deadline, signal);
      } catch (error) {
        if (statusOf(error) === NOT_FOUND && signal?.aborted !== true) return;
        throw error;
      }

      checkResponse(version, name);
      // Zeroes what it's given. A payload holding a JSON object is cached whole and by key.
      if (version.data.length > 0) sink.setBytesWithJsonKeys(version.data);
    } finally {
      // Covers a refused response, a retried one, and one that arrived after an abort.
      capture.close();
    }
  }

  // The client's gRPC stub, which the client creates - signing in - on first use.
  async #stub(signal: AbortSignal | undefined): Promise<GrpcStub> {
    const stub: unknown = await untilAborted(this.#client.initialize(), signal);
    if (typeof (stub as Partial<GrpcStub> | undefined)?.makeUnaryRequest !== 'function') {
      throw new InvalidArgumentError('The client must use gRPC (the default), so the cache can take the payload out of the response before the '
        + 'client parses it; it was created with fallback (REST).');
    }
    return stub as GrpcStub;
  }
}

function checkProjectId(projectId: unknown): asserts projectId is string {
  if (typeof projectId !== 'string' || projectId === '') throw new InvalidArgumentError('projectId must be a non-empty string.');
  // Spliced into every resource name, so nothing that could change the path is allowed.
  if (!/^[A-Za-z0-9.:-]+$/.test(projectId)) throw new InvalidArgumentError(`'${projectId}' isn't a Google Cloud project ID or number.`);
}

function checkOptions(options: GoogleSecretManagerSecretCacheOptions): number {
  if (typeof options !== 'object' || options === null) throw new InvalidArgumentError('GoogleSecretManagerSecretCache options must be an object.');
  const timeoutMs: unknown = options.timeoutMs ?? GoogleSecretManagerSecretCache.DEFAULT_TIMEOUT_MS;
  if (typeof timeoutMs !== 'number' || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new InvalidArgumentError(`timeoutMs must be a positive number of milliseconds; got ${String(timeoutMs)}.`);
  }
  return timeoutMs;
}

// The call, retried on RESOURCE_EXHAUSTED and UNAVAILABLE while the deadline allows; the last
// failure rejects.
async function callWithRetries(stub: GrpcStub, resourceName: string, capture: ResponseCapture, deadline: number,
  signal: AbortSignal | undefined): Promise<AccessedSecretVersion> {
  const request = Buffer.from(protos.google.cloud.secretmanager.v1.AccessSecretVersionRequest.encode({ name: resourceName }).finish());
  const headers = withHeaders(resourceName);
  let delay = retrySettings.initialDelayMs;
  for (;;) {
    try {
      return await callOnce(stub, request, capture, { deadline, interceptors: [headers] }, signal);
    } catch (error) {
      const status = statusOf(error);
      if ((status !== RESOURCE_EXHAUSTED && status !== UNAVAILABLE) || signal?.aborted === true) throw error;
      // Jitter, as the client's own retries have; from the CSPRNG, though nothing secret depends on it.
      const wait = randomInt(0, Math.floor(delay) + 1);
      if (Date.now() + wait >= deadline) throw error;
      await sleep(wait, signal);
      delay = Math.min(delay * retrySettings.delayMultiplier, retrySettings.maxDelayMs);
    }
  }
}

// One AccessSecretVersion call, its response parsed by capture. Aborting cancels it.
function callOnce(stub: GrpcStub, request: Buffer, capture: ResponseCapture, options: object,
  signal: AbortSignal | undefined): Promise<AccessedSecretVersion> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted === true) {
      reject(abortReason(signal));
      return;
    }
    let call: { cancel(): void } | undefined;
    const onAbort = () => {
      call?.cancel();
      reject(abortReason(signal!));
    };
    try {
      call = stub.makeUnaryRequest(METHOD, () => request, (raw) => capture.deserialize(raw), request, options, (error, response) => {
        signal?.removeEventListener('abort', onAbort);
        if (error) reject(error);
        else resolve(response!);
      });
    } catch (error) {
      // A closed client's channel refuses the call at once.
      reject(error);
      return;
    }
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

// A gRPC call interceptor adding the headers the client adds to its own AccessSecretVersion: the
// routing header and the client header. An interceptor, rather than a Metadata of the cache's own,
// so no copy of @grpc/grpc-js but the client's is involved.
function withHeaders(resourceName: string): (options: unknown, nextCall: (options: unknown) => InterceptedCall) => InterceptedCall {
  const routing = stringify({ name: resourceName });
  return (options, nextCall) => {
    const call = nextCall(options);
    const start = call.start.bind(call);
    call.start = (metadata, ...rest) => {
      metadata.set('x-goog-request-params', routing);
      metadata.set('x-goog-api-client', API_CLIENT_HEADER);
      start(metadata, ...rest);
    };
    return call;
  };
}

// The response must be a version of the secret asked for (its project comes back as a number, so
// only the secret ID can be compared), and match its checksum when it has one.
function checkResponse(version: AccessedSecretVersion, name: string): void {
  const reported = SECRET_VERSION_NAME.exec(version.name);
  if (reported === null || reported[1] !== name) {
    throw new InvalidSecretDataError(`Secret Manager answered a request for secret '${name}' with '${version.name}'.`);
  }
  if (version.dataCrc32c !== undefined && version.dataCrc32c !== BigInt(crc32c(version.data))) {
    throw new InvalidSecretDataError(`The payload of secret '${name}' doesn't match its CRC32C: it was corrupted in transit.`);
  }
}

function statusOf(error: unknown): unknown {
  return typeof error === 'object' && error !== null ? (error as { code?: unknown }).code : undefined;
}


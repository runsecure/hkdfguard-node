import { randomInt } from 'node:crypto';
import { stringify } from 'node:querystring';
import { protos, SecretManagerServiceClient } from '@google-cloud/secret-manager';
import { InvalidArgumentError, type PipelineDataProtector } from '@runsecure/hkdfguard-abstractions';
import { abortReason, crc32c, delay as sleep, untilAborted } from '@runsecure/hkdfguard-abstractions/internal';
import { InvalidSecretDataError, SecretPipelineWriter, type SecretRequest } from '@runsecure/hkdfguard-pipeline';
import { ResponseCapture, type AccessedSecretVersion } from './capture.js';

/** The options of a {@link GoogleSecretManagerSecretPipelineWriter}. */
export interface GoogleSecretManagerSecretPipelineWriterOptions {
  /**
   * How long one secret's read may take, retries included, in milliseconds; omitted is
   * {@link GoogleSecretManagerSecretPipelineWriter.DEFAULT_TIMEOUT_MS}.
   */
  readonly timeoutMs?: number;
}

/** The options of {@link GoogleSecretManagerSecretPipelineWriter.create}. */
export interface GoogleSecretManagerSecretPipelineWriterCreateOptions extends GoogleSecretManagerSecretPipelineWriterOptions {
  /**
   * The new client's options, e.g. `{ apiEndpoint: 'secretmanager.europe-west1.rep.googleapis.com' }`
   * or `{ keyFilename }`; omitted is the global endpoint, signed in with Application Default
   * Credentials (Workload Identity on GKE). `fallback` (REST) is refused.
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
 * How a read retries: as the client retries AccessSecretVersion by default (its
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

/** The few members of a @grpc/grpc-js Client - the client's stub - that a read uses. */
interface GrpcStub {
  makeUnaryRequest(method: string, serialize: (request: Buffer) => Buffer, deserialize: (raw: Buffer) => AccessedSecretVersion,
    argument: Buffer, options: object, callback: (error: Error | null, response?: AccessedSecretVersion) => void): { cancel(): void };
}

/** A gRPC call as an interceptor sees it: only start, whose metadata the writer adds its headers to. */
interface InterceptedCall {
  start(metadata: { set(key: string, value: string): void }, ...rest: unknown[]): void;
}

/**
 * The end of a provisioning pipeline - the Node port of .NET's GoogleSecretManagerSecretPipelineWriter:
 * pulls a fixed list of secrets from one Google Cloud project's Secret Manager, encrypts each with a
 * PipelineDataProtector as soon as it is read, and writes them out as one file per secret - the
 * folder layout FilePerSecretCache reads at runtime. It is independent of
 * @runsecure/hkdfguard-cache-googlesecretmanager's runtime cache, and of any key ring. Naming,
 * encrypting, keeping and writing are SecretPipelineWriter's.
 *
 * A secret name is a Secret Manager secret ID - 1-255 ASCII letters, digits, hyphens and underscores
 * - optionally with a key after '#': "api-key" reads the latest version's whole payload, and
 * "db-login#password" the password member of a payload holding a JSON object (written as api-key and
 * db-login__password). A member's string is read as its text; a number, true or false as its JSON
 * text. A payload that isn't UTF-8 text is refused with InvalidSecretDataError: the protector
 * encrypts text. Each secret's latest version is read with AccessSecretVersion, so the principal
 * needs only `secretmanager.versions.access` (the Secret Manager Secret Accessor role), never a list
 * permission.
 *
 * A secret that doesn't exist, or has no versions (NOT_FOUND), or whose payload is empty is missing.
 * Any other failure (permission denied, a disabled or destroyed latest version, Google unreachable,
 * the timeout passing) rejects with the gRPC error as @grpc/grpc-js reports it - an Error whose
 * `code` is the numeric gRPC status - and a credential that can't get a token with the client's own
 * error. A payload whose CRC32C doesn't match the checksum Google returns, or a response naming a
 * different secret, is refused with InvalidSecretDataError (as the Node cache refuses them; .NET
 * throws CryptographicException); a response that isn't well-formed protobuf fails as INTERNAL.
 *
 * **The payload never becomes a protobuf message or a string.** The writer makes AccessSecretVersion
 * itself, on the client's own gRPC stub - its channel, endpoint and credentials - with a response
 * deserializer of its own: it reads the few fields it needs straight from the message gRPC received,
 * copies the payload into a Uint8Array, and zeroes the received message (the counterpart of .NET's
 * ReceiveBufferScrubber); the copy is encrypted and zeroed, refused or not. The client's own debug
 * logging, which would log the whole response, is bypassed. Out of reach: the transport's buffers
 * below gRPC's message (HTTP/2 frames, TLS decryption).
 *
 * The client must use gRPC (the default); a REST (`fallback`) client is refused at the first read.
 * Every call carries the routing header the client would add, and is retried as the client retries
 * AccessSecretVersion by default (RESOURCE_EXHAUSTED and UNAVAILABLE, with exponential backoff), all
 * within `timeoutMs`. {@link create} makes a client of its own, which {@link close} closes; a client
 * passed in is never closed.
 */
export class GoogleSecretManagerSecretPipelineWriter extends SecretPipelineWriter {
  /** The longest ID Secret Manager accepts for a secret. */
  static readonly MAX_SECRET_NAME_LENGTH = 255;

  /** How long a read may take by default, retries included, in milliseconds: the client's own default. */
  static readonly DEFAULT_TIMEOUT_MS = 60_000;

  readonly #client: SecretManagerServiceClient;
  readonly #projectId: string;
  readonly #timeoutMs: number;
  #ownsClient = false;

  /**
   * A writer reading through a client the caller created, and closes.
   * @param client e.g. `new SecretManagerServiceClient()`; it must use gRPC (the default)
   * @param projectId the project whose secrets are read: its ID or number
   * @param protector encrypts every value read. Owned by the caller: the writer never closes it.
   * @param secretNames the secrets to pull, each a secret ID with the key to read after '#' if any.
   *   Copied: a later change to the array isn't seen.
   * @throws TypeError protector or secretNames is missing
   * @throws InvalidArgumentError client isn't a SecretManagerServiceClient; projectId is empty, or
   *   holds anything but ASCII letters, digits, hyphens, dots and colons; timeoutMs isn't a positive
   *   number; or secretNames is empty, or holds something that isn't a string, an ID Secret Manager
   *   can't hold (with a key), one whose file name isn't one FilePerSecretCache can read, or two with
   *   the same file name, in any case
   */
  constructor(
    client: SecretManagerServiceClient, projectId: string, protector: PipelineDataProtector, secretNames: readonly string[],
    options: GoogleSecretManagerSecretPipelineWriterOptions = {},
  ) {
    super(protector, secretNames, GoogleSecretManagerSecretPipelineWriter.isValidSecretName);
    if (typeof client !== 'object' || client === null || typeof (client as { initialize?: unknown }).initialize !== 'function') {
      throw new InvalidArgumentError('client must be a SecretManagerServiceClient from @google-cloud/secret-manager.');
    }
    checkProjectId(projectId);
    this.#timeoutMs = checkOptions(options);
    this.#client = client;
    this.#projectId = projectId;
  }

  /**
   * A writer reading secrets through a new gRPC client, which {@link close} closes: by default to the
   * global endpoint, signed in with Application Default Credentials - looked up at the first read,
   * which rejects if there are none.
   * @throws InvalidArgumentError as the constructor - the project and options checked before a
   *   client is created - or `clientOptions` asks for REST (`fallback`)
   * @throws TypeError as the constructor
   */
  static create(
    projectId: string, protector: PipelineDataProtector, secretNames: readonly string[], options: GoogleSecretManagerSecretPipelineWriterCreateOptions = {},
  ): GoogleSecretManagerSecretPipelineWriter {
    checkProjectId(projectId);
    checkOptions(options);
    if (options.clientOptions?.fallback) {
      throw new InvalidArgumentError('The client must use gRPC, so the writer can take the payload out of the response before the client parses it; '
        + 'remove fallback from clientOptions.');
    }

    const client = new SecretManagerServiceClient(options.clientOptions);
    try {
      const writer = new GoogleSecretManagerSecretPipelineWriter(client, projectId, protector, secretNames, options);
      writer.#ownsClient = true;
      return writer;
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
    return typeof name === 'string' && name.length <= GoogleSecretManagerSecretPipelineWriter.MAX_SECRET_NAME_LENGTH && /^[A-Za-z0-9_-]+$/.test(name);
  }

  /** Closes the client {@link create} made; a client passed in is left open. */
  protected override async closeStore(): Promise<void> {
    if (this.#ownsClient) await this.#client.close();
  }

  /**
   * @throws Error (rejecting) with the gRPC status as its `code`: any Secret Manager failure but NOT_FOUND
   * @throws InvalidSecretDataError (rejecting) the payload doesn't match its CRC32C, the response
   *   names a different secret, the payload isn't UTF-8 text, or a JSON object payload holds a key twice
   */
  protected override async readSecret(name: string, requests: readonly SecretRequest[], values: Map<string, string>, signal?: AbortSignal): Promise<void> {
    const deadline = Date.now() + this.#timeoutMs;
    const stub = await this.#stub(signal);
    const resourceName = `projects/${this.#projectId}/secrets/${name}/versions/latest`;
    const capture = new ResponseCapture();
    try {
      let version: AccessedSecretVersion;
      try {
        version = await callWithRetries(stub, resourceName, capture, deadline, signal);
      } catch (error) {
        // Missing: nothing handed over.
        if (statusOf(error) === NOT_FOUND && signal?.aborted !== true) return;
        throw error;
      }

      checkResponse(version, name);
      // Encrypted straight from the copy the deserializer made, which close() zeroes.
      this.protectSecret(version.data, requests, values);
    } finally {
      // Covers a refused response, a retried one, and one that arrived after an abort.
      capture.close();
    }
  }

  // The client's gRPC stub, which the client creates - signing in - on first use.
  async #stub(signal: AbortSignal | undefined): Promise<GrpcStub> {
    const stub: unknown = await untilAborted(this.#client.initialize(), signal);
    if (typeof (stub as Partial<GrpcStub> | undefined)?.makeUnaryRequest !== 'function') {
      throw new InvalidArgumentError('The client must use gRPC (the default), so the writer can take the payload out of the response before the '
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

function checkOptions(options: GoogleSecretManagerSecretPipelineWriterOptions): number {
  if (typeof options !== 'object' || options === null) {
    throw new InvalidArgumentError('GoogleSecretManagerSecretPipelineWriter options must be an object.');
  }
  const timeoutMs: unknown = options.timeoutMs ?? GoogleSecretManagerSecretPipelineWriter.DEFAULT_TIMEOUT_MS;
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
// routing header and the client header.
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

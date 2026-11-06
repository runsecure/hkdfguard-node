import { AsyncLocalStorage } from 'node:async_hooks';
import type { PipelinePolicy, PipelineRequest, PipelineResponse } from '@azure/core-rest-pipeline';
import { wipe } from '@runsecure/hkdfguard-abstractions';
import { PinnedBody } from '@runsecure/hkdfguard-pipeline';

/** The name of {@link secretCapturePolicy} in a pipeline. */
export const SECRET_CAPTURE_POLICY_NAME = 'hkdfguardPipelineSecretCapturePolicy';

/** The status of a Get Secret response that holds the secret: the only one captured. */
const OK = 200;

/** Takes a successful Get Secret response body: `buffer`'s first `length` bytes, zeroed once this returns. */
export type SecretBodyCapture = (buffer: Uint8Array, length: number) => void;

/** One read's capture, and whether its response reached it. */
export class Capture {
  /** Whether a 200 response passed through the policy, so its body went to {@link take}. */
  captured = false;

  /** @throws TypeError take isn't a function */
  constructor(readonly take: SecretBodyCapture) {
    if (typeof take !== 'function') throw new TypeError('take must be a function.');
  }
}

// The capture of the read whose requests are running, through every await between the read's
// getSecret call and the policy: the counterpart of .NET's HttpPipeline.CreateHttpMessagePropertiesScope.
const scope = new AsyncLocalStorage<Capture>();

/**
 * Runs `call` - a getSecret on a client whose pipeline holds {@link secretCapturePolicy} - so that
 * every request it makes hands its body to `capture`. The capture travels with the call's own
 * asynchronous context, never on the client, so another client sharing the options, or a call made
 * outside, is left as it is.
 * @throws TypeError capture isn't a Capture
 */
export function captureWithin<T>(capture: Capture, call: () => Promise<T>): Promise<T> {
  if (!(capture instanceof Capture)) throw new TypeError('capture must be a Capture.');
  return scope.run(capture, call);
}

const encoder = new TextEncoder();

/**
 * Takes the secret out of a Get Secret response before SecretClient can turn it into a string - the
 * counterpart of .NET's PipelineSecretCapturePolicy. Acts only on a request made within
 * {@link captureWithin}; every other request passes through untouched. Stateless: one instance
 * serves every client and every read.
 *
 * A per-retry policy - which the Azure SDK for JavaScript places after its Sign phase, closest to the
 * HTTP client, after any per-retry policy of the application's - so it runs on every attempt. For a
 * capturing request it adds 200 to the request's streamResponseStatusCodes, so the HTTP client hands
 * a 200's body over unread (decompressed, as a Node Readable) rather than decoding it into
 * bodyAsText. That body is read into a buffer of the library's own (PinnedBody: every chunk zeroed
 * once copied), handed to the capture and zeroed, and SecretClient is given, as bodyAsText, only the
 * secret's identifier taken from the request URL - `{"id":"https://{vault}/secrets/{name}"}`, which
 * it needs to build its result (.NET's SecretClient takes "{}"; this SDK's can't). Nothing of the
 * response reaches it, so every policy outside this one, the SDK's logging policy among them, sees no
 * part of the value. Any other status was never streamed, and is left for SecretClient's error
 * handling.
 *
 * An HTTP client that buffers the body regardless (one of the application's, given as the
 * `httpClient` client option) hands it over as bodyAsText, a string: it is captured all the same,
 * but that string can't be zeroed. Nor can the HTTP stack's own buffers (TLS decryption, socket
 * reads), below the pipeline.
 */
export const secretCapturePolicy: PipelinePolicy = {
  name: SECRET_CAPTURE_POLICY_NAME,
  async sendRequest(request, next) {
    const capture = scope.getStore();
    if (capture === undefined) return next(request);

    request.streamResponseStatusCodes = new Set([...(request.streamResponseStatusCodes ?? []), OK]);
    const response = await next(request);
    if (response.status !== OK) return response;

    // A real AbortSignal by now (the SDK's wrapAbortSignalLikePolicy makes one), but typed as its own AbortSignalLike.
    const signal = request.abortSignal instanceof AbortSignal ? request.abortSignal : undefined;
    await captureBody(response, capture.take, signal);
    response.readableStreamBody = undefined;
    response.browserStreamBody = undefined;
    response.bodyAsText = placeholder(request);
    capture.captured = true;
    return response;
  },
};

// The body SecretClient is given: the secret's identifier, as the request named it, and nothing else.
function placeholder(request: PipelineRequest): string {
  const url = new URL(request.url);
  let end = url.pathname.length;
  while (url.pathname[end - 1] === '/') end--;
  return JSON.stringify({ id: `${url.origin}${url.pathname.slice(0, end)}` });
}

// Hands the response's body to take, however the HTTP client left it: a stream, read to its end (and
// destroyed if that fails), or text it already decoded.
async function captureBody(response: PipelineResponse, take: SecretBodyCapture, signal: AbortSignal | undefined): Promise<void> {
  const stream = response.readableStreamBody ?? response.browserStreamBody;
  let body: { buffer: Uint8Array; length: number };
  if (stream !== undefined) {
    try {
      body = await PinnedBody.read(stream as AsyncIterable<Uint8Array>, signal);
    } catch (error) {
      if (response.readableStreamBody !== undefined) (response.readableStreamBody as NodeJS.ReadableStream & { destroy?(): void }).destroy?.();
      else void response.browserStreamBody?.cancel().catch(() => undefined);
      throw error;
    }
  } else {
    // Already a string the HTTP client made, which can't be zeroed; its bytes, which are ours, are.
    const buffer = encoder.encode(response.bodyAsText ?? '');
    body = { buffer, length: buffer.length };
  }
  try {
    take(body.buffer, body.length);
  } finally {
    wipe(body.buffer);
  }
}

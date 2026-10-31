import { AsyncLocalStorage } from 'node:async_hooks';
import type { PipelinePolicy, PipelineResponse } from '@azure/core-rest-pipeline';
import { wipe } from '@runsecure/hkdfguard-abstractions';
import { SecretJsonBody, SecretValueSink, type ResponseBody } from '@runsecure/hkdfguard-cache';

/** The name of {@link secretCapturePolicy} in a pipeline. */
export const SECRET_CAPTURE_POLICY_NAME = 'hkdfguardSecretCapturePolicy';

/** The status of a Get Secret response that holds the secret: the only one captured. */
const OK = 200;

/** One fetch's sink, and whether its response reached it. */
export class Capture {
  /** Whether a 200 response passed through the policy, so its value, if any, went to the sink. */
  captured = false;

  /** @throws TypeError sink isn't a SecretValueSink */
  constructor(readonly sink: SecretValueSink) {
    if (!(sink instanceof SecretValueSink)) throw new TypeError('sink must be a SecretValueSink.');
  }
}

// The capture of the fetch whose requests are running, through every await between the fetch's
// getSecret call and the policy: the counterpart of .NET's HttpPipeline.CreateHttpMessagePropertiesScope.
const scope = new AsyncLocalStorage<Capture>();

/**
 * Runs `call` - a getSecret on a client whose pipeline holds {@link secretCapturePolicy} - so that
 * every request it makes hands its secret to `capture`. The capture travels with the call's own
 * asynchronous context, never on the client, so any number of fetches can run through one client at
 * once, each capturing its own response.
 * @throws TypeError capture isn't a Capture
 */
export function captureWithin<T>(capture: Capture, call: () => Promise<T>): Promise<T> {
  if (!(capture instanceof Capture)) throw new TypeError('capture must be a Capture.');
  return scope.run(capture, call);
}

const decoder = new TextDecoder();
const encoder = new TextEncoder();

/**
 * Takes the secret out of a Get Secret response before SecretClient can turn it into a string. Acts
 * only on a request made within {@link captureWithin}; every other request passes through untouched.
 * Stateless: one instance serves every client and every fetch.
 *
 * A per-retry policy - which the Azure SDK for JavaScript places after its Sign phase, closest to
 * the HTTP client, after any per-retry policy of the application's - so it runs on every attempt,
 * and every other policy, the SDK's logging policy among them, sees only the redacted body. For a
 * capturing request it adds 200 to the request's streamResponseStatusCodes, so the HTTP client hands
 * a 200's body over unread (decompressed, as a Node Readable) rather than decoding it into
 * bodyAsText. That body is read through {@link SecretJsonBody.captureAsync} - every chunk zeroed once
 * copied - its top-level `value` handed to the capture's sink (a JSON object's members as keys too),
 * and the response given the body with `value` blanked, as bodyAsText, which is what SecretClient
 * deserializes. Any other status was never streamed, and is left for SecretClient's error handling.
 *
 * An HTTP client that buffers the body regardless (one of the application's, given as the
 * `httpClient` client option) hands it over as bodyAsText, a string: it is captured and redacted
 * all the same, but that string can't be zeroed. Nor can the HTTP stack's own buffers (TLS
 * decryption, socket reads), below the pipeline.
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
    const redacted = await captureBody(response, capture.sink, signal);
    response.readableStreamBody = undefined;
    response.browserStreamBody = undefined;
    response.bodyAsText = decoder.decode(redacted);
    capture.captured = true;
    return response;
  },
};

// The response's body with its value blanked, its value handed to sink, however the HTTP client
// left it: a stream, read to its end (and destroyed if that fails), or text it already decoded.
async function captureBody(response: PipelineResponse, sink: SecretValueSink, signal: AbortSignal | undefined): Promise<Uint8Array> {
  const stream = response.readableStreamBody ?? response.browserStreamBody;
  if (stream !== undefined) {
    try {
      return await SecretJsonBody.captureAsync(stream as ResponseBody, sink, 'value', signal === undefined ? {} : { signal });
    } catch (error) {
      if (response.readableStreamBody !== undefined) (response.readableStreamBody as NodeJS.ReadableStream & { destroy?(): void }).destroy?.();
      else void response.browserStreamBody?.cancel().catch(() => undefined);
      throw error;
    }
  }

  // Already a string the HTTP client made, which can't be zeroed; its bytes, which are ours, are.
  const body = encoder.encode(response.bodyAsText ?? '');
  try {
    return SecretJsonBody.capture(body, sink, 'value');
  } finally {
    wipe(body);
  }
}

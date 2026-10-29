import type { GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { SecretJsonBody, type ResponseBody, type SecretValueSink } from '@runsecure/hkdfguard-cache';

/** The response property holding a text secret. */
export const TEXT_PROPERTY = 'SecretString';

/** The response property holding a binary secret, base64-encoded. */
export const BINARY_PROPERTY = 'SecretBinary';

/** The capture middleware's name on a command's stack. */
export const MIDDLEWARE_NAME = 'hkdfguardSecretCaptureMiddleware';

/** The part of an HTTP response the capture reads and replaces: what the SDK's HttpResponse is. */
interface CapturableResponse {
  statusCode?: unknown;
  body?: unknown;
}

/**
 * The capture of one GetSecretValue call: a middleware on that one command's stack - never the
 * client's - that hands the secret in a successful response's body to {@link sink} and leaves the
 * SDK the body with it replaced by "". Records whether a successful response passed through it,
 * and why one was refused.
 *
 * It sits in the deserialize step at low priority and is added to the command after the client's
 * stack, so it is the innermost middleware of the call: the HTTP handler's response reaches it
 * before the SDK's deserializer, and before every middleware the application added to the client.
 * The retry middleware sits outside it, so each attempt is captured on its own.
 */
export class SecretCapture {
  #captured = false;
  #failure: unknown;
  #failed = false;

  /**
   * @param sink receives the secret
   * @param signal the fetch's signal, which also stops reading the body
   */
  constructor(readonly sink: SecretValueSink, private readonly signal: AbortSignal | undefined) {}

  /** Whether a successful response's body reached the capture. */
  get captured(): boolean {
    return this.#captured;
  }

  /** Why a response body was refused, the first reason winning; undefined if none was. */
  get failure(): unknown {
    return this.#failure;
  }

  /** Whether a response body was refused. */
  get failed(): boolean {
    return this.#failed;
  }

  /** Adds the capture to `command`'s own middleware stack, so it acts on that one call only. */
  attachTo(command: GetSecretValueCommand): void {
    command.middlewareStack.add((next) => async (args) => {
      const result = await next(args);
      const response = result.response as CapturableResponse | undefined;
      if (typeof response === 'object' && response !== null && isSuccess(response.statusCode)) {
        // Replaced in place, so every middleware outside this one - the deserializer's and the
        // application's - holds the same response object, and with it the redacted body.
        response.body = await this.capture(response.body);
      }
      return result;
    }, { step: 'deserialize', priority: 'low', name: MIDDLEWARE_NAME, tags: ['HKDFGUARD'] });
  }

  // Hands the secret in body to the sink and returns the body with it replaced by "". A missing body
  // is read as an empty one, which is refused as not a JSON object.
  private async capture(body: unknown): Promise<Uint8Array> {
    this.#captured = true;
    try {
      return await SecretJsonBody.captureAsync((body ?? new Uint8Array(0)) as ResponseBody, this.sink, TEXT_PROPERTY,
        { base64Property: BINARY_PROPERTY, signal: this.signal });
    } catch (error) {
      if (!this.#failed) {
        this.#failed = true;
        this.#failure = error;
      }
      throw error;
    }
  }
}

function isSuccess(status: unknown): boolean {
  return typeof status === 'number' && status >= 200 && status < 300;
}

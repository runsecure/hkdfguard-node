import type { GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { wipe } from '@runsecure/hkdfguard-abstractions';
import { PinnedBody } from '@runsecure/hkdfguard-pipeline';

/** The capture middleware's name on a command's stack. */
export const MIDDLEWARE_NAME = 'hkdfguardPipelineSecretCaptureMiddleware';

/** Takes a successful GetSecretValue response body: `buffer`'s first `length` bytes, zeroed once this returns. */
export type SecretBodyCapture = (buffer: Uint8Array, length: number) => void;

/** The part of an HTTP response the capture reads and replaces: what the SDK's HttpResponse is. */
interface CapturableResponse {
  statusCode?: unknown;
  body?: unknown;
}

/**
 * The capture of one GetSecretValue call - the counterpart of .NET's PipelineSecretCaptureHandler: a
 * middleware on that one command's stack, never the client's, that reads a successful response's
 * body off the network into a buffer of the library's own (PinnedBody: each chunk zeroed once
 * copied), hands it to {@link SecretBodyCapture}, zeroes it, and gives the SDK's deserializer an empty
 * object in its place - nothing the writer needs is in the response. Records whether a successful
 * response passed through it, and why one was refused.
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
   * @param capture receives the body
   * @param signal the read's signal, which also stops reading the body
   */
  constructor(private readonly capture: SecretBodyCapture, private readonly signal: AbortSignal | undefined) {}

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
        // application's - holds the same response object, and with it the empty body.
        response.body = await this.#take(response.body);
      }
      return result;
    }, { step: 'deserialize', priority: 'low', name: MIDDLEWARE_NAME, tags: ['HKDFGUARD'] });
  }

  // Hands body to the capture and returns the empty object the SDK parses instead. A missing body is
  // read as an empty one, which the capture refuses as not a JSON object. A whole body of bytes is
  // zeroed too: once replaced, nothing reads it again.
  async #take(body: unknown): Promise<Uint8Array> {
    this.#captured = true;
    try {
      const { buffer, length } = await PinnedBody.read((body ?? new Uint8Array(0)) as Uint8Array, this.signal);
      try {
        this.capture(buffer, length);
      } finally {
        wipe(buffer);
        if (body instanceof Uint8Array) wipe(body);
      }
      return new TextEncoder().encode('{}');
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

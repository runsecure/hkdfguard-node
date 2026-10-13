import { metrics, SpanStatusCode, trace, type Attributes, type Meter, type Span, type Tracer } from '@opentelemetry/api';
import { AttributeNames, EventNames } from './names.js';

/** Holds a sensitive-logging flag, possibly shared by several components. */
class Flag {
  value = false;
}

/**
 * One component's telemetry surface: a tracer and meter sharing that component's instrumentation
 * scope name, a sensitive-logging toggle, and the helpers every operation across the library
 * calls through.
 *
 * Tracers and meters come from the global OpenTelemetry API each time they are requested, so an
 * application may register its providers at any point - before or after this package is loaded.
 * Spans started with {@link withSpan} are made active, so with a context manager registered they
 * nest under the caller's span automatically.
 */
export class ComponentTelemetry {
  readonly #flag: Flag;

  /** @internal Use the instances on {@link HkdfGuardTelemetry}. */
  constructor(
    /** This component's tracer/meter scope name - e.g. "HkdfGuard.Cache". */
    readonly sourceName: string,
    sharedFlagOwner?: ComponentTelemetry,
  ) {
    this.#flag = sharedFlagOwner ? sharedFlagOwner.#flag : new Flag();
  }

  /** This component's tracer, from the global tracer provider. */
  get tracer(): Tracer {
    return trace.getTracer(this.sourceName);
  }

  /** This component's meter, from the global meter provider. */
  get meter(): Meter {
    return metrics.getMeter(this.sourceName);
  }

  /**
   * When enabled, sensitive operations emit additional debug telemetry (operation metadata such as
   * buffer lengths and identifiers). Raw key, plaintext, and ciphertext bytes are never logged,
   * whatever this says. Components sharing a flag owner (Cache, DataProtection and
   * EncryptedConfiguration share Root's) read and write that owner's flag.
   */
  get enableSensitiveLogging(): boolean {
    return this.#flag.value;
  }

  set enableSensitiveLogging(value: boolean) {
    this.#flag.value = value;
  }

  /**
   * Runs `operation` inside an active span named `spanName`. An error it throws - or a promise it
   * returns that rejects - is recorded on the span (see {@link recordException}) and rethrown; the
   * span ends when `operation` finishes either way.
   */
  withSpan<T>(spanName: string, operation: (span: Span) => T): T {
    return this.tracer.startActiveSpan(spanName, (span) => {
      let result: T;
      try {
        result = operation(span);
      } catch (error) {
        recordException(span, error);
        span.end();
        throw error;
      }

      if (result instanceof Promise) {
        return result.then(
          (value) => {
            span.end();
            return value;
          },
          (error: unknown) => {
            recordException(span, error);
            span.end();
            throw error;
          },
        ) as T;
      }
      span.end();
      return result;
    });
  }

  /**
   * Adds a fixed-name ({@link EventNames.sensitiveOperation}) event to `span` when sensitive
   * logging is enabled, carrying `operationName` as {@link AttributeNames.operationName} plus every
   * detail. Pass only non-sensitive metadata (lengths, identifiers, timings) - never raw key,
   * plaintext, or ciphertext bytes.
   */
  logSensitiveOperation(span: Span | undefined, operationName: string, details: Attributes = {}): void {
    if (!this.enableSensitiveLogging || span === undefined || !span.isRecording()) {
      return;
    }
    span.addEvent(EventNames.sensitiveOperation, { [AttributeNames.operationName]: operationName, ...details });
  }
}

/**
 * Records `error` on `span` as an exception event and marks the span as errored. An undefined span
 * is a no-op.
 */
export function recordException(span: Span | undefined, error: unknown): void {
  if (span === undefined) {
    return;
  }
  const exception = error instanceof Error ? error : new Error(String(error));
  span.recordException(exception);
  span.setStatus({ code: SpanStatusCode.ERROR, message: exception.message });
}

const root = new ComponentTelemetry('HkdfGuard');

/**
 * One {@link ComponentTelemetry} per component in the library. Root, Cache, DataProtection, and
 * EncryptedConfiguration share one sensitive-logging flag (set any of them, all four read the new
 * value); CryptoProviderAesGcm256 and KeyWrapping each keep their own.
 */
export const HkdfGuardTelemetry = {
  root,
  cache: new ComponentTelemetry('HkdfGuard.Cache', root),
  dataProtection: new ComponentTelemetry('HkdfGuard.DataEncryptionKey', root),
  encryptedConfiguration: new ComponentTelemetry('HkdfGuard.EncryptedConfiguration', root),
  cryptoProviderAesGcm256: new ComponentTelemetry('HkdfGuard.CryptoProvider.AesGcm256'),
  keyWrapping: new ComponentTelemetry('HkdfGuard.KeyWrapping.V1'),
} as const;

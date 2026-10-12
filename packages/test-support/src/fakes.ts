import { randomFillSync } from 'node:crypto';
import type { EncryptedFormatProvider, KeyTrackingValue, KeyWrapper } from '@runsecure/hkdfguard-abstractions';

/**
 * A KeyWrapper that reveals a key on every unwrap - a fresh random one, or `fixedKey` every time
 * (as a real wrapper does for one payload) - counting calls. Reconfigure it between calls to model a
 * KEK that becomes unreachable, or reveals the wrong length.
 */
export class FakeKeyWrapper implements KeyWrapper {
  unwrapCalls = 0;
  generateCalls = 0;
  unwrapError: unknown;
  writtenOverride: number | undefined;

  constructor(public fixedKey?: Uint8Array) {}

  async wrap(): Promise<number> {
    throw new Error('not supported');
  }

  async unwrap(_wrapped: Uint8Array, result: Uint8Array): Promise<number> {
    this.unwrapCalls++;
    if (this.unwrapError !== undefined) {
      throw this.unwrapError;
    }
    const written = this.writtenOverride ?? result.length;
    const target = result.subarray(0, Math.min(written, result.length));
    if (this.fixedKey === undefined) {
      randomFillSync(target);
    } else {
      target.set(this.fixedKey.subarray(0, target.length));
    }
    return written;
  }

  async generateAndWrap(result: Uint8Array): Promise<number> {
    this.generateCalls++;
    randomFillSync(result.subarray(0, 32));
    return 32;
  }
}

/** A log entry captured by {@link capturingLogger}. */
export interface CapturedEntry {
  level: string;
  message: string;
  attributes: Record<string, unknown>;
}

/** A console-shaped logger that records every entry, with a filter by event id. */
export function capturingLogger(): {
  logger: Record<'debug' | 'info' | 'warn' | 'error', (message: string, attributes: Record<string, unknown>) => void>;
  entries: CapturedEntry[];
  withEventId(id: number): CapturedEntry[];
} {
  const entries: CapturedEntry[] = [];
  const at = (level: string) => (message: string, attributes: Record<string, unknown>) => { entries.push({ level, message, attributes }); };
  return {
    logger: { debug: at('debug'), info: at('info'), warn: at('warn'), error: at('error') },
    entries,
    withEventId: (id) => entries.filter((e) => e.attributes['event.id'] === id),
  };
}

/** Formats values as "enc::v<version>::<base64>", like the dek package's DefaultFormatProvider. */
export class TestFormatProvider implements EncryptedFormatProvider {
  format(value: KeyTrackingValue): string {
    return `enc::v${value.keyVersion}::${Buffer.from(value.value).toString('base64')}`;
  }

  parse(encrypted: string): KeyTrackingValue {
    const match = /^enc::v(-?\d+)::([A-Za-z0-9+/=]*)$/.exec(encrypted);
    if (match === null) {
      throw new Error('malformed value');
    }
    return { keyVersion: Number(match[1]), value: new Uint8Array(Buffer.from(match[2]!, 'base64')) };
  }

  maxDecryptedLength(encrypted: string): number {
    return this.parse(encrypted).value.length;
  }
}

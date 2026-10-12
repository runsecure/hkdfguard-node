import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { InvalidArgumentError, InvalidServiceNameError, isZero, type KeyWrapper } from '@runsecure/hkdfguard-abstractions';
import { NotInstalledError, StatusError, UnsupportedPlatformError, UntrustedError } from './errors.js';
import { hostLibrary, swapLoaderForTesting } from './host.js';
import { NO_HARDENING, type KmsLibrary } from './library.js';
import { linuxStatusDescriptions, macStatusDescriptions, windowsStatusDescriptions } from './status.js';
import { DEK_LENGTH, hardenProcess, NativeKeyWrapperV1 } from './wrapper.js';

/** A KmsLibrary that records its calls and answers as configured. */
class FakeLibrary implements KmsLibrary {
  wrapStatus = 0; unwrapStatus = 0; generateStatus = 0;
  writtenOverride: number | undefined;
  wrapPayload: Uint8Array | undefined; unwrapPayload: Uint8Array | undefined; generatePayload: Uint8Array | undefined;
  scribbleOnFailure = false;
  calls: { op: string; service: string; input?: Uint8Array }[] = [];
  describe: (status: number) => string | undefined = () => undefined;
  harden: (() => number) | undefined;

  private emit(status: number, payload: Uint8Array, output: Uint8Array): [number, number] {
    if (status !== 0) return [status, 0];
    output.set(payload.subarray(0, output.length));
    return [0, this.writtenOverride ?? Math.min(payload.length, output.length)];
  }

  async wrapDek(service: string, dek: Uint8Array, output: Uint8Array): Promise<[number, number]> {
    this.calls.push({ op: 'wrap', service, input: Uint8Array.from(dek) });
    return this.emit(this.wrapStatus, this.wrapPayload ?? dek, output);
  }

  async unwrapDek(service: string, wrapped: Uint8Array, output: Uint8Array): Promise<[number, number]> {
    this.calls.push({ op: 'unwrap', service, input: Uint8Array.from(wrapped) });
    if (this.unwrapStatus !== 0 && this.scribbleOnFailure) output.fill(0xff);
    return this.emit(this.unwrapStatus, this.unwrapPayload ?? wrapped, output);
  }

  async generateAndWrapDek(service: string, output: Uint8Array): Promise<[number, number]> {
    this.calls.push({ op: 'generate', service });
    return this.emit(this.generateStatus, this.generatePayload ?? new Uint8Array(64), output);
  }

  describeStatus(status: number): string | undefined {
    return this.describe(status);
  }

  hardenProcess(): number {
    if (this.harden === undefined) throw new UnsupportedPlatformError(NO_HARDENING);
    return this.harden();
  }
}

const wrapper = (service: string, library: FakeLibrary) => NativeKeyWrapperV1.withLibrary(service, library);

describe('NativeKeyWrapperV1', () => {
  it('is a KeyWrapper', () => {
    const w: KeyWrapper = wrapper('test.service', new FakeLibrary());
    assert.ok(w);
  });

  it('delegates wrap, unwrap and generate-and-wrap to the library', async () => {
    const library = new FakeLibrary();
    library.wrapPayload = new Uint8Array([10, 20, 30, 40]);
    library.unwrapPayload = new Uint8Array([1, 2, 3, 4, 5]);
    library.generatePayload = new Uint8Array([11, 22, 33, 44, 55]);
    const w = wrapper('service.a', library);

    const wrapped = new Uint8Array(16);
    assert.equal(await w.wrap(new Uint8Array([1, 2, 3, 4, 5]), wrapped), 4);
    assert.deepEqual(wrapped.subarray(0, 4), new Uint8Array([10, 20, 30, 40]));
    const unwrapped = new Uint8Array(16);
    assert.equal(await w.unwrap(new Uint8Array([10, 20, 30, 40]), unwrapped), 5);
    assert.deepEqual(unwrapped.subarray(0, 5), new Uint8Array([1, 2, 3, 4, 5]));
    const generated = new Uint8Array(16);
    assert.equal(await w.generateAndWrap(generated), 5);
    assert.deepEqual(library.calls.map((c) => [c.op, c.service]), [['wrap', 'service.a'], ['unwrap', 'service.a'], ['generate', 'service.a']]);
  });

  it('reports a failure as a StatusError naming the operation, service and status', async () => {
    const operations: [string, (w: NativeKeyWrapperV1) => Promise<number>, (l: FakeLibrary, s: number) => void][] = [
      ['wrap', (w) => w.wrap(new Uint8Array(3), new Uint8Array(8)), (l, s) => { l.wrapStatus = s; }],
      ['unwrap', (w) => w.unwrap(new Uint8Array(3), new Uint8Array(8)), (l, s) => { l.unwrapStatus = s; }],
      ['generate-and-wrap', (w) => w.generateAndWrap(new Uint8Array(16)), (l, s) => { l.generateStatus = s; }],
    ];
    for (const [op, call, set] of operations) {
      for (const status of [-1, -2, -7]) {
        const library = new FakeLibrary();
        set(library, status);
        await assert.rejects(call(wrapper('service.d', library)), (e: unknown) =>
          e instanceof StatusError && e.status === status && e.operation === op
          && e.message === `Native KMS ${op} failed for service 'service.d' with status ${status}.`);
      }
    }
  });

  it('names what a status means when the library can say', async () => {
    const library = new FakeLibrary();
    library.unwrapStatus = -13;
    library.describe = (s) => (s === -13 ? 'this account is not authorized to use the KEK' : undefined);
    await assert.rejects(wrapper('service.d', library).unwrap(new Uint8Array(1), new Uint8Array(32)),
      { message: "Native KMS unwrap failed for service 'service.d' with status -13 (this account is not authorized to use the KEK)." });
  });

  it('zeroes the result of a failed unwrap', async () => {
    const library = new FakeLibrary();
    library.unwrapStatus = -6;
    library.scribbleOnFailure = true;
    const result = new Uint8Array(8).fill(0xab);
    await assert.rejects(wrapper('service.d', library).unwrap(new Uint8Array(3), result));
    assert.ok(isZero(result));
  });

  it('refuses a success claiming more bytes than the buffer holds', async () => {
    for (const written of [-1, 17]) {
      const library = new FakeLibrary();
      library.writtenOverride = written;
      const result = new Uint8Array(16).fill(0xab);
      await assert.rejects(wrapper('service.a', library).wrap(new Uint8Array(32), result), InvalidArgumentError);
      await assert.rejects(wrapper('service.a', library).unwrap(new Uint8Array(32), result), InvalidArgumentError);
      assert.ok(isZero(result));
    }
  });

  it('never reaches the library with an aborted signal', async () => {
    const library = new FakeLibrary();
    const w = wrapper('service.g', library);
    const signal = AbortSignal.abort();
    await assert.rejects(w.wrap(new Uint8Array(32), new Uint8Array(64), signal));
    await assert.rejects(w.unwrap(new Uint8Array(64), new Uint8Array(32), signal));
    await assert.rejects(w.generateAndWrap(new Uint8Array(64), signal));
    assert.equal(library.calls.length, 0);
  });

  it('rejects an invalid service name before any native call or load', () => {
    for (const name of ['', '.service', 'my..service', 'my-service', 'a'.repeat(129)]) {
      const library = new FakeLibrary();
      assert.throws(() => wrapper(name, library), InvalidServiceNameError);
      assert.throws(() => NativeKeyWrapperV1.create(name), InvalidServiceNameError);
      assert.equal(library.calls.length, 0);
    }
    assert.equal(DEK_LENGTH, 32);
  });
});

describe('hardenProcess', () => {
  it('succeeds when the library reports 0', () => {
    const library = new FakeLibrary();
    let calls = 0;
    library.harden = () => { calls++; return 0; };
    hardenProcess(library);
    assert.equal(calls, 1);
  });

  it('names a failure and its meaning, or just the status', () => {
    const library = new FakeLibrary();
    library.harden = () => -17;
    library.describe = () => 'could not disable core dumps';
    assert.throws(() => hardenProcess(library), { message: 'Native process hardening failed with status -17 (could not disable core dumps).' });
    const unknown = new FakeLibrary();
    unknown.harden = () => -99;
    assert.throws(() => hardenProcess(unknown), (e: unknown) => e instanceof StatusError && e.message.endsWith('status -99.'));
  });

  it('is unsupported where the library has no hardening call', () => {
    assert.throws(() => hardenProcess(new FakeLibrary()), (e: unknown) => e instanceof UnsupportedPlatformError && e.message.includes('Linux'));
  });
});

describe('hostLibrary', () => {
  it('loads once and returns the same binding every time', () => {
    let loads = 0;
    const library = new FakeLibrary();
    const restore = swapLoaderForTesting(() => { loads++; return library; });
    try {
      assert.equal(hostLibrary(), library);
      assert.equal(hostLibrary(), library);
      assert.equal(loads, 1);
    } finally {
      restore();
    }
  });

  it('does not cache a failure, and classifies an unexpected one as untrusted', () => {
    let attempts = 0;
    const library = new FakeLibrary();
    let restore = swapLoaderForTesting(() => {
      if (++attempts === 1) throw new NotInstalledError('not yet');
      return library;
    });
    try {
      assert.throws(() => hostLibrary(), NotInstalledError);
      assert.equal(hostLibrary(), library);
    } finally {
      restore();
    }

    const cause = new Error("lstat('/usr') failed with errno 13");
    restore = swapLoaderForTesting(() => { throw cause; });
    try {
      assert.throws(() => hostLibrary(), (e: unknown) => e instanceof UntrustedError && e.cause === cause);
      assert.throws(() => NativeKeyWrapperV1.create('test.service'), UntrustedError);
    } finally {
      restore();
    }
  });
});

describe('status tables', () => {
  const described = (table: ReadonlyMap<number, string>, statuses: number[]) => statuses.every((s) => (table.get(s) ?? '') !== '');
  const undescribed = (table: ReadonlyMap<number, string>, statuses: number[]) => statuses.every((s) => !table.has(s));

  it('describe every Windows status, and nothing else', () => {
    assert.ok(described(windowsStatusDescriptions, Array.from({ length: 14 }, (_, i) => -1 - i)));
    assert.ok(undescribed(windowsStatusDescriptions, [-15, 1]));
    assert.ok(/not authorized/.test(windowsStatusDescriptions.get(-13)!) && /HkdfGuardUsers/.test(windowsStatusDescriptions.get(-13)!));
  });

  it('describe every macOS status returned, but not the reserved ones', () => {
    assert.ok(described(macStatusDescriptions, [-1, -2, -5, -6, -7, -8, -9, -10, -11, -12, -13, -14, -15, -16, -17, -18]));
    assert.ok(undescribed(macStatusDescriptions, [-3, -4, -19]));
  });

  it('describe every Linux status returned, but not the reserved or unassigned ones', () => {
    assert.ok(described(linuxStatusDescriptions, [-1, -2, -3, -4, -5, -6, -8, -9, -16, -17]));
    assert.ok(undescribed(linuxStatusDescriptions, [-7, -10, -11, -12, -13, -14, -15, -18, 1]));
    assert.ok(linuxStatusDescriptions.get(-9)!.includes('provision') && linuxStatusDescriptions.get(-16)!.includes('different KEK'));
  });
});

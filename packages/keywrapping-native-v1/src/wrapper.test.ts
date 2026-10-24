import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { InvalidArgumentError, InvalidServiceNameError, isZero, MAX_WRAPPED_KEY_BYTES, type KeyWrapper } from '@runsecure/hkdfguard-abstractions';
import { KeyFileRefusedError, NotInstalledError, StatusError, UntrustedError } from './errors.js';
import { hostLibrary, swapLoaderForTesting } from './host.js';
import { HARDEN_REQUIRE_PROTECTED_SIGNATURE, NativeKmsLibrary, openKeyFile, type KmsLibrary } from './library.js';
import type { LibraryHandle, NativeAddon } from './native.js';
import {
  linuxStatusDescriptions, macStatusDescriptions, sharedStatusDescriptions, Status, windowsStatusDescriptions, WRAPPED_DEK_LENGTHS,
} from './status.js';
import { DEK_LENGTH, hardenProcess, hardenProcessForTests, NativeKeyWrapperV1, wrapperForTests } from './wrapper.js';

/** A KmsLibrary that records its calls and answers as configured. */
class FakeLibrary implements KmsLibrary {
  wrapStatus = 0; unwrapStatus = 0; generateStatus = 0; openStatus = 0;
  /** What hkdfguard_open_file "reads"; openRead overrides the count it reports. */
  fileContents: Uint8Array = new Uint8Array(132).fill(0x5a);
  openRead: number | undefined;
  openCapacities: number[] = [];
  writtenOverride: number | undefined;
  wrapPayload: Uint8Array | undefined; unwrapPayload: Uint8Array | undefined; generatePayload: Uint8Array | undefined;
  scribbleOnFailure = false;
  calls: { op: string; service: string; input?: Uint8Array }[] = [];
  describe: (status: number) => string | undefined = () => undefined;
  /** Answers hardenProcess; it succeeds when unset. */
  harden: ((flags: number) => number) | undefined;
  hardenFlags: number[] = [];

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

  async openFile(path: string, output: Uint8Array): Promise<[number, number]> {
    this.calls.push({ op: 'open', service: path });
    this.openCapacities.push(output.length);
    if (this.openStatus !== 0) return [this.openStatus, 0];
    output.set(this.fileContents.subarray(0, output.length));
    return [0, this.openRead ?? this.fileContents.length];
  }

  describeStatus(status: number): string | undefined {
    return this.describe(status);
  }

  hardenProcess(flags: number): number {
    this.hardenFlags.push(flags);
    return this.harden === undefined ? 0 : this.harden(flags);
  }
}

const wrapper = (service: string, library: FakeLibrary) => wrapperForTests(service, library);

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
  it('succeeds when the library reports 0, passing no flags by default', () => {
    const library = new FakeLibrary();
    hardenProcessForTests(undefined, library);
    hardenProcessForTests({}, library);
    hardenProcessForTests({ requireProtectedSignature: false }, library);
    hardenProcessForTests({ requireProtectedSignature: undefined }, library);
    assert.deepEqual(library.hardenFlags, [0, 0, 0, 0]);
  });

  it('passes the native flag for requireProtectedSignature', () => {
    const library = new FakeLibrary();
    hardenProcessForTests({ requireProtectedSignature: true }, library);
    assert.deepEqual(library.hardenFlags, [HARDEN_REQUIRE_PROTECTED_SIGNATURE]);
    assert.equal(HARDEN_REQUIRE_PROTECTED_SIGNATURE, 0x1); // HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE, the same bit on every platform
  });

  it('refuses an unknown or invalid option before loading or calling the native library', () => {
    let loads = 0;
    const restore = swapLoaderForTesting(() => { loads++; return new FakeLibrary(); });
    try {
      const library = new FakeLibrary();
      const invalid: unknown[] = [
        { requireProtectedSignatures: true }, { requireProtectedSignature: true, strict: true }, { requireProtectedSignature: 'yes' },
        { requireProtectedSignature: 1 }, { requireProtectedSignature: null }, null, [], 1, 'strict', true,
      ];
      for (const options of invalid) {
        assert.throws(() => hardenProcessForTests(options as never, library), InvalidArgumentError, JSON.stringify(options));
        assert.throws(() => hardenProcess(options as never), InvalidArgumentError, JSON.stringify(options));
      }
      assert.throws(() => hardenProcess({ strict: true } as never), { message: "Unknown process hardening option 'strict'." });
      assert.deepEqual(library.hardenFlags, []);
      assert.equal(loads, 0);
    } finally {
      restore();
    }
  });

  it('loads the host library when none is given', () => {
    const library = new FakeLibrary();
    const restore = swapLoaderForTesting(() => library);
    try {
      hardenProcess();
      hardenProcess({ requireProtectedSignature: true });
      assert.deepEqual(library.hardenFlags, [0, HARDEN_REQUIRE_PROTECTED_SIGNATURE]);
    } finally {
      restore();
    }
  });

  it('names a failure and its meaning, or just the status', () => {
    const library = new FakeLibrary();
    library.harden = () => -20;
    library.describe = () => 'process hardening failed';
    assert.throws(() => hardenProcessForTests({}, library), (e: unknown) => e instanceof StatusError && e.status === Status.processHardeningFailed
      && e.operation === 'process hardening' && e.service === undefined
      && e.message === 'Native process hardening failed with status -20 (process hardening failed).');
    const unknown = new FakeLibrary();
    unknown.harden = () => -99;
    assert.throws(() => hardenProcessForTests({ requireProtectedSignature: true }, unknown), (e: unknown) => e instanceof StatusError && e.message.endsWith('status -99.'));
  });

  it("describes a hardening failure in each platform's own terms", () => {
    for (const [table, hint] of [[windowsStatusDescriptions, 'access lists'], [linuxStatusDescriptions, 'ptrace'], [macStatusDescriptions, 'Hardened Runtime']] as const) {
      assert.ok(table.get(Status.processHardeningFailed)!.includes(hint), hint);
    }
  });
});

describe('NativeKmsLibrary', () => {
  /** An add-on whose library exports everything but `missing`, recording hardenProcess calls. */
  function fakeAddon(missing?: string): { addon: NativeAddon; hardenCalls: number[] } {
    const hardenCalls: number[] = [];
    const addon = {
      bind: () => (missing === undefined ? [] : [missing]),
      hardenProcess: (_library: LibraryHandle, flags: number) => { hardenCalls.push(flags); return flags === 0 ? 0 : Status.processHardeningFailed; },
    } as unknown as NativeAddon;
    return { addon, hardenCalls };
  }
  const handle = {} as LibraryHandle;

  it('requires hkdfguard_harden_process_with_flags like every other export', () => {
    const { addon } = fakeAddon('hkdfguard_harden_process_with_flags');
    assert.throws(() => NativeKmsLibrary.bind(addon, handle, '/lib/x', linuxStatusDescriptions),
      (e: unknown) => e instanceof UntrustedError && e.message.includes("no 'hkdfguard_harden_process_with_flags' export"));
  });

  it('passes the flags through and returns the status', () => {
    const { addon, hardenCalls } = fakeAddon();
    const library = NativeKmsLibrary.bind(addon, handle, '/lib/x', windowsStatusDescriptions);
    assert.equal(library.hardenProcess(0), 0);
    assert.equal(library.hardenProcess(HARDEN_REQUIRE_PROTECTED_SIGNATURE), Status.processHardeningFailed);
    assert.deepEqual(hardenCalls, [0, 1]);
    assert.throws(() => hardenProcessForTests({ requireProtectedSignature: true }, library), { message: /status -20 \(process hardening failed: .*access lists/ });
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

describe('status codes', () => {
  // HKDFGUARD_OK and HKDFGUARD_ERR_*, as every platform's hkdfguard.h defines them.
  const header: Record<keyof typeof Status, number> = {
    ok: 0, invalidArgument: -1, bufferTooSmall: -2, providerUnavailable: -3, providerError: -4, cryptoError: -5, internalError: -6,
    invalidServiceName: -8, policyInvalid: -9, payloadMalformed: -10, payloadAuthFailed: -11, payloadUnsupported: -12,
    kekFingerprintMismatch: -16, kekNotFound: -17, kekAccessDenied: -18, kekInvalid: -19, processHardeningFailed: -20,
    fileNotFound: -32, fileAccessDenied: -33, fileIo: -34, fileTooShort: -35, fileTooLong: -36, filePlaintextKey: -37, fileMalformed: -38, fileUntrusted: -39,
    winGroupInvalid: -64,
    macAccessControlCreationFailed: -96, macKeyGenerationFailed: -97, macKeychainWriteFailed: -98, macKekVerificationFailed: -99, macKeychainReadFailed: -100,
  };
  const defined = Object.values(header).filter((s) => s !== 0);
  const reserved = [-7, -13, -14, -15, ...Array.from({ length: 11 }, (_, i) => -21 - i), ...Array.from({ length: 24 }, (_, i) => -40 - i),
    -65, -79, -80, -95, -101, -111, -112, 0, 1, -1000];
  const tables: [string, ReadonlyMap<number, string>][] = [
    ['shared', sharedStatusDescriptions], ['Windows', windowsStatusDescriptions], ['Linux', linuxStatusDescriptions], ['macOS', macStatusDescriptions],
  ];

  it('are the header values', () => {
    assert.deepEqual({ ...Status }, header);
    assert.deepEqual(WRAPPED_DEK_LENGTHS, { win32: 132, linux: 276, darwin: 125 });
    for (const length of Object.values(WRAPPED_DEK_LENGTHS)) assert.ok(length <= MAX_WRAPPED_KEY_BYTES);
  });

  it('are each described on every platform, and no reserved code is', () => {
    for (const [name, table] of tables) {
      for (const status of defined) assert.ok((table.get(status) ?? '') !== '', `${name} ${status}`);
      for (const status of reserved) assert.equal(table.get(status), undefined, `${name} ${status}`);
      assert.equal(table.size, defined.length, name);
    }
  });

  it('share their meanings, each platform adding only its own hints', () => {
    const hinted = (table: ReadonlyMap<number, string>) => defined.filter((s) => table.get(s) !== sharedStatusDescriptions.get(s));
    assert.deepEqual(hinted(windowsStatusDescriptions), [Status.providerError, Status.policyInvalid, Status.kekNotFound, Status.kekAccessDenied, Status.kekInvalid, Status.processHardeningFailed]);
    assert.deepEqual(hinted(linuxStatusDescriptions), [Status.providerUnavailable, Status.providerError, Status.policyInvalid, Status.kekFingerprintMismatch, Status.processHardeningFailed]);
    assert.deepEqual(hinted(macStatusDescriptions), [Status.providerUnavailable, Status.payloadAuthFailed, Status.kekNotFound, Status.kekAccessDenied, Status.kekInvalid, Status.processHardeningFailed]);

    const kekAccessDenied = windowsStatusDescriptions.get(Status.kekAccessDenied)!;
    assert.ok(kekAccessDenied.includes('not authorized') && kekAccessDenied.includes('HkdfGuardUsers') && kekAccessDenied.includes('KeyUseGroups'));
    assert.ok(windowsStatusDescriptions.get(Status.policyInvalid)!.includes('HKLM\\Software\\Policies\\HkdfGuard'));
    assert.ok(windowsStatusDescriptions.get(Status.kekNotFound)!.includes('run hkdfguard provision'));
    assert.ok(linuxStatusDescriptions.get(Status.policyInvalid)!.includes('/etc/hkdfguard/policy.toml'));
    assert.ok(linuxStatusDescriptions.get(Status.kekNotFound)!.includes('run hkdfguard provision'));
    assert.ok(linuxStatusDescriptions.get(Status.kekFingerprintMismatch)!.includes('different KEK'));
    assert.ok(macStatusDescriptions.get(Status.kekAccessDenied)!.includes('keychain'));
    assert.ok(macStatusDescriptions.get(Status.providerUnavailable)!.includes('Secure Enclave'));
    assert.ok(macStatusDescriptions.get(Status.kekNotFound)!.includes('hkdfguard provision'));
    assert.ok(sharedStatusDescriptions.get(Status.filePlaintextKey)!.includes('UNWRAPPED'));
  });
});

describe('openKeyFile and readKeyFile', () => {
  it('return exactly the bytes the library read, from a MAX_WRAPPED_KEY_BYTES buffer', async () => {
    const library = new FakeLibrary();
    library.fileContents = Uint8Array.from({ length: 132 }, (_, i) => i);
    const bytes = await openKeyFile(library, 'C:\\keys\\v1.bin');
    assert.deepEqual(bytes, library.fileContents);
    assert.deepEqual(library.openCapacities, [MAX_WRAPPED_KEY_BYTES]);
    assert.deepEqual(library.calls, [{ op: 'open', service: 'C:\\keys\\v1.bin' }]);
  });

  it('map each refusal to an fs-style code, naming the path, status and meaning', async () => {
    const expected: [number, string][] = [
      [Status.fileNotFound, 'ENOENT'], [Status.fileAccessDenied, 'EACCES'], [Status.fileUntrusted, 'EACCES'],
      [Status.fileIo, 'EIO'], [Status.fileTooShort, 'ERR_HKDFGUARD_INVALID_KEY_FILE'], [Status.fileTooLong, 'ERR_HKDFGUARD_INVALID_KEY_FILE'],
      [Status.filePlaintextKey, 'ERR_HKDFGUARD_INVALID_KEY_FILE'], [Status.fileMalformed, 'ERR_HKDFGUARD_INVALID_KEY_FILE'],
      [Status.invalidArgument, 'ERR_HKDFGUARD_INVALID_ARGUMENT'], [Status.internalError, 'EIO'], [-7, 'EIO'],
    ];
    for (const [status, code] of expected) {
      const library = new FakeLibrary();
      library.openStatus = status;
      library.describe = (s) => windowsStatusDescriptions.get(s);
      const description = windowsStatusDescriptions.get(status) ?? 'unknown status';
      await assert.rejects(openKeyFile(library, '/keys/v1.bin'), (e: unknown) =>
        e instanceof KeyFileRefusedError && e.code === code && e.status === status && e.path === '/keys/v1.bin'
        && e.description === windowsStatusDescriptions.get(status)
        && e.message === `Key file '/keys/v1.bin' was refused by the native library with status ${status} (${description}).`, String(status));
    }
  });

  it('refuse a success claiming an impossible byte count', async () => {
    for (const read of [0, -1, MAX_WRAPPED_KEY_BYTES + 1]) {
      const library = new FakeLibrary();
      library.openRead = read;
      await assert.rejects(openKeyFile(library, 'k'), InvalidArgumentError, String(read));
    }
  });

  it('never reach the library with an empty path', async () => {
    const library = new FakeLibrary();
    await assert.rejects(openKeyFile(library, ''), InvalidArgumentError);
    await assert.rejects(wrapper('service.k', library).readKeyFile(''), InvalidArgumentError);
    assert.equal(library.calls.length, 0);
  });

  it('readKeyFile delegates to the library, surfacing its refusal', async () => {
    const library = new FakeLibrary();
    library.fileContents = new Uint8Array(132).fill(9);
    const w: KeyWrapper = wrapper('service.k', library);
    assert.deepEqual(await w.readKeyFile!('key.bin'), library.fileContents);
    library.openStatus = Status.filePlaintextKey;
    library.describe = (s) => sharedStatusDescriptions.get(s);
    await assert.rejects(w.readKeyFile!('key.bin'), (e: unknown) => e instanceof KeyFileRefusedError && e.status === Status.filePlaintextKey && /UNWRAPPED/.test(e.message));
    await assert.rejects(w.readKeyFile!('key.bin', AbortSignal.abort()));
    assert.deepEqual(library.calls.map((c) => [c.op, c.service]), [['open', 'key.bin'], ['open', 'key.bin']]);
  });
});

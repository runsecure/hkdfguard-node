import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { after, afterEach, beforeEach, describe, it } from 'node:test';
import {
  ClosedError, EncryptionLimitReachedError, InvalidArgumentError, isZero, KeyAccessSuspendedError, RefreshFailurePolicy,
  type CryptoProvider, type CryptoProviderFactory,
} from '@runsecure/hkdfguard-abstractions';
import { EventNames, SpanNames } from '@runsecure/hkdfguard-diagnostics';
import { capturingLogger, FakeKeyWrapper, useSpanRecorder } from '@runsecure/hkdfguard-test-support';
import { AesGcmCryptoProvider, AesGcmCryptoProviderFactory, createProviderForTests, type AesGcmProviderOptions } from './provider.js';
import { EncryptionBudget, OVERHEAD } from './session.js';

const utf8 = (s: string) => new TextEncoder().encode(s);
const kekDown = new Error('KEK unavailable');
const open: AesGcmCryptoProvider[] = [];
after(async () => { await Promise.all(open.map((p) => p.close())); });

async function manual(wrapper: FakeKeyWrapper, options: Partial<AesGcmProviderOptions> = {}, budget?: EncryptionBudget): Promise<AesGcmCryptoProvider> {
  const provider = await createProviderForTests(wrapper, utf8('wrapped'), { expirySeconds: 60, ...options }, { budget, manualRefresh: true });
  open.push(provider);
  return provider;
}

function encrypt(provider: CryptoProvider, plaintext: string, aad?: Uint8Array): Uint8Array {
  const result = new Uint8Array(provider.encryptedAllocationLength(utf8(plaintext).length));
  provider.encrypt(utf8(plaintext), result, aad);
  return result;
}

function decrypt(provider: CryptoProvider, ciphertext: Uint8Array, aad?: Uint8Array): string {
  const result = new Uint8Array(provider.decryptedAllocationLength(ciphertext.length));
  return new TextDecoder().decode(result.subarray(0, provider.decrypt(ciphertext, result, aad)));
}

describe('AesGcmCryptoProvider.create', () => {
  it('reveals the key once, eagerly', async () => {
    const wrapper = new FakeKeyWrapper();
    await manual(wrapper);
    assert.equal(wrapper.unwrapCalls, 1);
  });

  it("reports the key wrapper's error", async () => {
    const wrapper = new FakeKeyWrapper();
    wrapper.unwrapError = kekDown;
    await assert.rejects(manual(wrapper), kekDown);
  });

  it('refuses bad arguments or an aborted signal without calling the key wrapper', async () => {
    const aborted = AbortSignal.abort();
    for (const options of [{ expirySeconds: 0 }, { expirySeconds: 301 }, { expirySeconds: 1.5 }, { signal: aborted }]) {
      const wrapper = new FakeKeyWrapper();
      await assert.rejects(manual(wrapper, options));
      assert.equal(wrapper.unwrapCalls, 0);
    }
  });

  it('refuses a wrong-length key rather than using it', async () => {
    for (const n of [0, 16, 31, 33]) {
      const wrapper = new FakeKeyWrapper();
      wrapper.writtenOverride = n;
      await assert.rejects(manual(wrapper), (e: unknown) => e instanceof InvalidArgumentError && e.message.includes(`revealed ${n} bytes`));
    }
  });
});

describe('AesGcmCryptoProvider', () => {
  it('computes allocation lengths', async () => {
    const provider = await manual(new FakeKeyWrapper());
    assert.equal(provider.encryptedAllocationLength(10), 38);
    assert.equal(provider.decryptedAllocationLength(38), 10);
    for (const n of [0, 27, 28]) assert.equal(provider.decryptedAllocationLength(n), 0);
    assert.equal(OVERHEAD, 28);
  });

  it('refreshes by revealing the key again, and decrypts across the swap', async () => {
    const wrapper = new FakeKeyWrapper(new Uint8Array(randomBytes(32)));
    const provider = await manual(wrapper);
    const ciphertext = encrypt(provider, 'before');
    await provider.refresh();
    assert.equal(wrapper.unwrapCalls, 2);
    assert.equal(decrypt(provider, ciphertext), 'before');
  });

  it('refreshes on its own timer, which does not keep the process alive', async () => {
    const wrapper = new FakeKeyWrapper();
    const provider = await AesGcmCryptoProvider.create(wrapper, utf8('wrapped'), { expirySeconds: 1 });
    open.push(provider);
    await new Promise((resolve) => setTimeout(resolve, 1300));
    assert.ok(wrapper.unwrapCalls >= 2);
  });

  it('records a failed refresh on its span, keeping the current key', async () => {
    const recorder = useSpanRecorder();
    try {
      const wrapper = new FakeKeyWrapper(new Uint8Array(randomBytes(32)));
      const provider = await manual(wrapper);
      const ciphertext = encrypt(provider, 'still works');
      wrapper.unwrapError = kekDown;
      await provider.refresh();
      wrapper.unwrapError = undefined;
      wrapper.writtenOverride = 16;
      await provider.refresh();

      const failed = recorder.spans().filter((s) => s.name === SpanNames.cryptoProviderAesGcm256.backgroundRefresh && s.status.code === 2);
      assert.equal(failed.length, 2);
      assert.ok(failed[1]!.status.message?.includes('revealed 16 bytes'));
      assert.equal(decrypt(provider, ciphertext), 'still works');
    } finally {
      await recorder.dispose();
    }
  });

  it('close stops refreshing, zeroes the wrapped key, and fails later operations', async () => {
    const wrapper = new FakeKeyWrapper();
    const wrapped = utf8('wrapped payload');
    const provider = await AesGcmCryptoProvider.create(wrapper, wrapped, { expirySeconds: 1 });
    await provider.close();
    await provider.close();
    await new Promise((resolve) => setTimeout(resolve, 1200));
    assert.equal(wrapper.unwrapCalls, 1);
    assert.ok(isZero(wrapped));
    assert.throws(() => provider.encrypt(utf8('x'), new Uint8Array(64)), ClosedError);
    assert.throws(() => provider.decrypt(new Uint8Array(64), new Uint8Array(64)), ClosedError);
    assert.ok(!provider.keyAccessSuspended);
  });

  it('close during an in-flight refresh cancels it and logs nothing', async () => {
    const { logger, entries } = capturingLogger();
    let started!: () => void;
    const refreshStarted = new Promise<void>((resolve) => { started = resolve; });
    let calls = 0;
    const wrapper = {
      wrap: async () => 0,
      generateAndWrap: async () => 0,
      readKeyFile: async () => new Uint8Array(0),
      unwrap: async (_w: Uint8Array, result: Uint8Array, signal?: AbortSignal) => {
        if (++calls === 1) { result.set(randomBytes(32)); return 32; }
        started();
        await new Promise((_, reject) => signal?.addEventListener('abort', () => reject(new Error('KMS connection closed during shutdown'))));
        return 0;
      },
    };
    const provider = await createProviderForTests(wrapper, utf8('wrapped'), { expirySeconds: 60, logger }, { manualRefresh: true });
    const refresh = provider.refresh();
    await refreshStarted;
    await provider.close();
    await refresh;
    assert.equal(entries.length, 0);
  });

  it('refuses to encrypt past the limit, while decryption still works', async () => {
    const provider = await manual(new FakeKeyWrapper(new Uint8Array(randomBytes(32))), {}, new EncryptionBudget(1, 2));
    const ciphertext = encrypt(provider, 'value');
    encrypt(provider, 'value');
    assert.throws(() => encrypt(provider, 'value'), (e: unknown) => e instanceof EncryptionLimitReachedError && e.message.includes('must be rotated'));
    assert.equal(provider.encryptionCount, 2);
    assert.equal(decrypt(provider, ciphertext), 'value');
  });

  it('keeps the count across a refresh, since the key is the same', async () => {
    const provider = await manual(new FakeKeyWrapper(new Uint8Array(randomBytes(32))), {}, new EncryptionBudget(1, 4));
    encrypt(provider, 'one');
    encrypt(provider, 'two');
    await provider.refresh();
    encrypt(provider, 'three');
    encrypt(provider, 'four');
    assert.equal(provider.encryptionCount, 4);
    assert.throws(() => encrypt(provider, 'five'), EncryptionLimitReachedError);
  });

  it('raises one span event and one log warning at the warning threshold', async () => {
    const recorder = useSpanRecorder();
    const { logger, withEventId } = capturingLogger();
    try {
      const provider = await manual(new FakeKeyWrapper(new Uint8Array(randomBytes(32))), { logger }, new EncryptionBudget(2, 10));
      for (let i = 0; i < 4; i++) encrypt(provider, 'value');
      const events = recorder.spans().flatMap((s) => s.events).filter((e) => e.name === EventNames.encryptionBudgetWarning);
      assert.equal(events.length, 1);
      assert.equal(withEventId(10).length, 1);
      assert.ok(withEventId(10)[0]!.message.includes('2 encryptions of its 10'));
    } finally {
      await recorder.dispose();
    }
  });

  it('shares one count between providers revealing the same key, which outlives them', async () => {
    const key = new Uint8Array(randomBytes(32));
    const first = await manual(new FakeKeyWrapper(key));
    const second = await manual(new FakeKeyWrapper(key));
    const other = await manual(new FakeKeyWrapper(new Uint8Array(randomBytes(32))));
    encrypt(first, 'one');
    encrypt(second, 'two');
    encrypt(second, 'three');
    assert.deepEqual([first.encryptionCount, second.encryptionCount, other.encryptionCount], [3, 3, 0]);
    await first.close();
    await second.close();
    assert.equal((await manual(new FakeKeyWrapper(key))).encryptionCount, 3);
  });

  it('defaults to failing closed after three failures', async () => {
    assert.equal((await manual(new FakeKeyWrapper())).refreshFailurePolicy.maxFailures, 3);
  });
});

describe('refresh-failure policy', () => {
  it('fails closed after the configured failures, until a refresh succeeds', async () => {
    const recorder = useSpanRecorder();
    const { logger, withEventId } = capturingLogger();
    try {
      const wrapper = new FakeKeyWrapper(new Uint8Array(randomBytes(32)));
      const provider = await manual(wrapper, { logger, refreshFailurePolicy: RefreshFailurePolicy.failClosedAfter(2) });
      const ciphertext = encrypt(provider, 'survives');

      wrapper.unwrapError = kekDown;
      await provider.refresh();
      assert.ok(!provider.keyAccessSuspended);
      await provider.refresh();
      assert.ok(provider.keyAccessSuspended);

      const plaintext = utf8('x');
      assert.throws(() => provider.encrypt(plaintext, new Uint8Array(64)), KeyAccessSuspendedError);
      assert.ok(isZero(plaintext));
      assert.throws(() => decrypt(provider, ciphertext), KeyAccessSuspendedError);
      assert.equal(withEventId(3).length, 2);
      assert.ok(withEventId(3)[1]!.message.includes('fail closed after 2 consecutive failures'));
      assert.equal(withEventId(4).length, 1);
      assert.equal(recorder.spans().flatMap((s) => s.events).filter((e) => e.name === EventNames.keyAccessSuspended).length, 1);

      wrapper.unwrapError = undefined;
      await provider.refresh();
      assert.ok(!provider.keyAccessSuspended);
      assert.equal(decrypt(provider, ciphertext), 'survives');
      assert.equal(withEventId(5).length, 1);
    } finally {
      await recorder.dispose();
    }
  });

  it('counts only consecutive failures', async () => {
    const wrapper = new FakeKeyWrapper(new Uint8Array(randomBytes(32)));
    const provider = await manual(wrapper, { refreshFailurePolicy: RefreshFailurePolicy.failClosedAfter(2) });
    wrapper.unwrapError = kekDown;
    await provider.refresh();
    wrapper.unwrapError = undefined;
    await provider.refresh();
    wrapper.unwrapError = kekDown;
    await provider.refresh();
    assert.ok(!provider.keyAccessSuspended);
  });

  it('fail-open logs every failure but never suspends', async () => {
    const { logger, withEventId } = capturingLogger();
    const wrapper = new FakeKeyWrapper(new Uint8Array(randomBytes(32)));
    const provider = await manual(wrapper, { logger, refreshFailurePolicy: RefreshFailurePolicy.failOpen() });
    wrapper.unwrapError = kekDown;
    for (let i = 0; i < 4; i++) await provider.refresh();
    wrapper.unwrapError = undefined;
    await provider.refresh();
    assert.equal(withEventId(3).length, 4);
    assert.ok(withEventId(3)[1]!.message.includes('(2 consecutive)') && withEventId(3)[0]!.message.includes('fail open'));
    assert.equal(withEventId(4).length + withEventId(5).length, 0);
    assert.ok(!provider.keyAccessSuspended);
    assert.equal(decrypt(provider, encrypt(provider, 'ok')), 'ok');
  });

  it('successful refreshes log nothing', async () => {
    const { logger, entries } = capturingLogger();
    const provider = await manual(new FakeKeyWrapper(), { logger, refreshFailurePolicy: RefreshFailurePolicy.failClosedAfter(1) });
    await provider.refresh();
    await provider.refresh();
    assert.equal(entries.length, 0);
  });

  it('closing while suspended reports closed, not suspended', async () => {
    const wrapper = new FakeKeyWrapper();
    const provider = await manual(wrapper, { refreshFailurePolicy: RefreshFailurePolicy.failClosedAfter(1) });
    wrapper.unwrapError = kekDown;
    await provider.refresh();
    assert.ok(provider.keyAccessSuspended);
    await provider.close();
    assert.ok(!provider.keyAccessSuspended);
    assert.throws(() => encrypt(provider, 'x'), ClosedError);
  });
});

describe('refresh failures the key wrapper or the logger cause', () => {
  // The provider's own timers are unref'd, so a test waiting only on them must hold the event loop open.
  let keepAlive: NodeJS.Timeout;
  beforeEach(() => { keepAlive = setInterval(() => undefined, 1000); });
  afterEach(() => { clearInterval(keepAlive); });

  it('still suspends at the limit when the logger throws', async () => {
    const throwing = { debug: boom, info: boom, warn: boom, error: boom };
    function boom(): never { throw new Error('logging sink is down'); }
    const wrapper = new FakeKeyWrapper(new Uint8Array(randomBytes(32)));
    const provider = await manual(wrapper, { logger: throwing, refreshFailurePolicy: RefreshFailurePolicy.failClosedAfter(2) });

    wrapper.unwrapError = kekDown;
    await provider.refresh();
    await provider.refresh();
    assert.ok(provider.keyAccessSuspended);

    // A throwing "resumed" log can't turn a successful refresh into a failure either.
    wrapper.unwrapError = undefined;
    await provider.refresh();
    assert.ok(!provider.keyAccessSuspended);
  });

  it('counts each timed-out refresh while the key wrapper hangs, without piling up calls', async () => {
    const { logger, withEventId } = capturingLogger();
    const wrapper = new FakeKeyWrapper(new Uint8Array(randomBytes(32)));
    const provider = await createProviderForTests(wrapper, utf8('wrapped'),
      { expirySeconds: 60, logger, refreshFailurePolicy: RefreshFailurePolicy.failClosedAfter(2) },
      { manualRefresh: true, refreshTimeoutMs: 50 });
    open.push(provider);
    const ciphertext = encrypt(provider, 'survives');
    let release!: () => void;
    wrapper.hangUntil = new Promise<void>((resolve) => { release = resolve; });
    const callsBefore = wrapper.unwrapCalls;

    await provider.refresh(); // hangs, times out: failure 1
    assert.ok(!provider.keyAccessSuspended);
    await provider.refresh(); // the abandoned reveal is still running: failure 2, no second call
    assert.ok(provider.keyAccessSuspended);
    assert.equal(wrapper.unwrapCalls, callsBefore + 1);
    assert.equal(withEventId(3).length, 2);

    // The key wrapper recovers: the abandoned call settles, its key discarded, and the next refresh resumes.
    wrapper.hangUntil = undefined;
    release();
    await new Promise((resolve) => setImmediate(resolve));
    await provider.refresh();
    assert.ok(!provider.keyAccessSuspended);
    assert.equal(decrypt(provider, ciphertext), 'survives');
  });

  it('close does not wait for a key wrapper that hangs', async () => {
    const wrapper = new FakeKeyWrapper();
    const provider = await createProviderForTests(wrapper, utf8('wrapped'), { expirySeconds: 60 }, { manualRefresh: true });
    let release!: () => void;
    wrapper.hangUntil = new Promise<void>((resolve) => { release = resolve; });
    void provider.refresh(); // stuck in the key wrapper, for up to a minute

    const started = Date.now();
    await provider.close();
    release();
    assert.ok(Date.now() - started < 500, `close took ${Date.now() - started} ms`);
    assert.throws(() => provider.encrypt(utf8('x'), new Uint8Array(64)), ClosedError);
  });
});

describe('AesGcmCryptoProviderFactory', () => {
  const factory: CryptoProviderFactory = new AesGcmCryptoProviderFactory();

  it('builds working providers, ephemeral ones generating once then revealing once', async () => {
    const created = await factory.create(new FakeKeyWrapper(), utf8('wrapped'), { expirySeconds: 60 });
    const wrapper = new FakeKeyWrapper();
    const ephemeral = await factory.createEphemeral(wrapper, { expirySeconds: 60 });
    try {
      for (const provider of [created, ephemeral]) assert.equal(decrypt(provider, encrypt(provider, 'top secret')), 'top secret');
      assert.deepEqual([wrapper.generateCalls, wrapper.unwrapCalls], [1, 1]);
    } finally {
      await created.close();
      await ephemeral.close();
    }
  });

  it('passes the policy and its logger to every provider', async () => {
    const { logger } = capturingLogger();
    const withLogger = new AesGcmCryptoProviderFactory({ logger });
    const created = await withLogger.create(new FakeKeyWrapper(), utf8('wrapped'), { expirySeconds: 60, refreshFailurePolicy: RefreshFailurePolicy.failClosedAfter(4) }) as AesGcmCryptoProvider;
    const ephemeral = await withLogger.createEphemeral(new FakeKeyWrapper(), { expirySeconds: 60, refreshFailurePolicy: RefreshFailurePolicy.failOpen() }) as AesGcmCryptoProvider;
    try {
      assert.equal(created.refreshFailurePolicy.maxFailures, 4);
      assert.ok(!ephemeral.refreshFailurePolicy.failsClosed);
    } finally {
      await created.close();
      await ephemeral.close();
    }
  });

  it('never reaches the key wrapper with bad arguments or an aborted signal', async () => {
    for (const options of [{ expirySeconds: 0 }, { expirySeconds: 301 }, { expirySeconds: 60, signal: AbortSignal.abort() }]) {
      const wrapper = new FakeKeyWrapper();
      await assert.rejects(factory.create(wrapper, utf8('wrapped'), options));
      await assert.rejects(factory.createEphemeral(wrapper, options));
      assert.equal(wrapper.unwrapCalls + wrapper.generateCalls, 0);
    }
  });
});

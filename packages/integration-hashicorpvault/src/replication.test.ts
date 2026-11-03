import { strict as assert } from 'node:assert';
import { createHmac } from 'node:crypto';
import { afterEach, describe, it } from 'node:test';
import { harness, type Harness } from './fake-vault.test-support.js';
import { compareReplicationStates, ReplicationStateCache, VaultReplication, VaultReplicationState } from './replication.js';

const state = (local: string | number, replicated: string | number = local, cluster = 'c1', hmac = '') =>
  Buffer.from(`v1:${cluster}:${local}:${replicated}:${hmac}`).toString('base64');

describe('VaultReplicationState', () => {
  it('reads indexes as unsigned', () => {
    const parsed = VaultReplicationState.parse(state('18446744073709551615', 7));
    assert.equal(parsed.cluster, 'c1');
    assert.equal(parsed.localIndex, 18446744073709551615n);
    assert.equal(parsed.replicatedIndex, 7n);
  });

  it('verifies the HMAC given a key', () => {
    const key = Buffer.from('key');
    const hmac = createHmac('sha256', key).update('v1:c1:1:2').digest('hex');
    assert.equal(VaultReplicationState.parse(state(1, 2, 'c1', hmac), key).localIndex, 1n);
    assert.throws(() => VaultReplicationState.parse(state(1, 3, 'c1', hmac), key), /mismatch/);
  });

  for (const raw of ['not base64!', Buffer.from('nocolons').toString('base64'), state('x'), state(1, '18446744073709551616'), state(1, 1, ''),
    Buffer.from('v2:c:1:1:').toString('base64'), state(1, 1, 'c1', 'zz')]) {
    it(`refuses ${raw}`, () => assert.throws(() => VaultReplicationState.parse(raw), RangeError));
  }
});

describe('VaultReplication', () => {
  it('compares states, and merges keeping the newest', () => {
    assert.equal(compareReplicationStates(state(2), state(1)), 1);
    assert.equal(compareReplicationStates(state(1), state(1)), 1);
    assert.equal(compareReplicationStates(state(1), state(2)), -1);
    assert.equal(compareReplicationStates(state(2, 1), state(1, 2)), 0);
    assert.throws(() => compareReplicationStates(state(1), state(1, 1, 'c2')), RangeError);
    assert.deepEqual(VaultReplication.mergeReplicationStates([], state(1)), [state(1)]);
    assert.deepEqual(VaultReplication.mergeReplicationStates([state(1)], state(2)), [state(2)]);
    assert.deepEqual(VaultReplication.mergeReplicationStates([state(3)], state(2)), [state(3)]);
    assert.deepEqual(VaultReplication.mergeReplicationStates([state(2, 1)], state(1, 2)), [state(2, 1), state(1, 2)].sort());
    assert.deepEqual(VaultReplication.mergeReplicationStates(['junk'], state(2)), [state(2)]);
    assert.deepEqual(VaultReplication.mergeReplicationStates([state(1), state(1), state(1)], state(2)), [state(2)]);
  });

  describe('through a client', () => {
    let h: Harness;
    afterEach(async () => {
      await h.closeAll();
    });

    it('carries a state from a response to a request', async () => {
      h = await harness();
      h.vault.answer(200, '{"data":{}}', { 'X-Vault-Index': state(5) });
      const client = h.client();
      let recorded: string | undefined;
      await client.write('a', {}, { responseCallbacks: [VaultReplication.recordReplicationState((s) => { recorded = s; })] });
      assert.equal(recorded, state(5));
      await client.read('a', { requestCallbacks: [VaultReplication.requireReplicationStates(recorded!)] });
      assert.equal(h.vault.requests[1]!.header('X-Vault-Index'), state(5));
    });
  });

  it('has a cache ignoring responses without a state, whose copies are independent', () => {
    const cache = new ReplicationStateCache();
    cache.record({});
    assert.deepEqual(cache.snapshot(), []);
    cache.record({ 'x-vault-index': state(1) });
    const copy = cache.copy();
    copy.record({ 'x-vault-index': state(2) });
    assert.deepEqual(cache.snapshot(), [state(1)]);
    assert.deepEqual(copy.snapshot(), [state(2)]);
  });
});

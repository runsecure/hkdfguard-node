// Read-your-writes across a Vault Enterprise cluster: the replication states (X-Vault-Index) Vault
// returns and requires, and how a VaultClient forwards requests to the active node.
import { createHmac, timingSafeEqual } from 'node:crypto';
import type { IncomingHttpHeaders } from 'node:http';
import type { VaultRequest, VaultRequestCallback, VaultResponseCallback } from './client-options.js';

/** The header a replication state goes in, returned and required. */
export const INDEX_HEADER = 'X-Vault-Index';

/** Whether a performance standby forwards requests to the active node (Vault Enterprise). */
export const ReplicationForwardingMode = {
  /** No forwarding header. */
  none: 'none',
  /**
   * X-Vault-Forward: a performance standby forwards every request to the active node; see
   * https://developer.hashicorp.com/vault/docs/enterprise/consistency#unconditional-forwarding-performance-standbys-only.
   */
  always: 'always',
  /**
   * X-Vault-Inconsistent: a performance standby forwards a request to the active node only when it
   * hasn't caught up with the replication state it requires - see
   * {@link VaultReplication.requireReplicationStates}.
   */
  inconsistent: 'inconsistent',
} as const;

/** A {@link ReplicationForwardingMode} value. */
export type ReplicationForwardingMode = (typeof ReplicationForwardingMode)[keyof typeof ReplicationForwardingMode];

const MAX_INDEX = (1n << 64n) - 1n;

/** A cluster's replication state from an X-Vault-Index header: the sdk's WALState. */
export class VaultReplicationState {
  /**
   * @param cluster the cluster's id
   * @param localIndex the local write-ahead log index, unsigned
   * @param replicatedIndex the replicated write-ahead log index, unsigned
   */
  constructor(readonly cluster: string, readonly localIndex: bigint, readonly replicatedIndex: bigint) {}

  /**
   * The state `raw` holds: base64 of v1:cluster-id:local-index:replicated-index:hmac. With an
   * `hmacKey`, the hmac (hex HMAC-SHA256 of everything before it) is verified as well.
   * @throws RangeError raw isn't a replication state, or its HMAC doesn't match
   */
  static parse(raw: string, hmacKey?: Uint8Array): VaultReplicationState {
    if (typeof raw !== 'string') throw new TypeError('raw must be a string.');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(raw) || raw.length % 4 !== 0) throw new RangeError('Could not decode the replication state: not base64.');
    let decoded: string;
    try {
      decoded = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(raw, 'base64'));
    } catch {
      throw new RangeError('Could not decode the replication state: not UTF-8.');
    }

    const colon = decoded.lastIndexOf(':');
    if (colon < 0) throw new RangeError('Invalid replication state header format.');
    const state = decoded.slice(0, colon);
    const hmacText = decoded.slice(colon + 1);
    if (!/^([0-9A-Fa-f]{2})*$/.test(hmacText)) throw new RangeError(`Invalid replication state header HMAC '${hmacText}'.`);
    if (hmacKey !== undefined && hmacKey.length > 0) {
      const expected = createHmac('sha256', hmacKey).update(state, 'utf8').digest();
      const actual = Buffer.from(hmacText, 'hex');
      if (actual.length !== expected.length || !timingSafeEqual(expected, actual)) throw new RangeError('Invalid replication state header HMAC (mismatch).');
    }

    const pieces = state.split(':');
    if (pieces.length !== 4 || pieces[0] !== 'v1' || pieces[1] === '') throw new RangeError('Invalid replication state header format.');
    return new VaultReplicationState(pieces[1]!, parseIndex(pieces[2]!, 'local'), parseIndex(pieces[3]!, 'replicated'));
  }
}

/**
 * Read-your-writes across a Vault Enterprise cluster by hand - what
 * {@link VaultClientOptions.enforceReadYourWritesConsistency} does for every request: record the
 * state a write's response carries, then require it of a later read; see
 * https://developer.hashicorp.com/vault/docs/enterprise/consistency#conditional-forwarding-performance-standbys-only.
 */
export const VaultReplication = {
  /** A response callback handing `record` the response's replication state (X-Vault-Index), or undefined if it has none. */
  recordReplicationState(record: (state: string | undefined) => void): VaultResponseCallback {
    if (typeof record !== 'function') throw new TypeError('record must be a function.');
    return (_request, _status, headers) => record(header(headers, INDEX_HEADER));
  },

  /** A request callback requiring `states` (X-Vault-Index) of the node that answers - states recorded with {@link recordReplicationState}. */
  requireReplicationStates(...states: string[]): VaultRequestCallback {
    const copied = [...states];
    return (request: VaultRequest) => {
      for (const state of copied) request.addHeader(INDEX_HEADER, state);
    };
  },

  /**
   * The states to require after seeing `newState`, given those required so far: each old state
   * newer than `newState` kept, `newState` kept if newer than any - both when neither is newer -
   * sorted, with no duplicates. Just `newState` when there are no old states or more than two, or
   * when any can't be compared with it (unparsable, or another cluster's).
   */
  mergeReplicationStates(oldStates: readonly string[], newState: string): string[] {
    if (!Array.isArray(oldStates) || typeof newState !== 'string') throw new TypeError('oldStates must be an array, and newState a string.');
    if (oldStates.length === 0 || oldStates.length > 2) return [newState];

    const merged: string[] = [];
    for (const old of oldStates) {
      let comparison: number;
      try {
        comparison = compareReplicationStates(old, newState);
      } catch {
        return [newState];
      }
      if (comparison === 1) merged.push(old);
      else if (comparison === -1) merged.push(newState);
      else merged.push(old, newState);
    }
    // strutil.RemoveDuplicates: trimmed, empties dropped, distinct, sorted.
    return [...new Set(merged.map((s) => s.trim()).filter((s) => s !== ''))].sort();
  },
} as const;

/**
 * 1 if `s1` is newer than `s2` or the same, -1 if older, 0 if neither is.
 * @throws RangeError either isn't a replication state, or they're different clusters'
 */
export function compareReplicationStates(s1: string, s2: string): number {
  const r1 = VaultReplicationState.parse(s1);
  const r2 = VaultReplicationState.parse(s2);
  if (r1.cluster !== r2.cluster) throw new RangeError("Can't compare replication states from different clusters.");
  const sign = (a: bigint, b: bigint) => (a > b ? 1 : a < b ? -1 : 0);
  const local = sign(r1.localIndex, r2.localIndex);
  const replicated = sign(r1.replicatedIndex, r2.replicatedIndex);
  if (local >= 0 && replicated >= 0) return 1;
  if (local <= 0 && replicated <= 0) return -1;
  return 0;
}

/**
 * The replication states a client has seen, for
 * {@link VaultClientOptions.enforceReadYourWritesConsistency}: at most two, as
 * {@link VaultReplication.mergeReplicationStates} keeps them.
 */
export class ReplicationStateCache {
  #states: readonly string[];

  constructor(states: readonly string[] = []) {
    this.#states = [...states];
  }

  /** Merges the state `headers` carry, if any, into those seen. */
  record(headers: IncomingHttpHeaders): void {
    const state = header(headers, INDEX_HEADER);
    if (state === undefined || state === '') return;
    this.#states = VaultReplication.mergeReplicationStates(this.#states, state);
  }

  /** The states seen so far, to require of the next request. */
  snapshot(): readonly string[] {
    return this.#states;
  }

  copy(): ReplicationStateCache {
    return new ReplicationStateCache(this.#states);
  }
}

// The first value of name in a response's headers.
function header(headers: IncomingHttpHeaders, name: string): string | undefined {
  const value = headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

// A uint64: ASCII digits only, as .NET's NumberStyles.None reads them.
function parseIndex(digits: string, which: string): bigint {
  if (!/^\d+$/.test(digits) || BigInt(digits) > MAX_INDEX) throw new RangeError(`Invalid ${which} index in replication state header.`);
  return BigInt(digits);
}

// What VaultClient's tests share: a fake Vault on loopback, a key ring's token protector, and
// decrypting what it protected.
import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import type { DataProtector } from '@runsecure/hkdfguard-abstractions';
import { KeyRing } from '@runsecure/hkdfguard-dek';
import { RecordingKey } from '@runsecure/hkdfguard-test-support';
import { VaultClient } from './client.js';
import type { VaultClientOptions } from './client-options.js';
import type { StaticVaultToken } from './token.js';

export const TOKEN = 'hvs.CAESIFakeTokenForTests';

/** A status, a body ('' for none) and any extra headers; a status of -1 drops the connection. */
export interface Answer {
  status: number;
  body?: string;
  headers?: Record<string, string>;
}

export const DROP: Answer = { status: -1 };

/** A request as it arrived. */
export class Received {
  constructor(readonly method: string, readonly target: string, readonly headers: IncomingHttpHeaders, readonly body: Buffer) {}

  /** The header's values joined with ","; undefined if it wasn't sent. */
  header(name: string): string | undefined {
    const value = this.headers[name.toLowerCase()];
    return Array.isArray(value) ? value.join(',') : value;
  }

  get path(): string {
    return this.target.split('?', 1)[0]!;
  }

  get bodyText(): string | undefined {
    return this.body.length > 0 ? this.body.toString('utf8') : undefined;
  }
}

type Responder = (request: Received) => Answer | Promise<Answer>;

/**
 * Vault's HTTP API on 127.0.0.1 (http, which the client allows on loopback): every request is
 * recorded as it arrives, then answered by the next queued responder, or by {@link respond} once
 * the queue is empty.
 */
export class FakeVault {
  readonly requests: Received[] = [];
  readonly queued: Responder[] = [];
  respond: Responder = () => ({ status: 200, body: '{"data":{}}' });
  /** How long to wait before answering, in milliseconds. */
  delayMs = 0;
  readonly #server: Server;
  readonly #stopping = Promise.withResolvers<void>();

  private constructor() {
    this.#server = createServer((request, response) => {
      const chunks: Buffer[] = [];
      request.on('data', (chunk: Buffer) => chunks.push(chunk));
      request.on('end', () => {
        void (async () => {
          const received = new Received(request.method ?? '', request.url ?? '', request.headers, Buffer.concat(chunks));
          this.requests.push(received);
          if (this.delayMs > 0) await Promise.race([new Promise((resolve) => setTimeout(resolve, this.delayMs)), this.#stopping.promise]);
          const responder = this.queued.shift() ?? this.respond;
          const answer = await responder(received);
          if (answer.status < 0) {
            request.socket.destroy();
            return;
          }
          const data = Buffer.from(answer.body ?? '', 'utf8');
          const headers: Record<string, string> = { ...answer.headers, 'Content-Length': String(data.length) };
          if (data.length > 0) headers['Content-Type'] ??= 'application/json';
          response.writeHead(answer.status, headers);
          response.end(data);
        })().catch(() => request.socket.destroy());
      });
    });
  }

  static async start(): Promise<FakeVault> {
    const vault = new FakeVault();
    await new Promise<void>((resolve) => vault.#server.listen(0, '127.0.0.1', resolve));
    return vault;
  }

  get port(): number {
    return (this.#server.address() as { port: number }).port;
  }

  get address(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  /** Queues an answer: a status, body and headers, or a responder. */
  answer(status: number | Responder, body = '', headers: Record<string, string> = {}): this {
    this.queued.push(typeof status === 'function' ? status : () => ({ status, body, headers }));
    return this;
  }

  single(): Received {
    if (this.requests.length !== 1) throw new Error(`Expected one request; there were ${this.requests.length}.`);
    return this.requests[0]!;
  }

  async close(): Promise<void> {
    this.#stopping.resolve();
    this.#server.closeAllConnections();
    await new Promise<void>((resolve) => this.#server.close(() => resolve()));
  }
}

export function makeRing(version = 1): KeyRing {
  const ring = new KeyRing();
  ring.add(version, new RecordingKey());
  return ring;
}

export function makeProtector(ring = makeRing()): DataProtector {
  return ring.createProtector(VaultClient.TOKEN_PURPOSE);
}

/** What a protected token decrypts to. */
export async function decrypt(protector: DataProtector, protectedToken: string | StaticVaultToken | undefined): Promise<string> {
  if (protectedToken === undefined) throw new Error('No token.');
  const text = typeof protectedToken === 'string' ? protectedToken : await protectedToken.getToken();
  const result = new Uint8Array(protector.maxDecryptedLength(text));
  return Buffer.from(result.subarray(0, protector.decrypt(text, result))).toString('utf8');
}

/** The test's fake Vault, a protector, and a client of the fake whose options `options` replaces; closed after each test by {@link closeAll}. */
export interface Harness {
  vault: FakeVault;
  protector: DataProtector;
  client(options?: VaultClientOptions): VaultClient;
  closeAll(): Promise<void>;
}

export async function harness(): Promise<Harness> {
  const vault = await FakeVault.start();
  const protector = makeProtector();
  const clients: VaultClient[] = [];
  return {
    vault,
    protector,
    client(options: VaultClientOptions = {}) {
      const client = new VaultClient(protector, {
        address: vault.address, token: undefined, retry: { retryWaitMinMs: 1, retryWaitMaxMs: 2 }, ...options,
      });
      if (options.token === undefined && !Object.hasOwn(options, 'token')) client.setToken(TOKEN);
      clients.push(client);
      return client;
    },
    async closeAll() {
      for (const client of clients) client.close();
      await vault.close();
    },
  };
}

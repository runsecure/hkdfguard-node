// What Vault answers with, and how a VaultClient reads it: the response envelope, a login's token
// and a wrapped response's - protected as they are read, never strings - and the errors a refusal lists.
import { STATUS_CODES, type IncomingHttpHeaders, type IncomingMessage } from 'node:http';
import { Readable } from 'node:stream';
import { wipe, type DataProtector } from '@runsecure/hkdfguard-abstractions';
import { JsonReader, JsonToken, MalformedJsonError } from '@runsecure/hkdfguard-abstractions/internal';
import { readVaultErrors } from './body.js';
import { VaultJsonError, VaultResponseError } from './client-errors.js';
import { JsonValue } from './json.js';
import { isValidToken, StaticVaultToken } from './token.js';

/** An MFA method. */
export interface VaultMfaMethod {
  /** The method's type: totp, duo, okta or pingid. */
  readonly type: string | undefined;
  /** The method's id. */
  readonly id: string | undefined;
  /** Whether it takes a passcode. */
  readonly usesPasscode: boolean;
}

/** A constraint any one of whose methods satisfies it. */
export interface VaultMfaConstraint {
  /** The methods that satisfy it. */
  readonly any: readonly VaultMfaMethod[] | undefined;
}

/** The multi-factor validation a login needs. */
export interface VaultMfaRequirement {
  /** The id to validate against (sys/mfa/validate). */
  readonly mfaRequestId: string | undefined;
  /** The constraints, by name: each satisfied by any one of its methods. */
  readonly mfaConstraints: Readonly<Record<string, VaultMfaConstraint>> | undefined;
}

/** Reads a {@link VaultMfaRequirement}. */
export const VaultMfaRequirement = {
  read(json: JsonValue): VaultMfaRequirement {
    json.requireObject('mfa_requirement');
    const method = (m: JsonValue): VaultMfaMethod => {
      m.requireObject('any');
      return { type: m.member('type').readString(), id: m.member('id').readString(), usesPasscode: m.member('uses_passcode').readBoolean() === true };
    };
    const constraint = (c: JsonValue): VaultMfaConstraint => {
      c.requireObject('mfa_constraints');
      return { any: c.member('any').readArray((m) => m.readModel(method)) };
    };
    return {
      mfaRequestId: json.member('mfa_request_id').readString(),
      mfaConstraints: json.member('mfa_constraints').readRecord((c) => c.readModel(constraint)),
    };
  },
} as const;

/** The token a login issued, and about it. */
export interface VaultResponseAuth {
  /**
   * The token, protected by the client's token protector as the response was read - it never was a
   * string. Hand it to {@link VaultClient.setToken} or {@link VaultRequestOptions.token}.
   */
  readonly clientToken: StaticVaultToken | undefined;
  /** The token's accessor: for looking it up or revoking it, not for making requests. */
  readonly accessor: string | undefined;
  /** Every policy the token carries. */
  readonly policies: readonly string[] | undefined;
  /** The policies attached to the token itself. */
  readonly tokenPolicies: readonly string[] | undefined;
  /** The policies the token gets from its identity. */
  readonly identityPolicies: readonly string[] | undefined;
  /** The auth method's metadata about the login. */
  readonly metadata: Readonly<Record<string, string>> | undefined;
  /** Whether the token has no parent. */
  readonly orphan: boolean;
  /** The identity entity the token belongs to. */
  readonly entityId: string | undefined;
  /** How long the token lasts, in seconds. */
  readonly leaseDuration: number;
  /** Whether the token can be renewed. */
  readonly renewable: boolean;
  /** Set when the login needs multi-factor validation before it issues a token. */
  readonly mfaRequirement: VaultMfaRequirement | undefined;
}

/** A wrapped response: the token that unwraps it, and about it. */
export interface VaultResponseWrapInfo {
  /** The wrapping token, protected by the client's token protector as the response was read. Hand it to {@link VaultClient.unwrap}. */
  readonly token: StaticVaultToken | undefined;
  /** The wrapping token's accessor. */
  readonly accessor: string | undefined;
  /** How long the wrapping token lasts, in seconds. */
  readonly ttl: number;
  /** When the response was wrapped. */
  readonly creationTime: Date | undefined;
  /** The path whose response was wrapped. */
  readonly creationPath: string | undefined;
  /** When a token is wrapped, that token's accessor. */
  readonly wrappedAccessor: string | undefined;
}

/**
 * What Vault answers most requests with. A response without a "data", "auth" or "wrap_info" member
 * - sys/health, sys/leader and sys/seal-status, for instance - is read whole into {@link data}.
 */
export interface VaultResponse<T> {
  /** The id of the request this answers. */
  readonly requestId?: string;
  /** The lease on a dynamic secret, for renewing or revoking it. */
  readonly leaseId?: string;
  /** How long the lease lasts, in seconds; 0 if none. */
  readonly leaseDuration: number;
  /** Whether the lease can be renewed. */
  readonly renewable: boolean;
  /** The response's contents, whose shape depends on the endpoint: a generated model, or a record of JSON values. */
  readonly data?: T;
  /** Things Vault wants noticed that didn't fail the request. */
  readonly warnings?: readonly string[];
  /** The token a login issued, and about it; undefined for anything but a login. */
  readonly auth?: VaultResponseAuth;
  /** The wrapping token, when the response was wrapped ({@link VaultRequestOptions.responseWrappingTtlMs}). */
  readonly wrapInfo?: VaultResponseWrapInfo;
}

/**
 * Vault's response as it is, from {@link VaultClient.readRaw}: not parsed, not checked for an error
 * status, its body to read - {@link body}, or iterate this - and {@link close}. Unlike Node's
 * response, it gives no way back to the request, which carried the token.
 */
export class VaultRawResponse implements AsyncIterable<Buffer> {
  readonly #response: IncomingMessage;
  #body: Readable | undefined;

  constructor(response: IncomingMessage) {
    this.#response = response;
  }

  /** The status Vault answered with. */
  get statusCode(): number {
    return this.#response.statusCode ?? 0;
  }

  /** The response's headers. */
  get headers(): IncomingHttpHeaders {
    return this.#response.headers;
  }

  /**
   * The body: a stream of its chunks - a stream of its own over Node's response, never the response
   * itself, whose `req` (and socket) lead back to the request and its X-Vault-Token header.
   * Destroying it closes the response.
   */
  get body(): NodeJS.ReadableStream {
    this.#body ??= Readable.from(this.#chunks(), { objectMode: false });
    return this.#body;
  }

  [Symbol.asyncIterator](): AsyncIterator<Buffer> {
    return this.#chunks();
  }

  // The response's chunks, through an iterator of their own: nothing handed out is the response.
  async *#chunks(): AsyncGenerator<Buffer> {
    for await (const chunk of this.#response) yield chunk as Buffer;
  }

  /** Closes the body and its connection, if the body wasn't read to its end. Safe to call more than once. */
  close(): void {
    if (!this.#response.complete) this.#response.destroy();
  }
}

/**
 * `body` as a response - the standard envelope when it has a "data" member (as vault-client-go
 * decides), or "auth" or "wrap_info", so a token is never mistaken for data; otherwise the body
 * whole as its data - its data read with `reader`; undefined if it is empty. The tokens in
 * auth.client_token and wrap_info.token are protected straight from the body's bytes.
 * @throws VaultJsonError the body isn't JSON, or not of the shape `reader` reads
 */
export function readResponse<T>(body: Uint8Array, tokenProtector: DataProtector, reader: (json: JsonValue) => T | undefined): VaultResponse<T> | undefined {
  if (body.length === 0) return undefined;
  if (!isEnvelope(body)) return { leaseDuration: 0, renewable: false, data: JsonValue.parse(body).readModel(reader) };

  try {
    const json = new JsonReader(body);
    json.read();
    const fields: { -readonly [K in keyof VaultResponse<T>]: VaultResponse<T>[K] } = { leaseDuration: 0, renewable: false };
    while (json.read() && json.token() === JsonToken.PropertyName) {
      const name = json.getString();
      json.read();
      if (name === 'auth') {
        fields.auth = readAuth(json, tokenProtector);
        continue;
      }
      if (name === 'wrap_info') {
        fields.wrapInfo = readWrapInfo(json, tokenProtector);
        continue;
      }
      const value = JsonValue.readFrom(json);
      switch (name) {
        case 'request_id': fields.requestId = value.readString(); break;
        case 'lease_id': fields.leaseId = value.readString(); break;
        case 'lease_duration': fields.leaseDuration = value.readInteger() ?? 0; break;
        case 'renewable': fields.renewable = value.readBoolean() === true; break;
        case 'data': fields.data = value.readModel(reader); break;
        case 'warnings': fields.warnings = value.readArray((w) => w.readString()); break;
        default: break; // Not part of the envelope.
      }
    }
    if (json.read()) throw new VaultJsonError("Vault's response holds more than one JSON value.");
    return fields;
  } catch (error) {
    if (error instanceof MalformedJsonError) throw new VaultJsonError(`Vault's response isn't JSON: ${error.message}`);
    throw error;
  }
}

/** How much of a body that isn't Vault's JSON a refusal's message quotes, in bytes. */
export const MAX_QUOTED_BODY_BYTES = 512;

/**
 * The error a refusal is reported as: the errors `body` lists, as {"errors":[...]} or
 * {"error":"..."}. A JSON object listing none - a KV v2 read of a deleted version answers 404 with
 * the secret's metadata, custom metadata included - is reported by its status alone: the message is
 * what reaches logs, and the body isn't Vault saying what went wrong. Anything else - a proxy's error
 * page, say - is quoted, at most {@link MAX_QUOTED_BODY_BYTES} of it. Either way the whole body is
 * kept in rawResponseBytes.
 */
export function responseError(status: number, body: Uint8Array, method: string, url: string): VaultResponseError {
  const reason = reasonPhrase(status);
  const errors = readVaultErrors(body);
  if (errors !== undefined && errors.length > 0) return new VaultResponseError(`${status}${reason}: ${errors.join(', ')}`, status, errors, undefined, method, url);
  const raw = body.length > 0 ? Uint8Array.from(body) : undefined;
  const message = raw === undefined || errors !== undefined ? `${status}${reason}` : `${status}${reason}: ${quoted(raw)}`;
  return new VaultResponseError(message, status, [], raw, method, url);
}

// The start of a body as text: at most MAX_QUOTED_BODY_BYTES, cut on a character boundary, saying how
// long the whole was when it is cut.
function quoted(body: Uint8Array): string {
  if (body.length <= MAX_QUOTED_BODY_BYTES) return new TextDecoder().decode(body);
  // stream: an incomplete last character is held back rather than shown as U+FFFD.
  const start = new TextDecoder().decode(body.subarray(0, MAX_QUOTED_BODY_BYTES), { stream: true });
  return `${start}... (${body.length} bytes)`;
}

/** " Not Found" for 404: the space and the status's reason, as Go's http.StatusText; "" for one without a name. */
export function reasonPhrase(status: number): string {
  const phrase = STATUS_CODES[status];
  return phrase === undefined ? '' : ` ${phrase}`;
}

// Whether body is an object with a "data", "auth" or "wrap_info" member. Malformed, it isn't.
function isEnvelope(body: Uint8Array): boolean {
  try {
    const reader = new JsonReader(body);
    if (!reader.read() || reader.token() !== JsonToken.StartObject) return false;
    while (reader.read() && reader.token() === JsonToken.PropertyName) {
      if (reader.valueTextEquals('data') || reader.valueTextEquals('auth') || reader.valueTextEquals('wrap_info')) return true;
      reader.read();
      reader.skip();
    }
  } catch (error) {
    if (!(error instanceof MalformedJsonError)) throw error;
  }
  return false;
}

function readAuth(json: JsonReader, tokenProtector: DataProtector): VaultResponseAuth | undefined {
  if (json.token() === JsonToken.Null) return undefined;
  if (json.token() !== JsonToken.StartObject) throw new VaultJsonError('Expected a JSON object for auth.');
  const { token, members } = readMembers(json, 'client_token', tokenProtector);
  const member = (name: string) => members.get(name) ?? JsonValue.NULL;
  return {
    clientToken: token,
    accessor: member('accessor').readString(),
    policies: member('policies').readArray((v) => v.readString()),
    tokenPolicies: member('token_policies').readArray((v) => v.readString()),
    identityPolicies: member('identity_policies').readArray((v) => v.readString()),
    metadata: member('metadata').readRecord((v) => v.readString()),
    orphan: member('orphan').readBoolean() === true,
    entityId: member('entity_id').readString(),
    leaseDuration: member('lease_duration').readInteger() ?? 0,
    renewable: member('renewable').readBoolean() === true,
    mfaRequirement: member('mfa_requirement').readModel(VaultMfaRequirement.read),
  };
}

function readWrapInfo(json: JsonReader, tokenProtector: DataProtector): VaultResponseWrapInfo | undefined {
  if (json.token() === JsonToken.Null) return undefined;
  if (json.token() !== JsonToken.StartObject) throw new VaultJsonError('Expected a JSON object for wrap_info.');
  const { token, members } = readMembers(json, 'token', tokenProtector);
  const member = (name: string) => members.get(name) ?? JsonValue.NULL;
  return {
    token,
    accessor: member('accessor').readString(),
    ttl: member('ttl').readInteger() ?? 0,
    creationTime: member('creation_time').readDate(),
    creationPath: member('creation_path').readString(),
    wrappedAccessor: member('wrapped_accessor').readString(),
  };
}

// The members of the object json has just started, the one named tokenName protected rather than read.
function readMembers(json: JsonReader, tokenName: string, tokenProtector: DataProtector): { token: StaticVaultToken | undefined; members: Map<string, JsonValue> } {
  let token: StaticVaultToken | undefined;
  const members = new Map<string, JsonValue>();
  while (json.read() && json.token() === JsonToken.PropertyName) {
    const isToken = json.valueTextEquals(tokenName);
    const name = json.getString();
    json.read();
    if (isToken) token = protectToken(json, tokenProtector);
    else members.set(name, JsonValue.readFrom(json));
  }
  return { token, members };
}

// The token string json has just read, protected: unescaped into a buffer zeroed once it's
// encrypted - DataProtector.encrypt takes the bytes, so the token never becomes a string. Undefined
// for null or an empty string.
function protectToken(json: JsonReader, tokenProtector: DataProtector): StaticVaultToken | undefined {
  if (json.token() === JsonToken.Null) return undefined;
  if (json.token() !== JsonToken.String) {
    json.skip();
    throw new VaultJsonError('Expected a token string.');
  }
  // Unescaped, a string is never longer than it is escaped.
  const unescaped = new Uint8Array(json.valueLength);
  try {
    const length = json.copyString(unescaped);
    if (length === 0) return undefined;
    const token = unescaped.subarray(0, length);
    if (!isValidToken(token)) throw new VaultJsonError("Vault returned a token that isn't one: printable ASCII, with no spaces.");
    let protectedToken: string;
    try {
      protectedToken = tokenProtector.encrypt(token);
    } catch (error) {
      throw new VaultJsonError(`Vault's token couldn't be protected: ${(error as Error)?.name ?? 'Error'}.`);
    }
    return new StaticVaultToken(protectedToken);
  } finally {
    wipe(unescaped);
  }
}

// The errors a VaultClient reports Vault's refusals, and answers that aren't what was expected, as.
import { HkdfGuardError } from '@runsecure/hkdfguard-abstractions';
import { VaultRequestError } from './errors.js';

/**
 * Vault answered a {@link VaultClient} request with a status outside 200-399 - vault-client-go's
 * ResponseError. A request that gets no answer (Vault unreachable, say) rejects with Node's own
 * network error instead.
 */
export class VaultResponseError extends VaultRequestError {
  /** The errors Vault listed in its response; empty if it listed none. */
  readonly errors: readonly string[];
  /** The response body, when it held no errors to list; undefined otherwise. */
  readonly rawResponseBytes: Uint8Array | undefined;
  /** The method of the request Vault refused. */
  readonly requestMethod: string;
  /** The URL of the request Vault refused, without its token (which is never in a URL). */
  readonly requestUrl: string;

  constructor(message: string, statusCode: number, errors: readonly string[], rawResponseBytes: Uint8Array | undefined, requestMethod: string,
    requestUrl: string) {
    super(message, { statusCode });
    this.errors = Object.freeze([...errors]);
    this.rawResponseBytes = rawResponseBytes;
    this.requestMethod = requestMethod;
    this.requestUrl = requestUrl;
  }
}

/**
 * Vault answered a {@link VaultClient} request with a redirect (301, 302 or 307) the client wouldn't
 * follow: redirects are off ({@link VaultClientOptions.followRedirects}), it was the request's
 * second, it would go from https to http, or its location couldn't be read - vault-client-go's
 * RedirectError.
 */
export class VaultRedirectError extends VaultRequestError {
  /** Why the redirect wasn't followed. */
  readonly reason: string;
  /** Where the redirect pointed, if that could be read; undefined otherwise. */
  readonly redirectLocation: string | undefined;
  /** The method of the redirected request. */
  readonly requestMethod: string;
  /** The URL of the redirected request. */
  readonly requestUrl: string;

  constructor(statusCode: number, reason: string, redirectLocation: string | undefined, requestMethod: string, requestUrl: string) {
    super(`${statusCode}: redirect error: ${reason}`, { statusCode });
    this.reason = reason;
    this.redirectLocation = redirectLocation;
    this.requestMethod = requestMethod;
    this.requestUrl = requestUrl;
  }
}

/**
 * A response Vault returned isn't the JSON a {@link VaultClient} method reads: malformed, or a value
 * of another type where a model expects an object, a number or a date-time. Its message never quotes
 * the response, which may hold a secret.
 */
export class VaultJsonError extends HkdfGuardError {
  constructor(message: string) {
    super('ERR_HKDFGUARD_VAULT_JSON', message);
  }
}

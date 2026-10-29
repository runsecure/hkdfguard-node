/**
 * A protected read-only cache over HashiCorp Vault's KV secrets engine - the Node port of the .NET
 * HkdfGuard.Cache.HashiCorpVault library: each secret is read on its first lookup, through Node's own
 * http/https client, parsed straight from the response stream before it can become a string,
 * encrypted under the key ring's current key and cached only as ciphertext.
 *
 *  - HashiCorpVaultSecretCache: the cache. A name is a secret's path and the key to read,
 *    "myapp/db#password"; "myapp/db" reads the default key ("value"). One read caches every key
 *    the secret holds. KV version 2 (the default) or 1, any mount, an Enterprise namespace.
 *  - HashiCorpVaultSecretCacheOptions: the mount, KV version, default key, namespace, timeout,
 *    retries, the https agent (a private CA, a client certificate) and the logger.
 *  - VaultTokenProvider: supplies the token, protected by the cache's token protector
 *    (keyRing.createProtector(HashiCorpVaultSecretCache.TOKEN_PURPOSE)); StaticVaultToken holds one
 *    issued elsewhere. The token is decrypted only to build each request.
 *  - VaultRequestError: Vault refused a read (403, a 404 naming an error, 503 sealed...), with its
 *    status and errors, never the token.
 */
export { HashiCorpVaultSecretCache } from './cache.js';
export { VaultRequestError } from './errors.js';
export { HashiCorpVaultSecretCacheOptions, VaultKvVersion } from './options.js';
export { StaticVaultToken, type VaultTokenProvider } from './token.js';

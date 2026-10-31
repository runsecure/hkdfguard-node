/**
 * A KeyWrapper over one key in a HashiCorp Vault transit secrets engine - the Node port of the .NET
 * HkdfGuard.KeyWrapping.HashiCorpVault library. DEKs are wrapped with encrypt and revealed with
 * decrypt (the key pinned by its path), and generated with datakey/wrapped when no context is bound;
 * a context is bound as Vault's associated_data. HashiCorp ships no Node SDK, and the community
 * client parses Vault's answers into strings, so the wrapper talks to Vault's HTTP API through Node's
 * own http and https clients, with no third-party dependency: a DEK never becomes a string, and
 * every buffer that held one is zeroed. Key files are Vault's ciphertext, "vault:v{n}:...", in ASCII
 * - byte for byte those of the .NET, Go, Java and Python wrappers - and are read only from where no
 * untrusted account could have written or replaced them (@runsecure/hkdfguard-securefile).
 *
 *  - HashiCorpVaultTransitKeyWrapper: the wrapper. {@link HashiCorpVaultTransitKeyWrapper.close}
 *    releases its connections.
 *  - HashiCorpVaultTransitKeyWrapperOptions: the context, key file trust, mount, namespace, timeout,
 *    retries and the https agent (a private CA, a client certificate).
 *  - VaultTokenSource: supplies the token, copied into a buffer the wrapper zeroes;
 *    StaticVaultTokenSource holds one issued elsewhere.
 *  - HashiCorpVaultTransitError: Vault refused a call (403, 400 for a ciphertext that doesn't
 *    authenticate, 503 sealed...) or couldn't be reached, with its status and errors, never the token.
 *
 * ```ts
 * import { HashiCorpVaultTransitKeyWrapper, StaticVaultTokenSource } from '@runsecure/hkdfguard-keywrapping-hashicorpvault';
 *
 * const token = new StaticVaultTokenSource(process.env.VAULT_TOKEN!);
 * const wrapper = new HashiCorpVaultTransitKeyWrapper('https://vault.example.com:8200', 'myapp-kek', token,
 *   { context: 'com.example.myapp' });
 * ```
 */
export {
  GENERATED_KEY_LENGTH, HashiCorpVaultTransitKeyWrapper, MAX_CONTEXT_LENGTH, MAX_KEY_NAME_LENGTH, MAX_PLAINTEXT_LENGTH, MAX_TOKEN_LENGTH,
} from './wrapper.js';
export { HashiCorpVaultTransitKeyWrapperOptions } from './options.js';
export { StaticVaultTokenSource, type VaultTokenSource } from './token.js';
export { HashiCorpVaultTransitError } from './errors.js';
export { KeyFileError, KeyFileTrust, type KeyFileTrustOptions } from '@runsecure/hkdfguard-securefile';

/**
 * The AES-256-GCM implementation of CryptoProviderFactory, CryptoProvider and PipelineDataProtector
 * - the Node port of the .NET HkdfGuard.CryptoProvider.AesGcm256 library. One interchangeable
 * cipher: everything above it depends only on the abstractions, so another AEAD's package can
 * replace it by supplying its own CryptoProviderFactory.
 *
 * Ciphertext is [12-byte random nonce | ciphertext | 16-byte GCM tag], byte-compatible with the
 * other ports.
 */
export {
  AesGcmCryptoProvider, AesGcmCryptoProviderFactory, MAX_EXPIRY_SECONDS, MIN_EXPIRY_SECONDS, type AesGcmProviderOptions,
} from './provider.js';
export { AesGcmPipelineDataProtector } from './pipeline.js';
export {
  ENCRYPTION_WARNING_THRESHOLD, KEY_SIZE, MAX_ENCRYPTIONS_PER_KEY, NONCE_SIZE, OVERHEAD, TAG_SIZE,
} from './session.js';

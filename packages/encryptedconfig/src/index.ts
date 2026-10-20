/**
 * Reads secrets a deployment pipeline encrypted into configuration - the Node port of the .NET
 * HkdfGuard.EncryptedConfiguration library.
 *
 * At deploy time a PipelineDataProtector encrypts each secret bound to the configuration key it is
 * stored under (see configurationPurpose) and writes the enc::v<version>::<base64> value into
 * configuration. At runtime an EncryptedConfigurationReader looks that value up by the same key and
 * decrypts it through the key ring the pipeline's key was registered in; a value moved to a
 * different key fails authentication.
 *
 * The reader works with any configuration source through a Lookup function. envLookup, mapLookup
 * and flattenJson adapt the conventions .NET configuration uses, so one pipeline output serves every
 * port.
 */
export { EncryptedConfigurationReader, type Lookup, type ProtectorFactory } from './reader.js';
export { DuplicateKeyError, envLookup, flattenJson, mapLookup } from './lookup.js';

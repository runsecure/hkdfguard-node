import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import { InvalidArgumentError } from '@runsecure/hkdfguard-abstractions';
import * as envelope from './envelope.js';
import { KeyVaultKeyId } from './keyId.js';

const WRAP_VERSION = '0123456789abcdef0123456789abcdef';
const SIGN_VERSION = 'fedcba9876543210fedcba9876543210';

class FormatError extends Error {}
const fail: envelope.Fail = (message) => new FormatError(message);

const random = (length: number) => new Uint8Array(randomBytes(length));
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');

function build(ciphertextLength: number): Uint8Array {
  const unsigned = envelope.buildUnsigned(WRAP_VERSION, random(ciphertextLength), fail);
  const result = new Uint8Array(unsigned.length + 80);
  envelope.write(unsigned, SIGN_VERSION, random(64), result, fail);
  return result;
}

/** A predicate for assert.throws: a FormatError whose message holds `text`. */
const formatError = (text: string) => (e: unknown) => e instanceof FormatError && e.message.includes(text);

describe('the wrapped-DEK envelope', () => {
  it('round-trips every part through write and parse', () => {
    const ciphertext = random(256);
    const signature = random(64);
    const unsigned = envelope.buildUnsigned(WRAP_VERSION.toUpperCase(), ciphertext, fail);
    const result = new Uint8Array(512);

    const length = envelope.write(unsigned, SIGN_VERSION, signature, result, fail);
    const parts = envelope.parse(result.subarray(0, length), fail);

    assert.equal(length, 256 + envelope.OVERHEAD);
    assert.deepEqual(parts, {
      wrappingKeyVersion: WRAP_VERSION, wrappedDek: ciphertext, signingKeyVersion: SIGN_VERSION, signature, unsignedLength: envelope.HEADER_LENGTH + 256,
    });
  });

  it('is the .NET, Java and Python wrappers\' layout, byte for byte', () => {
    // The format every port writes and reads; a key file made by any of them must be read by the
    // others. The same bytes as the Java and Python tests'.
    const unsigned = envelope.buildUnsigned(WRAP_VERSION, new Uint8Array([0xc1, 0xc2, 0xc3]), fail);
    const result = new Uint8Array(unsigned.length + 80);
    envelope.write(unsigned, SIGN_VERSION, new Uint8Array(64).fill(0x5a), result, fail);

    assert.equal(hex(result), `48474b56${'01'}${WRAP_VERSION}${'0003'}${'c1c2c3'}${SIGN_VERSION}${'5a'.repeat(64)}`);
    assert.equal(hex(envelope.signedData(unsigned, envelope.encodeContext('myapp'))),
      Buffer.from('HkdfGuard-AzureKeyVault-wrap-v1\0').toString('hex') + '0005' + Buffer.from('myapp').toString('hex') + hex(unsigned));
  });

  it('refuses to parse what is not an envelope', () => {
    for (const data of [new Uint8Array(envelope.OVERHEAD), random(300), new Uint8Array(0), new TextEncoder().encode('HGKV')]) {
      assert.throws(() => envelope.parse(data, fail), formatError('not a wrapped DEK written by AzureKeyVaultKeyWrapper'));
    }
  });

  it('refuses another format version', () => {
    const data = build(256);
    data[4] = 2;
    assert.throws(() => envelope.parse(data, fail), formatError('format version 2'));
  });

  it('refuses a length that disagrees with the header', () => {
    const data = build(256);
    for (const changed of [data.subarray(0, data.length - 1), Uint8Array.of(...data, 0)]) {
      assert.throws(() => envelope.parse(changed, fail), formatError('but its header describes'));
    }
  });

  it('reads the ciphertext length as unsigned', () => {
    assert.equal(envelope.parse(build(0x8001), fail).wrappedDek.length, 0x8001);
  });

  it('refuses an empty ciphertext', () => {
    const data = build(256);
    data[21] = 0;
    data[22] = 0;
    assert.throws(() => envelope.parse(data.subarray(0, envelope.OVERHEAD + 1), fail), FormatError);
  });

  it('parses into copies, so a later change to the envelope changes no part', () => {
    const data = build(256);
    const parts = envelope.parse(data, fail);
    const before = { wrappedDek: Uint8Array.from(parts.wrappedDek), signature: Uint8Array.from(parts.signature) };
    data.fill(0);
    assert.deepEqual(parts.wrappedDek, before.wrappedDek);
    assert.deepEqual(parts.signature, before.signature);
  });

  it('refuses to build a ciphertext it can\'t encode', () => {
    for (const length of [0, 0x10000]) {
      assert.throws(() => envelope.buildUnsigned(WRAP_VERSION, new Uint8Array(length), fail), formatError(`a ${length}-byte wrapped key`));
    }
  });

  it('refuses a version that isn\'t Key Vault\'s, leaving result as it was', () => {
    for (const version of [undefined, '', WRAP_VERSION.slice(0, 31), `${WRAP_VERSION}0`, 'g'.repeat(32), '０'.repeat(32), ` ${WRAP_VERSION.slice(1)}`]) {
      assert.throws(() => envelope.buildUnsigned(version, random(256), fail), formatError('not 32 hex digits'));

      const unsigned = envelope.buildUnsigned(WRAP_VERSION, random(256), fail);
      const result = new Uint8Array(512).fill(0xaa);
      assert.throws(() => envelope.write(unsigned, version, random(64), result, fail), formatError('not 32 hex digits'));
      assert.deepEqual(result, new Uint8Array(512).fill(0xaa));
    }
  });

  it('refuses a signature that isn\'t ES256\'s', () => {
    const unsigned = envelope.buildUnsigned(WRAP_VERSION, random(256), fail);
    for (const length of [0, 63, 65, 96]) {
      assert.throws(() => envelope.write(unsigned, SIGN_VERSION, new Uint8Array(length), new Uint8Array(512), fail), formatError(`a ${length}-byte signature`));
    }
  });

  it('refuses a result too small, leaving it as it was', () => {
    const unsigned = envelope.buildUnsigned(WRAP_VERSION, random(256), fail);
    const result = new Uint8Array(358).fill(0xaa);
    assert.throws(() => envelope.write(unsigned, SIGN_VERSION, random(64), result, fail),
      (e: unknown) => e instanceof InvalidArgumentError && e.message.includes('is 359 bytes; result holds 358'));
    assert.deepEqual(result, new Uint8Array(358).fill(0xaa));
  });

  it('signs over the domain, the context and the envelope', () => {
    const unsigned = envelope.buildUnsigned(WRAP_VERSION, random(256), fail);
    const context = envelope.encodeContext('app');
    const signed = hex(envelope.signedData(unsigned, context));

    assert.notEqual(signed, hex(envelope.signedData(unsigned, envelope.encodeContext('apq'))));
    assert.notEqual(signed, hex(envelope.signedData(unsigned, new Uint8Array(0))));
    const changed = Uint8Array.from(unsigned);
    changed[changed.length - 1]! ^= 1;
    assert.notEqual(signed, hex(envelope.signedData(changed, context)));
    // The context is length-prefixed, so it can't run into the envelope.
    const tail = unsigned.subarray(4);
    assert.notEqual(hex(envelope.signedData(Uint8Array.of(...envelope.MAGIC, ...tail), new TextEncoder().encode('ab'))),
      hex(envelope.signedData(Uint8Array.of(0x62, ...envelope.MAGIC, ...tail), new TextEncoder().encode('a'))));
  });

  it('encodes the context as UTF-8', () => {
    assert.deepEqual(envelope.encodeContext(undefined), new Uint8Array(0));
    assert.deepEqual(envelope.encodeContext(''), new Uint8Array(0));
    assert.equal(Buffer.from(envelope.encodeContext('café \u{1f511}')).toString('utf8'), 'café \u{1f511}');
    assert.equal(envelope.encodeContext('x'.repeat(65_535)).length, 65_535);
  });

  it('refuses a context too long to length-prefix, not well-formed, or not a string', () => {
    const invalid = (text: string) => (e: unknown) => e instanceof InvalidArgumentError && e.message.includes(text);
    assert.throws(() => envelope.encodeContext('x'.repeat(65_536)), invalid('65536 bytes in UTF-8; at most 65535'));
    assert.throws(() => envelope.encodeContext('é'.repeat(32_768)), invalid('at most 65535'));
    assert.throws(() => envelope.encodeContext('\udc00app'), invalid('lone surrogate'));
    assert.throws(() => envelope.encodeContext(42 as unknown as string), invalid('must be a string'));
  });
});

describe('Key Vault key identifiers', () => {
  it('are parsed and normalized', () => {
    const key = KeyVaultKeyId.parse('https://MyVault.Vault.Azure.NET/keys/My-Key');
    assert.deepEqual([key.vault, key.name, key.version], ['https://myvault.vault.azure.net', 'My-Key', undefined]);
    const versioned = KeyVaultKeyId.parse(`HTTPS://myvault.vault.azure.net:08443/keys/k/${WRAP_VERSION}/`);
    assert.deepEqual([versioned.vault, versioned.name, versioned.version], ['https://myvault.vault.azure.net:8443', 'k', WRAP_VERSION]);
    assert.equal(KeyVaultKeyId.parse('https://myvault.managedhsm.azure.net/keys/k/').toString(), 'https://myvault.managedhsm.azure.net/keys/k');
  });

  it('name the same key whatever the version and the name\'s case, but not in another vault', () => {
    const key = KeyVaultKeyId.parse('https://myvault.vault.azure.net/keys/my-key');

    assert.ok(key.sameKey(KeyVaultKeyId.parse(`https://MYVAULT.vault.azure.net/keys/MY-KEY/${WRAP_VERSION}`)));
    assert.ok(!key.sameKey(KeyVaultKeyId.parse('https://myvault.vault.azure.net:443/keys/my-key')));
    assert.ok(!key.sameKey(KeyVaultKeyId.parse('https://other.vault.azure.net/keys/my-key')));
    assert.ok(!key.sameKey(KeyVaultKeyId.parse('https://myvault.vault.azure.net/keys/my-key2')));
  });

  it('name a version of the same key withVersion', () => {
    const key = KeyVaultKeyId.parse('https://myvault.vault.azure.net/keys/my-key');

    assert.equal(key.withVersion(WRAP_VERSION).toString(), `https://myvault.vault.azure.net/keys/my-key/${WRAP_VERSION}`);
    assert.equal(key.version, undefined);
  });

  it('refuse what isn\'t a key identifier', () => {
    for (const keyId of [
      undefined, null, 1, '', 'https://myvault.vault.azure.net/keys/k'.split(''), `https://myvault.vault.azure.net/keys/${'k'.repeat(128)}`,
      'https://myvault.vault.azure.net/keys/k/v-1', 'https://myvault.vault.azure.net//keys/k', 'https:///keys/k', 'https://myvault.vault.azure.net/keys/k%2D1',
      'https://-myvault.vault.azure.net/keys/k', 'http://myvault.vault.azure.net/keys/k', 'https://myvault.vault.azure.net/secrets/k',
      'https://myvault.vault.azure.net/Keys/k', 'https://myvault.vault.azure.net\\keys\\k', 'https://myvault.vault.azure.net/keys/./k',
      'https://myvault.vault.azure.net/keys/x/../k', 'https://user@myvault.vault.azure.net/keys/k', 'https://myvault.vault.azure.net:99999/keys/k',
      'https://myvault.vault.azure.net/keys/k?api-version=7.4', 'https://myvault.vault.azure.net/keys/k#v', ' https://myvault.vault.azure.net/keys/k',
      'https://myvault.vault.azure.net/keys/k\n', 'https://[::1]/keys/k', 'https://myvault.vault.azure.net/keys/k/v/w',
    ]) {
      assert.throws(() => KeyVaultKeyId.parse(keyId as string),
        (e: unknown) => e instanceof InvalidArgumentError && e.message.includes('isn\'t a Key Vault key identifier'), String(keyId));
    }
  });
});

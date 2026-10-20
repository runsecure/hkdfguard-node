import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import { AuthenticationFailedError, configurationPurpose, type DataProtector } from '@runsecure/hkdfguard-abstractions';
import { ProtectedCache } from '@runsecure/hkdfguard-cache';
import { buildKeyRing, DataEncryptionKey, DefaultFormatProvider, KeyRing } from '@runsecure/hkdfguard-dek';
import { EncryptedConfigurationReader, flattenJson, mapLookup } from '@runsecure/hkdfguard-encryptedconfig';
import { FakeKeyWrapper } from '@runsecure/hkdfguard-test-support';
import { AesGcmPipelineDataProtector } from './pipeline.js';
import { AesGcmCryptoProviderFactory } from './provider.js';

// AES-256-GCM plugged into the dek and cache packages, end to end - and the interop between
// pipeline-protected values and a key ring that is the whole point of the pipeline protector.

const VERSION = 3;
const ID = 'ConnectionStrings:Admin';

function unprotect(p: DataProtector, formatted: string): string {
  const result = new Uint8Array(p.maxDecryptedLength(formatted));
  return new TextDecoder().decode(result.subarray(0, p.decrypt(formatted, result)));
}

/** A ring holding `key` at VERSION, through AES-256-GCM. */
async function ringWithKey(key: Uint8Array): Promise<KeyRing> {
  const provider = await new AesGcmCryptoProviderFactory().create(new FakeKeyWrapper(Uint8Array.from(key)), new TextEncoder().encode('wrapped'), { expirySeconds: 60 });
  const ring = new KeyRing(new DefaultFormatProvider());
  ring.add(VERSION, new DataEncryptionKey(provider));
  return ring;
}

/** A pipeline protector and its key, read back through keyBase64. */
function pipelineAndKey(): { pipeline: AesGcmPipelineDataProtector; key: Uint8Array } {
  const pipeline = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), VERSION);
  const key = new Uint8Array(Buffer.from(new TextDecoder().decode(pipeline.keyBase64()), 'base64'));
  return { pipeline, key };
}

describe('AES-256-GCM with the dek and cache packages', () => {
  it('builds a working key ring', async () => {
    const ring = await buildKeyRing({ keyWrapper: new FakeKeyWrapper(new Uint8Array(randomBytes(32))), cryptoProviderFactory: new AesGcmCryptoProviderFactory(), keyRefreshInterval: 60, ephemeralKeys: [1] });
    try {
      const protector = ring.createProtector('end to end');
      assert.equal(unprotect(protector, protector.encrypt('hello')), 'hello');
    } finally {
      await ring.close();
    }
  });

  it("decrypts pipeline values through a ring protector for the identifier's purpose", async () => {
    const { pipeline, key } = pipelineAndKey();
    const ring = await ringWithKey(key);
    try {
      assert.equal(unprotect(ring.createProtector(configurationPurpose(ID)), pipeline.encrypt('hello', ID)), 'hello');
    } finally {
      pipeline.close();
      await ring.close();
    }
  });

  it("decrypts ring values for the identifier's purpose through the pipeline protector", async () => {
    const { pipeline, key } = pipelineAndKey();
    const ring = await ringWithKey(key);
    try {
      const formatted = ring.createProtector(configurationPurpose(ID)).encrypt('hello');
      const result = new Uint8Array(16);
      assert.equal(new TextDecoder().decode(result.subarray(0, pipeline.decrypt(formatted, ID, result))), 'hello');
    } finally {
      pipeline.close();
      await ring.close();
    }
  });

  it('never decrypts pipeline values under a plain purpose of the same name', async () => {
    const { pipeline, key } = pipelineAndKey();
    const ring = await ringWithKey(key);
    try {
      assert.throws(() => unprotect(ring.createProtector(ID), pipeline.encrypt('hello', ID)), AuthenticationFailedError);
    } finally {
      pipeline.close();
      await ring.close();
    }
  });

  it('serves a protected cache', async () => {
    const ring = await ringWithKey(new Uint8Array(randomBytes(32)));
    try {
      const cache = new ProtectedCache(ring);
      cache.add('Api-Key', new TextEncoder().encode('secret'));
      const result = new Uint8Array((await cache.maxDecryptedLength('API-KEY'))!);
      assert.equal(new TextDecoder().decode(result.subarray(0, await cache.decrypt('api-key', result))), 'secret');
    } finally {
      await ring.close();
    }
  });

  it('decrypts at runtime every secret the pipeline encrypted into an appsettings.json', async () => {
    // Deploy time: the pipeline encrypts each secret for its configuration key into the file.
    const { pipeline, key } = pipelineAndKey();
    const secrets: Record<string, string> = {
      'ConnectionStrings:Admin': 'Server=db;Password=hunter2',
      'ConnectionStrings:Reporting': 'Server=db;Password=reporting',
      'Payments:ApiKey': 'pk_live_ünïcode_✓',
    };
    const document = JSON.stringify({
      ConnectionStrings: { Admin: pipeline.encrypt(secrets['ConnectionStrings:Admin']!, 'ConnectionStrings:Admin'), Reporting: pipeline.encrypt(secrets['ConnectionStrings:Reporting']!, 'ConnectionStrings:Reporting') },
      Payments: { ApiKey: pipeline.encrypt(secrets['Payments:ApiKey']!, 'Payments:ApiKey') },
      Logging: { Level: 'Information' },
    });
    pipeline.close();
    assert.ok(!document.includes('hunter2'), 'the configuration file holds a plaintext secret');

    // Runtime: the file is read, and each secret decrypted through a ring holding the same key.
    const ring = await ringWithKey(key);
    try {
      const values = flattenJson(document);
      const reader = new EncryptedConfigurationReader(ring, mapLookup(values));
      for (const [name, want] of Object.entries(secrets)) {
        for (const spelling of [name, name.toLowerCase()]) {
          const result = new Uint8Array((await reader.maxDecryptedLength(spelling))!);
          assert.equal(new TextDecoder().decode(result.subarray(0, await reader.decrypt(spelling, result))), want, spelling);
        }
      }

      // A secret moved to another key in the file fails rather than decrypting.
      const moved = new EncryptedConfigurationReader(ring, mapLookup({ ...values, 'ConnectionStrings:Reporting': values['ConnectionStrings:Admin']! }));
      await assert.rejects(moved.decrypt('ConnectionStrings:Reporting', new Uint8Array(64)), AuthenticationFailedError);
    } finally {
      await ring.close();
    }
  });
});

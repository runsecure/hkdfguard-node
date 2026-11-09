import { strict as assert } from 'node:assert';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import {
  IMAGE_DLLCHARACTERISTICS_GUARD_CF, LOAD_LIBRARY_SEARCH_SYSTEM32, peDependentLoadFlags, peDllCharacteristics,
} from '@runsecure/hkdfguard-test-support';

/*
 * Windows only: the add-on's own imports - crypt32 and ncrypt, neither a KnownDLL - resolve from
 * System32 only, never from its own folder (Node loads an add-on with LOAD_WITH_ALTERED_SEARCH_PATH),
 * so no DLL planted beside it signs or decrypts in the store's place; and it is built with Control
 * Flow Guard, as the other add-ons are.
 */

const ADDON = join(__dirname, '..', 'build', 'Release', 'hkdfguard_certificate.node');

describe('the certificate add-on', { skip: process.platform !== 'win32' && 'Windows only' }, () => {
  it('resolves the DLLs it imports from System32 only', () => {
    const flags = peDependentLoadFlags(ADDON);
    assert.equal(flags & LOAD_LIBRARY_SEARCH_SYSTEM32, LOAD_LIBRARY_SEARCH_SYSTEM32,
      `DependentLoadFlags is 0x${flags.toString(16)}; binding.gyp must link with /DEPENDENTLOADFLAG:0x800`);
  });

  it('is built with Control Flow Guard', () => {
    const characteristics = peDllCharacteristics(ADDON);
    assert.equal(characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF, IMAGE_DLLCHARACTERISTICS_GUARD_CF,
      `DllCharacteristics is 0x${characteristics.toString(16)}; binding.gyp must compile and link with /guard:cf`);
  });
});

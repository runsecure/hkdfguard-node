import { strict as assert } from 'node:assert';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { LOAD_LIBRARY_SEARCH_SYSTEM32, peDependentLoadFlags } from '@runsecure/hkdfguard-test-support';

/*
 * Windows only: the add-on's own imports - wintrust, crypt32 and version among them, none a
 * KnownDLL - resolve from System32 only. Node loads an add-on with LOAD_WITH_ALTERED_SEARCH_PATH,
 * so without /DEPENDENTLOADFLAG a wintrust.dll planted beside it would be the WinVerifyTrust that
 * decides whether HkdfGuard.dll is trusted. The port of the .NET NativeImportSearchPathTests.
 */

describe('the native add-on', { skip: process.platform !== 'win32' && 'Windows only' }, () => {
  it('resolves the DLLs it imports from System32 only', () => {
    const flags = peDependentLoadFlags(join(__dirname, '..', 'build', 'Release', 'hkdfguard_native.node'));
    assert.equal(flags & LOAD_LIBRARY_SEARCH_SYSTEM32, LOAD_LIBRARY_SEARCH_SYSTEM32,
      `DependentLoadFlags is 0x${flags.toString(16)}; binding.gyp must link with /DEPENDENTLOADFLAG:0x800`);
  });
});

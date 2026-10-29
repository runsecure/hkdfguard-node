import { strict as assert } from 'node:assert';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { LOAD_LIBRARY_SEARCH_SYSTEM32, peDependentLoadFlags } from '@runsecure/hkdfguard-test-support';

/*
 * Windows only: the add-on's own imports resolve from System32 only, never from its own folder
 * (Node loads an add-on with LOAD_WITH_ALTERED_SEARCH_PATH), so no DLL planted beside it answers
 * the owner, DACL and path questions the key-file rules are decided on. The port of the .NET
 * NativeImportSearchPathTests.
 */

describe('the securefile add-on', { skip: process.platform !== 'win32' && 'Windows only' }, () => {
  it('resolves the DLLs it imports from System32 only', () => {
    const flags = peDependentLoadFlags(join(__dirname, '..', 'build', 'Release', 'hkdfguard_securefile.node'));
    assert.equal(flags & LOAD_LIBRARY_SEARCH_SYSTEM32, LOAD_LIBRARY_SEARCH_SYSTEM32,
      `DependentLoadFlags is 0x${flags.toString(16)}; binding.gyp must link with /DEPENDENTLOADFLAG:0x800`);
  });
});

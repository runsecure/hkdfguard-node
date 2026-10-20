import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { isValidServiceName } from '@runsecure/hkdfguard-abstractions';
import { MAC_CODE_REQUIREMENT, MAC_TEAM_ID } from './macpolicy.js';
import { DEFAULT_TEST_SERVICE, UNPROVISIONED_SERVICE_NAME } from './testservices.test-support.js';
import { WIN_CODE_SIGNING_EKU, WIN_EXPECTED_PROFILE_EKU, WIN_EXPECTED_PUBLISHER, WIN_EXPECTED_ROOT_SHA256, WIN_FILE_NAME } from './windowspolicy.js';

// The provisioning scripts vet the native tool against the same pins the loader vets the library
// against, and provision the services the tests look for; this keeps them from drifting apart.

const script = (name: string) => readFileSync(join(__dirname, '..', 'scripts', name), 'utf8');

describe('provisioning scripts', () => {
  it("the Windows script pins what the loader pins", () => {
    const text = script('provision-windows-test-key.ps1');
    const pins: Record<string, string> = {
      ExpectedPublisher: WIN_EXPECTED_PUBLISHER,
      ExpectedRootSha256: WIN_EXPECTED_ROOT_SHA256,
      ExpectedProfileEku: WIN_EXPECTED_PROFILE_EKU,
      CodeSigningEku: WIN_CODE_SIGNING_EKU,
    };
    for (const [variable, want] of Object.entries(pins)) {
      assert.equal(new RegExp(`^\\$${variable} = '([^']*)'$`, 'm').exec(text)?.[1], want, variable);
    }
  });

  it('the Windows and Linux scripts run the installed hkdfguard tool', () => {
    assert.match(script('provision-windows-test-key.ps1'), /^\$tool = Join-Path \$programFiles 'HkdfGuard\\v1\\hkdfguard\.exe'$/m);
    assert.equal(WIN_FILE_NAME, 'HkdfGuard.dll');
    assert.match(script('provision-linux-test-key.sh'), /^readonly TOOL="\/usr\/bin\/hkdfguard"$/m);
    for (const name of ['provision-windows-test-key.ps1', 'provision-linux-test-key.sh']) assert.doesNotMatch(script(name), /v1-initialize|HkdfGuardV1/, name);
  });

  it("the macOS script pins the loader's team and requirement, naming the tool", () => {
    const text = script('provision-macos-test-key.sh');
    assert.equal(/^readonly TEAM_ID="([^"]*)"$/m.exec(text)?.[1], MAC_TEAM_ID);
    assert.equal(/^readonly REQUIREMENT='([^']*)'$/m.exec(text)?.[1],
      MAC_CODE_REQUIREMENT.replace('identifier "libhkdfguard_v1"', 'identifier "hkdfguard-v1-initialize"'));
  });

  it('each script provisions the one default service the tests look for', () => {
    const service = DEFAULT_TEST_SERVICE.replace(/[.]/g, '\\.');
    assert.match(script('provision-linux-test-key.sh'), new RegExp(`^readonly SERVICE="${service}"$`, 'm'));
    assert.match(script('provision-linux-test-key.sh'), /^readonly OTHER_SERVICE="\$\{SERVICE\}\.other"$/m);
    assert.match(script('provision-macos-test-key.sh'), new RegExp(`^readonly SERVICE="${service}"$`, 'm'));
    assert.match(script('provision-windows-test-key.ps1'), new RegExp(`^    \\[string\\] \\$ServiceName = '${service}',?$`, 'm'));
    for (const name of [DEFAULT_TEST_SERVICE, `${DEFAULT_TEST_SERVICE}.other`, UNPROVISIONED_SERVICE_NAME]) {
      assert.ok(isValidServiceName(name), name);
    }
  });

  it('the Linux script accepts a policy written by any port', () => {
    const text = script('provision-linux-test-key.sh');
    assert.match(text, /^readonly MARKER="# Written by hkdfguard-node packages\/keywrapping-native-v1\/scripts\/provision-linux-test-key\.sh - test hosts only\."$/m);
    // Every port's copy writes the same policy under its own marker, and accepts all five.
    for (const port of ['dotnet scripts', 'go keywrapping/nativev1/scripts', 'java scripts', 'node packages/keywrapping-native-v1/scripts', 'python scripts']) {
      assert.ok(text.includes(`    "# Written by hkdfguard-${port}/provision-linux-test-key.sh - test hosts only."\n`), port);
    }
    assert.match(text, /for marker in "\$\{KNOWN_MARKERS\[@\]\}"; do/);
  });
});

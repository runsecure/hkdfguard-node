import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { isValidServiceName } from '@runsecure/hkdfguard-abstractions';
import { MAC_CODE_REQUIREMENT, MAC_TEAM_ID } from './macpolicy.js';
import { DEFAULT_TEST_SERVICES, UNPROVISIONED_SERVICE_NAME } from './testservices.test-support.js';
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

  it('each script provisions the default service the tests look for', () => {
    const quote = (s: string) => s.replace(/[.]/g, '\\.');
    assert.match(script('provision-linux-test-key.sh'), new RegExp(`^readonly SERVICE="${quote(DEFAULT_TEST_SERVICES.linux!)}"$`, 'm'));
    assert.match(script('provision-linux-test-key.sh'), /^readonly OTHER_SERVICE="\$\{SERVICE\}\.other"$/m);
    assert.match(script('provision-macos-test-key.sh'), new RegExp(`^readonly SERVICE="${quote(DEFAULT_TEST_SERVICES.darwin!)}"$`, 'm'));
    assert.match(script('provision-windows-test-key.ps1'), new RegExp(`^    \\[string\\] \\$ServiceName = '${quote(DEFAULT_TEST_SERVICES.win32!)}'$`, 'm'));
    for (const name of [...Object.values(DEFAULT_TEST_SERVICES), `${DEFAULT_TEST_SERVICES.linux}.other`, UNPROVISIONED_SERVICE_NAME]) {
      assert.ok(isValidServiceName(name), name);
    }
  });

  it('the Linux script accepts a policy written by any port', () => {
    const text = script('provision-linux-test-key.sh');
    for (const marker of ['MARKER', 'GO_MARKER', 'DOTNET_MARKER']) assert.match(text, new RegExp(`^readonly ${marker}="# Written by `, 'm'));
    assert.match(text, /\$\{first\} == "\$\{MARKER\}" \|\| \$\{first\} == "\$\{GO_MARKER\}" \|\| \$\{first\} == "\$\{DOTNET_MARKER\}"/);
  });
});

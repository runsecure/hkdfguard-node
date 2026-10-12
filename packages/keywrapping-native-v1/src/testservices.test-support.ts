// The services the native integration tests run against - shared by native.test.ts and
// scripts.test.ts, which checks them against the provisioning scripts. Not part of the package.

export const TEST_SERVICE_VARIABLE = 'HKDFGUARD_TEST_SERVICE';
export const TEST_OTHER_SERVICE_VARIABLE = 'HKDFGUARD_TEST_SERVICE_OTHER';
export const UNPROVISIONED_SERVICE_NAME = 'hkdfguard.integrationtest.unprovisioned';

/** The test KEK each platform's provisioning script creates. */
export const DEFAULT_TEST_SERVICES: Record<string, string> = {
  win32: 'com.hkdfguard.native.windows.test', // scripts/provision-windows-test-key.ps1
  darwin: 'com.hkdfguard.native.macos.test', // scripts/provision-macos-test-key.sh
  linux: 'com.hkdfguard.native.linux.test', // scripts/provision-linux-test-key.sh
};

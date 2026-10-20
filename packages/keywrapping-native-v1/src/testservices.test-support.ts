// The services the native integration tests run against - shared by native.test.ts and
// scripts.test.ts, which checks them against the provisioning scripts. Not part of the package.

export const TEST_SERVICE_VARIABLE = 'HKDFGUARD_TEST_SERVICE';
export const TEST_OTHER_SERVICE_VARIABLE = 'HKDFGUARD_TEST_SERVICE_OTHER';
export const UNPROVISIONED_SERVICE_NAME = 'hkdfguard.integrationtest.unprovisioned';

/**
 * The test KEK every platform's provisioning script creates (scripts/provision-windows-test-key.ps1,
 * provision-macos-test-key.sh and provision-linux-test-key.sh) - one name shared by every HkdfGuard port.
 */
export const DEFAULT_TEST_SERVICE = 'com.hkdfguard.integration.test.221';

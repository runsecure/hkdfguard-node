#!/usr/bin/env bash
#
# Provisions the Secure Enclave KEK the native integration tests use on macOS.
#
# Runs the installed hkdfguard tool's "provision" command for the test service, which
# creates a Secure Enclave KEK for it in this account's login keychain, or finds the existing one.
# Safe to run repeatedly. It never wraps a DEK and never touches a key file.
#
# Before running the tool, the script checks that it is the signed HkdfGuard tool from the install
# location the library loader uses (system-wide first, then per-user), under the same anchor,
# Developer ID and team the loader requires of the library (macCodeRequirement in macpolicy.ts),
# so an impostor is never run.
#
# Run it as the account that runs the tests, never with sudo: in the native library's legacy
# keychain mode the KEK lives in the login keychain of whoever provisions it.
#
# Then, from the repository root, the native tests - the key wrapper's own and the end-to-end
# ones - find the service by themselves:
#
#   npm test --workspace packages/keywrapping-native-v1 --workspace packages/integration
#
# The KEK's keychain item names the binary that created it (this tool) on its access list, so the
# first native call from each node executable (a new Node.js version is a new one) is answered with
# a keychain dialog: click "Always Allow". From a session with no UI (ssh, a CI agent) the library reports
# kekAccessDenied (-18) instead, so run the tests from a logged-in session.
#
# Usage (from packages/keywrapping-native-v1):
#   scripts/provision-macos-test-key.sh            # provision
#   scripts/provision-macos-test-key.sh --remove   # retire the test KEK, by the fingerprint status reports
#
# Retiring a KEK makes everything wrapped under it permanently unrecoverable; the test KEK is only
# ever used by these tests.

set -euo pipefail

readonly SERVICE="com.hkdfguard.integration.test.221"
readonly TEAM_ID="MFW3T8R8J3"
readonly SYSTEM_DIR="/Library/Application Support/HkdfGuard/v1"
readonly USER_DIR="${HOME}/.hkdfguard/v1"
readonly LIBRARY="libhkdfguard.dylib"
readonly TOOL_NAME="hkdfguard"
# The loader's requirement for the library, naming the tool's identifier instead; keep it in step
# with macCodeRequirement in macpolicy.ts (scripts.test.ts checks).
readonly REQUIREMENT='identifier "hkdfguard" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "MFW3T8R8J3"'

die() { echo "error: $*" >&2; exit 1; }
note() { echo "==> $*"; }

[[ $(uname -s) == Darwin ]] || die "this script provisions a macOS Secure Enclave KEK and must run on macOS"
[[ $(uname -m) == arm64 ]] || die "the HkdfGuard native library requires Apple silicon; this Mac is $(uname -m)"
[[ ${EUID} -ne 0 ]] || die "run this as the account that runs the tests, not as root: the KEK is created in that account's login keychain"

remove=false
case "${1-}" in
    "") ;;
    --remove) remove=true ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument '$1' (expected --remove or nothing)" ;;
esac

# The install the loader would use: the system one whenever it exists, else the per-user one.
if [[ -e "${SYSTEM_DIR}/${LIBRARY}" ]]; then
    install_dir="${SYSTEM_DIR}"
elif [[ -e "${USER_DIR}/${LIBRARY}" ]]; then
    install_dir="${USER_DIR}"
else
    die "the HkdfGuard native library is not installed at '${SYSTEM_DIR}' or '${USER_DIR}'; install the native package first"
fi
tool="${install_dir}/${TOOL_NAME}"
[[ -x ${tool} ]] || die "${tool} is not installed beside the library"

note "checking the signature of ${tool}"
codesign --verify --strict -R="${REQUIREMENT}" "${tool}" \
    || die "${tool} is not validly signed by the HkdfGuard team (${TEAM_ID}); refusing to run it"

service_status() { "${tool}" status --service-name "${SERVICE}"; }

if ${remove}; then
    current="$(service_status)"
    if ! grep -q '^kek: present' <<<"${current}"; then
        note "no KEK is provisioned for ${SERVICE}; nothing to remove"
        exit 0
    fi
    fingerprint="$(sed -n 's/^fingerprint: //p' <<<"${current}")"
    [[ ${fingerprint} =~ ^[0-9a-f]{64}$ ]] || die "could not read the KEK's fingerprint from:"$'\n'"${current}"
    "${tool}" retire --service-name "${SERVICE}" --fingerprint "${fingerprint}"
    note "retired the KEK for ${SERVICE} (fingerprint ${fingerprint})"
    exit 0
fi

note "provisioning the KEK for ${SERVICE}"
"${tool}" provision --service-name "${SERVICE}"
note "status:"
service_status

cat <<EOT

Done. Run the native integration tests from the hkdfguard-node repository root; they find ${SERVICE} by themselves:

  npm test --workspace packages/keywrapping-native-v1 --workspace packages/integration

The first native call from each node executable shows a keychain dialog: click "Always Allow".
EOT

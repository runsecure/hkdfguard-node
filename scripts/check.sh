#!/usr/bin/env bash
#
# Every check CI runs, in one place, so a developer runs exactly what a pull request will: a clean
# install from the lockfile (which compiles the native add-on), a forced build of every package -
# one tsc build type-checks every platform's loader, whatever this host is - each package's tests,
# npm audit of the runtime dependencies, and a dry-run pack of each published package to check what
# it would ship. Stops at the first failure.
#
# Usage (from the repository root, or anywhere):
#   scripts/check.sh                                 # every package
#   scripts/check.sh packages/keywrapping-native-v1  # one or more package directories (tests only)
#
# Needs Node.js 22 or later. With an older node on PATH:
#   npx -y -p node@22 -c scripts/check.sh
#
# Environment:
#   HKDFGUARD_CHECK_INSTALL 0 skips the clean install (npm ci), keeping node_modules as it is.
#   HKDFGUARD_CHECK_AUDIT   0 skips npm audit (no network).
#   HKDFGUARD_TEST_SERVICE  a provisioned native service: the native round trips then run too.
#
# The native round trips (keywrapping-native-v1, and the end-to-end tests in packages/integration)
# are reported as skipped unless this host has a provisioned test service; see
# packages/keywrapping-native-v1/scripts.

set -euo pipefail

cd "$(dirname "$0")/.."

note() { echo; echo "==> $*"; }
die() { echo "error: $*" >&2; exit 1; }

command -v node >/dev/null || die "node is not on PATH"
node_major="$(node -p 'process.versions.node.split(".")[0]')"
[[ ${node_major} -ge 22 ]] || die "Node.js 22 or later is required (this is $(node --version)); run: npx -y -p node@22 -c scripts/check.sh"

# Every published package, in dependency order.
readonly PUBLISHED_PACKAGES=(
    packages/diagnostics
    packages/abstractions
    packages/cryptoprovider-aesgcm256
    packages/keywrapping-native-v1
    packages/dek
    packages/cache
    packages/encryptedconfig
)
# Tested, never published: the end-to-end tests across the packages over the native KEK.
readonly TEST_ONLY_PACKAGES=(packages/integration)
packages=("$@")
[[ ${#packages[@]} -gt 0 ]] || packages=("${PUBLISHED_PACKAGES[@]}" "${TEST_ONLY_PACKAGES[@]}")
for package in "${packages[@]}"; do
    [[ -f "${package}/package.json" ]] || die "${package} is not a package directory"
done

echo "node $(node --version), npm $(npm --version)"

if [[ ${HKDFGUARD_CHECK_INSTALL:-1} == 1 ]]; then
    note "clean install from package-lock.json (compiles the native add-on)"
    npm ci
fi

note "build: every package, type-checked for every platform"
node_modules/.bin/tsc --build --force

for package in "${packages[@]}"; do
    note "${package}: test"
    npm test --workspace "${package}"
done

[[ $# -eq 0 ]] || { note "checks passed for: $*"; exit 0; }

if [[ ${HKDFGUARD_CHECK_AUDIT:-1} == 1 ]]; then
    note "npm audit: runtime dependencies"
    npm audit --omit=dev
fi

note "pack: what each published package would ship"
for package in "${PUBLISHED_PACKAGES[@]}"; do
    npm pack --dry-run --json --workspace "${package}" 2>/dev/null | node -e '
        const [{ name, files }] = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
        const paths = files.map((f) => f.path);
        const problems = [];
        if (!paths.includes("dist/index.js") || !paths.includes("dist/index.d.ts")) problems.push("dist/index.js or dist/index.d.ts is missing");
        for (const path of paths) {
            if (/\.test(-support)?\./.test(path)) problems.push(`ships test file ${path}`);
            if (path.endsWith(".ts") && !path.endsWith(".d.ts")) problems.push(`ships TypeScript source ${path}`);
            if (path.startsWith("build/")) problems.push(`ships compiled add-on output ${path}`);
        }
        if (problems.length > 0) { console.error(`${name}:\n  ${problems.join("\n  ")}`); process.exit(1); }
        console.log(`${name}: ${paths.length} files`);
    '
done

note "all checks passed"

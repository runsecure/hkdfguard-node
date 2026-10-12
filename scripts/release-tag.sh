#!/usr/bin/env bash
#
# Turns a release tag into the version it releases, and checks every published package can be
# released at it. Prints key=value lines (what the release workflow writes to $GITHUB_OUTPUT):
#
#   version     the tag's version, without the v
#   prerelease  true for a 0.x version or one with a pre-release suffix (a GitHub pre-release)
#   dist_tag    the npm dist-tag to publish under: "next" for a pre-release suffix, else "latest"
#
# Every package is released together, at one version, by one tag: vMAJOR.MINOR.PATCH[-suffix].
# The tag is refused unless every published package's package.json already has that version, and
# every reference between them pins exactly that version - otherwise a consumer would install a
# mix of releases. scripts/set-version.mjs makes both true; commit its result, then tag.
#
# Usage: scripts/release-tag.sh <tag>

set -euo pipefail

cd "$(dirname "$0")/.."

die() { echo "error: $*" >&2; exit 1; }

tag="${1:?usage: scripts/release-tag.sh <tag>}"
readonly SEMVER='v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?'
[[ ${tag} =~ ^${SEMVER}$ ]] || die "tag '${tag}' is not vMAJOR.MINOR.PATCH (optionally -suffix)"
version="${tag#v}"

# Every published package (not private), and every @runsecure reference to one from any workspace.
node - "${version}" <<'EOF' || exit 1
const { readFileSync } = require('node:fs');
const version = process.argv[2];
const root = JSON.parse(readFileSync('package.json', 'utf8'));
const manifests = root.workspaces.map((w) => ({ dir: w, json: JSON.parse(readFileSync(`${w}/package.json`, 'utf8')) }));
const published = new Set(manifests.filter((m) => !m.json.private).map((m) => m.json.name));
const problems = [];
for (const { dir, json } of manifests) {
  if (published.has(json.name) && json.version !== version) {
    problems.push(`${dir}/package.json is version ${json.version}, not ${version}`);
  }
  for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    for (const [name, range] of Object.entries(json[field] ?? {})) {
      if (published.has(name) && range !== version) problems.push(`${dir}/package.json ${field} pins ${name} at "${range}", not "${version}"`);
    }
  }
}
if (problems.length > 0) {
  console.error(`error: not every package is at ${version}:\n  ${problems.join('\n  ')}\nRun: node scripts/set-version.mjs ${version} && npm install, commit, then tag.`);
  process.exit(1);
}
EOF

prerelease=false
[[ ${version} == 0.* || ${version} == *-* ]] && prerelease=true
dist_tag=latest
[[ ${version} == *-* ]] && dist_tag=next

cat <<EOT
version=${version}
prerelease=${prerelease}
dist_tag=${dist_tag}
EOT

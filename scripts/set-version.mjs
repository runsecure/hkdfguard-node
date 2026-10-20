#!/usr/bin/env node
//
// Sets every published package to one version, and every reference between them - from any
// workspace, published or not - to exactly that version, which is what scripts/release-tag.sh
// requires of a release. Edits the package.json files in place, keeping their formatting; run
// `npm install` afterwards so package-lock.json follows, then commit both and tag v<version>.
//
// Usage: node scripts/set-version.mjs <version>     e.g. 0.2.0, or 1.0.0-rc.1

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const version = process.argv[2];
if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$/.test(version ?? '')) {
  console.error('usage: node scripts/set-version.mjs <MAJOR.MINOR.PATCH[-suffix]>');
  process.exit(2);
}

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const workspaces = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).workspaces;
const files = workspaces.map((w) => join(root, w, 'package.json'));
const published = files
  .map((file) => JSON.parse(readFileSync(file, 'utf8')))
  .filter((json) => !json.private)
  .map((json) => json.name);

const escape = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
for (const file of files) {
  const text = readFileSync(file, 'utf8');
  let updated = text;
  if (!JSON.parse(text).private) {
    // The first "version" field is the package's own: name, then version, in every manifest here.
    updated = updated.replace(/("version"\s*:\s*)"[^"]*"/, `$1"${version}"`);
  }
  for (const name of published) {
    updated = updated.replace(new RegExp(`("${escape(name)}"\\s*:\\s*)"[^"]*"`, 'g'), `$1"${version}"`);
  }
  if (updated !== text) {
    JSON.parse(updated); // never write a manifest that no longer parses
    writeFileSync(file, updated);
    console.log(`updated ${file.slice(root.length + 1)}`);
  }
}
console.log(`\nEvery published package is now ${version}. Next: npm install, commit, git tag v${version}.`);

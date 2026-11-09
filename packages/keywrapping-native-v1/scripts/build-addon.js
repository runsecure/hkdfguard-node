#!/usr/bin/env node
//
// The package's install script: compiles the add-on that loads and calls the native KMS library
// (native/hkdfguard_native.c), on every platform.
//
// It runs node-gyp rebuild with this Node.js, never through a shell or a PATH lookup - as the
// securefile and options-certificate packages build theirs - so a node-gyp planted earlier on PATH,
// or a package manager that puts its own bin directories first, can't decide what compiles the code
// every DEK will pass through: the node-gyp npm runs install scripts with (npm sets
// npm_config_node_gyp to it), else a node-gyp installed as a package where this one is. It needs
// Python 3 and a C compiler (Visual Studio Build Tools on Windows, build-essential or the
// distribution's equivalent on Linux, the Xcode command line tools on macOS).

'use strict';

const { spawnSync } = require('node:child_process');

function findNodeGyp() {
  if (process.env.npm_config_node_gyp) return process.env.npm_config_node_gyp;
  try {
    return require.resolve('node-gyp/bin/node-gyp.js', { paths: [process.cwd(), __dirname] });
  } catch {
    return undefined;
  }
}

const nodeGyp = findNodeGyp();
if (nodeGyp === undefined) {
  console.error('Could not find node-gyp to build the HkdfGuard native key wrapper add-on: install with npm, which provides it, '
    + 'or add node-gyp to the project (npm install --save-dev node-gyp, or the equivalent for your package manager).');
  process.exit(1);
}

const result = spawnSync(process.execPath, [nodeGyp, 'rebuild'], { stdio: 'inherit' });
if (result.error) {
  console.error(`Could not run node-gyp: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status ?? 1);

#!/usr/bin/env node
//
// The package's install script. The add-on is only needed on Windows, where a key file's owner, DACL,
// reparse points, final path and drive type can only be read through Win32 calls; on Linux and macOS
// everything TrustedKeyFile checks is in Node's own fs, so nothing is built there and no C toolchain
// is needed to install the package.
//
// On Windows it runs node-gyp rebuild - the node-gyp npm runs install scripts with (npm sets
// npm_config_node_gyp to it), else one on PATH - which needs Python 3 and Visual Studio Build Tools.

'use strict';

const { spawnSync } = require('node:child_process');

if (process.platform !== 'win32') {
  process.exit(0);
}

const bundled = process.env.npm_config_node_gyp;
const result = bundled
  ? spawnSync(process.execPath, [bundled, 'rebuild'], { stdio: 'inherit' })
  : spawnSync('node-gyp.cmd', ['rebuild'], { stdio: 'inherit', shell: true });
if (result.error) {
  console.error(`Could not run node-gyp: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status ?? 1);

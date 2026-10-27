#!/usr/bin/env node
//
// The package's install script. The add-on is only needed on Windows, where a key file's owner, DACL,
// reparse points, final path and drive type can only be read through Win32 calls; on Linux and macOS
// everything TrustedKeyFile checks is in Node's own fs, so nothing is built there and no C toolchain
// is needed to install the package.
//
// On Windows it runs node-gyp rebuild with this Node.js, never through a shell or a PATH lookup: the
// node-gyp npm runs install scripts with (npm sets npm_config_node_gyp to it), else a node-gyp
// installed as a package where this one is. It needs Python 3 and Visual Studio Build Tools.

'use strict';

const { spawnSync } = require('node:child_process');

if (process.platform !== 'win32') {
  process.exit(0);
}

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
  console.error('Could not find node-gyp to build the HkdfGuard SecureFile add-on: install with npm, which provides it, '
    + 'or add node-gyp to the project (npm install --save-dev node-gyp, or the equivalent for your package manager).');
  process.exit(1);
}

const result = spawnSync(process.execPath, [nodeGyp, 'rebuild'], { stdio: 'inherit' });
if (result.error) {
  console.error(`Could not run node-gyp: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status ?? 1);

#!/usr/bin/env node
//
// The package's install script. The add-on reads what Node's fs can't: on Windows a file's owner,
// DACL, reparse points, final path and drive type; on Linux and macOS a path's access control list,
// which can grant write to accounts its permission bits don't show. Nothing is built elsewhere.
//
// It runs node-gyp rebuild with this Node.js, never through a shell or a PATH lookup: the node-gyp
// npm runs install scripts with (npm sets npm_config_node_gyp to it), else a node-gyp installed as
// a package where this one is. It needs Python 3 and a C compiler: Visual Studio Build Tools on
// Windows, build-essential (or the distribution's equivalent) on Linux, the Xcode command line tools
// on macOS.

'use strict';

const { spawnSync } = require('node:child_process');

if (!['win32', 'linux', 'darwin'].includes(process.platform)) {
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

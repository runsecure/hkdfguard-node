#!/usr/bin/env node
//
// The package's install script. The add-on is only needed where an operating system store holds the
// key - the Windows certificate store (crypt32 and CNG) and the macOS keychains (the Security
// framework); a file or a Linux OpenSSL provider key is reached through Node's own node:crypto and
// node:tls, so on Linux (and any other platform) nothing is built and no C toolchain is needed to
// install the package.
//
// On Windows and macOS it runs node-gyp rebuild with this Node.js, never through a shell or a PATH
// lookup: the node-gyp npm runs install scripts with (npm sets npm_config_node_gyp to it), else a
// node-gyp installed as a package where this one is. It needs Python 3 and a C compiler (Visual Studio
// Build Tools on Windows, the Xcode command line tools on macOS).

'use strict';

const { spawnSync } = require('node:child_process');

if (process.platform !== 'win32' && process.platform !== 'darwin') {
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
  console.error('Could not find node-gyp to build the HkdfGuard certificate add-on: install with npm, which provides it, '
    + 'or add node-gyp to the project (npm install --save-dev node-gyp, or the equivalent for your package manager).');
  process.exit(1);
}

const result = spawnSync(process.execPath, [nodeGyp, 'rebuild'], { stdio: 'inherit' });
if (result.error) {
  console.error(`Could not run node-gyp: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status ?? 1);

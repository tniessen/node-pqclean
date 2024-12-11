'use strict';

import { spawn } from 'node:child_process';
import * as events from 'node:events';
import { access, rm, writeFile } from 'node:fs/promises';

if (process.env.npm_lifecycle_event !== 'install') {
  console.error('Please use "npm install".');
  process.exit(1);
}

const backends = {
  // Try to compile the native addon; if that succeeds, use it. Otherwise, use
  // the WebAssembly module.
  'prefer-native': { wantNative: true },
  // Compile and use the native addon.
  'native': { wantNative: true, nativeRequired: true },
  // Do not compile the native addon; always use the WebAssembly module.
  'wasm': { wantNative: false },
};

const backendName = process.env.npm_config_pqclean_backend || 'prefer-native';
const backend = backends[backendName];
if (!backend) {
  console.error(`"backend" must be one of ${Object.keys(backends)}, found ` +
                `'${backendName}'.`);
  process.exit(1);
}

let wasmRequired = true;

if (backend.wantNative) {
  try {
    await access('native/gen/binding.gyp');
    await access('native/gen/algorithm-inl.h');
    console.log('Generated sources exist. To regenerate, please use "npm run regenerate-native".');
  } catch {
    const proc = spawn(process.env.npm_node_execpath || process.execPath, [
      process.env.npm_execpath, 'run', 'regenerate-native'
    ], {
      stdio: 'inherit'
    });
    const [code] = await events.once(proc, 'close');
    if (code === 0) {
      console.log('Successfully generated native source files.');
    } else {
      console.error('Generating native source files failed. Please check the output above.');
      process.exit(1);
    }
  }

  const proc = spawn(process.env.npm_node_execpath || process.execPath, [
    process.env.npm_execpath, 'run', 'build-native'
  ], {
    stdio: 'inherit'
  });
  const [code] = await events.once(proc, 'close');
  if (code === 0) {
    console.log('Successfully built native addon.');
    wasmRequired = false;
  } else {
    console.error('Building the native addon failed. Please check the output above.');
    if (backend.nativeRequired) {
      process.exit(1);
    }
  }
} else {
  await rm('build', { force: true, recursive: true });
}

if (wasmRequired) {
  try {
    await access('wasm/gen/pqclean.wasm');
    console.log('WebAssembly module exists. To rebuild, please use "npm run build-wasm".');
  } catch {
    const proc = spawn(process.env.npm_node_execpath || process.execPath, [
      process.env.npm_execpath, 'run', 'build-wasm'
    ], {
      stdio: 'inherit'
    });
    const [code] = await events.once(proc, 'close');
    if (code === 0) {
      console.log('Successfully built WebAssembly module.');
    } else {
      console.error('Building the WebAssembly module failed. Please check the output above.');
      process.exit(1);
    }
  }
}

await writeFile('install-config.gen.js', `module.exports.backend = '${backendName}';\n`);

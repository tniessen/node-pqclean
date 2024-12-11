'use strict';

const installConfig = require('./install-config.gen.js');

const { kem, sign, KEM, Sign } = (function loadBackend(backend) {
  switch (backend) {
    case 'prefer-native':
      try {
        return loadBackend('native');
      } catch (err) {
        // Use WebAssembly backend only if native bindings are not available.
        process.emitWarning(`Using WebAssembly backend: ${err.message}`);
        return loadBackend('wasm');
      }
    case 'native':
      return require('bindings')('node_pqclean');
    case 'wasm':
      return require('./wasm/');
    default:
      throw new Error(`Unsupported backend: ${backend}`);
  }
})(installConfig.backend);

// TODO: should we deep-freeze these?
Object.freeze(kem.supportedAlgorithms);
Object.freeze(sign.supportedAlgorithms);

Object.freeze(KEM.supportedAlgorithms);
Object.freeze(Sign.supportedAlgorithms);

Object.defineProperties(module.exports, {
  kem: { value: kem, enumerable: true },
  sign: { value: sign, enumerable: true },
  KEM: { value: KEM, enumerable: true },
  Sign: { value: Sign, enumerable: true }
});

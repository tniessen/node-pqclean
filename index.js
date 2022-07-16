'use strict';

let kem, sign, KEM, Sign;
try {
  // Try to load native bindings first.
  ({ kem, sign, KEM, Sign } = require('bindings')('node_pqclean'));
} catch (err) {
  // If native bindings are not available, use WebAssembly instead.
  ({ kem, sign, KEM, Sign } = require('./wasm/'));
  process.emitWarning(`Using WebAssembly backend: ${err.message}`);
}

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

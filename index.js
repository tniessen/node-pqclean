'use strict';

let KEM, Sign;
try {
  // Try to load native bindings first.
  ({ KEM, Sign } = require('bindings')('node_pqclean'));
} catch (err) {
  // If native bindings are not available, use WebAssembly instead.
  ({ KEM, Sign } = require('./wasm/'));
  process.emitWarning(`Using WebAssembly backend: ${err.message}`);
}

Object.freeze(KEM.supportedAlgorithms);
Object.freeze(Sign.supportedAlgorithms);

Object.defineProperties(module.exports, {
  KEM: { value: KEM },
  Sign: { value: Sign }
});

'use strict';

const { randomFillSync } = require('node:crypto');
const events = require('events');
const { readFileSync } = require('node:fs');
const { Worker } = require('node:worker_threads');

const algorithms = require('./gen/algorithms.json');

// The WebAssembly backend currently only supports background tasks through the
// newer key-centric API. The classic API instead simply schedules async work
// using setImmediate.
// TODO: either fix that or deprecate the classic API eventually.

const wasm = new WebAssembly.Module(readFileSync(`${__dirname}/gen/pqclean.wasm`));
const instance = new WebAssembly.Instance(wasm, {
  env: {
    PQCLEAN_randombytes(ptr, nBytes) {
      randomFillSync(mem(), ptr, nBytes);
    }
  },
  wasi_snapshot_preview1: {
    proc_exit() {
      throw new Error(`WebAssembly code requested exit through WASI (${[...arguments]})`);
    }
  }
});

const mem = () => Buffer.from(instance.exports.memory.buffer);
const store = (ptr, bytes) => mem().set(bytes, ptr);
const loadCopy = (ptr, size) => Uint8Array.prototype.slice.call(mem(), ptr, ptr + size);
const storeSize = (ptr, value) => mem().writeUInt32LE(value, ptr);
const loadSize = (ptr) => mem().readUInt32LE(ptr);

function scopedAlloc(size, fn) {
  const ptr = instance.exports.malloc(size);
  if (ptr === 0) {
    throw new Error('WebAssembly memory allocation failed');
  }

  function invoke(fn) {
    let escaped = false;
    function escape() {
      escaped = true;
      return invoke;
    }

    try {
      return fn(ptr, escape);
    } finally {
      if (!escaped) {
        // Overwrite dynamically allocated memory before free() to erase
        // sensitive data (e.g., private key or shared secret).
        mem().fill(0, ptr, ptr + size);
        instance.exports.free(ptr);
      }
    }
  }

  return invoke(fn);
}

const byName = (algorithm) => ({ properties: { name } }) => name === algorithm;

////////////////////////////////////////////////////////////////////////////////
// Classic API
////////////////////////////////////////////////////////////////////////////////

class KEM {
  #algorithm;

  constructor(algorithm) {
    if (arguments.length !== 1) {
      throw new TypeError('Wrong number of arguments');
    }

    if (typeof algorithm !== 'string') {
      throw new TypeError('First argument must be a string');
    }

    if ((this.#algorithm = algorithms.kem.find(byName(algorithm))) == null) {
      throw new Error('No such implementation');
    }
  }

  get algorithm() {
    return this.#algorithm.properties.name;
  }

  get description() {
    return this.#algorithm.properties.description;
  }

  get publicKeySize() {
    return this.#algorithm.properties.publicKeySize;
  }

  get privateKeySize() {
    return this.#algorithm.properties.privateKeySize;
  }

  get keySize() {
    return this.#algorithm.properties.keySize;
  }

  get encryptedKeySize() {
    return this.#algorithm.properties.encryptedKeySize;
  }

  keypair(callback) {
    if (arguments.length > 1) {
      throw new TypeError('Wrong number of arguments');
    }

    if (arguments.length === 1) {
      if (typeof callback !== 'function') {
        throw new TypeError('First argument must be a function');
      }

      setImmediate(() => {
        let result;
        try {
          result = this.keypair();
        } catch (err) {
          callback(err);
          return;
        }
        callback(undefined, result);
      });
    } else {
      const { privateKeySize, publicKeySize } = this.#algorithm.properties;

      return scopedAlloc(privateKeySize + publicKeySize, (ptr) => {
        const privateKeyPtr = ptr, publicKeyPtr = ptr + privateKeySize;
        const ret = instance.exports[this.#algorithm.functions.keypair](publicKeyPtr, privateKeyPtr);
        if (ret !== 0) {
          throw new Error('Failed to generate keypair');
        }

        const publicKey = loadCopy(publicKeyPtr, publicKeySize);
        const privateKey = loadCopy(privateKeyPtr, privateKeySize);
        return { publicKey, privateKey };
      });
    }
  }

  generateKey(publicKey, callback) {
    const { publicKeySize, keySize, encryptedKeySize } = this.#algorithm.properties;

    if (arguments.length !== 1 && arguments.length !== 2) {
      throw new TypeError('Wrong number of arguments');
    }

    if (!ArrayBuffer.isView(publicKey)) {
      // TODO: isView means ArrayBufferView, not TypedArray.
      throw new TypeError('First argument must be a TypedArray');
    }

    if (publicKey.byteLength !== publicKeySize) {
      throw new TypeError('Invalid public key size');
    }

    return scopedAlloc(publicKeySize, (publicKeyPtr, escapePublicKey) => {
      store(publicKeyPtr, publicKey);

      const generate = () => {
        return scopedAlloc(keySize + encryptedKeySize, (ptr) => {
          const keyPtr = ptr, encryptedKeyPtr = ptr + keySize;
          const ret = instance.exports[this.#algorithm.functions.enc](encryptedKeyPtr, keyPtr, publicKeyPtr);
          if (ret !== 0) {
            throw new Error('Encapsulation failed');
          }

          const key = loadCopy(keyPtr, keySize);
          const encryptedKey = loadCopy(encryptedKeyPtr, encryptedKeySize);
          return { key, encryptedKey };
        });
      };

      if (arguments.length === 2) {
        if (typeof callback !== 'function') {
          throw new TypeError('Second argument must be a function');
        }

        const publicKeyContext = escapePublicKey();
        setImmediate(() => {
          let result;
          try {
            result = publicKeyContext(() => generate());
          } catch (err) {
            callback(err);
            return;
          }
          callback(undefined, result);
        })
      } else {
        return generate();
      }
    });
  }

  decryptKey(privateKey, encryptedKey, callback) {
    const { privateKeySize, keySize, encryptedKeySize } = this.#algorithm.properties;

    if (arguments.length !== 2 && arguments.length !== 3) {
      throw new TypeError('Wrong number of arguments');
    }

    if (!ArrayBuffer.isView(privateKey)) {
      // TODO: isView means ArrayBufferView, not TypedArray.
      throw new TypeError('First argument must be a TypedArray');
    }

    if (privateKey.byteLength !== privateKeySize) {
      throw new TypeError('Invalid private key size');
    }

    if (!ArrayBuffer.isView(encryptedKey)) {
      // TODO: isView means ArrayBufferView, not TypedArray.
      throw new TypeError('Second argument must be a TypedArray');
    }

    if (encryptedKey.byteLength !== encryptedKeySize) {
      throw new TypeError('Invalid encrypted key size');
    }

    return scopedAlloc(privateKeySize + encryptedKeySize, (inPtr, escapeInput) => {
      const privateKeyPtr = inPtr, encryptedKeyPtr = inPtr + privateKeySize;
      store(privateKeyPtr, privateKey);
      store(encryptedKeyPtr, encryptedKey);

      const decrypt = () => {
        return scopedAlloc(keySize, (keyPtr) => {
          const ret = instance.exports[this.#algorithm.functions.dec](keyPtr, encryptedKeyPtr, privateKeyPtr);
          if (ret !== 0) {
            throw new Error('Decryption failed');
          }

          return loadCopy(keyPtr, keySize);
        });
      };

      if (arguments.length === 3) {
        if (typeof callback !== 'function') {
          throw new TypeError('Third argument must be a function');
        }

        const inputContext = escapeInput();
        setImmediate(() => {
          let result;
          try {
            result = inputContext(() => decrypt());
          } catch (err) {
            callback(err);
            return;
          }
          callback(undefined, result);
        })
      } else {
        return decrypt();
      }
    });
  }
}

Object.defineProperty(KEM, 'supportedAlgorithms', {
  value: algorithms.kem.map(({ properties: { name } }) => name)
});

class Sign {
  #algorithm;

  constructor(algorithm) {
    if (arguments.length !== 1) {
      throw new TypeError('Wrong number of arguments');
    }

    if (typeof algorithm !== 'string') {
      throw new TypeError('First argument must be a string');
    }

    if ((this.#algorithm = algorithms.sign.find(byName(algorithm))) == null) {
      throw new Error('No such implementation');
    }
  }

  get algorithm() {
    return this.#algorithm.properties.name;
  }

  get description() {
    return this.#algorithm.properties.description;
  }

  get publicKeySize() {
    return this.#algorithm.properties.publicKeySize;
  }

  get privateKeySize() {
    return this.#algorithm.properties.privateKeySize;
  }

  get signatureSize() {
    return this.#algorithm.properties.signatureSize;
  }

  keypair(callback) {
    if (arguments.length > 1) {
      throw new TypeError('Wrong number of arguments');
    }

    if (arguments.length === 1) {
      if (typeof callback !== 'function') {
        throw new TypeError('First argument must be a function');
      }

      setImmediate(() => {
        let result;
        try {
          result = this.keypair();
        } catch (err) {
          callback(err);
          return;
        }
        callback(undefined, result);
      });
    } else {
      const { privateKeySize, publicKeySize } = this.#algorithm.properties;

      return scopedAlloc(privateKeySize + publicKeySize, (ptr) => {
        const privateKeyPtr = ptr, publicKeyPtr = ptr + privateKeySize;
        const ret = instance.exports[this.#algorithm.functions.keypair](publicKeyPtr, privateKeyPtr);
        if (ret !== 0) {
          throw new Error('Failed to generate keypair');
        }

        const publicKey = loadCopy(publicKeyPtr, publicKeySize);
        const privateKey = loadCopy(privateKeyPtr, privateKeySize);
        return { publicKey, privateKey };
      });
    }
  }

  sign(privateKey, message, callback) {
    const { privateKeySize, signatureSize } = this.#algorithm.properties;

    if (arguments.length !== 2 && arguments.length !== 3) {
      throw new TypeError('Wrong number of arguments');
    }

    if (!ArrayBuffer.isView(privateKey)) {
      // TODO: isView means ArrayBufferView, not TypedArray.
      throw new TypeError('First argument must be a TypedArray');
    }

    if (privateKey.byteLength !== privateKeySize) {
      throw new TypeError('Invalid private key size');
    }

    if (!ArrayBuffer.isView(message)) {
      // TODO: isView means ArrayBufferView, not TypedArray.
      throw new TypeError('Second argument must be a TypedArray');
    }

    return scopedAlloc(privateKeySize + message.byteLength, (inPtr, escapeInput) => {
      const privateKeyPtr = inPtr, messagePtr = inPtr + privateKeySize;
      store(privateKeyPtr, privateKey);
      store(messagePtr, message);

      const sign = () => {
        return scopedAlloc(4 + signatureSize, (ptr) => {
          const signatureSizePtr = ptr, signaturePtr = ptr + 4;
          storeSize(signatureSizePtr, signatureSize);

          const ret = instance.exports[this.#algorithm.functions.signature](signaturePtr, signatureSizePtr, messagePtr, message.byteLength, privateKeyPtr);
          if (ret !== 0) {
            throw new Error('Sign operation failed');
          }

          const actualSize = loadSize(signatureSizePtr);
          if (actualSize > signatureSize) {
            throw new Error(`Actual signature size (${actualSize}) exceeds maximum size (${signatureSize}).`);
          }
          return loadCopy(signaturePtr, actualSize);
        });
      };

      if (arguments.length === 3) {
        if (typeof callback !== 'function') {
          throw new TypeError('Third argument must be a function');
        }

        const inputContext = escapeInput();
        setImmediate(() => {
          let result;
          try {
            result = inputContext(() => sign());
          } catch (err) {
            callback(err);
            return;
          }
          callback(undefined, result);
        })
      } else {
        return sign();
      }
    });
  }

  verify(publicKey, message, signature, callback) {
    const { publicKeySize, signatureSize } = this.#algorithm.properties;

    if (arguments.length !== 3 && arguments.length !== 4) {
      throw new TypeError('Wrong number of arguments');
    }

    if (!ArrayBuffer.isView(publicKey)) {
      // TODO: isView means ArrayBufferView, not TypedArray.
      throw new TypeError('First argument must be a TypedArray');
    }

    if (publicKey.byteLength !== publicKeySize) {
      throw new TypeError('Invalid public key size');
    }

    if (!ArrayBuffer.isView(message)) {
      // TODO: isView means ArrayBufferView, not TypedArray.
      throw new TypeError('Second argument must be a TypedArray');
    }

    if (!ArrayBuffer.isView(signature)) {
      // TODO: isView means ArrayBufferView, not TypedArray.
      throw new TypeError('Third argument must be a TypedArray');
    }

    if (signature.byteLength > signatureSize) {
      throw new TypeError('Invalid signature size');
    }

    return scopedAlloc(publicKeySize + signatureSize + message.byteLength, (inPtr, escapeInput) => {
      const publicKeyPtr = inPtr,
            signaturePtr = inPtr + publicKeySize,
            messagePtr = inPtr + publicKeySize + signatureSize;
      store(publicKeyPtr, publicKey);
      store(signaturePtr, signature);
      store(messagePtr, message);

      const verify = () => {
        // TODO: can we distinguish verification errors from other internal errors?
        return 0 === instance.exports[this.#algorithm.functions.verify](signaturePtr, signature.byteLength, messagePtr, message.byteLength, publicKeyPtr);
      };

      if (arguments.length === 4) {
        if (typeof callback !== 'function') {
          throw new TypeError('Fourth argument must be a function');
        }

        const inputContext = escapeInput();
        setImmediate(() => {
          let result;
          try {
            result = inputContext(() => verify());
          } catch (err) {
            callback(err);
            return;
          }
          callback(undefined, result);
        })
      } else {
        return verify();
      }
    });
  }
}

Object.defineProperty(Sign, 'supportedAlgorithms', {
  value: algorithms.sign.map(({ properties: { name } }) => name)
});

Object.assign(module.exports, { KEM, Sign });

////////////////////////////////////////////////////////////////////////////////
// Key-centric API
////////////////////////////////////////////////////////////////////////////////

Object.assign(module.exports, require('./key-centric').init(algorithms, async () => {
  const newWorker = new Worker(`${__dirname}/worker.js`, {
    workerData: { wasmModule: wasm }
  });
  await events.once(newWorker, 'online');
  return newWorker;
}));

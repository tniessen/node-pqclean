'use strict';

const { randomFillSync } = require('node:crypto');
const { readFileSync } = require('node:fs');
const os = require('node:os');
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

const maxWorkers = os.cpus().length;
const allWorkers = [];
const idleWorkers = [];
const queue = [];

function markWorkerIdle(worker) {
  const next = queue.shift();
  if (next) {
    runInIdleWorker(worker, next.task, next.resolve);
  } else {
    idleWorkers.push(worker);
    worker.unref();
  }
}

function runInIdleWorker(worker, task, resolve, reject) {
  worker.ref();
  worker.once('message', (response) => {
    markWorkerIdle(worker);
    if (response.memoryAllocationFailed) {
      reject(new Error('Memory allocation failed'));
    } else {
      resolve(response);
    }
  });
  worker.postMessage(task);
}

function runInWorker(task) {
  return new Promise((resolve, reject) => {
    const idleWorker = idleWorkers.shift();
    if (idleWorker !== undefined) {
      // There is a worker that is currently idle. Use it.
      runInIdleWorker(idleWorker, task, resolve, reject);
    } else {
      // No worker is idle right now, so add to the queue.
      const queueSize = queue.push({ task, resolve, reject });
      if (queueSize > allWorkers.length ** 2 && allWorkers.length < maxWorkers) {
        // There are too many tasks queued, spin up a new worker.
        const newWorker = new Worker(`${__dirname}/worker.js`, {
          workerData: { wasmModule: wasm }
        });
        // Add the worker to the list of workers to prevent more from being
        // created immediately, but only mark it as idle once it is online.
        allWorkers.push(newWorker);
        // TODO: error handling for workers
        newWorker.once('online', () => markWorkerIdle(newWorker));
      }
    }
  });
}

class PQCleanKEMPublicKey {
  #algorithm;
  #material;

  constructor(name, key) {
    if (arguments.length !== 2) {
      throw new TypeError('Wrong number of arguments');
    }

    if (typeof name !== 'string') {
      throw new TypeError('First argument must be a string');
    }

    if (key instanceof ArrayBuffer) {
      this.#material = key.slice(0);
    } else if (ArrayBuffer.isView(key)) {
      this.#material =
          key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength);
    } else {
      throw new TypeError('Second argument must be a BufferSource');
    }

    if ((this.#algorithm = algorithms.kem.find(byName(name))) == null) {
      throw new Error('No such implementation');
    }

    if (this.#material.byteLength !== this.#algorithm.properties.publicKeySize) {
      throw new Error('Invalid public key size');
    }
  }

  get algorithm() {
    return { ...this.#algorithm.properties };
  }

  export() {
    return this.#material.slice(0);
  }

  generateKey() {
    if (arguments.length !== 0) {
      throw new TypeError('Wrong number of arguments');
    }

    const { keySize, encryptedKeySize } = this.#algorithm.properties;
    return runInWorker({
      fn: this.#algorithm.functions.enc,
      inputs: [this.#material],
      outputs: [{ type: 'ArrayBuffer', byteLength: encryptedKeySize },
                { type: 'ArrayBuffer', byteLength: keySize }]
    }).then(({ result, outputs }) => {
      if (result !== 0) {
        return Promise.reject(new Error('Encapsulation failed'));
      } else {
        return Promise.resolve({ key: outputs[1], encryptedKey: outputs[0] });
      }
    });
  }
}

class PQCleanKEMPrivateKey {
  #algorithm;
  #material;

  constructor(name, key) {
    if (arguments.length !== 2) {
      throw new TypeError('Wrong number of arguments');
    }

    if (typeof name !== 'string') {
      throw new TypeError('First argument must be a string');
    }

    if (key instanceof ArrayBuffer) {
      this.#material = key.slice(0);
    } else if (ArrayBuffer.isView(key)) {
      this.#material =
          key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength);
    } else {
      throw new TypeError('Second argument must be a BufferSource');
    }

    if ((this.#algorithm = algorithms.kem.find(byName(name))) == null) {
      throw new Error('No such implementation');
    }

    if (this.#material.byteLength !== this.#algorithm.properties.privateKeySize) {
      throw new Error('Invalid private key size');
    }
  }

  get algorithm() {
    return { ...this.#algorithm.properties };
  }

  export() {
    return this.#material.slice(0);
  }

  decryptKey(encryptedKey) {
    if (arguments.length !== 1) {
      throw new TypeError('Wrong number of arguments');
    }

    let encryptedKeyArrayBuffer;
    if (encryptedKey instanceof ArrayBuffer) {
      encryptedKeyArrayBuffer = encryptedKey.slice();
    } else if (ArrayBuffer.isView(encryptedKey)) {
      encryptedKeyArrayBuffer = encryptedKey.buffer.slice(
          encryptedKey.byteOffset, encryptedKey.byteOffset + encryptedKey.byteLength);
    } else {
      throw new TypeError('First argument must be a BufferSource');
    }

    const { keySize, encryptedKeySize } = this.#algorithm.properties;
    if (encryptedKeyArrayBuffer.byteLength !== encryptedKeySize) {
      throw new Error('Invalid ciphertext size');
    }

    return runInWorker({
      fn: this.#algorithm.functions.dec,
      inputs: [encryptedKeyArrayBuffer, this.#material],
      outputs: [{ type: 'ArrayBuffer', byteLength: keySize }]
    }).then(({ result, outputs }) => {
      if (result !== 0) {
        return Promise.reject(new Error('Decryption failed'));
      } else {
        return Promise.resolve(outputs[0]);
      }
    });
  }
}

function generateKEMKeyPair(name) {
  if (arguments.length !== 1) {
    throw new TypeError('Wrong number of arguments');
  }

  if (typeof name !== 'string') {
    throw new TypeError('First argument must be a string');
  }

  const algorithm = algorithms.kem.find(byName(name));
  if (algorithm == null) {
    throw new Error('No such implementation');
  }

  const { publicKeySize, privateKeySize } = algorithm.properties;

  return runInWorker({
    fn: algorithm.functions.keypair,
    inputs: [],
    outputs: [{ type: 'ArrayBuffer', byteLength: publicKeySize},
              { type: 'ArrayBuffer', byteLength: privateKeySize } ]
  }).then(({ result, outputs }) => {
    if (result !== 0) {
      return Promise.reject(new Error('Failed to generate keypair'));
    } else {
      // TODO: avoid copying the output ArrayBuffers
      return Promise.resolve({
        publicKey: new PQCleanKEMPublicKey(name, outputs[0]),
        privateKey: new PQCleanKEMPrivateKey(name, outputs[1])
      });
    }
  });
}

class PQCleanSignPublicKey {
  #algorithm;
  #material;

  constructor(name, key) {
    if (arguments.length !== 2) {
      throw new TypeError('Wrong number of arguments');
    }

    if (typeof name !== 'string') {
      throw new TypeError('First argument must be a string');
    }

    if (key instanceof ArrayBuffer) {
      this.#material = key.slice(0);
    } else if (ArrayBuffer.isView(key)) {
      this.#material =
          key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength);
    } else {
      throw new TypeError('Second argument must be a BufferSource');
    }

    if ((this.#algorithm = algorithms.sign.find(byName(name))) == null) {
      throw new Error('No such implementation');
    }

    if (this.#material.byteLength !== this.#algorithm.properties.publicKeySize) {
      throw new Error('Invalid public key size');
    }
  }

  get algorithm() {
    return { ...this.#algorithm.properties };
  }

  export() {
    return this.#material.slice(0);
  }

  verify(message, signature) {
    if (arguments.length !== 2) {
      throw new TypeError('Wrong number of arguments');
    }

    let messageArrayBuffer;
    if (message instanceof ArrayBuffer) {
      messageArrayBuffer = message.slice();
    } else if (ArrayBuffer.isView(message)) {
      messageArrayBuffer = message.buffer.slice(
          message.byteOffset, message.byteOffset + message.byteLength);
    } else {
      throw new TypeError('First argument must be a BufferSource');
    }

    let signatureArrayBuffer;
    if (signature instanceof ArrayBuffer) {
      signatureArrayBuffer = signature.slice();
    } else if (ArrayBuffer.isView(signature)) {
      signatureArrayBuffer = signature.buffer.slice(
          signature.byteOffset, signature.byteOffset + signature.byteLength);
    } else {
      throw new TypeError('Second argument must be a BufferSource');
    }

    const { signatureSize: maxSignatureSize } = this.#algorithm.properties;
    if (signatureArrayBuffer.byteLength > maxSignatureSize) {
      throw new Error('Invalid signature size');
    }

    return runInWorker({
      fn: this.#algorithm.functions.verify,
      inputs: [
        signatureArrayBuffer, signatureArrayBuffer.byteLength,
        messageArrayBuffer, messageArrayBuffer.byteLength,
        this.#material
      ],
      outputs: []
    }).then(({ result }) => {
      // TODO: can we distinguish verification errors from other internal errors?
      return Promise.resolve(result === 0);
    })
  }
}

class PQCleanSignPrivateKey {
  #algorithm;
  #material;

  constructor(name, key) {
    if (arguments.length !== 2) {
      throw new TypeError('Wrong number of arguments');
    }

    if (typeof name !== 'string') {
      throw new TypeError('First argument must be a string');
    }

    if (key instanceof ArrayBuffer) {
      this.#material = key.slice(0);
    } else if (ArrayBuffer.isView(key)) {
      this.#material =
          key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength);
    } else {
      throw new TypeError('Second argument must be a BufferSource');
    }

    if ((this.#algorithm = algorithms.sign.find(byName(name))) == null) {
      throw new Error('No such implementation');
    }

    if (this.#material.byteLength !== this.#algorithm.properties.privateKeySize) {
      throw new Error('Invalid private key size');
    }
  }

  get algorithm() {
    return { ...this.#algorithm.properties };
  }

  export() {
    return this.#material.slice(0);
  }

  sign(message) {
    if (arguments.length !== 1) {
      throw new TypeError('Wrong number of arguments');
    }

    let messageArrayBuffer;
    if (message instanceof ArrayBuffer) {
      messageArrayBuffer = message.slice();
    } else if (ArrayBuffer.isView(message)) {
      messageArrayBuffer = message.buffer.slice(
          message.byteOffset, message.byteOffset + message.byteLength);
    } else {
      throw new TypeError('First argument must be a BufferSource');
    }

    const { signatureSize } = this.#algorithm.properties;
    const messageSize = messageArrayBuffer.byteLength;

    return runInWorker({
      fn: this.#algorithm.functions.signature,
      inputs: [messageArrayBuffer, messageSize, this.#material],
      outputs: [{ type: 'ArrayBuffer', byteLength: signatureSize },
                { type: 'u32', init: signatureSize }]
    }).then(({ result, outputs }) => {
      if (result !== 0) {
        return Promise.reject(new Error('Sign operation failed'));
      } else {
        // TODO: avoid copying here by somehow getting the properly sized
        // ArrayBuffer from the worker directly.
        const actualSize = outputs[1];
        if (actualSize > signatureSize) {
          return Promise.reject(
              new Error(`Actual signature size (${actualSize}) exceeds maximum size (${signatureSize}).`));
        }
        return Promise.resolve(outputs[0].slice(0, actualSize));
      }
    });
  }
}

function generateSignKeyPair(name) {
  if (arguments.length !== 1) {
    throw new TypeError('Wrong number of arguments');
  }

  if (typeof name !== 'string') {
    throw new TypeError('First argument must be a string');
  }

  const algorithm = algorithms.sign.find(byName(name));
  if (algorithm == null) {
    throw new Error('No such implementation');
  }

  const { publicKeySize, privateKeySize } = algorithm.properties;

  return runInWorker({
    fn: algorithm.functions.keypair,
    inputs: [],
    outputs: [{ type: 'ArrayBuffer', byteLength: publicKeySize},
              { type: 'ArrayBuffer', byteLength: privateKeySize } ]
  }).then(({ result, outputs }) => {
    if (result !== 0) {
      return Promise.reject(new Error('Failed to generate keypair'));
    } else {
      // TODO: avoid copying the output ArrayBuffers
      return Promise.resolve({
        publicKey: new PQCleanSignPublicKey(name, outputs[0]),
        privateKey: new PQCleanSignPrivateKey(name, outputs[1])
      });
    }
  });
}

Object.assign(module.exports, {
  kem: Object.defineProperties({}, {
    PublicKey: { value: PQCleanKEMPublicKey },
    PrivateKey: { value: PQCleanKEMPrivateKey },
    generateKeyPair: { value: generateKEMKeyPair },
    supportedAlgorithms: {
      value: algorithms.kem.map(({ properties }) => ({ ...properties }))
    }
  }),
  sign: Object.defineProperties({}, {
    PublicKey: { value: PQCleanSignPublicKey },
    PrivateKey: { value: PQCleanSignPrivateKey },
    generateKeyPair: { value: generateSignKeyPair },
    supportedAlgorithms: {
      value: algorithms.sign.map(({ properties }) => ({ ...properties }))
    }
  })
});

'use strict';

const { randomFillSync } = require('node:crypto');

const algorithms = require('./gen/algorithms.json');

// The WebAssembly backend currently does not support background tasks, instead,
// async operations are simply scheduled using setImmediate.
// TODO: fix that (e.g., using worker threads)

const wasm = new WebAssembly.Module(require('fs').readFileSync(`${__dirname}/gen/pqclean.wasm`));
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
const loadSlice = (ptr, size) => instance.exports.memory.buffer.slice(ptr, ptr + size);
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

function fakeAsync(fn) {
  return new Promise((resolve, reject) => {
    setImmediate(() => fn().then(resolve, reject));
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
      this.#material = key.buffer.slice(key.byteOffset, key.byteLength);
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

    return fakeAsync(async () => {
      const { publicKeySize, keySize, encryptedKeySize } = this.#algorithm.properties;

      return scopedAlloc(publicKeySize + keySize + encryptedKeySize, (ptr) => {
        const publicKeyPtr = ptr, keyPtr = ptr + publicKeySize, encryptedKeyPtr = ptr + publicKeySize + keySize;
        store(publicKeyPtr, new Uint8Array(this.#material));

        const ret = instance.exports[this.#algorithm.functions.enc](encryptedKeyPtr, keyPtr, publicKeyPtr);
        if (ret !== 0) {
          throw new Error('Encapsulation failed');
        }

        const key = loadSlice(keyPtr, keySize);
        const encryptedKey = loadSlice(encryptedKeyPtr, encryptedKeySize);
        return { key, encryptedKey };
      });
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
      this.#material = key.buffer.slice(key.byteOffset, key.byteLength);
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

    let encryptedKeyTypedArray;
    if (encryptedKey instanceof ArrayBuffer) {
      encryptedKeyTypedArray = new Uint8Array(encryptedKey);
    } else if (ArrayBuffer.isView(encryptedKey)) {
      if (encryptedKey instanceof DataView) {
        encryptedKeyTypedArray = new Uint8Array(encryptedKey.buffer, encryptedKey.byteOffset, encryptedKey.byteLength);
      } else {
        encryptedKeyTypedArray = encryptedKey;
      }
    } else {
      throw new TypeError('First argument must be a BufferSource');
    }

    const { privateKeySize, keySize, encryptedKeySize } = this.#algorithm.properties;
    if (encryptedKeyTypedArray.byteLength !== encryptedKeySize) {
      throw new Error('Invalid ciphertext size');
    }

    return scopedAlloc(encryptedKeySize, (encryptedKeyPtr, escapeEncryptedKey) => {
      store(encryptedKeyPtr, encryptedKeyTypedArray);

      const encryptedKeyContext = escapeEncryptedKey();
      return fakeAsync(async () => encryptedKeyContext(() => {
        return scopedAlloc(privateKeySize + keySize, (ptr) => {
          const privateKeyPtr = ptr, keyPtr = ptr + privateKeySize;
          store(privateKeyPtr, new Uint8Array(this.#material));

          const ret = instance.exports[this.#algorithm.functions.dec](keyPtr, encryptedKeyPtr, privateKeyPtr);
          if (ret !== 0) {
            throw new Error('Decryption failed');
          }

          return loadSlice(keyPtr, keySize);
        });
      }));
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

  return fakeAsync(async () => {
    const { privateKeySize, publicKeySize } = algorithm.properties;

    return scopedAlloc(privateKeySize + publicKeySize, (ptr) => {
      const privateKeyPtr = ptr, publicKeyPtr = ptr + privateKeySize;
      const ret = instance.exports[algorithm.functions.keypair](publicKeyPtr, privateKeyPtr);
      if (ret !== 0) {
        throw new Error('Failed to generate keypair');
      }

      // TODO: avoid all the copying, maybe just maintain a pointer to the
      // WebAssembly memory.
      return {
        publicKey: new PQCleanKEMPublicKey(name, loadSlice(publicKeyPtr, publicKeySize)),
        privateKey: new PQCleanKEMPrivateKey(name, loadSlice(privateKeyPtr, privateKeySize))
      };
    });
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
      this.#material = key.buffer.slice(key.byteOffset, key.byteLength);
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

    let messageTypedArray;
    if (message instanceof ArrayBuffer) {
      messageTypedArray = new Uint8Array(message);
    } else if (ArrayBuffer.isView(message)) {
      if (message instanceof DataView) {
        messageTypedArray = new Uint8Array(message.buffer, message.byteOffset, message.byteLength);
      } else {
        messageTypedArray = message;
      }
    } else {
      throw new TypeError('First argument must be a BufferSource');
    }

    let signatureTypedArray;
    if (signature instanceof ArrayBuffer) {
      signatureTypedArray = new Uint8Array(signature);
    } else if (ArrayBuffer.isView(signature)) {
      if (signature instanceof DataView) {
        signatureTypedArray = new Uint8Array(signature.buffer, signature.byteOffset, signature.byteLength);
      } else {
        signatureTypedArray = signature;
      }
    } else {
      throw new TypeError('Second argument must be a BufferSource');
    }

    const messageSize = messageTypedArray.byteLength;
    const signatureSize = signatureTypedArray.byteLength;

    const { publicKeySize, signatureSize: maxSignatureSize } = this.#algorithm.properties;

    if (signatureSize > maxSignatureSize) {
      throw new Error('Invalid signature size');
    }

    return scopedAlloc(messageSize + signatureSize, (inputPtr, escapeInput) => {
      const messagePtr = inputPtr, signaturePtr = inputPtr + messageSize;
      store(messagePtr, messageTypedArray);
      store(signaturePtr, signatureTypedArray);

      const inputContext = escapeInput();
      return fakeAsync(async () => inputContext(() => {
        return scopedAlloc(publicKeySize, (publicKeyPtr) => {
          store(publicKeyPtr, new Uint8Array(this.#material));

          // TODO: can we distinguish verification errors from other internal errors?
          return 0 === instance.exports[this.#algorithm.functions.verify](signaturePtr, signatureSize, messagePtr, messageSize, publicKeyPtr);
        });
      }));
    });
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
      this.#material = key.buffer.slice(key.byteOffset, key.byteLength);
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

    let messageTypedArray;
    if (message instanceof ArrayBuffer) {
      messageTypedArray = new Uint8Array(message);
    } else if (ArrayBuffer.isView(message)) {
      if (message instanceof DataView) {
        messageTypedArray = new Uint8Array(message.buffer, message.byteOffset, message.byteLength);
      } else {
        messageTypedArray = message;
      }
    } else {
      throw new TypeError('First argument must be a BufferSource');
    }

    const { privateKeySize, signatureSize } = this.#algorithm.properties;

    const messageSize = messageTypedArray.byteLength;
    return scopedAlloc(messageSize, (messagePtr, escapeMessage) => {
      store(messagePtr, messageTypedArray);

      const messageContext = escapeMessage();
      return fakeAsync(async () => messageContext(() => {
        return scopedAlloc(privateKeySize + 4 + signatureSize, (ptr) => {
          const privateKeyPtr = ptr, signatureSizePtr = ptr + privateKeySize, signaturePtr = ptr + privateKeySize + 4;
          store(privateKeyPtr, new Uint8Array(this.#material));
          storeSize(signatureSizePtr, signatureSize);

          const ret = instance.exports[this.#algorithm.functions.signature](signaturePtr, signatureSizePtr, messagePtr, messageSize, privateKeyPtr);
          if (ret !== 0) {
            throw new Error('Sign operation failed');
          }

          const actualSize = loadSize(signatureSizePtr);
          if (actualSize > signatureSize) {
            throw new Error(`Actual signature size (${actualSize}) exceeds maximum size (${signatureSize}).`);
          }

          return loadSlice(signaturePtr, actualSize);
        });
      }));
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

  return fakeAsync(async () => {
    const { privateKeySize, publicKeySize } = algorithm.properties;

    return scopedAlloc(privateKeySize + publicKeySize, (ptr) => {
      const privateKeyPtr = ptr, publicKeyPtr = ptr + privateKeySize;
      const ret = instance.exports[algorithm.functions.keypair](publicKeyPtr, privateKeyPtr);
      if (ret !== 0) {
        throw new Error('Failed to generate keypair');
      }

      // TODO: avoid all the copying, maybe just maintain a pointer to the
      // WebAssembly memory.
      return {
        publicKey: new PQCleanSignPublicKey(name, loadSlice(publicKeyPtr, publicKeySize)),
        privateKey: new PQCleanSignPrivateKey(name, loadSlice(privateKeyPtr, privateKeySize))
      };
    });
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

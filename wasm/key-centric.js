'use strict';

module.exports.init = (algorithms, createWorker) => {
  const byName = (algorithm) => ({ properties: { name } }) => name === algorithm;

  const maxWorkers = (() => {
    if (typeof navigator === 'object' && navigator.hardwareConcurrency) {
      return navigator.hardwareConcurrency;
    } else if (typeof require === 'function') {
      const os = require('node:os');
      if (typeof os.availableParallelism === 'function') {
        return os.availableParallelism();
      } else {
        return os.cpus().length;
      }
    } else {
      return 2;
    }
  })();

  let nWorkers = 0;
  const idleWorkers = [];
  const queue = [];

  function markWorkerIdle(worker) {
    const next = queue.shift();
    if (next) {
      runInIdleWorker(worker, next.task, next.resolve, next.reject);
    } else {
      idleWorkers.push(worker);
      if (typeof worker.unref === 'function') {
        // In Node.js, do not explicitly terminate idle workers, but allow the
        // runtime to do so if no other threads have work left to do.
        worker.unref();
      } else if (idleWorkers.length === nWorkers) {
        // In runtimes such as deno, we need to manually manage the lifetime of
        // our worker threads to prevent them from keeping the process alive
        // after all other threads are done. To prevent that, if all workers are
        // idle, schedule a macrotask, which, when invoked, checks if all
        // workers are still idle and then terminates all of them.
        setTimeout(() => {
          if (idleWorkers.length === nWorkers) {
            nWorkers = 0;
            for (const worker of idleWorkers.splice(0)) {
              worker.terminate();
            }
          }
        }, 0);
      }
    }
  }

  function runInIdleWorker(worker, task, resolve, reject) {
    if (typeof worker.ref === 'function') worker.ref();
    const isEventTarget = typeof worker.addEventListener === 'function';
    worker[isEventTarget ? 'addEventListener' : 'once']('message', function onResponse(response) {
      isEventTarget && worker.removeEventListener('message', onResponse);
      markWorkerIdle(worker);
      response = response.data || response;
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
        if (queueSize > nWorkers ** 2 && nWorkers < maxWorkers) {
          // There are too many tasks queued, spin up a new worker.
          nWorkers++;
          createWorker().then((newWorker) => {
            markWorkerIdle(newWorker);
          }, (err) => {
            if (!--nWorkers) {
              for (const { reject } of queue.splice(0)) {
                reject(err);
              }
            }
          });
        }
      }
    });
  }

  const internal = Symbol();

  class PQCleanKEMPublicKey {
    #algorithm;
    #material;

    constructor(name, key) {
      if (arguments.length === 1 && typeof name === 'object' && internal in name) {
        [this.#algorithm, this.#material] = name[internal];
        return;
      }

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
      if (arguments.length === 1 && typeof name === 'object' && internal in name) {
        [this.#algorithm, this.#material] = name[internal];
        return;
      }

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
        return Promise.resolve({
          publicKey: new PQCleanKEMPublicKey({ [internal]: [algorithm, outputs[0]] }),
          privateKey: new PQCleanKEMPrivateKey({ [internal]: [algorithm, outputs[1]] })
        });
      }
    });
  }

  class PQCleanSignPublicKey {
    #algorithm;
    #material;

    constructor(name, key) {
      if (arguments.length === 1 && typeof name === 'object' && internal in name) {
        [this.#algorithm, this.#material] = name[internal];
        return;
      }

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

    open(signedMessage) {
      if (arguments.length !== 1) {
        throw new TypeError('Wrong number of arguments');
      }

      let signedMessageArrayBuffer;
      if (signedMessage instanceof ArrayBuffer) {
        signedMessageArrayBuffer = signedMessage.slice();
      } else if (ArrayBuffer.isView(signedMessage)) {
        signedMessageArrayBuffer = signedMessage.buffer.slice(
            signedMessage.byteOffset,
            signedMessage.byteOffset + signedMessage.byteLength);
      } else {
        throw new TypeError('First argument must be a BufferSource');
      }

      const messageSize = signedMessageArrayBuffer.byteLength;

      return runInWorker({
        fn: this.#algorithm.functions.open,
        inputs: [signedMessageArrayBuffer, messageSize, this.#material],
        outputs: [{ type: 'ArrayBuffer', byteLength: messageSize },
                  { type: 'u32', init: messageSize }]
      }).then(({ result, outputs }) => {
        if (result !== 0) {
          return Promise.reject(new Error('Open operation failed'));
        } else {
          // TODO: avoid copying here by somehow getting the properly sized
          // ArrayBuffer from the worker directly.
          const actualSize = outputs[1];
          return Promise.resolve(outputs[0].slice(0, actualSize));
        }
      });
    }
  }

  class PQCleanSignPrivateKey {
    #algorithm;
    #material;

    constructor(name, key) {
      if (arguments.length === 1 && typeof name === 'object' && internal in name) {
        [this.#algorithm, this.#material] = name[internal];
        return;
      }

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

    signEmbed(message) {
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
      const signedMessageSize = messageSize + signatureSize;

      return runInWorker({
        fn: this.#algorithm.functions.sign,
        inputs: [messageArrayBuffer, messageSize, this.#material],
        outputs: [{ type: 'ArrayBuffer', byteLength: signedMessageSize },
                  { type: 'u32', init: signedMessageSize }]
      }).then(({ result, outputs }) => {
        if (result !== 0) {
          return Promise.reject(new Error('Sign operation failed'));
        } else {
          // TODO: avoid copying here by somehow getting the properly sized
          // ArrayBuffer from the worker directly.
          const actualSize = outputs[1];
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
        return Promise.resolve({
          publicKey: new PQCleanSignPublicKey({ [internal]: [algorithm, outputs[0]] }),
          privateKey: new PQCleanSignPrivateKey({ [internal]: [algorithm, outputs[1]] })
        });
      }
    });
  }

  return {
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
  };
};

'use strict';

const randomBytes = (typeof crypto === 'object' && crypto.getRandomValues.bind(crypto)) || require('node:crypto').randomFillSync;

const isWebWorker = typeof WorkerGlobalScope !== 'undefined' && self instanceof WorkerGlobalScope;
const parentPort = isWebWorker ? self : require('node:worker_threads').parentPort;

const instance = new WebAssembly.Instance(typeof wasmModule === 'object' ? wasmModule : require('node:worker_threads').workerData.wasmModule, {
  env: {
    PQCLEAN_randombytes(ptr, nBytes) {
      randomBytes(new Uint8Array(instance.exports.memory.buffer, ptr, nBytes));
    }
  },
  wasi_snapshot_preview1: {
    proc_exit() {
      throw new Error(`WebAssembly code requested exit through WASI (${[...arguments]})`);
    }
  }
});

const store = (ptr, bytes) => new Uint8Array(instance.exports.memory.buffer).set(bytes, ptr);
const loadSlice = (ptr, size) => instance.exports.memory.buffer.slice(ptr, ptr + size);
const storeU32 = (ptr, value) => new DataView(instance.exports.memory.buffer).setUint32(ptr, value, true);
const loadU32 = (ptr) => new DataView(instance.exports.memory.buffer).getUint32(ptr, true);

parentPort.addEventListener('message', (event) => {
  const { fn, outputs, inputs } = event.data;
  let alloc = 0;
  for (const o of outputs) {
    if (o.type === 'u32') alloc += 4;
    else alloc += o.byteLength;
  }
  for (const i of inputs) {
    if (typeof i !== 'number') {
      alloc += i.byteLength;
    }
  }

  const ptr = instance.exports.malloc(alloc);
  if (ptr === 0) {
    parentPort.postMessage({ memoryAllocationFailed: true });
    return;
  }

  try {
    let offset = ptr;
    const outputArgs = outputs.map((output) => {
      if (output.type === 'u32') {
        const { init } = output;
        storeU32(offset, init);
        return (offset += 4) - 4;
      } else if (output.type === 'ArrayBuffer') {
        const { byteLength } = output;
        return (offset += byteLength) - byteLength;
      }
    });
    const inputArgs = inputs.map((input) => {
      if (typeof input === 'number') {
        return input;
      } else {
        store(offset, new Uint8Array(input));
        return (offset += input.byteLength) - input.byteLength;
      }
    });

    const result = instance.exports[fn](...outputArgs, ...inputArgs);
    const outputValues = outputs.map((output, i) => {
      const offset = outputArgs[i];
      if (output.type === 'u32') {
        return loadU32(offset);
      } else if (output.type === 'ArrayBuffer') {
        const { byteLength } = output;
        return loadSlice(offset, byteLength);
      }
    });

    parentPort.postMessage({ result, outputs: outputValues },
                           outputValues.filter((v) => v instanceof ArrayBuffer));
  } finally {
    instance.exports.free(ptr);
  }
});

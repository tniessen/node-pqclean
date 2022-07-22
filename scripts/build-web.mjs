import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';

const moduleCode = await readFile('wasm/key-centric.js', 'utf8');
const algorithms = JSON.parse(await readFile('wasm/gen/algorithms.json', 'utf8'));
const workerCode = await readFile('wasm/worker.js', 'utf8');

await mkdir('web/dist', { recursive: true });

const workerWrapped = `'use strict';
self.addEventListener('message', function startWorker(initMessage) {
  self.removeEventListener('message', startWorker);
  const wasmModule = initMessage.data;
  (() => {${workerCode}})();
});`;

await writeFile('web/dist/pqclean.nomodule.js', `'use strict';
const initObj = { exports: {} };
(function(module) {
${moduleCode}
})(initObj);
const scriptURL = document.currentScript.src;
(typeof globalThis !== 'undefined' ? globalThis : window).PQClean = initObj.exports.init(${JSON.stringify(algorithms)}, () => {
  return fetch(new URL('pqclean.wasm', scriptURL)).then((wasmResponse) => {
    return WebAssembly.compileStreaming(wasmResponse);
  }).then((wasmModule) => {
    const worker = new Worker('data:text/javascript,${encodeURIComponent(workerWrapped).replace(/'/g, '%27')}');
    worker.postMessage(wasmModule);
    return worker;
  });
});
`);

await writeFile('web/dist/pqclean.js', `const initObj = { exports: {} };
(function(module) {
${moduleCode}
})(initObj);
export default initObj.exports.init(${JSON.stringify(algorithms)}, () => {
  return fetch(new URL('pqclean.wasm', import.meta.url)).then((wasmResponse) => {
    return WebAssembly.compileStreaming(wasmResponse);
  }).then((wasmModule) => {
    const worker = new Worker('data:text/javascript,${encodeURIComponent(workerWrapped).replace(/'/g, '%27')}', {
      type: 'module'
    });
    worker.postMessage(wasmModule);
    return worker;
  });
});
`);

await copyFile('wasm/gen/pqclean.wasm', 'web/dist/pqclean.wasm');

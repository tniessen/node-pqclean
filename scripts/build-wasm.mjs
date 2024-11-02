import { spawn } from 'node:child_process';
import * as events from 'node:events';
import { mkdir, readdir, readFile, stat, unlink, writeFile } from 'node:fs/promises';

const buildDir = 'wasm/gen';
const depDir = 'deps/PQClean';

await mkdir(buildDir, { recursive: true });

const kemNames = (await readdir(`${depDir}/crypto_kem`)).sort();
const signNames = (await readdir(`${depDir}/crypto_sign`)).sort();

console.log(`Found ${kemNames.length} KEM algorithms, ${signNames.length} sign algorithms`);

const ns = (name) => `PQCLEAN_${name.toUpperCase().replace(/\-/g, '')}_CLEAN_`;

async function readApi(name, type) {
  const text = await readFile(`${depDir}/crypto_${type}/${name}/clean/api.h`, 'utf8');
  const prefix = `${ns(name)}CRYPTO_`;
  return Object.fromEntries(
      [...text.matchAll(/^\s*#define\s+(\w+)\s+(?:(\d+)|"([^"]+)")\s*(?:$|\/\/)/gm)]
          .map(([, key, intValue, strValue]) => [key, strValue ?? parseInt(intValue, 10)])
          .filter(([key]) => key.startsWith(prefix))
          .map(([key, value]) => [key.substring(prefix.length), value]));
}

async function readAlgorithms(names, type, props, functions) {
  return Promise.all(names.map(async (name) => {
    const api = await readApi(name, type);
    return {
      properties: {
        name,
        description: api.ALGNAME,
        publicKeySize: api.PUBLICKEYBYTES,
        privateKeySize: api.SECRETKEYBYTES,
        ...props(api)
      },
      functions: Object.fromEntries(functions.map((fn) => [fn, `${ns(name)}crypto_${type}_${fn}`]))
    };
  }));
}

const kemAlgorithms = await readAlgorithms(kemNames, 'kem', (api) => ({
  keySize: api.BYTES,
  encryptedKeySize: api.CIPHERTEXTBYTES
}), ['keypair', 'enc', 'dec']);

const signAlgorithms = await readAlgorithms(signNames, 'sign', (api) => ({
  signatureSize: api.BYTES
}), ['keypair', 'signature', 'verify']);

await writeFile(`${buildDir}/algorithms.json`, JSON.stringify({
  kem: kemAlgorithms,
  sign: signAlgorithms
}, null, 2));

const functions = (names, type, ...fns) => names.map((name) => fns.map((fn) => `${ns(name)}crypto_${type}_${fn}`))
                                                .flat();

const wantedExports = JSON.stringify([
  'malloc', 'free',
  ...functions(kemNames, 'kem', 'keypair', 'enc', 'dec'),
  ...functions(signNames, 'sign', 'keypair', 'signature', 'verify')
].map((e) => `_${e}`));

const sources = async (dir, filter) => (await readdir(`${depDir}/${dir}`))
                                       .filter((name) => name.endsWith('.c') && (!filter || filter(name)))
                                       .map((name) => `${depDir}/${dir}/${name}`);

const commonSourceFiles = await sources('common', (name) => name !== 'randombytes.c');
const kemSourceFiles = (await Promise.all(kemNames.map((kem) => sources(`crypto_kem/${kem}/clean`)))).flat();
const signSourceFiles = (await Promise.all(signNames.map((sign) => sources(`crypto_sign/${sign}/clean`)))).flat();

const wrapperCode = `// Some implementations do not provide certain functions as symbols but only as
// macros with parameters, which we cannot export. Implement symbols here.

${signNames.map((sign) => `#include "../../${depDir}/crypto_sign/${sign}/clean/api.h"`).join('\n')}

${functions(signNames, 'sign', 'signature').map((fn) => `#ifdef ${fn}
static inline int _fn_symbol_${fn}(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
  return ${fn}(sig, siglen, m, mlen, sk);
}
#undef ${fn}
int ${fn}(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
  return _fn_symbol_${fn}(sig, siglen, m, mlen, sk);
}
#endif`).join('\n')}
${functions(signNames, 'sign', 'verify').map((fn) => `#ifdef ${fn}
static inline int _fn_symbol_${fn}(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
  return ${fn}(sig, siglen, m, mlen, pk);
}
#undef ${fn}
int ${fn}(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
  return _fn_symbol_${fn}(sig, siglen, m, mlen, pk);
}
#endif`).join('\n')}
`;

await writeFile(`${buildDir}/missing-symbols.c`, wrapperCode);

console.log(`Compiling ${commonSourceFiles.length} common source files, ${kemSourceFiles.length} KEM source files, ${signSourceFiles.length} sign source files, and missing symbols`);

const proc = spawn('emcc', [
  '-std=c11',
  `-I${depDir}/common`,
  '-s', 'ERROR_ON_UNDEFINED_SYMBOLS=0',
  '-s', `EXPORTED_FUNCTIONS=${wantedExports}`,
  '-s', 'WASM=1',
  // 5MB was the default STACK_SIZE in emscripten prior to 3.1.27. Ideally, we
  // should figure out how much memory we actually need instead of restoring
  // that default here.
  '-s', 'STACK_SIZE=5MB',
  '-Wl,--no-entry',
  '-flto', '-Os',
  '-Wall', '-Wextra', '-Wno-unused-function',
  '-fvisibility=default',
  '-o', `${buildDir}/pqclean.wasm`,
  ...commonSourceFiles,
  ...kemSourceFiles,
  ...signSourceFiles,
  `${buildDir}/missing-symbols.c`,
], {
  stdio: 'inherit'
});
const [code, signal] = await events.once(proc, 'close');
if (code !== 0) {
  throw new Error(`emcc exited with ${code !== null ? `code ${code}` : `signal ${signal}`}`);
}

await unlink(`${buildDir}/missing-symbols.c`);

const { size } = await stat(`${buildDir}/pqclean.wasm`);
console.log(`WebAssembly module size is ${(size / 1024).toFixed(1)} KiB`);

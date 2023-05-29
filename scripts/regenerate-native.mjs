import assert from 'node:assert';
import { mkdir, readdir, writeFile } from 'node:fs/promises';

const outDir = 'native/gen';
const headerFile = `${outDir}/algorithm-inl.h`;
const gypFile = `${outDir}/binding.gyp`;

await mkdir(outDir, { recursive: true });

const kemImpls = (await readdir('deps/PQClean/crypto_kem')).sort();
const signImpls = (await readdir('deps/PQClean/crypto_sign')).sort();

// These (clean) implementations are known to use large stack allocations, so we
// disable them on Windows, where the default stack size is only 1 MiB.
// TODO: undo if https://github.com/nodejs/node/issues/43630 gets fixed.
const largeStackKemImpls = [
  'mceliece348864',
  'mceliece348864f',
  'mceliece460896',
  'mceliece460896f',
  'mceliece6688128',
  'mceliece6688128f',
  'mceliece6960119',
  'mceliece6960119f',
  'mceliece8192128',
  'mceliece8192128f'
];
const largeStackSignImpls = [
];

const nKemImpls = kemImpls.length;
const nLargeStackKemImpls = largeStackKemImpls.length;
assert(largeStackKemImpls.every((impl) => kemImpls.includes(impl)));
const nNotLargeStackKemImpls = nKemImpls - nLargeStackKemImpls;

const nSignImpls = signImpls.length;
const nLargeStackSignImpls = largeStackSignImpls.length;
assert(largeStackSignImpls.every((impl) => signImpls.includes(impl)));
const nNotLargeStackSignImpls = nSignImpls - nLargeStackSignImpls;

async function listSources(dir) {
  return (await readdir(dir)).filter((name) => name.endsWith('.c'))
      .sort().map((source) => `${dir}/${source}`);
}

const commonSources = await listSources('deps/PQClean/common');
const kemSources = Object.fromEntries(await Promise.all(kemImpls.map(async (impl) => {
  return [impl, await listSources(`deps/PQClean/crypto_kem/${impl}/clean`)];
})));
const signSources = Object.fromEntries(await Promise.all(signImpls.map(async (impl) => {
  return [impl, await listSources(`deps/PQClean/crypto_sign/${impl}/clean`)];
})));

await writeFile(gypFile, `# This file was generated automatically. Do not edit.

{
  'targets': [
    {
      'target_name': 'pqclean',
      'type': 'none',
      'dependencies': [
        'pqclean_common',
${kemImpls.map((impl) => `        'pqclean_kem_${impl}',`).join('\n')}
${signImpls.map((impl) => `        'pqclean_sign_${impl}',`).join('\n')}
      ]
    },
    {
      'target_name': 'pqclean_common',
      'type': 'static_library',
      'sources': [
${commonSources.filter((name) => name.endsWith('.c')).map((source) => `        '../../${source}',`).join('\n')}
      ]
    },
${kemImpls.map((impl) => `    {
      'target_name': 'pqclean_kem_${impl}',
      'type': 'static_library',
      'sources': [
${kemSources[impl].filter((name) => name.endsWith('.c')).map((source) => `        '../../${source}',`).join('\n')}
      ],
      'include_dirs': [
        '../../deps/PQClean/common',
      ],
      'cflags': ['-fPIC']
    },`).join('\n')}
${signImpls.map((impl) => `    {
      'target_name': 'pqclean_sign_${impl}',
      'type': 'static_library',
      'sources': [
${signSources[impl].filter((name) => name.endsWith('.c')).map((source) => `        '../../${source}',`).join('\n')}
      ],
      'include_dirs': [
        '../../deps/PQClean/common',
      ],
      'cflags': ['-fPIC']
    },`).join('\n')}
  ]
}
`);

function ifLargeStack(wrapped) {
  return `#if NODE_PQCLEAN_HAS_LARGE_STACK
${wrapped}
#endif  // NODE_PQCLEAN_HAS_LARGE_STACK`;
}

const id = (impl) => impl.toUpperCase().replace(/\-/g, '');

await writeFile(headerFile, `// This file was generated automatically. Do not edit.

#include <array>
#include "../algorithm.h"

extern "C" {

${kemImpls.map((impl) => `#include \"../../deps/PQClean/crypto_kem/${impl}/clean/api.h\"`).join('\n')}
${signImpls.map((impl) => `#include \"../../deps/PQClean/crypto_sign/${impl}/clean/api.h\"`).join('\n')}

}  // extern "C"

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)
#  define NODE_PQCLEAN_HAS_LARGE_STACK 0
#else
#  define NODE_PQCLEAN_HAS_LARGE_STACK 1
#endif

namespace pqclean {
namespace kem {

constexpr unsigned int N_ALGORITHMS = NODE_PQCLEAN_HAS_LARGE_STACK ? ${nKemImpls} : ${nNotLargeStackKemImpls};

const std::array<Algorithm, N_ALGORITHMS>& algorithms() {
  static const std::array<Algorithm, N_ALGORITHMS> all = {{
${kemImpls.map((impl) => (largeStackKemImpls.includes(impl) ? ifLargeStack : (x) => x)(`    {
      "${impl}",
      PQCLEAN_${id(impl)}_CLEAN_CRYPTO_ALGNAME,
      PQCLEAN_${id(impl)}_CLEAN_CRYPTO_PUBLICKEYBYTES,
      PQCLEAN_${id(impl)}_CLEAN_CRYPTO_SECRETKEYBYTES,
      PQCLEAN_${id(impl)}_CLEAN_CRYPTO_CIPHERTEXTBYTES,
      PQCLEAN_${id(impl)}_CLEAN_CRYPTO_BYTES,
      PQCLEAN_${id(impl)}_CLEAN_crypto_kem_keypair,
      PQCLEAN_${id(impl)}_CLEAN_crypto_kem_enc,
      PQCLEAN_${id(impl)}_CLEAN_crypto_kem_dec
    },`)).join('\n')}
  }};
  return all;
}

}  // namespace kem

namespace sign {

constexpr unsigned int N_ALGORITHMS = NODE_PQCLEAN_HAS_LARGE_STACK ? ${nSignImpls} : ${nNotLargeStackSignImpls};

const std::array<Algorithm, N_ALGORITHMS>& algorithms() {
  static const std::array<Algorithm, N_ALGORITHMS> all = {{
${signImpls.map((impl) => (largeStackSignImpls.includes(impl) ? ifLargeStack : (x) => x)(`    {
      "${impl}",
      PQCLEAN_${id(impl)}_CLEAN_CRYPTO_ALGNAME,
      PQCLEAN_${id(impl)}_CLEAN_CRYPTO_PUBLICKEYBYTES,
      PQCLEAN_${id(impl)}_CLEAN_CRYPTO_SECRETKEYBYTES,
      PQCLEAN_${id(impl)}_CLEAN_CRYPTO_BYTES,
#ifdef PQCLEAN_${id(impl)}_CLEAN_CRYPTO_SEEDBYTES
      PQCLEAN_${id(impl)}_CLEAN_CRYPTO_SEEDBYTES,
#else
      0,
#endif
      PQCLEAN_${id(impl)}_CLEAN_crypto_sign_keypair,
      PQCLEAN_${id(impl)}_CLEAN_crypto_sign_signature,
      PQCLEAN_${id(impl)}_CLEAN_crypto_sign_verify
    },`)).join('\n')}
  }};
  return all;
}

}  // namespace sign
}  // namespace pqclean
`);

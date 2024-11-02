import assert from 'node:assert';
import { mkdir, readdir, writeFile } from 'node:fs/promises';

const outDir = 'native/gen';
const headerFile = `${outDir}/algorithm-inl.h`;
const gypFile = `${outDir}/binding.gyp`;

await mkdir(outDir, { recursive: true });

const kemImpls = (await readdir('deps/PQClean/crypto_kem')).sort();
const signImpls = (await readdir('deps/PQClean/crypto_sign')).sort();

const nKemImpls = kemImpls.length;
const nSignImpls = signImpls.length;

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

const id = (impl) => impl.toUpperCase().replace(/\-/g, '');

await writeFile(headerFile, `// This file was generated automatically. Do not edit.

#include <array>
#include "../algorithm.h"

extern "C" {

${kemImpls.map((impl) => `#include \"../../deps/PQClean/crypto_kem/${impl}/clean/api.h\"`).join('\n')}
${signImpls.map((impl) => `#include \"../../deps/PQClean/crypto_sign/${impl}/clean/api.h\"`).join('\n')}

}  // extern "C"

namespace pqclean {
namespace kem {

constexpr unsigned int N_ALGORITHMS = ${nKemImpls};

const std::array<Algorithm, N_ALGORITHMS>& algorithms() {
  static const std::array<Algorithm, N_ALGORITHMS> all = {{
${kemImpls.map((impl) => `    {
      "${impl}",
      PQCLEAN_${id(impl)}_CLEAN_CRYPTO_ALGNAME,
      PQCLEAN_${id(impl)}_CLEAN_CRYPTO_PUBLICKEYBYTES,
      PQCLEAN_${id(impl)}_CLEAN_CRYPTO_SECRETKEYBYTES,
      PQCLEAN_${id(impl)}_CLEAN_CRYPTO_CIPHERTEXTBYTES,
      PQCLEAN_${id(impl)}_CLEAN_CRYPTO_BYTES,
      PQCLEAN_${id(impl)}_CLEAN_crypto_kem_keypair,
      PQCLEAN_${id(impl)}_CLEAN_crypto_kem_enc,
      PQCLEAN_${id(impl)}_CLEAN_crypto_kem_dec
    },`).join('\n')}
  }};
  return all;
}

}  // namespace kem

namespace sign {

constexpr unsigned int N_ALGORITHMS = ${nSignImpls};

// Some implementations do not provide certain functions as symbols but only as
// macros with parameters, which we cannot use as function pointers directly.
namespace {
${signImpls.map((impl) => `#ifdef PQCLEAN_${id(impl)}_CLEAN_crypto_sign_signature
inline int _fn_symbol_PQCLEAN_${id(impl)}_CLEAN_crypto_sign_signature(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* sk) {
  return PQCLEAN_${id(impl)}_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}
#endif
#ifdef PQCLEAN_${id(impl)}_CLEAN_crypto_sign_verify
inline int _fn_symbol_PQCLEAN_${id(impl)}_CLEAN_crypto_sign_verify(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk) {
  return PQCLEAN_${id(impl)}_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}
#endif`).join('\n')}
}

const std::array<Algorithm, N_ALGORITHMS>& algorithms() {
  static const std::array<Algorithm, N_ALGORITHMS> all = {{
${signImpls.map((impl) => `    {
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
#ifndef PQCLEAN_${id(impl)}_CLEAN_crypto_sign_signature
      PQCLEAN_${id(impl)}_CLEAN_crypto_sign_signature,
#else
      _fn_symbol_PQCLEAN_${id(impl)}_CLEAN_crypto_sign_signature,
#endif
#ifndef PQCLEAN_${id(impl)}_CLEAN_crypto_sign_verify
      PQCLEAN_${id(impl)}_CLEAN_crypto_sign_verify
#else
      _fn_symbol_PQCLEAN_${id(impl)}_CLEAN_crypto_sign_verify
#endif
    },`).join('\n')}
  }};
  return all;
}

}  // namespace sign
}  // namespace pqclean
`);

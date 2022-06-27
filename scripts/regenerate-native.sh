#!/bin/bash
set -e

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/..

out_dir=native/gen
header_file="$out_dir/algorithm-inl.h"
gyp_file="$out_dir/binding.gyp"

mkdir -p "$out_dir"

kem_impls=($(ls -1 deps/PQClean/crypto_kem))
sign_impls=($(ls -1 deps/PQClean/crypto_sign))
(
  echo "# This file was generated automatically. Do not edit."
  echo
  echo "{"
  echo "  'targets': ["
  echo "    {"
  echo "      'target_name': 'pqclean',"
  echo "      'type': 'none',"
  echo "      'dependencies': ["
  echo "        'pqclean_common',"
  for impl in "${kem_impls[@]}"; do
    echo "        'pqclean_kem_$impl',"
  done
  for impl in "${sign_impls[@]}"; do
    echo "        'pqclean_sign_$impl',"
  done
  echo "      ]"
  echo "    },"
  echo "    {"
  echo "      'target_name': 'pqclean_common',"
  echo "      'type': 'static_library',"
  echo "      'sources': ["
  ls -1 deps/PQClean/common/*.c | sort | while read source; do
    echo "        '../../$source',"
  done
  echo "      ]"
  echo "    },"
  for impl in "${kem_impls[@]}"; do
    echo "    {"
    echo "      'target_name': 'pqclean_kem_$impl',"
    echo "      'type': 'static_library',"
    echo "      'sources': ["
    find deps/PQClean/crypto_kem/$impl/clean -type f -name '*.c' | sort | while read source; do
      echo "        '../../$source',"
    done
    echo "      ],"
    echo "      'include_dirs': ["
    echo "        '../../deps/PQClean/common'",
    echo "      ],"
    echo "      'cflags': ['-fPIC']"
    echo "    },"
  done
  for impl in "${sign_impls[@]}"; do
    echo "    {"
    echo "      'target_name': 'pqclean_sign_$impl',"
    echo "      'type': 'static_library',"
    echo "      'sources': ["
    find deps/PQClean/crypto_sign/$impl/clean -type f -name '*.c' | sort | while read source; do
      echo "        '../../$source',"
    done
    echo "      ],"
    echo "      'include_dirs': ["
    echo "        '../../deps/PQClean/common'",
    echo "      ],"
    echo "      'cflags': ['-fPIC']"
    echo "    },"
  done
  echo "  ]"
  echo "}"
) >"$gyp_file"

(
  echo "// This file was generated automatically. Do not edit."
  echo
  echo '#include <array>'
  echo '#include "../algorithm.h"'
  echo
  echo 'extern "C" {'
  echo
  for impl in "${kem_impls[@]}"; do
    echo "#include \"../../deps/PQClean/crypto_kem/$impl/clean/api.h\""
  done
  for impl in "${sign_impls[@]}"; do
    echo "#include \"../../deps/PQClean/crypto_sign/$impl/clean/api.h\""
  done
  echo
  echo '}  // extern "C"'
  echo
  echo "namespace pqclean {"
  echo "namespace kem {"
  echo
  echo "const std::array<Algorithm, ${#kem_impls[@]}>& algorithms() {"
  echo "  static const std::array<Algorithm, ${#kem_impls[@]}> all = {{"
  for impl in "${kem_impls[@]}"; do
    upper=${impl^^}
    id=${upper//-}
    echo "    {"
    echo "      \"$impl\","
    echo "      PQCLEAN_${id}_CLEAN_CRYPTO_ALGNAME,"
    echo "      PQCLEAN_${id}_CLEAN_CRYPTO_PUBLICKEYBYTES,"
    echo "      PQCLEAN_${id}_CLEAN_CRYPTO_SECRETKEYBYTES,"
    echo "      PQCLEAN_${id}_CLEAN_CRYPTO_CIPHERTEXTBYTES,"
    echo "      PQCLEAN_${id}_CLEAN_CRYPTO_BYTES,"
    echo "      PQCLEAN_${id}_CLEAN_crypto_kem_keypair,"
    echo "      PQCLEAN_${id}_CLEAN_crypto_kem_enc,"
    echo "      PQCLEAN_${id}_CLEAN_crypto_kem_dec"
    echo "    },"
  done
  echo "  }};"
  echo "  return all;"
  echo "}"
  echo
  echo "}  // namespace kem"
  echo
  echo "namespace sign {"
  echo
  echo "const std::array<Algorithm, ${#sign_impls[@]}>& algorithms() {"
  echo "  static const std::array<Algorithm, ${#sign_impls[@]}> all = {{"
  for impl in "${sign_impls[@]}"; do
    upper=${impl^^}
    id=${upper//-}
    echo "    {"
    echo "      \"$impl\","
    echo "      PQCLEAN_${id}_CLEAN_CRYPTO_ALGNAME,"
    echo "      PQCLEAN_${id}_CLEAN_CRYPTO_PUBLICKEYBYTES,"
    echo "      PQCLEAN_${id}_CLEAN_CRYPTO_SECRETKEYBYTES,"
    echo "      PQCLEAN_${id}_CLEAN_CRYPTO_BYTES,"
    echo "#ifdef PQCLEAN_${id}_CLEAN_CRYPTO_SEEDBYTES"
    echo "      PQCLEAN_${id}_CLEAN_CRYPTO_SEEDBYTES,"
    echo "#else"
    echo "      0,"
    echo "#endif"
    echo "      PQCLEAN_${id}_CLEAN_crypto_sign_keypair,"
    echo "      PQCLEAN_${id}_CLEAN_crypto_sign_signature,"
    echo "      PQCLEAN_${id}_CLEAN_crypto_sign_verify"
    echo "    },"
  done
  echo "  }};"
  echo "  return all;"
  echo "}"
  echo
  echo "}  // namespace sign"
  echo "}  // namespace pqclean"
) >"$header_file"

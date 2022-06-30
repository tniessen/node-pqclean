#!/bin/bash
set -e

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/..

out_dir=native/gen
header_file="$out_dir/algorithm-inl.h"
gyp_file="$out_dir/binding.gyp"

mkdir -p "$out_dir"

kem_impls=($(ls -1 deps/PQClean/crypto_kem))
sign_impls=($(ls -1 deps/PQClean/crypto_sign))

# These (clean) implementations are known to use large stack allocations, so we
# disable them on Windows, where the default stack size is only 1 MiB.
# TODO: undo if https://github.com/nodejs/node/issues/43630 gets fixed.
large_stack_kem_impls=(
  frodokem1344aes
  frodokem1344shake
  frodokem976aes
  frodokem976shake
  mceliece348864
  mceliece348864f
  mceliece460896
  mceliece460896f
  mceliece6688128
  mceliece6688128f
  mceliece6960119
  mceliece6960119f
  mceliece8192128
  mceliece8192128f
)
large_stack_sign_impls=(
  rainbowIII-circumzenithal
  rainbowIII-compressed
  rainbowV-circumzenithal
  rainbowV-classic
  rainbowV-compressed
)

n_kem_impls=${#kem_impls[@]}
n_large_stack_kem_impls=${#large_stack_kem_impls[@]}
n_not_large_stack_kem_impls=$((n_kem_impls - n_large_stack_kem_impls))

n_sign_impls=${#sign_impls[@]}
n_large_stack_sign_impls=${#large_stack_sign_impls[@]}
n_not_large_stack_sign_impls=$((n_sign_impls - n_large_stack_sign_impls))

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
  echo "#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__)"
  echo "#  define NODE_PQCLEAN_HAS_LARGE_STACK 0"
  echo "#else"
  echo "#  define NODE_PQCLEAN_HAS_LARGE_STACK 1"
  echo "#endif"
  echo
  echo "namespace pqclean {"
  echo "namespace kem {"
  echo
  echo "constexpr unsigned int N_ALGORITHMS = NODE_PQCLEAN_HAS_LARGE_STACK ? $n_kem_impls : $n_not_large_stack_kem_impls;"
  echo
  echo "const std::array<Algorithm, N_ALGORITHMS>& algorithms() {"
  echo "  static const std::array<Algorithm, N_ALGORITHMS> all = {{"
  for impl in "${kem_impls[@]}"; do
    upper=${impl^^}
    id=${upper//-}
    if [[ " ${large_stack_kem_impls[*]} " =~ " ${impl} " ]]; then
      echo "#if NODE_PQCLEAN_HAS_LARGE_STACK"
    fi
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
    if [[ " ${large_stack_kem_impls[*]} " =~ " ${impl} " ]]; then
      echo "#endif  // NODE_PQCLEAN_HAS_LARGE_STACK"
    fi
  done
  echo "  }};"
  echo "  return all;"
  echo "}"
  echo
  echo "}  // namespace kem"
  echo
  echo "namespace sign {"
  echo
  echo "constexpr unsigned int N_ALGORITHMS = NODE_PQCLEAN_HAS_LARGE_STACK ? $n_sign_impls : $n_not_large_stack_sign_impls;"
  echo
  echo "const std::array<Algorithm, N_ALGORITHMS>& algorithms() {"
  echo "  static const std::array<Algorithm, N_ALGORITHMS> all = {{"
  for impl in "${sign_impls[@]}"; do
    upper=${impl^^}
    id=${upper//-}
    if [[ " ${large_stack_sign_impls[*]} " =~ " ${impl} " ]]; then
      echo "#if NODE_PQCLEAN_HAS_LARGE_STACK"
    fi
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
    if [[ " ${large_stack_sign_impls[*]} " =~ " ${impl} " ]]; then
      echo "#endif  // NODE_PQCLEAN_HAS_LARGE_STACK"
    fi
  done
  echo "  }};"
  echo "  return all;"
  echo "}"
  echo
  echo "}  // namespace sign"
  echo "}  // namespace pqclean"
) >"$header_file"

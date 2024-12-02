#ifndef NATIVE_ALGORITHM_H
#define NATIVE_ALGORITHM_H

#include <string>

namespace pqclean {
namespace kem {

typedef int (*keypair_fn)(unsigned char* pk, unsigned char* sk);

typedef int (*enc_fn)(unsigned char* ct, unsigned char* k,
                      const unsigned char* pk);

typedef int (*dec_fn)(unsigned char* k, const unsigned char* ct,
                      const unsigned char* sk);

struct Algorithm {
  std::string id;
  std::string description;
  size_t publicKeySize;
  size_t privateKeySize;
  size_t ciphertextSize;
  size_t keySize;
  keypair_fn keypair;
  enc_fn enc;
  dec_fn dec;
};

}  // namespace kem

namespace sign {

typedef int (*keypair_fn)(unsigned char* pk, unsigned char* sk);

typedef int (*signature_fn)(uint8_t* sig, size_t* siglen,
                            const uint8_t* m, size_t mlen,
                            const uint8_t* sk);

typedef int (*sign_fn)(uint8_t* sm, size_t* smlen,
                       const uint8_t* m, size_t mlen,
                       const uint8_t* sk);

typedef int (*verify_fn)(const uint8_t* sig, size_t siglen,
                         const uint8_t* m, size_t mlen,
                         const uint8_t* pk);

typedef int (*open_fn)(uint8_t* m, size_t* mlen,
                       const uint8_t* sm, size_t smlen,
                       const uint8_t* pk);

struct Algorithm {
  std::string id;
  std::string description;
  size_t publicKeySize;
  size_t privateKeySize;
  size_t signatureSize;
  size_t seedSize;
  keypair_fn keypair;
  signature_fn signature;
  sign_fn sign;
  verify_fn verify;
  open_fn open;
};

}  // namespace sign
}  // namespace pqclean

#endif  // NATIVE_ALGORITHM_H

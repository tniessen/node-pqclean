#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <napi.h>

#include "algorithm.h"
#include "gen/algorithm-inl.h"

namespace {

const pqclean::kem::Algorithm* get_kem(const std::string& name) {
  for (auto& algo : pqclean::kem::algorithms()) {
    if (algo.id == name) {
      return &algo;
    }
  }
  return NULL;
}

const pqclean::sign::Algorithm* get_sign(const std::string& name) {
  for (auto& algo : pqclean::sign::algorithms()) {
    if (algo.id == name) {
      return &algo;
    }
  }
  return NULL;
}

template <typename T>
inline T* Malloc(size_t size) {
  return reinterpret_cast<T*>(malloc(size));
}

void Free(Napi::Env env, void* p) {
  free(p);
}

template <typename T>
inline T* Duplicate(const void* mem, size_t size) {
  T* copy = Malloc<T>(size);
  if (copy != nullptr)
    memcpy(copy, mem, size);
  return copy;
}

////////////////////////////////////////////////////////////////////////////////
// Classic API
////////////////////////////////////////////////////////////////////////////////

template <typename Algorithm>
class GenerateKeyPairWorker : public Napi::AsyncWorker {
 public:
  GenerateKeyPairWorker(Napi::Function& callback, const Algorithm* impl)
      : AsyncWorker(callback), impl(impl) {}

  ~GenerateKeyPairWorker() {}

  void Execute() override {
    public_key = Malloc<unsigned char>(impl->publicKeySize);
    private_key = Malloc<unsigned char>(impl->privateKeySize);

    if (public_key == nullptr || private_key == nullptr) {
      free(public_key);
      free(private_key);
      return SetError("Failed to allocate memory");
    }

    if (impl->keypair(public_key, private_key) != 0) {
      free(public_key);
      free(private_key);
      return SetError("failed to generate keypair");
    }
  }

  std::vector<napi_value> GetResult(Napi::Env env) override {
    const auto public_key_buf = Napi::Buffer<unsigned char>::New(env, public_key, impl->publicKeySize, Free);
    const auto private_key_buf = Napi::Buffer<unsigned char>::New(env, private_key, impl->privateKeySize, Free);

    Napi::Object obj = Napi::Object::New(env);
    obj.Set("publicKey", public_key_buf);
    obj.Set("privateKey", private_key_buf);
    return { env.Undefined(), obj };
  }

 private:
  const Algorithm* impl;
  unsigned char* public_key;
  unsigned char* private_key;
};

class GenerateKeyWorker : public Napi::AsyncWorker {
 public:
  GenerateKeyWorker(Napi::Function& callback, const pqclean::kem::Algorithm* impl,
                    const void* publicKey)
      : AsyncWorker(callback), impl(impl),
        publicKey(Duplicate<unsigned char>(publicKey, impl->publicKeySize)) {}

  void Execute() override {
    if (publicKey == nullptr)
      return SetError("Failed to allocate memory");

    actualKey = Malloc<unsigned char>(impl->keySize);
    ciphertext = Malloc<unsigned char>(impl->ciphertextSize);
    if (actualKey == nullptr || ciphertext == nullptr) {
      free(actualKey);
      free(ciphertext);
      return SetError("Failed to allocate memory");
    }

    if (impl->enc(ciphertext, actualKey, publicKey) != 0) {
      free(actualKey);
      free(ciphertext);
      return SetError("Key encapsulation failed");
    }
  }

  std::vector<napi_value> GetResult(Napi::Env env) override {
    const auto key = Napi::Buffer<unsigned char>::New(env, actualKey, impl->keySize, Free);
    const auto ct = Napi::Buffer<unsigned char>::New(env, ciphertext, impl->ciphertextSize, Free);
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("key", key);
    obj.Set("encryptedKey", ct);
    return { env.Undefined(), obj };
  }

  ~GenerateKeyWorker() {
    free(publicKey);
  }

 private:
  const pqclean::kem::Algorithm* impl;
  unsigned char* publicKey;
  unsigned char* ciphertext = nullptr;
  unsigned char* actualKey = nullptr;
};

class DecryptWorker : public Napi::AsyncWorker {
 public:
  DecryptWorker(Napi::Function& callback, const pqclean::kem::Algorithm* impl,
                const void* private_key, const void* ciphertext)
      : AsyncWorker(callback), impl(impl) {
    this->private_key = Duplicate<unsigned char>(private_key, impl->privateKeySize);
    this->ciphertext = Duplicate<unsigned char>(ciphertext, impl->ciphertextSize);
  }

  void Execute() override {
    if (private_key == nullptr || ciphertext == nullptr)
      return SetError("Failed to allocate memory");

    actual_key = Malloc<unsigned char>(impl->keySize);
    if (actual_key == nullptr)
      return SetError("Failed to allocate memory");

    if (impl->dec(actual_key, ciphertext, private_key) != 0) {
      free(actual_key);
      return SetError("decryption failed");
    }
  }

  std::vector<napi_value> GetResult(Napi::Env env) override {
    const auto key = Napi::Buffer<unsigned char>::New(env, actual_key, impl->keySize, Free);
    return { env.Undefined(), key };
  }

  ~DecryptWorker() {
    free(private_key);
    free(ciphertext);
  }

 private:
  const pqclean::kem::Algorithm* impl;
  unsigned char* private_key;
  unsigned char* ciphertext;
  unsigned char* actual_key;
};

class SignWorker : public Napi::AsyncWorker {
 public:
  SignWorker(Napi::Function& callback, const pqclean::sign::Algorithm* impl,
             const void* privateKey, const void* message, size_t messageSize)
      : AsyncWorker(callback), impl(impl),
        privateKey(Duplicate<unsigned char>(privateKey, impl->privateKeySize)),
        message(Duplicate<unsigned char>(message, messageSize)),
        messageSize(messageSize) {}

  void Execute() override {
    if (privateKey == nullptr || (messageSize != 0 && message == nullptr))
      return SetError("Failed to allocate memory");

    signature = Malloc<unsigned char>(impl->signatureSize);
    if (signature == nullptr)
      return SetError("Failed to allocate memory");

    signatureSize = impl->signatureSize;
    int r = impl->signature(signature, &signatureSize, message, messageSize, privateKey);
    if (r != 0) {
      free(signature);
      return SetError("sign operation failed");
    }
    if (signatureSize != impl->signatureSize) {
      if (signatureSize > impl->signatureSize) {
        Napi::Error::Fatal("SignWorker", "signatureSize > impl->signatureSize");
      }
    }
  }

  std::vector<napi_value> GetResult(Napi::Env env) override {
    const auto key = Napi::Buffer<unsigned char>::New(env, signature, signatureSize, Free);
    return { env.Undefined(), key };
  }

  ~SignWorker() {
    free(privateKey);
    free(message);
  }

 private:
  const pqclean::sign::Algorithm* impl;
  unsigned char* privateKey;
  unsigned char* message;
  size_t messageSize;
  unsigned char* signature = nullptr;
  size_t signatureSize;
};

class VerifyWorker : public Napi::AsyncWorker {
 public:
  VerifyWorker(Napi::Function& callback, const pqclean::sign::Algorithm* impl,
               const void* publicKey, const void* message, size_t messageSize,
               const void* signature, size_t signatureSize)
      : AsyncWorker(callback), impl(impl),
        publicKey(Duplicate<unsigned char>(publicKey, impl->publicKeySize)),
        message(Duplicate<unsigned char>(message, messageSize)),
        messageSize(messageSize),
        signature(Duplicate<unsigned char>(signature, signatureSize)),
        signatureSize(signatureSize) {}

  void Execute() override {
    if (publicKey == nullptr || (messageSize != 0 && message == nullptr) ||
        (signatureSize != 0 && signature == nullptr))
      return SetError("Failed to allocate memory");

    // TODO: can we distinguish verification errors from other internal errors?
    ok = 0 == impl->verify(signature, signatureSize, message, messageSize, publicKey);
  }

  std::vector<napi_value> GetResult(Napi::Env env) override {
    return { env.Undefined(), Napi::Value::From(env, ok) };
  }

  ~VerifyWorker() {
    free(publicKey);
    free(message);
    free(signature);
  }

 private:
  const pqclean::sign::Algorithm* impl;
  unsigned char* publicKey;
  unsigned char* message;
  size_t messageSize;
  unsigned char* signature;
  size_t signatureSize;
  bool ok;
};

class KEM : public Napi::ObjectWrap<KEM> {
 public:
  KEM(const Napi::CallbackInfo& info) : Napi::ObjectWrap<KEM>(info) {
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return;
    }

    if (!info[0].IsString()) {
      Napi::TypeError::New(env, "First argument must be a string")
          .ThrowAsJavaScriptException();
      return;
    }

    std::string name = info[0].As<Napi::String>();
    if ((this->impl = get_kem(name)) == nullptr) {
      Napi::Error::New(env, "No such implementation")
          .ThrowAsJavaScriptException();
    }
  }

  Napi::Value Keypair(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() > 0) {
      if (info.Length() == 1) {
        if (info[0].IsFunction()) {
          Napi::Function cb = info[0].As<Napi::Function>();
          auto worker = new GenerateKeyPairWorker<pqclean::kem::Algorithm>(cb, impl);
          worker->Queue();
          return env.Undefined();
        } else {
          Napi::TypeError::New(env, "First argument must be a function")
              .ThrowAsJavaScriptException();
          return env.Undefined();
        }
      } else {
        Napi::TypeError::New(env, "Wrong number of arguments")
            .ThrowAsJavaScriptException();
        return env.Undefined();
      }
    }

    Napi::Buffer<unsigned char> public_key = Napi::Buffer<unsigned char>::New(env, impl->publicKeySize);
    Napi::Buffer<unsigned char> private_key = Napi::Buffer<unsigned char>::New(env, impl->privateKeySize);
    int r = impl->keypair(public_key.Data(), private_key.Data());
    if (r != 0) {
      Napi::Error::New(env, "failed to generate keypair").ThrowAsJavaScriptException();
      return env.Undefined();
    }

    Napi::Object obj = Napi::Object::New(env);
    obj.Set("publicKey", public_key);
    obj.Set("privateKey", private_key);
    return obj;
  }

  Napi::Value GenerateKey(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() == 0 || info.Length() > 2) {
      Napi::TypeError::New(env, "Wrong number of arguments")
            .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    if (!info[0].IsTypedArray()) {
      Napi::TypeError::New(env, "First argument must be a TypedArray").ThrowAsJavaScriptException();
      return env.Undefined();
    }

    Napi::Buffer<unsigned char> public_key = info[0].As<Napi::Buffer<unsigned char>>();
    if (public_key.Length() != impl->publicKeySize) {
      Napi::TypeError::New(env, "Invalid public key size")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    if (info.Length() == 2) {
      if (info[1].IsFunction()) {
        Napi::Function cb = info[1].As<Napi::Function>();
        auto worker = new GenerateKeyWorker(cb, impl, public_key.Data());
        worker->Queue();
        return env.Undefined();
      } else {
        Napi::TypeError::New(env, "Second argument must be a function")
            .ThrowAsJavaScriptException();
        return env.Undefined();
      }
    }

    auto encrypted_key = Napi::Buffer<unsigned char>::New(env, impl->ciphertextSize);
    auto actual_key = Napi::Buffer<unsigned char>::New(env, impl->keySize);

    int r = impl->enc(encrypted_key.Data(), actual_key.Data(), public_key.Data());
    if (r != 0) {
      Napi::Error::New(env, "encryption failed").ThrowAsJavaScriptException();
      return env.Undefined();
    }

    Napi::Object obj = Napi::Object::New(env);
    obj.Set("key", actual_key);
    obj.Set("encryptedKey", encrypted_key);
    return obj;
  }

  Napi::Value DecryptKey(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 2 && info.Length() != 3) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    if (!info[0].IsTypedArray()) {
      Napi::TypeError::New(env, "First argument must be a TypedArray").ThrowAsJavaScriptException();
      return env.Undefined();
    }

    Napi::Buffer<unsigned char> private_key = info[0].As<Napi::Buffer<unsigned char>>();
    if (private_key.Length() != impl->privateKeySize) {
      Napi::TypeError::New(env, "Invalid private key size")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    if (!info[1].IsTypedArray()) {
      Napi::TypeError::New(env, "Second argument must be a TypedArray").ThrowAsJavaScriptException();
      return env.Undefined();
    }

    Napi::Buffer<unsigned char> encrypted_key = info[1].As<Napi::Buffer<unsigned char>>();
    if (encrypted_key.Length() != impl->ciphertextSize) {
      Napi::TypeError::New(env, "Invalid ciphertext size")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    if (info.Length() == 3) {
      if (info[2].IsFunction()) {
        Napi::Function cb = info[2].As<Napi::Function>();
        DecryptWorker* worker = new DecryptWorker(cb, impl, private_key.Data(), encrypted_key.Data());
        worker->Queue();
        return env.Undefined();
      } else {
        Napi::TypeError::New(env, "Third argument must be a function")
            .ThrowAsJavaScriptException();
        return env.Undefined();
      }
    }

    Napi::Buffer<unsigned char> actual_key = Napi::Buffer<unsigned char>::New(env, impl->keySize);

    int r = impl->dec(actual_key.Data(), encrypted_key.Data(), private_key.Data());
    if (r != 0) {
      Napi::Error::New(env, "decryption failed").ThrowAsJavaScriptException();
      return env.Undefined();
    }

    return actual_key;
  }

  Napi::Value GetAlgorithm(const Napi::CallbackInfo& info) {
    return Napi::Value::From(info.Env(), impl->id);
  }

  Napi::Value GetDescription(const Napi::CallbackInfo& info) {
    return Napi::Value::From(info.Env(), impl->description);
  }

  Napi::Value GetKeySize(const Napi::CallbackInfo& info) {
    return Napi::Value::From(info.Env(), impl->keySize);
  }

  Napi::Value GetEncryptedKeySize(const Napi::CallbackInfo& info) {
    return Napi::Value::From(info.Env(), impl->ciphertextSize);
  }

  Napi::Value GetPublicKeySize(const Napi::CallbackInfo& info) {
    return Napi::Value::From(info.Env(), impl->publicKeySize);
  }

  Napi::Value GetPrivateKeySize(const Napi::CallbackInfo& info) {
    return Napi::Value::From(info.Env(), impl->privateKeySize);
  }

 private:
  const pqclean::kem::Algorithm* impl;
};

class Sign : public Napi::ObjectWrap<Sign> {
 public:
  Sign(const Napi::CallbackInfo& info) : Napi::ObjectWrap<Sign>(info) {
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return;
    }

    if (!info[0].IsString()) {
      Napi::TypeError::New(env, "First argument must be a string")
          .ThrowAsJavaScriptException();
      return;
    }

    std::string name = info[0].As<Napi::String>();
    if ((this->impl = get_sign(name)) == nullptr) {
      Napi::Error::New(env, "No such implementation")
          .ThrowAsJavaScriptException();
    }
  }

  Napi::Value Keypair(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() > 0) {
      if (info.Length() == 1) {
        if (info[0].IsFunction()) {
          Napi::Function cb = info[0].As<Napi::Function>();
          auto worker = new GenerateKeyPairWorker<pqclean::sign::Algorithm>(cb, impl);
          worker->Queue();
          return env.Undefined();
        } else {
          Napi::TypeError::New(env, "First argument must be a function")
              .ThrowAsJavaScriptException();
          return env.Undefined();
        }
      } else {
        Napi::TypeError::New(env, "Wrong number of arguments")
            .ThrowAsJavaScriptException();
        return env.Undefined();
      }
    }

    auto public_key = Napi::Buffer<unsigned char>::New(env, impl->publicKeySize);
    auto private_key = Napi::Buffer<unsigned char>::New(env, impl->privateKeySize);
    int r = impl->keypair(public_key.Data(), private_key.Data());
    if (r != 0) {
      Napi::Error::New(env, "failed to generate keypair").ThrowAsJavaScriptException();
      return env.Undefined();
    }

    Napi::Object obj = Napi::Object::New(env);
    obj.Set("publicKey", public_key);
    obj.Set("privateKey", private_key);
    return obj;
  }

  Napi::Value DoSign(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 2 || info.Length() > 3) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    if (!info[0].IsTypedArray()) {
      Napi::TypeError::New(env, "First argument must be a TypedArray").ThrowAsJavaScriptException();
      return env.Undefined();
    }

    Napi::Buffer<unsigned char> private_key = info[0].As<Napi::Buffer<unsigned char>>();
    if (private_key.Length() != impl->privateKeySize) {
      Napi::TypeError::New(env, "Invalid private key size")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    if (!info[1].IsTypedArray()) {
      Napi::TypeError::New(env, "Second argument must be a TypedArray").ThrowAsJavaScriptException();
      return env.Undefined();
    }

    Napi::Buffer<unsigned char> message = info[1].As<Napi::Buffer<unsigned char>>();

    if (info.Length() == 3) {
      if (info[2].IsFunction()) {
        Napi::Function cb = info[2].As<Napi::Function>();
        auto worker = new SignWorker(cb, impl, private_key.Data(), message.Data(), message.Length());
        worker->Queue();
        return env.Undefined();
      } else {
        Napi::TypeError::New(env, "Third argument must be a function")
            .ThrowAsJavaScriptException();
        return env.Undefined();
      }
    }

    Napi::Buffer<unsigned char> signature = Napi::Buffer<unsigned char>::New(env, impl->signatureSize);

    size_t signatureSize = impl->signatureSize;
    int r = impl->signature(signature.Data(), &signatureSize, message.Data(), message.Length(), private_key.Data());
    if (r != 0) {
      Napi::Error::New(env, "sign operation failed").ThrowAsJavaScriptException();
      return env.Undefined();
    }
    if (signatureSize != impl->signatureSize) {
      if (signatureSize > impl->signatureSize) {
        Napi::Error::Fatal("DoSign", "signatureSize > impl->signatureSize");
      }
      signature = Napi::Buffer<unsigned char>::Copy(env, signature.Data(), signatureSize);
    }

    return signature;
  }

  Napi::Value Verify(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 3 || info.Length() > 4) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    if (!info[0].IsTypedArray()) {
      Napi::TypeError::New(env, "First argument must be a TypedArray")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    Napi::Buffer<unsigned char> publicKey = info[0].As<Napi::Buffer<unsigned char>>();
    if (publicKey.Length() != impl->publicKeySize) {
      Napi::TypeError::New(env, "Invalid public key size")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    if (!info[1].IsTypedArray()) {
      Napi::TypeError::New(env, "Second argument must be a TypedArray")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    Napi::Buffer<unsigned char> message = info[1].As<Napi::Buffer<unsigned char>>();

    if (!info[2].IsTypedArray()) {
      Napi::TypeError::New(env, "Third argument must be a TypedArray")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    Napi::Buffer<unsigned char> signature = info[2].As<Napi::Buffer<unsigned char>>();
    if (signature.Length() > impl->signatureSize) {
      Napi::TypeError::New(env, "Invalid signature size")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    if (info.Length() == 4) {
      if (info[3].IsFunction()) {
        Napi::Function cb = info[3].As<Napi::Function>();
        auto* worker = new VerifyWorker(cb, impl, publicKey.Data(), message.Data(), message.Length(), signature.Data(), signature.Length());
        worker->Queue();
        return env.Undefined();
      } else {
        Napi::TypeError::New(env, "Fourth argument must be a function")
            .ThrowAsJavaScriptException();
        return env.Undefined();
      }
    }

    // TODO: can we distinguish verification errors from other internal errors?
    bool ok = 0 == impl->verify(signature.Data(), signature.Length(), message.Data(), message.Length(), publicKey.Data());
    return Napi::Value::From(env, ok);
  }

  Napi::Value GetAlgorithm(const Napi::CallbackInfo& info) {
    return Napi::Value::From(info.Env(), impl->id);
  }

  Napi::Value GetDescription(const Napi::CallbackInfo& info) {
    return Napi::Value::From(info.Env(), impl->description);
  }

  Napi::Value GetSignatureSize(const Napi::CallbackInfo& info) {
    return Napi::Value::From(info.Env(), impl->signatureSize);
  }

  Napi::Value GetPublicKeySize(const Napi::CallbackInfo& info) {
    return Napi::Value::From(info.Env(), impl->publicKeySize);
  }

  Napi::Value GetPrivateKeySize(const Napi::CallbackInfo& info) {
    return Napi::Value::From(info.Env(), impl->privateKeySize);
  }

 private:
  const pqclean::sign::Algorithm* impl;
};

Napi::Function InitKEM(Napi::Env env) {
  Napi::Function func = KEM::DefineClass(env, "KEM", {
    Napi::ObjectWrap<KEM>::InstanceMethod("keypair", &KEM::Keypair),
    Napi::ObjectWrap<KEM>::InstanceMethod("generateKey", &KEM::GenerateKey),
    Napi::ObjectWrap<KEM>::InstanceMethod("decryptKey", &KEM::DecryptKey),

    Napi::ObjectWrap<KEM>::InstanceAccessor("algorithm", &KEM::GetAlgorithm, nullptr),
    Napi::ObjectWrap<KEM>::InstanceAccessor("description", &KEM::GetDescription, nullptr),
    Napi::ObjectWrap<KEM>::InstanceAccessor("keySize", &KEM::GetKeySize, nullptr),
    Napi::ObjectWrap<KEM>::InstanceAccessor("encryptedKeySize", &KEM::GetEncryptedKeySize, nullptr),
    Napi::ObjectWrap<KEM>::InstanceAccessor("publicKeySize", &KEM::GetPublicKeySize, nullptr),
    Napi::ObjectWrap<KEM>::InstanceAccessor("privateKeySize", &KEM::GetPrivateKeySize, nullptr)
  });

  const auto& algorithms = pqclean::kem::algorithms();
  Napi::Array supported_algorithms = Napi::Array::New(env, algorithms.size());
  for (size_t i = 0; i < algorithms.size(); i++) {
    supported_algorithms[i] = Napi::String::New(env, algorithms[i].id);
  }
  func.DefineProperty(Napi::PropertyDescriptor::Value("supportedAlgorithms", supported_algorithms));

  return func;
}

Napi::Function InitSign(Napi::Env env) {
  Napi::Function func = Sign::DefineClass(env, "Sign", {
    Napi::ObjectWrap<Sign>::InstanceMethod("keypair", &Sign::Keypair),
    Napi::ObjectWrap<Sign>::InstanceMethod("sign", &Sign::DoSign),
    Napi::ObjectWrap<Sign>::InstanceMethod("verify", &Sign::Verify),

    Napi::ObjectWrap<Sign>::InstanceAccessor("algorithm", &Sign::GetAlgorithm, nullptr),
    Napi::ObjectWrap<Sign>::InstanceAccessor("description", &Sign::GetDescription, nullptr),
    Napi::ObjectWrap<Sign>::InstanceAccessor("signatureSize", &Sign::GetSignatureSize, nullptr),
    Napi::ObjectWrap<Sign>::InstanceAccessor("publicKeySize", &Sign::GetPublicKeySize, nullptr),
    Napi::ObjectWrap<Sign>::InstanceAccessor("privateKeySize", &Sign::GetPrivateKeySize, nullptr)
  });

  const auto& algorithms = pqclean::sign::algorithms();
  Napi::Array supported_algorithms = Napi::Array::New(env, algorithms.size());
  for (size_t i = 0; i < algorithms.size(); i++) {
    supported_algorithms[i] = Napi::String::New(env, algorithms[i].id);
  }
  func.DefineProperty(Napi::PropertyDescriptor::Value("supportedAlgorithms", supported_algorithms));

  return func;
}

////////////////////////////////////////////////////////////////////////////////
// Key-centric API
////////////////////////////////////////////////////////////////////////////////

struct KeyPairConstructors {
  Napi::FunctionReference* publicKeyConstructor;
  Napi::FunctionReference* privateKeyConstructor;
  Napi::FunctionReference* asymmetricKeyContainerConstructor;
};

struct AddonData {
  KeyPairConstructors kemKeyPairConstructors;
  KeyPairConstructors signKeyPairConstructors;
};

// TODO: replace with std::u8string_view (C++20) at some point in the future
struct ArrayBufferSlice {
  unsigned char* data;
  size_t byteLength;
};

inline ArrayBufferSlice GetArrayBufferAsSlice(Napi::ArrayBuffer arrayBuffer) {
  return {
    static_cast<unsigned char*>(arrayBuffer.Data()),
    arrayBuffer.ByteLength()
  };
}

template <typename T>
inline ArrayBufferSlice GetArrayBufferViewAsSlice(T view) {
  auto slice = GetArrayBufferAsSlice(view.ArrayBuffer());
  slice.data += view.ByteOffset();
  NAPI_CHECK(slice.byteLength >= view.ByteLength(),
             "PQClean:GetArrayBufferViewAsSlice",
             "ArrayBufferView.byteLength must be less than or equal to "
             "ArrayBufferView.buffer.byteLength.");
  slice.byteLength = view.ByteLength();
  return slice;
}

inline bool GetBufferSourceAsSlice(Napi::Value v, ArrayBufferSlice* out) {
  if (v.IsArrayBuffer()) {
    *out = GetArrayBufferAsSlice(v.As<Napi::ArrayBuffer>());
    return true;
  } else if (v.IsTypedArray()) {
    *out = GetArrayBufferViewAsSlice<Napi::TypedArray>(v.As<Napi::TypedArray>());
    return true;
  } else if (v.IsDataView()) {
    *out = GetArrayBufferViewAsSlice<Napi::DataView>(v.As<Napi::DataView>());
    return true;
  } else {
    return false;
  }
}

Napi::Object GetAlgorithmObject(Napi::Env env, const pqclean::kem::Algorithm* impl) {
  Napi::Object algorithm = Napi::Object::New(env);
  algorithm.Set("name", impl->id);
  algorithm.Set("description", impl->description);
  algorithm.Set("publicKeySize", impl->publicKeySize);
  algorithm.Set("privateKeySize", impl->privateKeySize);
  algorithm.Set("keySize", impl->keySize);
  algorithm.Set("encryptedKeySize", impl->ciphertextSize);
  return algorithm;
}

Napi::Object GetAlgorithmObject(Napi::Env env, const pqclean::sign::Algorithm* impl) {
  Napi::Object algorithm = Napi::Object::New(env);
  algorithm.Set("name", impl->id);
  algorithm.Set("description", impl->description);
  algorithm.Set("publicKeySize", impl->publicKeySize);
  algorithm.Set("privateKeySize", impl->privateKeySize);
  algorithm.Set("signatureSize", impl->signatureSize);
  return algorithm;
}

template <typename Algorithm>
class AsymmetricKey {
 public:
  typedef std::shared_ptr<AsymmetricKey> Ptr;

  enum class Type { publicKey, privateKey };

  class Builder {
   public:
    Builder(const Algorithm* impl, Type type)
        : impl(impl),
          bytes(type == Type::publicKey ? impl->publicKeySize : impl->privateKeySize) {}

    inline size_t size() {
      return bytes.size();
    }

    inline unsigned char* data() {
      return bytes.data();
    }

    inline Ptr release() && {
      return Ptr(new AsymmetricKey(impl, std::move(bytes)));
    }

   private:
    const Algorithm* impl;
    std::vector<unsigned char> bytes;
  };

  AsymmetricKey(const Algorithm* impl, Type type,
                unsigned char* p, size_t s)
      : impl(impl), bytes(p, p + s) {
    size_t expected = (type == Type::publicKey) ? impl->publicKeySize
                                                : impl->privateKeySize;
    NAPI_CHECK(s == expected, "PQClean:AsymmetricKey", "unexpected key size");
  }

  inline const Algorithm* algorithm() {
    return impl;
  }

  inline const std::vector<unsigned char>& material() {
    return bytes;
  }

 private:
  AsymmetricKey(const Algorithm* impl, std::vector<unsigned char>&& bytes)
      : impl(impl), bytes(std::move(bytes)) {}

  const Algorithm* impl;
  std::vector<unsigned char> bytes;
};

template <typename Algorithm>
class AsymmetricKeyContainer : public Napi::ObjectWrap<AsymmetricKeyContainer<Algorithm>> {
 public:
  AsymmetricKeyContainer(const Napi::CallbackInfo& info)
      : Napi::ObjectWrap<AsymmetricKeyContainer<Algorithm>>(info) {}

  void Embed(const typename AsymmetricKey<Algorithm>::Ptr& key) {
    this->key = key;
  }

  const typename AsymmetricKey<Algorithm>::Ptr& GetEmbedded() {
    return key;
  }

 private:
  typename AsymmetricKey<Algorithm>::Ptr key;
};

template <typename Algorithm>
void GetKeyPairConstructors(
    AddonData* addonData, const KeyPairConstructors** constructors);

template <>
void GetKeyPairConstructors<pqclean::kem::Algorithm>(
    AddonData* addonData, const KeyPairConstructors** constructors) {
  *constructors = &addonData->kemKeyPairConstructors;
}

template <>
void GetKeyPairConstructors<pqclean::sign::Algorithm>(
    AddonData* addonData, const KeyPairConstructors** constructors) {
  *constructors = &addonData->signKeyPairConstructors;
}

class KeyEncapsulationWorker : public Napi::AsyncWorker {
 public:
  static Napi::Value Q(Napi::Env env, const AsymmetricKey<pqclean::kem::Algorithm>::Ptr& publicKey) {
    KeyEncapsulationWorker* worker = new KeyEncapsulationWorker(env, publicKey);
    worker->Queue();
    return worker->deferred.Promise();
  }

 protected:
  void Execute() override {
    if (publicKey->algorithm()->enc(&encryptedKey[0], &key[0], publicKey->material().data()) != 0) {
      return SetError("failed to generate keypair");
    }
  }

  virtual void OnOK() override {
    Napi::Env env = Env();

    // TODO: avoid new allocation / copying
    auto key = Napi::ArrayBuffer::New(env, publicKey->algorithm()->keySize);
    auto ct = Napi::ArrayBuffer::New(env, publicKey->algorithm()->ciphertextSize);
    std::copy(&this->key[0], &this->key[0] + publicKey->algorithm()->keySize, reinterpret_cast<unsigned char*>(key.Data()));
    std::copy(&this->encryptedKey[0], &this->encryptedKey[0] + publicKey->algorithm()->ciphertextSize, reinterpret_cast<unsigned char*>(ct.Data()));

    Napi::Object obj = Napi::Object::New(env);
    obj.Set("key", key);
    obj.Set("encryptedKey", ct);
    deferred.Resolve(obj);
  }

  virtual void OnError(const Napi::Error& e) override {
    deferred.Reject(e.Value());
  }

 private:
  KeyEncapsulationWorker(Napi::Env env, const AsymmetricKey<pqclean::kem::Algorithm>::Ptr& publicKey)
      : Napi::AsyncWorker(env),
        deferred(Napi::Promise::Deferred::New(env)),
        publicKey(publicKey),
        key(new unsigned char[publicKey->algorithm()->keySize]),
        encryptedKey(new unsigned char[publicKey->algorithm()->ciphertextSize]) {}

  Napi::Promise::Deferred deferred;

  // Input:
  AsymmetricKey<pqclean::kem::Algorithm>::Ptr publicKey;

  // Outputs:
  std::unique_ptr<unsigned char[]> key;
  std::unique_ptr<unsigned char[]> encryptedKey;
};

class KeyDecapsulationWorker : public Napi::AsyncWorker {
 public:
  static Napi::Value Q(Napi::Env env, const AsymmetricKey<pqclean::kem::Algorithm>::Ptr& privateKey,
                       std::unique_ptr<unsigned char[]>&& encryptedKey) {
    KeyDecapsulationWorker* worker = new KeyDecapsulationWorker(env, privateKey, std::move(encryptedKey));
    worker->Queue();
    return worker->deferred.Promise();
  }

 protected:
  void Execute() override {
    if (privateKey->algorithm()->dec(&key[0], &encryptedKey[0], privateKey->material().data()) != 0) {
      return SetError("decryption failed");
    }
  }

  virtual void OnOK() override {
    Napi::Env env = Env();

    // TODO: avoid new allocation / copying
    auto key = Napi::ArrayBuffer::New(env, privateKey->algorithm()->keySize);
    std::copy(&this->key[0], &this->key[0] + privateKey->algorithm()->keySize, reinterpret_cast<unsigned char*>(key.Data()));

    deferred.Resolve(key);
  }

  virtual void OnError(const Napi::Error& e) override {
    deferred.Reject(e.Value());
  }

 private:
  KeyDecapsulationWorker(Napi::Env env, const AsymmetricKey<pqclean::kem::Algorithm>::Ptr& privateKey,
                         std::unique_ptr<unsigned char[]>&& encryptedKey)
      : Napi::AsyncWorker(env),
        deferred(Napi::Promise::Deferred::New(env)),
        privateKey(privateKey),
        encryptedKey(std::move(encryptedKey)),
        key(new unsigned char[privateKey->algorithm()->keySize]) {}

  Napi::Promise::Deferred deferred;

  // Inputs:
  AsymmetricKey<pqclean::kem::Algorithm>::Ptr privateKey;
  std::unique_ptr<unsigned char[]> encryptedKey;

  // Output:
  std::unique_ptr<unsigned char[]> key;
};

class KEMPublicKey : public Napi::ObjectWrap<KEMPublicKey> {
 public:
  KEMPublicKey(const Napi::CallbackInfo& info)
      : Napi::ObjectWrap<KEMPublicKey>(info) {
    Napi::Env env = info.Env();

    // We use instances of AsymmetricKeyContainer to pass AsymmetricKey::Ptr
    // to the constructor. This class is not exposed to users, so this is not
    // part of the public API.
    if (info.Length() == 1 && info[0].IsObject()) {
      Napi::Object container = info[0].As<Napi::Object>();
      AddonData* addonData = env.GetInstanceData<AddonData>();
      if (container.InstanceOf(addonData->kemKeyPairConstructors.asymmetricKeyContainerConstructor->Value())) {
        key = AsymmetricKeyContainer<pqclean::kem::Algorithm>::Unwrap(container)->GetEmbedded();
        return;
      }
    }

    if (info.Length() != 2) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return;
    }

    if (!info[0].IsString()) {
      Napi::TypeError::New(env, "First argument must be a string")
          .ThrowAsJavaScriptException();
      return;
    }

    ArrayBufferSlice material;
    if (!GetBufferSourceAsSlice(info[1], &material)) {
      Napi::TypeError::New(env, "Second argument must be a BufferSource")
          .ThrowAsJavaScriptException();
      return;
    }

    std::string name = info[0].As<Napi::String>();
    auto impl = get_kem(name);
    if (impl == nullptr) {
      Napi::Error::New(env, "No such implementation")
          .ThrowAsJavaScriptException();
      return;
    }

    if (material.byteLength != impl->publicKeySize) {
      Napi::Error::New(env, "Invalid public key size")
          .ThrowAsJavaScriptException();
      return;
    }

    key = std::make_shared<AsymmetricKey<pqclean::kem::Algorithm>>(impl, AsymmetricKey<pqclean::kem::Algorithm>::Type::publicKey,
                                          material.data, material.byteLength);
  }

  Napi::Value GenerateKey(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 0) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    return KeyEncapsulationWorker::Q(env, key);
  }

  Napi::Value Export(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 0) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    auto& mat = this->key->material();
    auto out = Napi::ArrayBuffer::New(env, mat.size());
    std::copy(mat.begin(), mat.end(), reinterpret_cast<unsigned char*>(out.Data()));
    return out;
  }

  Napi::Value GetAlgorithm(const Napi::CallbackInfo& info) {
    return GetAlgorithmObject(Env(), key->algorithm());
  }

 private:
  AsymmetricKey<pqclean::kem::Algorithm>::Ptr key;
};

class KEMPrivateKey : public Napi::ObjectWrap<KEMPrivateKey> {
 public:
  KEMPrivateKey(const Napi::CallbackInfo& info)
      : Napi::ObjectWrap<KEMPrivateKey>(info) {
    Napi::Env env = info.Env();

    // We use instances of AsymmetricKeyContainer to pass AsymmetricKey::Ptr
    // to the constructor. This class is not exposed to users, so this is not
    // part of the public API.
    if (info.Length() == 1 && info[0].IsObject()) {
      Napi::Object container = info[0].As<Napi::Object>();
      AddonData* addonData = env.GetInstanceData<AddonData>();
      if (container.InstanceOf(addonData->kemKeyPairConstructors.asymmetricKeyContainerConstructor->Value())) {
        key = AsymmetricKeyContainer<pqclean::kem::Algorithm>::Unwrap(container)->GetEmbedded();
        return;
      }
    }

    if (info.Length() != 2) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return;
    }

    if (!info[0].IsString()) {
      Napi::TypeError::New(env, "First argument must be a string")
          .ThrowAsJavaScriptException();
      return;
    }

    ArrayBufferSlice material;
    if (!GetBufferSourceAsSlice(info[1], &material)) {
      Napi::TypeError::New(env, "Second argument must be a BufferSource")
          .ThrowAsJavaScriptException();
      return;
    }

    std::string name = info[0].As<Napi::String>();
    auto impl = get_kem(name);
    if (impl == nullptr) {
      Napi::Error::New(env, "No such implementation")
          .ThrowAsJavaScriptException();
      return;
    }

    if (material.byteLength != impl->privateKeySize) {
      Napi::Error::New(env, "Invalid private key size")
          .ThrowAsJavaScriptException();
      return;
    }

    key = std::make_shared<AsymmetricKey<pqclean::kem::Algorithm>>(impl, AsymmetricKey<pqclean::kem::Algorithm>::Type::privateKey,
                                          material.data, material.byteLength);
  }

  Napi::Value DecryptKey(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    ArrayBufferSlice encryptedKey;
    if (!GetBufferSourceAsSlice(info[0], &encryptedKey)) {
      Napi::TypeError::New(env, "First argument must be a BufferSource")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    if (encryptedKey.byteLength != key->algorithm()->ciphertextSize) {
      Napi::Error::New(env, "Invalid ciphertext size")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    std::unique_ptr<unsigned char[]> encryptedKeyCopy = std::make_unique<unsigned char[]>(encryptedKey.byteLength);
    std::copy(encryptedKey.data, encryptedKey.data + encryptedKey.byteLength, &encryptedKeyCopy[0]);

    return KeyDecapsulationWorker::Q(env, key, std::move(encryptedKeyCopy));
  }

  Napi::Value Export(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 0) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    auto& mat = this->key->material();
    auto out = Napi::ArrayBuffer::New(env, mat.size());
    std::copy(mat.begin(), mat.end(), reinterpret_cast<unsigned char*>(out.Data()));
    return out;
  }

  Napi::Value GetAlgorithm(const Napi::CallbackInfo& info) {
    return GetAlgorithmObject(Env(), key->algorithm());
  }

 private:
  AsymmetricKey<pqclean::kem::Algorithm>::Ptr key;
};

template <typename Algorithm>
class KeyPairWorker : public Napi::AsyncWorker {
 public:
  static Napi::Value Q(Napi::Env env, const Algorithm* impl) {
    KeyPairWorker<Algorithm>* worker = new KeyPairWorker<Algorithm>(env, impl);
    worker->Queue();
    return worker->deferred.Promise();
  }

 protected:
  void Execute() override {
    typename AsymmetricKey<Algorithm>::Builder publicKey(impl, AsymmetricKey<Algorithm>::Type::publicKey);
    typename AsymmetricKey<Algorithm>::Builder privateKey(impl, AsymmetricKey<Algorithm>::Type::privateKey);

    if (impl->keypair(publicKey.data(), privateKey.data()) != 0) {
      return SetError("failed to generate keypair");
    }

    this->publicKey = std::move(publicKey).release();
    this->privateKey = std::move(privateKey).release();
  }

  virtual void OnOK() override {
    Napi::Env env = Env();
    AddonData* addonData = env.GetInstanceData<AddonData>();

    const KeyPairConstructors* ctors;
    GetKeyPairConstructors<Algorithm>(addonData, &ctors);

    auto publicKeyContainer = ctors->asymmetricKeyContainerConstructor->New({});
    AsymmetricKeyContainer<Algorithm>::Unwrap(publicKeyContainer)->Embed(publicKey);

    auto privateKeyContainer = ctors->asymmetricKeyContainerConstructor->New({});
    AsymmetricKeyContainer<Algorithm>::Unwrap(privateKeyContainer)->Embed(privateKey);

    Napi::Object obj = Napi::Object::New(env);
    obj.Set("publicKey", ctors->publicKeyConstructor->New({ publicKeyContainer }));
    obj.Set("privateKey", ctors->privateKeyConstructor->New({ privateKeyContainer }));

    deferred.Resolve(obj);
  }

  virtual void OnError(const Napi::Error& e) override {
    deferred.Reject(e.Value());
  }

 private:
  KeyPairWorker(Napi::Env env, const Algorithm* impl)
      : Napi::AsyncWorker(env),
        deferred(Napi::Promise::Deferred::New(env)),
        impl(impl) {}

  Napi::Promise::Deferred deferred;

  // Input:
  const Algorithm* impl;

  // Outputs:
  typename AsymmetricKey<Algorithm>::Ptr publicKey;
  typename AsymmetricKey<Algorithm>::Ptr privateKey;
};

Napi::Value GenerateKEMKeyPair(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() != 1) {
    Napi::TypeError::New(env, "Wrong number of arguments")
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }

  if (!info[0].IsString()) {
    Napi::TypeError::New(env, "First argument must be a string")
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }

  std::string name = info[0].As<Napi::String>();
  const pqclean::kem::Algorithm* impl = get_kem(name);
  if (impl == nullptr) {
    Napi::Error::New(env, "No such implementation")
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }

  return KeyPairWorker<pqclean::kem::Algorithm>::Q(env, impl);
}

Napi::Object InitKeyCentricKEM(Napi::Env env, AddonData* addonData) {
  Napi::Object obj = Napi::Object::New(env);
  auto ctors = &addonData->kemKeyPairConstructors;

  auto publicKeyClass = KEMPublicKey::DefineClass(env, "PQCleanKEMPublicKey", {
    Napi::ObjectWrap<KEMPublicKey>::InstanceAccessor("algorithm", &KEMPublicKey::GetAlgorithm, nullptr, napi_enumerable),
    Napi::ObjectWrap<KEMPublicKey>::InstanceMethod("generateKey", &KEMPublicKey::GenerateKey),
    Napi::ObjectWrap<KEMPublicKey>::InstanceMethod("export", &KEMPublicKey::Export)
  });
  obj.DefineProperty(Napi::PropertyDescriptor::Value("PublicKey", publicKeyClass, napi_enumerable));

  ctors->publicKeyConstructor = new Napi::FunctionReference();
  *ctors->publicKeyConstructor = Napi::Persistent(publicKeyClass);

  auto privateKeyClass = KEMPrivateKey::DefineClass(env, "PQCleanKEMPrivateKey", {
    Napi::ObjectWrap<KEMPrivateKey>::InstanceAccessor("algorithm", &KEMPrivateKey::GetAlgorithm, nullptr, napi_enumerable),
    Napi::ObjectWrap<KEMPrivateKey>::InstanceMethod("decryptKey", &KEMPrivateKey::DecryptKey),
    Napi::ObjectWrap<KEMPrivateKey>::InstanceMethod("export", &KEMPrivateKey::Export)
  });
  obj.DefineProperty(Napi::PropertyDescriptor::Value("PrivateKey", privateKeyClass, napi_enumerable));

  ctors->privateKeyConstructor = new Napi::FunctionReference();
  *ctors->privateKeyConstructor = Napi::Persistent(privateKeyClass);

  auto asymmetricKeyContainerClass = AsymmetricKeyContainer<pqclean::kem::Algorithm>::DefineClass(env, "InternalKEMKeyContainer", {});
  ctors->asymmetricKeyContainerConstructor = new Napi::FunctionReference();
  *ctors->asymmetricKeyContainerConstructor = Napi::Persistent(asymmetricKeyContainerClass);

  obj.DefineProperty(Napi::PropertyDescriptor::Value("generateKeyPair", Napi::Function::New<GenerateKEMKeyPair>(env), napi_enumerable));

  const auto& algorithms = pqclean::kem::algorithms();
  Napi::Array supported_algorithms = Napi::Array::New(env, algorithms.size());
  for (size_t i = 0; i < algorithms.size(); i++) {
    supported_algorithms[i] = GetAlgorithmObject(env, &algorithms[i]);
  }
  obj.DefineProperty(Napi::PropertyDescriptor::Value("supportedAlgorithms", supported_algorithms, napi_enumerable));

  return obj;
}

class SignatureWorker : public Napi::AsyncWorker {
 public:
  static Napi::Value Q(Napi::Env env, const AsymmetricKey<pqclean::sign::Algorithm>::Ptr& privateKey,
                       std::unique_ptr<unsigned char[]>&& message, size_t messageSize) {
    SignatureWorker* worker = new SignatureWorker(env, privateKey, std::move(message), messageSize);
    worker->Queue();
    return worker->deferred.Promise();
  }

 protected:
  void Execute() override {
    auto impl = privateKey->algorithm();

    signatureSize = impl->signatureSize;
    int r = impl->signature(&signature[0], &signatureSize, &message[0], messageSize, privateKey->material().data());
    if (r != 0) {
      return SetError("sign operation failed");
    }

    NAPI_CHECK(signatureSize <= impl->signatureSize, "PQClean:SignatureWorker",
               "Actual signature size must not exceed maximum signature size.");
  }

  virtual void OnOK() override {
    Napi::Env env = Env();

    // TODO: avoid new allocation / copying
    auto key = Napi::ArrayBuffer::New(env, signatureSize);
    std::copy(&this->signature[0], &this->signature[0] + signatureSize, reinterpret_cast<unsigned char*>(key.Data()));

    deferred.Resolve(key);
  }

  virtual void OnError(const Napi::Error& e) override {
    deferred.Reject(e.Value());
  }

 private:
  SignatureWorker(Napi::Env env, const AsymmetricKey<pqclean::sign::Algorithm>::Ptr& privateKey,
                  std::unique_ptr<unsigned char[]>&& message, size_t messageSize)
      : Napi::AsyncWorker(env),
        deferred(Napi::Promise::Deferred::New(env)),
        privateKey(privateKey),
        message(std::move(message)),
        messageSize(messageSize),
        signature(new unsigned char[privateKey->algorithm()->signatureSize]) {}

  Napi::Promise::Deferred deferred;

  // Inputs:
  AsymmetricKey<pqclean::sign::Algorithm>::Ptr privateKey;
  std::unique_ptr<unsigned char[]> message;
  size_t messageSize;

  // Output:
  std::unique_ptr<unsigned char[]> signature;
  size_t signatureSize;
};

class EmbeddedSignatureWorker : public Napi::AsyncWorker {
 public:
  static Napi::Value Q(Napi::Env env, const AsymmetricKey<pqclean::sign::Algorithm>::Ptr& privateKey,
                       std::unique_ptr<unsigned char[]>&& message, size_t messageSize) {
    EmbeddedSignatureWorker* worker = new EmbeddedSignatureWorker(env, privateKey, std::move(message), messageSize);
    worker->Queue();
    return worker->deferred.Promise();
  }

 protected:
  void Execute() override {
    auto impl = privateKey->algorithm();

    const size_t maxSignedMessageSize = messageSize + impl->signatureSize;
    signedMessageSize = maxSignedMessageSize;
    int r = impl->sign(&signedMessage[0], &signedMessageSize, &message[0], messageSize, privateKey->material().data());
    if (r != 0) {
      return SetError("signEmbed operation failed");
    }

    NAPI_CHECK(signedMessageSize <= maxSignedMessageSize, "PQClean:EmbeddedSignatureWorker",
               "Actual signature size must not exceed maximum signature size.");
  }

  virtual void OnOK() override {
    Napi::Env env = Env();

    // TODO: avoid new allocation / copying
    auto result = Napi::ArrayBuffer::New(env, signedMessageSize);
    std::copy(&this->signedMessage[0],
              &this->signedMessage[0] + signedMessageSize,
              reinterpret_cast<unsigned char*>(result.Data()));

    deferred.Resolve(result);
  }

  virtual void OnError(const Napi::Error& e) override {
    deferred.Reject(e.Value());
  }

 private:
  EmbeddedSignatureWorker(Napi::Env env, const AsymmetricKey<pqclean::sign::Algorithm>::Ptr& privateKey,
                          std::unique_ptr<unsigned char[]>&& message, size_t messageSize)
      : Napi::AsyncWorker(env),
        deferred(Napi::Promise::Deferred::New(env)),
        privateKey(privateKey),
        message(std::move(message)),
        messageSize(messageSize),
        signedMessage(new unsigned char[messageSize + privateKey->algorithm()->signatureSize]) {}

  Napi::Promise::Deferred deferred;

  // Inputs:
  AsymmetricKey<pqclean::sign::Algorithm>::Ptr privateKey;
  std::unique_ptr<unsigned char[]> message;
  size_t messageSize;

  // Output:
  std::unique_ptr<unsigned char[]> signedMessage;
  size_t signedMessageSize;
};

class VerificationWorker : public Napi::AsyncWorker {
 public:
  static Napi::Value Q(Napi::Env env, const AsymmetricKey<pqclean::sign::Algorithm>::Ptr& publicKey,
                       std::unique_ptr<unsigned char[]>&& message, size_t messageSize,
                       std::unique_ptr<unsigned char[]>&& signature, size_t signatureSize) {
    VerificationWorker* worker = new VerificationWorker(env, publicKey, std::move(message), messageSize, std::move(signature), signatureSize);
    worker->Queue();
    return worker->deferred.Promise();
  }

 protected:
  void Execute() override {
    auto impl = publicKey->algorithm();

    // TODO: can we distinguish verification errors from other internal errors?
    ok = 0 == impl->verify(&signature[0], signatureSize, &message[0], messageSize, publicKey->material().data());
  }

  virtual void OnOK() override {
    deferred.Resolve(Napi::Value::From(Env(), ok));
  }

  virtual void OnError(const Napi::Error& e) override {
    deferred.Reject(e.Value());
  }

 private:
  VerificationWorker(Napi::Env env, const AsymmetricKey<pqclean::sign::Algorithm>::Ptr& publicKey,
                     std::unique_ptr<unsigned char[]>&& message, size_t messageSize,
                     std::unique_ptr<unsigned char[]>&& signature, size_t signatureSize)
      : Napi::AsyncWorker(env),
        deferred(Napi::Promise::Deferred::New(env)),
        publicKey(publicKey),
        message(std::move(message)), messageSize(messageSize),
        signature(std::move(signature)), signatureSize(signatureSize) {}

  Napi::Promise::Deferred deferred;

  // Inputs:
  AsymmetricKey<pqclean::sign::Algorithm>::Ptr publicKey;
  std::unique_ptr<unsigned char[]> message;
  size_t messageSize;
  std::unique_ptr<unsigned char[]> signature;
  size_t signatureSize;

  // Outputs:
  bool ok;
};

class OpenWorker : public Napi::AsyncWorker {
 public:
  static Napi::Value Q(Napi::Env env, const AsymmetricKey<pqclean::sign::Algorithm>::Ptr& publicKey,
                       std::unique_ptr<unsigned char[]>&& signedMessage, size_t signedMessageSize) {
    OpenWorker* worker = new OpenWorker(env, publicKey, std::move(signedMessage), signedMessageSize);
    worker->Queue();
    return worker->deferred.Promise();
  }

 protected:
  void Execute() override {
    auto impl = publicKey->algorithm();

    messageSize = signedMessageSize;

    // TODO: can we distinguish verification errors from other internal errors?
    bool ok = 0 == impl->open(&message[0], &messageSize,
                              &signedMessage[0], signedMessageSize,
                              publicKey->material().data());
    if (!ok) {
      return SetError("signature verification failed");
    }

    NAPI_CHECK(messageSize < signedMessageSize, "PQClean:OpenWorker",
               "Embedded message size must be less than signed message size.");
  }

  virtual void OnOK() override {
    Napi::Env env = Env();

    // TODO: avoid new allocation / copying
    auto result = Napi::ArrayBuffer::New(env, messageSize);
    std::copy(&this->message[0], &this->message[0] + messageSize,
              reinterpret_cast<unsigned char*>(result.Data()));

    deferred.Resolve(result);
  }

  virtual void OnError(const Napi::Error& e) override {
    deferred.Reject(e.Value());
  }

 private:
  OpenWorker(Napi::Env env, const AsymmetricKey<pqclean::sign::Algorithm>::Ptr& publicKey,
             std::unique_ptr<unsigned char[]>&& signedMessage, size_t signedMessageSize)
      : Napi::AsyncWorker(env),
        deferred(Napi::Promise::Deferred::New(env)),
        publicKey(publicKey),
        signedMessage(std::move(signedMessage)),
        signedMessageSize(signedMessageSize),
        message(new unsigned char[signedMessageSize]) {}

  Napi::Promise::Deferred deferred;

  // Inputs:
  AsymmetricKey<pqclean::sign::Algorithm>::Ptr publicKey;
  std::unique_ptr<unsigned char[]> signedMessage;
  size_t signedMessageSize;

  // Outputs:
  std::unique_ptr<unsigned char[]> message;
  size_t messageSize;
};

class SignPublicKey : public Napi::ObjectWrap<SignPublicKey> {
 public:
  SignPublicKey(const Napi::CallbackInfo& info)
      : Napi::ObjectWrap<SignPublicKey>(info) {
    Napi::Env env = info.Env();

    // We use instances of AsymmetricKeyContainer to pass AsymmetricKey::Ptr
    // to the constructor. This class is not exposed to users, so this is not
    // part of the public API.
    if (info.Length() == 1 && info[0].IsObject()) {
      Napi::Object container = info[0].As<Napi::Object>();
      AddonData* addonData = env.GetInstanceData<AddonData>();
      if (container.InstanceOf(addonData->signKeyPairConstructors.asymmetricKeyContainerConstructor->Value())) {
        key = AsymmetricKeyContainer<pqclean::sign::Algorithm>::Unwrap(container)->GetEmbedded();
        return;
      }
    }

    if (info.Length() != 2) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return;
    }

    if (!info[0].IsString()) {
      Napi::TypeError::New(env, "First argument must be a string")
          .ThrowAsJavaScriptException();
      return;
    }

    ArrayBufferSlice material;
    if (!GetBufferSourceAsSlice(info[1], &material)) {
      Napi::TypeError::New(env, "Second argument must be a BufferSource")
          .ThrowAsJavaScriptException();
      return;
    }

    std::string name = info[0].As<Napi::String>();
    auto impl = get_sign(name);
    if (impl == nullptr) {
      Napi::Error::New(env, "No such implementation")
          .ThrowAsJavaScriptException();
      return;
    }

    if (material.byteLength != impl->publicKeySize) {
      Napi::Error::New(env, "Invalid public key size")
          .ThrowAsJavaScriptException();
      return;
    }

    key = std::make_shared<AsymmetricKey<pqclean::sign::Algorithm>>(impl, AsymmetricKey<pqclean::sign::Algorithm>::Type::publicKey,
                                          material.data, material.byteLength);
  }

  Napi::Value Verify(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 2) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    ArrayBufferSlice message;
    if (!GetBufferSourceAsSlice(info[0], &message)) {
      Napi::TypeError::New(env, "First argument must be a BufferSource")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    ArrayBufferSlice signature;
    if (!GetBufferSourceAsSlice(info[1], &signature)) {
      Napi::TypeError::New(env, "Second argument must be a BufferSource")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    if (signature.byteLength > key->algorithm()->signatureSize) {
      Napi::Error::New(env, "Invalid signature size")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    std::unique_ptr<unsigned char[]> messageCopy = std::make_unique<unsigned char[]>(message.byteLength);
    std::copy(message.data, message.data + message.byteLength, &messageCopy[0]);

    std::unique_ptr<unsigned char[]> signatureCopy = std::make_unique<unsigned char[]>(signature.byteLength);
    std::copy(signature.data, signature.data + signature.byteLength, &signatureCopy[0]);

    return VerificationWorker::Q(env, key, std::move(messageCopy), message.byteLength, std::move(signatureCopy), signature.byteLength);
  }

  Napi::Value Open(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    ArrayBufferSlice signedMessage;
    if (!GetBufferSourceAsSlice(info[0], &signedMessage)) {
      Napi::TypeError::New(env, "First argument must be a BufferSource")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    std::unique_ptr<unsigned char[]> signedMessageCopy = std::make_unique<unsigned char[]>(signedMessage.byteLength);
    std::copy(signedMessage.data, signedMessage.data + signedMessage.byteLength, &signedMessageCopy[0]);

    return OpenWorker::Q(env, key, std::move(signedMessageCopy), signedMessage.byteLength);
  }

  Napi::Value Export(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 0) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    auto& mat = this->key->material();
    auto out = Napi::ArrayBuffer::New(env, mat.size());
    std::copy(mat.begin(), mat.end(), reinterpret_cast<unsigned char*>(out.Data()));
    return out;
  }

  Napi::Value GetAlgorithm(const Napi::CallbackInfo& info) {
    return GetAlgorithmObject(Env(), key->algorithm());
  }

 private:
  AsymmetricKey<pqclean::sign::Algorithm>::Ptr key;
};

class SignPrivateKey : public Napi::ObjectWrap<SignPrivateKey> {
 public:
  SignPrivateKey(const Napi::CallbackInfo& info)
      : Napi::ObjectWrap<SignPrivateKey>(info) {
    Napi::Env env = info.Env();

    // We use instances of AsymmetricKeyContainer to pass AsymmetricKey::Ptr
    // to the constructor. This class is not exposed to users, so this is not
    // part of the public API.
    if (info.Length() == 1 && info[0].IsObject()) {
      Napi::Object container = info[0].As<Napi::Object>();
      AddonData* addonData = env.GetInstanceData<AddonData>();
      if (container.InstanceOf(addonData->signKeyPairConstructors.asymmetricKeyContainerConstructor->Value())) {
        key = AsymmetricKeyContainer<pqclean::sign::Algorithm>::Unwrap(container)->GetEmbedded();
        return;
      }
    }

    if (info.Length() != 2) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return;
    }

    if (!info[0].IsString()) {
      Napi::TypeError::New(env, "First argument must be a string")
          .ThrowAsJavaScriptException();
      return;
    }

    ArrayBufferSlice material;
    if (!GetBufferSourceAsSlice(info[1], &material)) {
      Napi::TypeError::New(env, "Second argument must be a BufferSource")
          .ThrowAsJavaScriptException();
      return;
    }

    std::string name = info[0].As<Napi::String>();
    auto impl = get_sign(name);
    if (impl == nullptr) {
      Napi::Error::New(env, "No such implementation")
          .ThrowAsJavaScriptException();
      return;
    }

    if (material.byteLength != impl->privateKeySize) {
      Napi::Error::New(env, "Invalid private key size")
          .ThrowAsJavaScriptException();
      return;
    }

    key = std::make_shared<AsymmetricKey<pqclean::sign::Algorithm>>(impl, AsymmetricKey<pqclean::sign::Algorithm>::Type::privateKey,
                                          material.data, material.byteLength);
  }

  Napi::Value Sign(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    ArrayBufferSlice message;
    if (!GetBufferSourceAsSlice(info[0], &message)) {
      Napi::TypeError::New(env, "First argument must be a BufferSource")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    std::unique_ptr<unsigned char[]> messageCopy = std::make_unique<unsigned char[]>(message.byteLength);
    std::copy(message.data, message.data + message.byteLength, &messageCopy[0]);

    return SignatureWorker::Q(env, key, std::move(messageCopy), message.byteLength);
  }

  Napi::Value SignEmbed(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 1) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    ArrayBufferSlice message;
    if (!GetBufferSourceAsSlice(info[0], &message)) {
      Napi::TypeError::New(env, "First argument must be a BufferSource")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    std::unique_ptr<unsigned char[]> messageCopy = std::make_unique<unsigned char[]>(message.byteLength);
    std::copy(message.data, message.data + message.byteLength, &messageCopy[0]);

    return EmbeddedSignatureWorker::Q(env, key, std::move(messageCopy), message.byteLength);
  }

  Napi::Value Export(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() != 0) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    auto& mat = this->key->material();
    auto out = Napi::ArrayBuffer::New(env, mat.size());
    std::copy(mat.begin(), mat.end(), reinterpret_cast<unsigned char*>(out.Data()));
    return out;
  }

  Napi::Value GetAlgorithm(const Napi::CallbackInfo& info) {
    return GetAlgorithmObject(Env(), key->algorithm());
  }

 private:
  AsymmetricKey<pqclean::sign::Algorithm>::Ptr key;
};

Napi::Value GenerateSignKeyPair(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() != 1) {
    Napi::TypeError::New(env, "Wrong number of arguments")
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }

  if (!info[0].IsString()) {
    Napi::TypeError::New(env, "First argument must be a string")
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }

  std::string name = info[0].As<Napi::String>();
  const pqclean::sign::Algorithm* impl = get_sign(name);
  if (impl == nullptr) {
    Napi::Error::New(env, "No such implementation")
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }

  return KeyPairWorker<pqclean::sign::Algorithm>::Q(env, impl);
}

Napi::Object InitKeyCentricSign(Napi::Env env, AddonData* addonData) {
  Napi::Object obj = Napi::Object::New(env);
  auto ctors = &addonData->signKeyPairConstructors;

  auto publicKeyClass = SignPublicKey::DefineClass(env, "PQCleanSignPublicKey", {
    Napi::ObjectWrap<SignPublicKey>::InstanceAccessor("algorithm", &SignPublicKey::GetAlgorithm, nullptr, napi_enumerable),
    Napi::ObjectWrap<SignPublicKey>::InstanceMethod("verify", &SignPublicKey::Verify),
    Napi::ObjectWrap<SignPublicKey>::InstanceMethod("open", &SignPublicKey::Open),
    Napi::ObjectWrap<SignPublicKey>::InstanceMethod("export", &SignPublicKey::Export)
  });
  obj.DefineProperty(Napi::PropertyDescriptor::Value("PublicKey", publicKeyClass, napi_enumerable));

  ctors->publicKeyConstructor = new Napi::FunctionReference();
  *ctors->publicKeyConstructor = Napi::Persistent(publicKeyClass);

  auto privateKeyClass = SignPrivateKey::DefineClass(env, "PQCleanSignPrivateKey", {
    Napi::ObjectWrap<SignPrivateKey>::InstanceAccessor("algorithm", &SignPrivateKey::GetAlgorithm, nullptr, napi_enumerable),
    Napi::ObjectWrap<SignPrivateKey>::InstanceMethod("sign", &SignPrivateKey::Sign),
    Napi::ObjectWrap<SignPrivateKey>::InstanceMethod("signEmbed", &SignPrivateKey::SignEmbed),
    Napi::ObjectWrap<SignPrivateKey>::InstanceMethod("export", &SignPrivateKey::Export)
  });
  obj.DefineProperty(Napi::PropertyDescriptor::Value("PrivateKey", privateKeyClass, napi_enumerable));

  ctors->privateKeyConstructor = new Napi::FunctionReference();
  *ctors->privateKeyConstructor = Napi::Persistent(privateKeyClass);

  auto asymmetricKeyContainerClass = AsymmetricKeyContainer<pqclean::sign::Algorithm>::DefineClass(env, "InternalSignKeyContainer", {});
  ctors->asymmetricKeyContainerConstructor = new Napi::FunctionReference();
  *ctors->asymmetricKeyContainerConstructor = Napi::Persistent(asymmetricKeyContainerClass);

  obj.DefineProperty(Napi::PropertyDescriptor::Value("generateKeyPair", Napi::Function::New<GenerateSignKeyPair>(env), napi_enumerable));

  const auto& algorithms = pqclean::sign::algorithms();
  Napi::Array supported_algorithms = Napi::Array::New(env, algorithms.size());
  for (size_t i = 0; i < algorithms.size(); i++) {
    supported_algorithms[i] = GetAlgorithmObject(env, &algorithms[i]);
  }
  obj.DefineProperty(Napi::PropertyDescriptor::Value("supportedAlgorithms", supported_algorithms, napi_enumerable));

  return obj;
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  Napi::HandleScope scope(env);

  exports.Set("KEM", InitKEM(env));
  exports.Set("Sign", InitSign(env));

  AddonData* addonData = new AddonData();
  exports.Set("kem", InitKeyCentricKEM(env, addonData));
  exports.Set("sign", InitKeyCentricSign(env, addonData));

  env.SetInstanceData(addonData);

  return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init);

}

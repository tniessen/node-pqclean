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

    if (info.Length() == 3 && info[2].IsFunction()) {
      Napi::Function cb = info[2].As<Napi::Function>();
      DecryptWorker* worker = new DecryptWorker(cb, impl, private_key.Data(), encrypted_key.Data());
      worker->Queue();
      return env.Undefined();
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

    Napi::Buffer<unsigned char> publicKey = info[0].As<Napi::Buffer<unsigned char>>();
    if (publicKey.Length() != impl->publicKeySize) {
      Napi::TypeError::New(env, "Invalid public key size")
          .ThrowAsJavaScriptException();
      return env.Undefined();
    }

    Napi::Buffer<unsigned char> message = info[1].As<Napi::Buffer<unsigned char>>();

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

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  Napi::HandleScope scope(env);

  exports.Set("KEM", InitKEM(env));
  exports.Set("Sign", InitSign(env));

  return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init);

}

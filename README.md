# PQClean bindings for Node.js

This package provides Node.js bindings for [PQClean][], a collection of
post-quantum cryptography algorithm implementations, including 46 key
encapsulation mechanisms and 53 digital signature algorithms.

## Installation

```sh
npm i pqclean
```

By default, node-pqclean will attempt to compile PQClean as a native addon for
Node.js. Only if that fails, for example, because necessary tools are not
installed or because the operating system is unsupported, the package will
continue with the installation, but only the WebAssembly backend will be
available at runtime.

**Because of the limited stack size on Windows (see [nodejs/node#43630][]), some
algorithms are disabled when using the native addon on Windows.** If access to
these algorithms is desired, keep reading.

It is possible to customize the installation procedure through the use of an npm
config variable `pqclean-backend`.

* `pqclean-backend=prefer-native` (default) attempts to build the native addon
  and only uses the WebAssembly backend if building the native addon fails.
* `pqclean-backend=native` builds and uses the native addon only. If building
  the native addon fails, the package installation fails as well.
* `pqclean-backend=wasm` does not build the native addon. Only the WebAssembly
  backend will be available at runtime. This option may be useful when loading
  native addons poses a security risk.
* `pqclean-backend=all-algorithms` behaves like the default (`prefer-native`)
  on non-Windows systems. On Windows, where the native addon does not support
  all algorithms, this behaves like `wasm`.

You can read more about npm config variables
[here](https://docs.npmjs.com/cli/v8/using-npm/config).

## Example

PQClean provides a consistent API for key encapsulation mechanisms. The Node.js
bindings expose this through the `KEM` class.

```javascript
const PQClean = require('pqclean');

const mceliece = new PQClean.KEM('mceliece8192128');
const { publicKey, privateKey } = mceliece.keypair();

const { key, encryptedKey } = mceliece.generateKey(publicKey);
console.log(`Bob is using the key ${key.toString('hex')}`);

const receivedKey = mceliece.decryptKey(privateKey, encryptedKey);
console.log(`Alice is using the key ${receivedKey.toString('hex')}`);
```

Similarly, PQClean's digital signature API is exposed through the `Sign` class.

```javascript
const PQClean = require('pqclean');

const falcon = new PQClean.Sign('falcon-1024');
const { publicKey, privateKey } = falcon.keypair();

const message = Buffer.from('Hello world!');
const signature = falcon.sign(privateKey, message);

const ok = falcon.verify(publicKey, message, signature);
console.assert(ok, 'signature is valid');
```

## API

The package exports two classes: `KEM` and `Sign`.

### Class `KEM`

The `KEM` class provides access to implementations of key encapsulation
mechanisms. Public keys can be used to encapsulate a shared secret key and
corresponding private keys can be used to recover the shared secret key.

#### `new KEM(algorithm)`

Creates a new instance using the specified algorithm. `algorithm` must be one of
the values contained in `KEM.supportedAlgorithms`.

#### `KEM.supportedAlgorithms`

This static field is an array of all supported algorithm names.

#### `instance.keySize`

The (maximum) key size in bytes that this instance can encapsulate.

#### `instance.encryptedKeySize`

The size of the encapsulated key in bytes.

#### `instance.publicKeySize`

The size of the public key in bytes.

#### `instance.privateKeySize`

The size of the private key in bytes.

#### `instance.keypair([callback])`

Creates and returns a new key pair `{ publicKey, privateKey }`. Both keys will
be returned as `Buffer`s.

If `callback` is given, `keypair` immediately returns `undefined` and calls
`callback(err, { publicKey, privateKey })` as soon as a new keypair has been
generated.

#### `instance.generateKey(publicKey[, callback])`

Generates a new symmetric key and encrypts (encapsulates) it using the given
`publicKey`. Returns `{ key, encryptedKey }`. Both objects will be `Buffer`s.

If `callback` is given, `generateKey` immediately returns `undefined` and calls
`callback(err, { key, encryptedKey })` as soon as the operation is completed.

#### `instance.decryptKey(privateKey, encryptedKey[, callback])`

Decrypts (decapsulates) the `encryptedKey` that was returned by
`instance.generateKey(publicKey)` and returns the decrypted key as a `Buffer`.

If `callback` is given, `decryptKey` immediately returns `undefined` and
calls `callback(err, key)` as soon as the key has been decrypted.

### Class `Sign`

The `Sign` class provides access to implementations of digital signature
algorithms. Private keys can be used to sign messages and the corresponding
public keys can be used to verify the authenticity of digital signatures.

#### `new Sign(algorithm)`

Creates a new instance using the specified algorithm. `algorithm` must be one of
the values contained in `Sign.supportedAlgorithms`.

#### `Sign.supportedAlgorithms`

This static field is an array of all supported algorithm names.

#### `instance.signatureSize`

The (maximum) signature size in bytes that this instance produces.

#### `instance.publicKeySize`

The size of the public key in bytes.

#### `instance.privateKeySize`

The size of the private key in bytes.

#### `instance.keypair([callback])`

Creates and returns a new key pair `{ publicKey, privateKey }`. Both keys will
be returned as `Buffer`s.

If `callback` is given, `keypair` immediately returns `undefined` and calls
`callback(err, { publicKey, privateKey })` when the requested keypair has been
generated.

#### `instance.sign(privateKey, message[, callback])`

Signs the given `message` using the given `privateKey` and returns the signature
as a `Buffer`.

If `callback` is given, `sign` immediately returns `undefined` and calls
`callback(err, signature)` when the operation is completed.

#### `instance.verify(publicKey, message, signature[, callback])`

Verifies the given `signature` for the given `message` using the given
`publicKey`. Returns `true` if verification succeeds, `false` otherwise.

If `callback` is given, `verify` immediately returns `undefined` and
calls `callback(err, result)` when the verification result is available.

## License

This project is distributed under the ISC license. Please check
[deps/PQClean](deps) for licenses that apply to individual algorithm
implementations.

[PQClean]: https://github.com/PQClean/PQClean
[nodejs/node#43630]: https://github.com/nodejs/node/issues/43630

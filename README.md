# PQClean for Node.js, Deno, and more

This package provides Node.js bindings for [PQClean][], a collection of
post-quantum cryptography algorithm implementations, including 19 key
encapsulation mechanisms and 44 digital signature algorithms.

In addition to the native addon for Node.js, this package also provides an
implementation for Deno and other JavaScript runtimes, such as browsers, based
on WebAssembly.

## Installation

To use this package in Node.js, install it as usual.

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

### Building for the web (Deno, browsers, etc.)

Clone the repository and run `npm run build-wasm && npm run build-web`. This
will produce the web distribution in `web/dist`.

## Key-centric API

This is the recommended API. It is available in Node.js (both through the native
backend and through the WebAssembly backend) and in the web implementation,
which can be used in Deno and modern browsers.

### Example

PQClean provides a consistent API for key encapsulation mechanisms, which is
exposed through the `kem` namespace.

```javascript
const PQClean = require('pqclean');

const {
  publicKey,
  privateKey
} = await PQClean.kem.generateKeyPair('mceliece8192128');

const { key, encryptedKey } = await publicKey.generateKey();
console.log("Bob's key", Buffer.from(key).toString('hex'));

const receivedKey = await privateKey.decryptKey(encryptedKey);
console.log("Alice's key", Buffer.from(receivedKey).toString('hex'));
```

Similarly, PQClean's digital signature API is exposed through the `sign`
namespace.

```javascript
const PQClean = require('pqclean');

const {
  publicKey,
  privateKey
} = await PQClean.sign.generateKeyPair('falcon-1024');

const message = Buffer.from('Hello world!');
const signature = await privateKey.sign(message);

const ok = await publicKey.verify(message, signature);
console.assert(ok, 'signature is valid');
```

### `kem.generateKeyPair(name)`

Generates a new key pair for the algorithm identified by `name`. Returns a
`Promise` that resolves to an object with properties named `publicKey` and
`privateKey`, which are instances of `kem.PublicKey` and `kem.PrivateKey`,
respectively.

### `kem.supportedAlgorithms`

Array of all supported key encapsulation algorithms. Each algorithm is
represented by an object with the following properties:

* `name` - unique identifier (e.g., `'mceliece8192128'`).
* `description` - display name (e.g., `'Classic McEliece 8192128'`).
* `publicKeySize` - size of the public key, in bytes.
* `privateKeySize` - size of the private key, in bytes.
* `keySize` - size of the encapsulated key, in bytes.
* `encryptedKeySize` - size of the ciphertext (encapsulated key), in bytes.

### Class `kem.PublicKey`

#### `new kem.PublicKey(name, bytes)`

Imports a public key for the algorithm identified by `name`. The key material
to be imported must be passed as a `BufferSource`.

#### `publicKey.algorithm`

Object describing the algorithm that this key can be used with. This property
has the same structure as the elements of `kem.supportedAlgorithms` (see above).

#### `publicKey.export()`

Returns an `ArrayBuffer` containing the key material. The key can later be
imported using `new kem.PublicKey(name, bytes)`.

#### `publicKey.generateKey()`

Generates a new shared secret key and encapsulates it using this public key.
Returns a `Promise` that resolves to an object with properties named `key` and
`encryptedKey`, which are the shared secret and the ciphertext (encapsulated
key), respectively. Both are returned as `ArrayBuffer` instances.

The size of the returned shared secret `key` is exactly
`privateKey.algorithm.keySize` bytes.

### Class `kem.PrivateKey`

#### `new kem.PrivateKey(name, bytes)`

Imports a private key for the algorithm identified by `name`. The key material
to be imported must be passed as a `BufferSource`.

#### `privateKey.algorithm`

Object describing the algorithm that this key can be used with. This property
has the same structure as the elements of `kem.supportedAlgorithms` (see above).

#### `privateKey.export()`

Returns an `ArrayBuffer` containing the key material. The key can later be
imported using `new kem.PrivateKey(name, bytes)`.

#### `privateKey.decryptKey(encryptedKey)`

Decapsulates a previously encapsulated key given the ciphertext, which must be
a `BufferSource`. Returns a `Promise` that resolves to the shared secret as an
`ArrayBuffer`.

The size of the returned shared secret is exactly
`privateKey.algorithm.keySize` bytes.

### `sign.generateKeyPair(name)`

Generates a new key pair for the algorithm identified by `name`. Returns a
`Promise` that resolves to an object with properties named `publicKey` and
`privateKey`, which are instances of `sign.PublicKey` and `sign.PrivateKey`,
respectively.

### `sign.supportedAlgorithms`

Array of all supported digital signature algorithms. Each algorithm is
represented by an object with the following properties:

* `name` - unique identifier (e.g., `'dilithium2'`).
* `description` - display name (e.g., `'Dilithium2'`).
* `publicKeySize` - size of the public key, in bytes.
* `privateKeySize` - size of the private key, in bytes.
* `signatureSize` - maximum size of a signature, in bytes.

### Class `sign.PublicKey`

#### `new sign.PublicKey(name, bytes)`

Imports a public key for the algorithm identified by `name`. The key material
to be imported must be passed as a `BufferSource`.

#### `publicKey.algorithm`

Object describing the algorithm that this key can be used with. This property
has the same structure as the elements of `sign.supportedAlgorithms` (see
above).

#### `publicKey.export()`

Returns an `ArrayBuffer` containing the key material. The key can later be
imported using `new sign.PublicKey(name, bytes)`.

#### `publicKey.verify(message, signature)`

Verifies that the given `signature` is correct for the given `message` using
this public key. Both arguments must be `BufferSource`s. Returns a `Promise`
that resolves to `true` if the signature is valid, and to `false` otherwise.

### Class `sign.PrivateKey`

#### `new sign.PrivateKey(name, bytes)`

Imports a private key for the algorithm identified by `name`. The key material
to be imported must be passed as a `BufferSource`.

#### `privateKey.algorithm`

Object describing the algorithm that this key can be used with. This property
has the same structure as the elements of `sign.supportedAlgorithms` (see
above).

#### `privateKey.export()`

Returns an `ArrayBuffer` containing the key material. The key can later be
imported using `new sign.PrivateKey(name, bytes)`.

#### `privateKey.sign(message)`

Computes a signature for the given `message` using this private key. The
`message` must be a `BufferSource`. Returns a `Promise` that resolves to an
`ArrayBuffer`, which is the signature.

The size of the signature is at most `privateKey.algorithm.signatureSize`.

## Classic API

The classic API is compatible with [node-mceliece-nist][]. It uses Node.js
`Buffer`s and callback-style functions instead of `Promise`s.

This API is only available in Node.js (both through the native backend and
through the WebAssembly backend). The web implementation for Deno and other
JavaScript runtimes only implements the new key-centric API (see above).

### Example

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
[node-mceliece-nist]: https://github.com/tniessen/node-mceliece-nist

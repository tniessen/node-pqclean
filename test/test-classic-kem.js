'use strict';

const test = require('tape');

const { KEM } = require('../');

test('KEM constructor', (t) => {
  t.plan(1);

  t.throws(() => new KEM('foo'),
           /No such implementation/,
           'should throw if the algorithm does not exist');
});

test('KEM.supportedAlgorithms', (t) => {
  t.plan(4);

  t.ok(Array.isArray(KEM.supportedAlgorithms),
       'KEM.supportedAlgorithms should be an array');

  t.ok(KEM.supportedAlgorithms.length >= 2,
       'KEM.supportedAlgorithms should contain multiple algorithms');

  t.throws(() => KEM.supportedAlgorithms = [],
           'KEM.supportedAlgorithms should not be writable');

  t.throws(() => KEM.supportedAlgorithms.shift(),
           'KEM.supportedAlgorithms should not be modifiable');
});

for (const algorithm of KEM.supportedAlgorithms) {
  test(`properties of ${algorithm}`, (st) => {
    st.plan(12);

    const isUint32 = (x) => x === (x >>> 0);
    const kem = new KEM(algorithm);

    st.equal(kem.algorithm, algorithm, `algorithm should be '${algorithm}'`);
    st.equal(typeof kem.description, 'string',
             'description should be a string');

    st.ok(isUint32(kem.keySize), 'keySize should be an unsigned integer');
    st.ok(16 <= kem.keySize && kem.keySize <= 64,
          'keySize should be between 128 and 512 bits ' + kem.keySize);
    st.throws(() => kem.keySize = kem.keySize,
              'keySize should not be writable');

    st.ok(isUint32(kem.encryptedKeySize),
          'encryptedKeySize should be an unsigned integer');
    st.ok(kem.encryptedKeySize >= kem.keySize,
          'encryptedKeySize should be greater than or equal to keySize');
    st.throws(() => kem.encryptedKeySize = kem.encryptedKeySize,
              'encryptedKeySize should not be writable');

    st.ok(isUint32(kem.publicKeySize),
          'publicKeySize should be an unsigned integer');
    st.throws(() => kem.publicKeySize = kem.publicKeySize,
              'publicKeySize should not be writable');

    st.ok(isUint32(kem.privateKeySize),
          'privateKeySize should be an unsigned integer');
    st.throws(() => kem.publicKeySize = kem.publicKeySize,
              'privateKeySize should not be writable');
  });

  test(`synchronous ${algorithm}`, async (t) => {
    t.plan(10);

    const kem = new KEM(algorithm);
    const { keySize, encryptedKeySize, publicKeySize, privateKeySize } = kem;

    // Generate a key pair.
    const { publicKey, privateKey } = kem.keypair();

    t.ok(Buffer.isBuffer(publicKey), 'publicKey should be a Buffer');
    t.equal(publicKey.length, publicKeySize,
            `publicKey.length should be ${publicKeySize}`);
    t.ok(Buffer.isBuffer(privateKey), 'privateKey should be a Buffer');
    t.equal(privateKey.length, privateKeySize,
            `privateKey.length should be ${privateKeySize}`);

    // Encrypt and decrypt.
    const { key, encryptedKey } = kem.generateKey(publicKey);
    t.ok(Buffer.isBuffer(key), 'key should be a Buffer');
    t.equal(key.length, keySize, `key.length should be ${keySize}`);
    t.ok(Buffer.isBuffer(encryptedKey), 'encryptedKey should be a Buffer');
    t.equal(encryptedKey.length, encryptedKeySize,
            `encryptedKey.length should be ${encryptedKeySize}`);

    const receivedKey = kem.decryptKey(privateKey, encryptedKey);
    t.ok(Buffer.isBuffer(receivedKey), 'decrypted key should be a Buffer');
    t.deepEqual(receivedKey, key, 'decrypted key should match generated key');
  });

  test(`asynchronous ${algorithm}`, (t) => {
    const kem = new KEM(algorithm);
    const { keySize, encryptedKeySize, publicKeySize, privateKeySize } = kem;

    // This variable will be set to true synchronously in order to detect whether
    // the main thread was blocked.
    let wasAsync = false;

    kem.keypair((err, result) => {
      t.ok(wasAsync, 'keypair with callback should be async');
      t.error(err, 'keypair should not fail');

      const { publicKey, privateKey } = result;

      t.ok(Buffer.isBuffer(publicKey), 'publicKey should be a Buffer');
      t.equal(publicKey.length, publicKeySize,
              `publicKey.length should be ${publicKeySize}`);
      t.ok(Buffer.isBuffer(privateKey), 'privateKey should be a Buffer');
      t.equal(privateKey.length, privateKeySize,
              `privateKey.length should be ${privateKeySize}`);

      wasAsync = false;
      kem.generateKey(publicKey, (err, { key, encryptedKey }) => {
        t.ok(wasAsync, 'generateKey with callback should be async');
        t.error(err, 'generateKey should not fail');

        t.ok(Buffer.isBuffer(key), 'key should be a Buffer');
        t.equal(key.length, keySize, `key.length should be ${keySize}`);
        t.ok(Buffer.isBuffer(encryptedKey), 'encryptedKey should be a Buffer');
        t.equal(encryptedKey.length, encryptedKeySize,
                `encryptedKey.length should be ${encryptedKeySize}`);

        wasAsync = false;
        kem.decryptKey(privateKey, encryptedKey, (err, receivedKey) => {
          t.ok(wasAsync, 'decryptKey with callback should be async');
          t.error(err, 'decryptKey should not fail');

          t.ok(Buffer.isBuffer(receivedKey),
               'decrypted key should be a Buffer');
          t.deepEqual(receivedKey, key,
                      'decrypted key should match generated key');
          t.end();
        });

        wasAsync = true;
      });

      wasAsync = true;
    });

    wasAsync = true;
  });
}

test('KEM argument validation', (t) => {
  t.throws(() => new KEM(), /number of arguments/,
           'Constructor throws with no arguments');
  for (const v of [undefined, {}, true, 123, 123n]) {
    t.throws(() => new KEM(v), /First argument must be a string/,
             `Constructor throws if first argument of type ${typeof v}`);
  }
  t.throws(() => new KEM('foo', 'bar'), /number of arguments/,
           'Constructor throws if more than one argument');

  const kem = new KEM(KEM.supportedAlgorithms[0]);
  const fakePublicKey = new Uint8Array(kem.publicKeySize);
  const fakePrivateKey = new Uint8Array(kem.privateKeySize);
  const fakeEncryptedKey = new Uint8Array(kem.encryptedKeySize);

  for (const v of [undefined, {}, true, 123, 123n, 'foo']) {
    t.throws(() => kem.keypair(v), /First argument must be a function/,
             `keypair throws if first argument of type ${typeof v}`);
  }
  t.throws(() => kem.keypair('foo', 'bar'), /number of arguments/,
           'keypair throws if more than one argument');

  t.throws(() => kem.generateKey(), /number of arguments/,
           'generateKey throws with no arguments');
  for (const v of [undefined, {}, true, 123, 123n, 'foo']) {
    t.throws(() => kem.generateKey(v), /First argument must be a TypedArray/,
             `generateKey throws if first argument of type ${typeof v}`);
    t.throws(() => kem.generateKey(fakePublicKey, v),
             /Second argument must be a function/,
             `generateKey throws if second argument of type ${typeof v}`);
  }
  t.throws(() => kem.generateKey('foo', 'bar', 'baz'), /number of arguments/,
           'generateKey throws if more than two arguments');

  t.throws(() => kem.decryptKey(), /number of arguments/,
           'decryptKey throws with no arguments');
  t.throws(() => kem.decryptKey(fakePrivateKey), /number of arguments/,
           'decryptKey throws with only one argument');
  for (const v of [undefined, {}, true, 123, 123n, 'foo']) {
    t.throws(() => kem.decryptKey(v, fakeEncryptedKey),
             /First argument must be a TypedArray/,
             `decryptKey throws if first argument of type ${typeof v}`);
    t.throws(() => kem.decryptKey(fakePrivateKey, v),
             /Second argument must be a TypedArray/,
             `decryptKey throws if second argument of type ${typeof v}`);
    t.throws(() => kem.decryptKey(fakePrivateKey, fakeEncryptedKey, v),
             /Third argument must be a function/,
             `decryptKey throws if third argument of type ${typeof v}`);
  }
  t.throws(() => kem.decryptKey(fakePrivateKey, fakeEncryptedKey, () => {}, 1),
           /number of arguments/,
           'decryptKey throws if more than three arguments');

  t.end();
});

test('KEM should be compatible with mceliece-nist', {
  // We currently disable McEliece when using the native addon on Windows
  // because Windows' default stack size is too small.
  skip: process.platform === 'win32' &&
        !KEM.supportedAlgorithms.includes('mceliece8192128')
}, (t) => {
  const { McEliece } = require('mceliece-nist');
  t.plan(1 + McEliece.supportedAlgorithms.length);
  t.ok(Array.isArray(McEliece.supportedAlgorithms),
       'McEliece.supportedAlgorithms should be an array');

  for (const algorithm of McEliece.supportedAlgorithms) {
    t.test(`KEM should be compatible with mceliece-nist ${algorithm}`, (st) => {
      st.plan(8);

      st.ok(KEM.supportedAlgorithms.includes(algorithm),
          `KEM should support mceliece-nist algorithm '${algorithm}'`);
      const kem = new KEM(algorithm);
      const mceliece = new McEliece(algorithm);
      const params = (o) => (({
        keySize, encryptedKeySize, publicKeySize, privateKeySize
      }) => ({ keySize, encryptedKeySize, publicKeySize, privateKeySize }))(o);
      st.deepEqual(params(kem), params(mceliece),
          'KEM parameters should be equal to mceliece-nist parameters');

      const pqcleanKeyPair = kem.keypair();
      const mcelieceKeyPair = mceliece.keypair();

      for (const [keypairGenerator, { publicKey, privateKey }] of [
        ['PQClean', pqcleanKeyPair], ['mceliece-nist', mcelieceKeyPair]
      ]) {
        const pqcleanEnc = kem.generateKey(publicKey);
        const mcelieceEnc = mceliece.generateKey(publicKey);
        for (const [enc, { key, encryptedKey }] of [
          ['PQClean', pqcleanEnc], ['mceliece-nist', mcelieceEnc]]
        ) {
          const pqcleanDec = kem.decryptKey(privateKey, encryptedKey);
          const mcelieceDec = mceliece.decryptKey(privateKey, encryptedKey);
          for (const [dec, decryptedKey] of [
            ['PQClean', pqcleanDec], ['mceliece-nist', mcelieceDec]
          ]) {
            if (keypairGenerator !== enc || enc !== dec) {
              st.deepEqual(key, decryptedKey,
                  `Key pair generated by ${keypairGenerator}, ` +
                  `key encapsulated by ${enc}, key decapsulated by ${dec}`);
            }
          }
        }
      }
    });
  }
});

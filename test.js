'use strict';

const { randomBytes } = require('node:crypto');
const test = require('tape');

const { KEM } = require('./');

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
    st.plan(10);

    const isUint32 = (x) => x === (x >>> 0);
    const kem = new KEM(algorithm);

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

  test(`synchronous ${algorithm}`, (t) => {
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

test('KEM should be compatible with mceliece-nist', (t) => {
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
          const mcelieceDec = kem.decryptKey(privateKey, encryptedKey);
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

const { Sign } = require('./');

test('Sign constructor', (t) => {
  t.plan(1);

  t.throws(() => new Sign('foo'),
           /No such implementation/,
           'should throw if the algorithm does not exist');
});

test('Sign.supportedAlgorithms', (t) => {
  t.plan(4);

  t.ok(Array.isArray(Sign.supportedAlgorithms),
       'Sign.supportedAlgorithms should be an array');

  t.ok(Sign.supportedAlgorithms.length >= 2,
       'Sign.supportedAlgorithms should contain multiple algorithms');

  t.throws(() => Sign.supportedAlgorithms = [],
           'Sign.supportedAlgorithms should not be writable');

  t.throws(() => Sign.supportedAlgorithms.shift(),
           'Sign.supportedAlgorithms should not be modifiable');
});

for (const algorithm of Sign.supportedAlgorithms) {
  test(`properties of ${algorithm}`, (st) => {
    st.plan(6);

    const isUint32 = (x) => x === (x >>> 0);
    const sign = new Sign(algorithm);

    st.ok(isUint32(sign.signatureSize),
          'signatureSize should be an unsigned integer');
    st.throws(() => sign.signatureSize = sign.signatureSize,
              'signatureSize should not be writable');

    st.ok(isUint32(sign.publicKeySize),
          'publicKeySize should be an unsigned integer');
    st.throws(() => sign.publicKeySize = sign.publicKeySize,
              'publicKeySize should not be writable');

    st.ok(isUint32(sign.privateKeySize),
          'privateKeySize should be an unsigned integer');
    st.throws(() => sign.publicKeySize = sign.publicKeySize,
              'privateKeySize should not be writable');
  });

  test(`synchronous ${algorithm}`, (t) => {
    t.plan(10);

    const sign = new Sign(algorithm);
    const { signatureSize, publicKeySize, privateKeySize } = sign;

    // Generate a key pair.
    const { publicKey, privateKey } = sign.keypair();

    t.ok(Buffer.isBuffer(publicKey),
         'publicKey should be a Buffer');
    t.equal(publicKey.length, publicKeySize,
            `publicKey.length should be ${publicKeySize}`);
    t.ok(Buffer.isBuffer(privateKey),
         'privateKey should be a Buffer');
    t.equal(privateKey.length, privateKeySize,
            `privateKey.length should be ${privateKeySize}`);

    const message = randomBytes(500);
    const signature = sign.sign(privateKey, message);
    t.ok(Buffer.isBuffer(signature), 'signature should be a Buffer');
    t.ok(signature.length <= signatureSize,
         `signature.length should be less than or equal to ${signatureSize}`);

    t.equal(sign.verify(publicKey, message, signature), true,
            'verify should return true when the signature is valid');

    // Change a single bit in the signature.
    const rand = (max) => Math.floor(max * Math.random());
    const tamperedSignature = Buffer.from(signature);
    tamperedSignature[rand(tamperedSignature.length)] ^= 1 << rand(7);
    t.equal(sign.verify(publicKey, message, tamperedSignature), false,
            'verify should return false when the signature is invalid');

    const tamperedMessage = Buffer.from(message);
    tamperedMessage[rand(tamperedMessage.length)] ^= 1 << rand(7);
    t.equal(sign.verify(publicKey, tamperedMessage, signature), false,
            'verify should return false when the message has been modified');

    // Use a different key pair.
    const differentKeyPair = sign.keypair();
    t.equal(sign.verify(differentKeyPair.publicKey, message, signature), false,
            'verify should return false when the public key is incorrect');
  });

  test(`asynchronous ${algorithm}`, (t) => {
    const sign = new Sign(algorithm);
    const { signatureSize, publicKeySize, privateKeySize } = sign;

    // This variable will be set to true synchronously in order to detect whether
    // the main thread was blocked.
    let wasAsync = false;

    sign.keypair((err, result) => {
      t.ok(wasAsync, 'keypair with callback should be async');
      t.error(err, 'keypair should not fail');

      const { publicKey, privateKey } = result;

      t.ok(Buffer.isBuffer(publicKey),
           'publicKey should be a Buffer');
      t.equal(publicKey.length, publicKeySize,
              `publicKey.length should be ${publicKeySize}`);
      t.ok(Buffer.isBuffer(privateKey),
           'privateKey should be a Buffer');
      t.equal(privateKey.length, privateKeySize,
              `privateKey.length should be ${privateKeySize}`);

      const message = randomBytes(500);
      wasAsync = false;
      sign.sign(privateKey, message, (err, signature) => {
        t.ok(wasAsync, 'sign with callback should be async');
        t.error(err, 'sign should not fail');

        t.ok(Buffer.isBuffer(signature), 'signature should be a Buffer');
        t.ok(signature.length <= signatureSize,
             `signature.length should be less than or equal to ${signatureSize}`);

        wasAsync = false;
        sign.verify(publicKey, message, signature, (err, ok) => {
          t.ok(wasAsync, 'verify with callback should be async');
          t.error(err, 'verify should not fail');

          t.equal(ok, true,
            'verification result should be true when the signature is valid');

          t.end();
        });
        wasAsync = true;
      });

      wasAsync = true;
    });

    wasAsync = true;
  });
}

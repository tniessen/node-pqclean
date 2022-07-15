'use strict';

const { randomBytes } = require('node:crypto');
const test = require('tape');

const { Sign } = require('../');

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
    st.plan(8);

    const isUint32 = (x) => x === (x >>> 0);
    const sign = new Sign(algorithm);

    st.equal(sign.algorithm, algorithm, `algorithm should be '${algorithm}'`);
    st.equal(typeof sign.description, 'string',
             'description should be a string');

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

test('Sign argument validation', (t) => {
  t.throws(() => new Sign(), /number of arguments/,
           'Constructor throws with no arguments');
  for (const v of [undefined, {}, true, 123, 123n]) {
    t.throws(() => new Sign(v), /First argument must be a string/,
             `Constructor throws if first argument of type ${typeof v}`);
  }
  t.throws(() => new Sign('foo', 'bar'), /number of arguments/,
           'Constructor throws if more than one argument');

  const sign = new Sign(Sign.supportedAlgorithms[0]);
  const fakePublicKey = new Uint8Array(sign.publicKeySize);
  const fakePrivateKey = new Uint8Array(sign.privateKeySize);
  const fakeSignature = new Uint8Array(sign.signatureSize);
  const m = new Uint8Array(1);

  for (const v of [undefined, {}, true, 123, 123n, 'foo']) {
    t.throws(() => sign.keypair(v), /First argument must be a function/,
             `keypair throws if first argument of type ${typeof v}`);
  }
  t.throws(() => sign.keypair('foo', 'bar'), /number of arguments/,
           'keypair throws if more than one argument');

  t.throws(() => sign.sign(), /number of arguments/,
           'sign throws with no arguments');
  t.throws(() => sign.sign('foo'), /number of arguments/,
           'sign throws with only one argument');
  for (const v of [undefined, {}, true, 123, 123n, 'foo']) {
    t.throws(() => sign.sign(v, ''), /First argument must be a TypedArray/,
             `sign throws if first argument of type ${typeof v}`);
    t.throws(() => sign.sign(fakePrivateKey, v),
             /Second argument must be a TypedArray/,
             `sign throws if second argument of type ${typeof v}`);
    t.throws(() => sign.sign(fakePrivateKey, m, v),
             /Third argument must be a function/,
             `sign throws if third argument of type ${typeof v}`);
  }
  t.throws(() => sign.sign('foo', 'bar', 'baz', 'qux'), /number of arguments/,
           'sign throws if more than three arguments');

  t.throws(() => sign.verify(), /number of arguments/,
           'verify throws with no arguments');
  t.throws(() => sign.verify(fakePublicKey), /number of arguments/,
           'verify throws with only one argument');
  t.throws(() => sign.verify(fakePublicKey, m), /number of arguments/,
           'verify throws with only two arguments');
  for (const v of [undefined, {}, true, 123, 123n, 'foo']) {
    t.throws(() => sign.verify(v, m, fakeSignature),
             /First argument must be a TypedArray/,
             `verify throws if first argument of type ${typeof v}`);
    t.throws(() => sign.verify(fakePublicKey, v, fakeSignature),
             /Second argument must be a TypedArray/,
             `verify throws if second argument of type ${typeof v}`);
    t.throws(() => sign.verify(fakePublicKey, m, v),
             /Third argument must be a TypedArray/,
             `verify throws if third argument of type ${typeof v}`);
    t.throws(() => sign.verify(fakePublicKey, m, fakeSignature, v),
             /Fourth argument must be a function/,
             `verify throws if fourth argument of type ${typeof v}`);
  }
  t.throws(() => sign.verify(fakePublicKey, m, fakeSignature, () => {}, 1),
           /number of arguments/,
           'verify throws if more than four arguments');

  t.end();
});

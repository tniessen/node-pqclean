'use strict';

const { randomBytes } = require('node:crypto');
const test = require('tape');

const { sign } = require('../');

test('sign.supportedAlgorithms', (t) => {
  t.plan(5);

  t.ok(Array.isArray(sign.supportedAlgorithms),
       'sign.supportedAlgorithms should be an array');

  t.ok(sign.supportedAlgorithms.every((a) => typeof a === 'object'),
       'sign.supportedAlgorithms should contain objects');

  t.ok(sign.supportedAlgorithms.length >= 2,
       'sign.supportedAlgorithms should contain multiple algorithms');

  t.throws(() => sign.supportedAlgorithms = [],
           'sign.supportedAlgorithms should not be writable');

  t.throws(() => sign.supportedAlgorithms.shift(),
           'sign.supportedAlgorithms should not be modifiable');
});

for (const algorithm of sign.supportedAlgorithms) {
  test(`properties of ${algorithm.name}`, (st) => {
    st.plan(6);

    const isUint32 = (x) => x === (x >>> 0);

    const expectedProperties = ['name', 'description',
                                'publicKeySize', 'privateKeySize',
                                'signatureSize'];
    st.deepEqual(Object.getOwnPropertyNames(algorithm), expectedProperties,
                 'should (only) have expected properties');

    st.equal(typeof algorithm.name, 'string', 'name should be a string');
    st.equal(typeof algorithm.description, 'string',
             'description should be a string');

    st.ok(isUint32(algorithm.signatureSize),
          'signatureSize should be an unsigned integer');

    st.ok(isUint32(algorithm.publicKeySize),
          'publicKeySize should be an unsigned integer');

    st.ok(isUint32(algorithm.privateKeySize),
          'privateKeySize should be an unsigned integer');
  });

  test(algorithm.name, async (t) => {
    const { signatureSize, publicKeySize, privateKeySize } = algorithm;

    const { publicKey, privateKey } = await sign.generateKeyPair(algorithm.name);
    t.pass('generateKeyPair should succeed');

    t.ok(publicKey instanceof sign.PublicKey,
         'publicKey should be a sign.PublicKey');
    t.equal(publicKey.constructor, sign.PublicKey,
            'publicKey constructor should be sign.PublicKey');
    t.equal(publicKey.constructor.name, 'PQCleanSignPublicKey',
            "publicKey constructor name should be 'PQCleanSignPublicKey'");

    t.ok(privateKey instanceof sign.PrivateKey,
         'privateKey should be a sign.PrivateKey');
    t.equal(privateKey.constructor, sign.PrivateKey,
            'privateKey constructor should be sign.PrivateKey');
    t.equal(privateKey.constructor.name, 'PQCleanSignPrivateKey',
            "privateKey constructor name should be 'PQCleanSignPrivateKey'");

    const { publicKey: otherPublicKey } = await sign.generateKeyPair(algorithm.name);
    for (const messageSize of [0, Math.ceil(Math.random() * 100000)]) {
      const message = randomBytes(messageSize);

      const signature = await privateKey.sign(message);
      t.pass(`signing a ${messageSize} byte message should succeed`);

      t.ok(signature instanceof ArrayBuffer, 'signature should be an ArrayBuffer');
      t.ok(signature.byteLength <= signatureSize,
          `signature.byteLength should be less than or equal to ${signatureSize}`);

      t.equal(await publicKey.verify(message, signature), true,
              'verify should return true when the signature is valid');

      // Change a single bit in the signature.
      const rand = (max) => Math.floor(max * Math.random());
      const tamperedSignature = Buffer.from(signature);
      tamperedSignature[rand(tamperedSignature.length)] ^= 1 << rand(7);
      t.equal(await publicKey.verify(message, tamperedSignature), false,
              'verify should return false when the signature is invalid');

      const tamperedMessage = Buffer.from(message);
      tamperedMessage[rand(tamperedMessage.length)] ^= 1 << rand(7);
      t.equal(await publicKey.verify(tamperedMessage, signature), false,
              'verify should return false when the message has been modified');

      // Use a different key pair.
      t.equal(await otherPublicKey.verify(message, signature), false,
              'verify should return false when the public key is incorrect');
    }
  });
}

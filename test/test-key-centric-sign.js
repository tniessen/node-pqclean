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

      const rand = (max) => Math.floor(max * Math.random());
      const copyArrayBufferToBuffer = (a) => Buffer.from(Buffer.from(a));

      // Change a single bit in the signature.
      const tamperedSignature = copyArrayBufferToBuffer(signature);
      tamperedSignature[rand(tamperedSignature.length)] ^= 1 << rand(8);
      t.equal(await publicKey.verify(message, tamperedSignature), false,
              'verify should return false when the signature is invalid');

      if (messageSize !== 0) {
        const tamperedMessage = copyArrayBufferToBuffer(message);
        tamperedMessage[rand(tamperedMessage.length)] ^= 1 << rand(8);
        t.equal(await publicKey.verify(tamperedMessage, signature), false,
                'verify should return false when the message has been modified');
      }

      // Use a different key pair.
      t.equal(await otherPublicKey.verify(message, signature), false,
              'verify should return false when the public key is incorrect');
    }

    for (const messageSize of [0, Math.ceil(Math.random() * 100000)]) {
      const message = randomBytes(messageSize);

      const signedMessage = await privateKey.signEmbed(message);
      t.pass(`signing a ${messageSize} byte message should succeed (embedded signature)`);

      t.ok(signedMessage instanceof ArrayBuffer, 'signedMessage should be an ArrayBuffer');
      t.ok(signedMessage.byteLength <= messageSize + signatureSize,
          `signedMessage.byteLength should be less than or equal to ${messageSize + signatureSize}`);

      t.deepEqual(await publicKey.open(signedMessage), new Uint8Array(message).buffer,
                  'open should return the embedded message when the signature is valid');

      const rand = (max) => Math.floor(max * Math.random());
      const copyArrayBufferToBuffer = (a) => Buffer.from(Buffer.from(a));

      // Change a single bit in the signed message.
      const tamperedSignedMessage = copyArrayBufferToBuffer(signedMessage);
      tamperedSignedMessage[rand(tamperedSignedMessage.length)] ^= 1 << rand(8);
      t.ok(await publicKey.open(tamperedSignedMessage).then(() => false, () => true),
           'open should reject when the signedMessage has been modified');

      // Use a different key pair.
      t.ok(await otherPublicKey.open(signedMessage).then(() => false, () => true),
           'open should reject when the public key is incorrect');
    }

    const exportedPublicKey = publicKey.export();
    t.ok(exportedPublicKey instanceof ArrayBuffer,
         'exported public key should be an ArrayBuffer');
    t.equal(exportedPublicKey.byteLength, publicKeySize,
            `exportedPublicKey.byteLength should be ${publicKeySize}`);

    const exportedPrivateKey = privateKey.export();
    t.ok(exportedPrivateKey instanceof ArrayBuffer,
         'exported private key should be an ArrayBuffer');
    t.equal(exportedPrivateKey.byteLength, privateKeySize,
            `exportedPrivateKey.byteLength should be ${privateKeySize}`);

    for (const [desc, KeyClass, material] of [
      ['public key', sign.PublicKey, exportedPublicKey],
      ['private key', sign.PrivateKey, exportedPrivateKey]
    ]) {
      for (const ArrayBufferView of [
        Uint8Array, Int8Array, Uint16Array, Int16Array, Uint32Array, Int32Array,
        BigUint64Array, BigInt64Array, Float32Array, Float64Array, DataView
      ]) {
        const message = `importing the ${desc} from a(n) ` +
                        `${ArrayBufferView.name} should work`;
        const bytesPerElement = ArrayBufferView.BYTES_PER_ELEMENT || 1;
        if (material.byteLength % bytesPerElement !== 0) {
          t.skip(message);
          continue;
        }
        const largerArrayBuffer = new ArrayBuffer(material.byteLength + 1000);
        new Uint8Array(largerArrayBuffer).set(
            new Uint8Array(material), 19 * bytesPerElement);
        const view = new ArrayBufferView(
            largerArrayBuffer, 19 * bytesPerElement,
            material.byteLength / bytesPerElement);
        const importedKey = new KeyClass(algorithm.name, view);
        t.deepEqual(importedKey.export(), material, message);
      }
    }
  });
}

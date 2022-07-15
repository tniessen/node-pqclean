'use strict';

const test = require('tape');

const { kem } = require('../');

test('kem.supportedAlgorithms', (t) => {
  t.plan(5);

  t.ok(Array.isArray(kem.supportedAlgorithms),
       'kem.supportedAlgorithms should be an array');

  t.ok(kem.supportedAlgorithms.every((a) => typeof a === 'object'),
       'kem.supportedAlgorithms should contain objects');

  t.ok(kem.supportedAlgorithms.length >= 2,
       'kem.supportedAlgorithms should contain multiple algorithms');

  t.throws(() => kem.supportedAlgorithms = [],
           'kem.supportedAlgorithms should not be writable');

  t.throws(() => kem.supportedAlgorithms.shift(),
           'kem.supportedAlgorithms should not be modifiable');
});

for (const algorithm of kem.supportedAlgorithms) {
  test(`properties of ${algorithm.name}`, (st) => {
    st.plan(9);

    const isUint32 = (x) => x === (x >>> 0);

    const expectedProperties = ['name', 'description',
                                'publicKeySize', 'privateKeySize',
                                'keySize', 'encryptedKeySize'];
    st.deepEqual(Object.getOwnPropertyNames(algorithm), expectedProperties,
                 'should (only) have expected properties');

    st.equal(typeof algorithm.name, 'string', 'name should be a string');
    st.equal(typeof algorithm.description, 'string',
             'description should be a string');

    st.ok(isUint32(algorithm.keySize), 'keySize should be an unsigned integer');
    st.ok(16 <= algorithm.keySize && algorithm.keySize <= 64,
          'keySize should be between 128 and 512 bits ' + algorithm.keySize);

    st.ok(isUint32(algorithm.encryptedKeySize),
          'encryptedKeySize should be an unsigned integer');
    st.ok(algorithm.encryptedKeySize >= algorithm.keySize,
          'encryptedKeySize should be greater than or equal to keySize');

    st.ok(isUint32(algorithm.publicKeySize),
          'publicKeySize should be an unsigned integer');

    st.ok(isUint32(algorithm.privateKeySize),
          'privateKeySize should be an unsigned integer');
  });

  test(algorithm.name, async (t) => {
    const { keySize, encryptedKeySize, publicKeySize, privateKeySize } = algorithm;

    const { publicKey, privateKey } = await kem.generateKeyPair(algorithm.name);
    t.pass('generateKeyPair should succeed');

    t.ok(publicKey instanceof kem.PublicKey,
         'publicKey should be a kem.PublicKey');
    t.equal(publicKey.constructor, kem.PublicKey,
            'publicKey constructor should be kem.PublicKey');
    t.equal(publicKey.constructor.name, 'PQCleanKEMPublicKey',
            "publicKey constructor name should be 'PQCleanKEMPublicKey'");

    t.ok(privateKey instanceof kem.PrivateKey,
         'privateKey should be a kem.PrivateKey');
    t.equal(privateKey.constructor, kem.PrivateKey,
            'privateKey constructor should be kem.PrivateKey');
    t.equal(privateKey.constructor.name, 'PQCleanKEMPrivateKey',
            "privateKey constructor name should be 'PQCleanKEMPrivateKey'");

    const { key, encryptedKey } = await publicKey.generateKey();
    t.pass('publicKey.generateKey should succeed');

    t.ok(key instanceof ArrayBuffer, 'key should be an ArrayBuffer');
    t.equal(key.byteLength, keySize, `key.byteLength should be ${keySize}`);
    t.ok(encryptedKey instanceof ArrayBuffer, 'encryptedKey should be an ArrayBuffer');
    t.equal(encryptedKey.byteLength, encryptedKeySize,
            `encryptedKey.byteLength should be ${encryptedKeySize}`);

    const receivedKey = await privateKey.decryptKey(encryptedKey);
    t.pass('privateKey.decryptKey should succeed');

    t.ok(receivedKey instanceof ArrayBuffer, 'receivedKey should be an ArrayBuffer');
    t.deepEqual(receivedKey, key, 'decrypted key should match generated key');

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
  });
}

test('kem should be compatible with mceliece-nist', {
  // We currently disable McEliece when using the native addon on Windows
  // because Windows' default stack size is too small.
  skip: process.platform === 'win32' &&
        !kem.supportedAlgorithms.find(({ name }) => name === 'mceliece8192128')
}, (t) => {
  const { McEliece } = require('mceliece-nist');
  t.plan(1 + McEliece.supportedAlgorithms.length);
  t.ok(Array.isArray(McEliece.supportedAlgorithms),
       'McEliece.supportedAlgorithms should be an array');

  for (const algoName of McEliece.supportedAlgorithms) {
    t.test(`kem should be compatible with mceliece-nist ${algoName}`, async (st) => {
      st.plan(8);

      const algorithm = kem.supportedAlgorithms.find(({ name }) => name === algoName);
      st.ok(algorithm,
            `kem should support mceliece-nist algorithm '${algoName}'`);

      const mceliece = new McEliece(algoName);
      const params = (o) => (({
        keySize, encryptedKeySize, publicKeySize, privateKeySize
      }) => ({ keySize, encryptedKeySize, publicKeySize, privateKeySize }))(o);
      st.deepEqual(params(algorithm), params(mceliece),
          'kem parameters should be equal to mceliece-nist parameters');

      const pqcleanKeyPair = await kem.generateKeyPair(algoName);
      const mcelieceKeyPair = mceliece.keypair();

      for (const [keypairGenerator, { publicKey, privateKey }] of [
        ['PQClean', pqcleanKeyPair], ['mceliece-nist', mcelieceKeyPair]
      ]) {
        // If pqclean generated the keys, export them for mceliece-nist.
        // If mceliece-nist generated the keys, import them for pqclean.
        const {
          publicKeyForPQClean,
          privateKeyForPQClean,
          publicKeyForMcEliece,
          privateKeyForMcEliece
        } = (keypairGenerator === 'PQClean') ? {
          publicKeyForPQClean: publicKey,
          privateKeyForPQClean: privateKey,
          publicKeyForMcEliece: Buffer.from(publicKey.export()),
          privateKeyForMcEliece: Buffer.from(privateKey.export())
        } : {
          publicKeyForPQClean: new kem.PublicKey(algoName, publicKey),
          privateKeyForPQClean: new kem.PrivateKey(algoName, privateKey),
          publicKeyForMcEliece: publicKey,
          privateKeyForMcEliece: privateKey
        };

        const pqcleanEnc = await publicKeyForPQClean.generateKey();
        const mcelieceEnc = mceliece.generateKey(publicKeyForMcEliece);
        for (const [enc, { key, encryptedKey }] of [
          ['PQClean', pqcleanEnc], ['mceliece-nist', mcelieceEnc]]
        ) {
          const encryptedKeyForMcEliece = (enc === 'PQClean') ? Buffer.from(encryptedKey) : encryptedKey;
          const pqcleanDec = await privateKeyForPQClean.decryptKey(encryptedKey);
          const mcelieceDec = mceliece.decryptKey(privateKeyForMcEliece, encryptedKeyForMcEliece);
          for (const [dec, decryptedKey] of [
            ['PQClean', pqcleanDec], ['mceliece-nist', mcelieceDec]
          ]) {
            if (keypairGenerator !== enc || enc !== dec) {
              st.deepEqual(Buffer.from(key), Buffer.from(decryptedKey),
                  `Key pair generated by ${keypairGenerator}, ` +
                  `key encapsulated by ${enc}, key decapsulated by ${dec}`);
            }
          }
        }
      }
    });
  }
});

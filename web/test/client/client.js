import PQClean from './dist/pqclean.js';

async function requireOK(response) {
  if (!response.ok) {
    throw new Error('fetch() failed');
  }
  return response;
}

const algorithmNames = [
  ...PQClean.kem.supportedAlgorithms.map(({ name }) => name),
  ...PQClean.sign.supportedAlgorithms.map(({ name }) => name)
];

const challenge = await fetch(new URL('./challenge', import.meta.url), {
  method: 'POST',
  body: JSON.stringify(algorithmNames)
}).then(requireOK).then((res) => res.arrayBuffer());

async function testKEM(algorithm) {
  typeof onTestStart === 'function' && onTestStart(algorithm.name);

  typeof onTestProgress === 'function' && onTestProgress(algorithm.name, 'generateKeyPair');
  const {
    publicKey,
    privateKey
  } = await PQClean.kem.generateKeyPair(algorithm.name);

  typeof onTestProgress === 'function' && onTestProgress(algorithm.name, 'generateKey');
  const { key, encryptedKey } = await publicKey.generateKey();

  const oneTimePaddedChallenge = new Uint8Array(key).map((v, i) => {
    return v ^ new Uint8Array(challenge)[i];
  });

  typeof onTestProgress === 'function' && onTestProgress(algorithm.name, 'export');
  const exportedPrivateKey = privateKey.export();
  const result = new Uint8Array(exportedPrivateKey.byteLength + encryptedKey.byteLength + oneTimePaddedChallenge.byteLength);
  result.set(new Uint8Array(exportedPrivateKey));
  result.set(new Uint8Array(encryptedKey), exportedPrivateKey.byteLength);
  result.set(new Uint8Array(oneTimePaddedChallenge), exportedPrivateKey.byteLength + encryptedKey.byteLength);

  typeof onTestProgress === 'function' && onTestProgress(algorithm.name, 'submit result');
  await fetch(new URL(`submit/${algorithm.name}`, import.meta.url), {
    method: 'POST',
    body: result
  }).then(requireOK);

  typeof onTestDone === 'function' && onTestDone(algorithm.name);
}

async function testSign(algorithm) {
  typeof onTestStart === 'function' && onTestStart(algorithm.name);

  typeof onTestProgress === 'function' && onTestProgress(algorithm.name, 'generateKeyPair');
  const {
    publicKey,
    privateKey
  } = await PQClean.sign.generateKeyPair(algorithm.name);

  typeof onTestProgress === 'function' && onTestProgress(algorithm.name, 'sign');
  const signature = await privateKey.sign(challenge);

  typeof onTestProgress === 'function' && onTestProgress(algorithm.name, 'export');
  const exportedPublicKey = publicKey.export();
  const result = new Uint8Array(exportedPublicKey.byteLength + signature.byteLength);
  result.set(new Uint8Array(exportedPublicKey));
  result.set(new Uint8Array(signature), exportedPublicKey.byteLength);

  typeof onTestProgress === 'function' && onTestProgress(algorithm.name, 'submit result');
  await fetch(new URL(`submit/${algorithm.name}`, import.meta.url), {
    method: 'POST',
    body: result
  }).then(requireOK);
  typeof onTestDone === 'function' && onTestDone(algorithm.name);
}

await Promise.all([
  ...PQClean.kem.supportedAlgorithms.map(testKEM),
  ...PQClean.sign.supportedAlgorithms.map(testSign)
]);

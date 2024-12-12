import PQClean from './dist/pqclean.js';

async function requireOK(response) {
  if (!response.ok) {
    throw new Error('fetch() failed');
  }
  return response;
}

function hex(binary) {
  if (binary instanceof ArrayBuffer) {
    binary = new Uint8Array(binary);
  }
  if (!(binary instanceof Uint8Array)) {
    throw new TypeError('Expected ArrayBuffer or Uint8Array');
  }
  let ret = '';
  for (let i = 0; i < binary.length; i++) {
    ret += binary[i].toString(16).padStart(2, '0');
  }
  return ret;
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

  typeof onTestProgress === 'function' && onTestProgress(algorithm.name, 'submit result');
  await fetch(new URL(`submit/${algorithm.name}`, import.meta.url), {
    method: 'POST',
    body: JSON.stringify({
      privateKey: hex(exportedPrivateKey),
      encryptedKey: hex(encryptedKey),
      ciphertext: hex(oneTimePaddedChallenge),
    }),
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
  const signedMessage = await privateKey.signEmbed(challenge);

  typeof onTestProgress === 'function' && onTestProgress(algorithm.name, 'export');
  const exportedPublicKey = publicKey.export();

  typeof onTestProgress === 'function' && onTestProgress(algorithm.name, 'submit result');
  await fetch(new URL(`submit/${algorithm.name}`, import.meta.url), {
    method: 'POST',
    body: JSON.stringify({
      publicKey: hex(exportedPublicKey),
      signature: hex(signature),
      signedMessage: hex(signedMessage),
    }),
  }).then(requireOK);
  typeof onTestDone === 'function' && onTestDone(algorithm.name);
}

await Promise.all([
  ...PQClean.kem.supportedAlgorithms.map(testKEM),
  ...PQClean.sign.supportedAlgorithms.map(testSign)
]);

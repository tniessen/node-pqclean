import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as events from 'node:events';
import { createServer } from 'node:http';
import { dirname } from 'node:path';
import * as timers from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import { Server as StaticFileServer } from 'node-static';

import PQClean from '../../index.js';

const dir = dirname(fileURLToPath(import.meta.url));
const clientStaticFileServer = new StaticFileServer(`${dir}/client`);
const distStaticFileServer = new StaticFileServer(`${dir}/../dist`);

let challenge;

const server = createServer((req, res) => {
  if (req.url === '/challenge') {
    (async () => {
      if (challenge !== undefined && challenge.remaining.size !== 0) {
        throw new Error('Only one challenge can be active at a time');
      }

      let body = Buffer.alloc(0);
      for await (const chunk of req) {
        body = Buffer.concat([body, chunk]);
      }

      const algorithmNames = JSON.parse(body.toString('utf8'));
      const remaining = new Set(algorithmNames);
      if (algorithmNames.length !== remaining.size) {
        throw new Error('Not all algorithm names are unique');
      }

      const nonce = randomBytes(Math.max(...PQClean.kem.supportedAlgorithms.map((algorithm) => algorithm.keySize)))
      challenge = { algorithmNames, remaining, nonce };
      console.log(`ok client requested challenge for ${algorithmNames.length} algorithms`);
      res.end(challenge.nonce);
    })().catch((err) => {
      console.error(err);
      res.statusCode = 500;
      res.end(`${err}`);
    });
  } else if (req.url.startsWith('/submit/')) {
    (async () => {
      const name = req.url.substring('/submit/'.length);

      let body = Buffer.alloc(0);
      for await (const chunk of req) {
        body = Buffer.concat([body, chunk]);
      }

      const kemAlgorithm = PQClean.kem.supportedAlgorithms.find((a) => a.name === name);
      const signatureAlgorithm = PQClean.sign.supportedAlgorithms.find((a) => a.name === name);
      if (kemAlgorithm) {
        let offset;
        const privateKeyBytes = body.subarray(offset = 0, offset += kemAlgorithm.privateKeySize);
        const encryptedKey = body.subarray(offset, offset += kemAlgorithm.encryptedKeySize);
        const oneTimePaddedChallenge = body.subarray(offset);
        const privateKey = new PQClean.kem.PrivateKey(name, privateKeyBytes);
        const key = await privateKey.decryptKey(encryptedKey);
        if (!new Uint8Array(key).every((v, i) => v ^ oneTimePaddedChallenge[i] === challenge.nonce[i])) {
          throw new Error('Invalid one-time padded ciphertext');
        }
      } else {
        const publicKeyBytes = body.subarray(0, signatureAlgorithm.publicKeySize);
        const signature = body.subarray(signatureAlgorithm.publicKeySize);
        const publicKey = new PQClean.sign.PublicKey(name, publicKeyBytes);
        const ok = await publicKey.verify(challenge.nonce, signature);
        if (!ok) throw new Error('Invalid signature');
      }

      if (!challenge.remaining.has(name)) {
        throw new Error(`Unexpected or duplicate submission for '${name}'`);
      }
      challenge.remaining.delete(name);
      console.log(`ok ${name} (${challenge.remaining.size} remaining)`);

      res.end();
    })().catch((err) => {
      console.error(err);
      res.statusCode = 500;
      res.end(`${err}`);
    });
  } else if (req.url.startsWith('/dist/')) {
    req.url = req.url.substring('/dist'.length);
    distStaticFileServer.serve(req, res);
  } else {
    clientStaticFileServer.serve(req, res);
  }
}).listen(0).unref();
await events.once(server, 'listening');

const baseUrl = `http://127.0.0.1:${server.address().port}/`;
console.log(`Server listening on ${baseUrl}`);

if (process.argv.length > 3) {
  throw new Error('Too many arguments');
} else if (process.argv[2] === 'deno') {
  const deno = spawn('deno', ['run', '--allow-read', '--allow-net', new URL('client.js', baseUrl)], {
    stdio: 'inherit'
  });

  const [exitCode] = await events.once(deno, 'close');
  if (exitCode !== 0) {
    throw new Error(`deno exited with code ${exitCode}`);
  }

  if (challenge?.remaining?.size !== 0) {
    throw new Error('deno did not request a challenge or did not submit solutions for all algorithms');
  }
} else if (process.argv[2] === 'chrome') {
  const puppeteer = await import('puppeteer');
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  await page.goto(baseUrl);
  while (challenge?.remaining?.size !== 0) {
    await timers.setTimeout(100);
  }
  await browser.close();
} else if (process.argv[2] === 'manual') {
  console.log('Please open the above URL in a browser.');
  server.ref();
} else {
  throw new Error(`Unsupported mode: '${process.argv[2]}'`);
}

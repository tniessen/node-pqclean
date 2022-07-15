'use strict';

import * as events from 'node:events';
import { readdir } from 'node:fs/promises';
import { basename, dirname} from 'node:path';
import { fileURLToPath } from 'node:url';
import * as util from 'node:util';
import { Worker } from 'node:worker_threads';

const dir = dirname(fileURLToPath(import.meta.url));

const testFiles = (await readdir(dir, { withFileTypes: true }))
    .filter((e) => e.isFile() &&
                   e.name !== basename(fileURLToPath(import.meta.url)))
    .map(({ name }) => name);

async function runTest(testFile) {
  const startTime = Date.now();
  const worker = new Worker(new URL(testFile, import.meta.url), {
    resourceLimits: {
      stackSizeMb: 8
    },
    stdout: true
  });
  let bufferedStdout = [];
  worker.stdout.on('data', (chunk) => bufferedStdout.push(Buffer.from(chunk)));
  worker.stdout.resume();
  try {
    const [workerExitCode] = await events.once(worker, 'exit');
    if (workerExitCode === 0) {
      const durationSecs = (Date.now() - startTime) / 1000;
      console.log(`ok ${testFile} (took ${durationSecs.toFixed(1)} seconds)`);
      return { ok: true }; 
    } else {
      console.log(`not ok ${testFile} failed (exit code ${workerExitCode}):`);
      console.log(Buffer.concat(bufferedStdout).toString().replace(/^/gm, '\t'));
      return { ok: false };
    }
  } catch (err) {
    console.error(`not ok ${testFile} failed:`);
    console.error(util.inspect(err).replace(/^/gm, '\t'));
    return { ok: false };
  }
}

console.log(`Running ${testFiles.length} test files.`);
const results = await Promise.all(testFiles.map(runTest));
const nFailed = results.filter(({ ok }) => !ok).length;

if (nFailed !== 0) {
  console.log(`\n${nFailed} test(s) failed.`);
  process.exit(1);
}

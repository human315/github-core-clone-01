// Entry point: wire this bot up to the trial environment.
//
// The env runs the trial. It owns port 8080 and drives the test suite against
// this process. This file is only the glue between the two sides:
//
//   1. Read MAKEFUN_ENV_URL, the env's base URL, from the environment.
//   2. Start the app server on a kernel-chosen port. Never 8080: that one
//      belongs to the env.
//   3. Tell the env which port we bound, with POST /register.
//   4. Keep polling GET /done until the env reports the trial is over.
//   5. Shut the server down and exit 0.
//
// The process must not exit before step 4 finishes. If the env is slow to
// come up or a request fails, retry with growing delays until it answers.

import { createApp } from './app.ts';

const envBase = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
if (envBase === '') {
  console.error('makefun entry: MAKEFUN_ENV_URL is not set');
  process.exit(1);
}

// One HTTP round trip may take at most this long before it is abandoned and
// retried.
const REQUEST_TIMEOUT_MS = 30_000;
// Retries start 250 ms apart and double each time, up to a 2 s ceiling.
const BACKOFF_START_MS = 250;
const BACKOFF_MAX_MS = 2_000;
const BACKOFF_GROWTH = 2;

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function backoffMs(failures: number): number {
  return Math.min(BACKOFF_MAX_MS, BACKOFF_START_MS * BACKOFF_GROWTH ** Math.min(failures, 8));
}

// Ask the env to record our port. A 200 means it took it; a 409 means some
// other entry got there first, which is fine — we just keep waiting for done.
// A 400 or 405 is a contract error and aborts the process; network failures
// and other statuses are retried, because the env may still be starting up.
async function announcePort(port: number): Promise<void> {
  let failures = 0;
  for (;;) {
    let response: Response;
    try {
      response = await fetch(`${envBase}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch {
      await wait(backoffMs(failures));
      failures += 1;
      continue;
    }
    if (response.status === 200 || response.status === 409) return;
    if (response.status === 400 || response.status === 405) {
      throw new Error(`register rejected with HTTP ${response.status}: ${await response.text()}`);
    }
    await wait(backoffMs(failures));
    failures += 1;
  }
}

// Keep asking the env whether the trial is over. A non-200 answer, a bad
// body, a timeout, or a network error all mean "not done yet": wait a bit
// and ask again. Only {"done": true} ends the loop.
async function waitUntilDone(): Promise<void> {
  let failures = 0;
  for (;;) {
    try {
      const response = await fetch(`${envBase}/done`, {
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (response.ok) {
        const payload = (await response.json()) as { done?: unknown };
        if (payload.done === true) return;
        failures = 0;
      }
    } catch {
      // Unreachable or timed out: not done, poll again after a backoff.
    }
    await wait(backoffMs(failures));
    failures += 1;
  }
}

async function run(): Promise<void> {
  const server = createApp();
  const port = await new Promise<number>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => {
      const bound = server.address();
      if (bound === null || typeof bound === 'string') {
        reject(new Error('server did not bind a TCP port'));
        return;
      }
      resolve(bound.port);
    });
  });
  console.log(`makefun entry: app listening on port ${port}`);

  await announcePort(port);
  console.log('makefun entry: registered, waiting for the trial to finish');

  await waitUntilDone();
  server.close();
  console.log('makefun entry: trial done, shutting down');
}

run().then(
  () => process.exit(0),
  (err: unknown) => {
    console.error(`makefun entry: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  },
);

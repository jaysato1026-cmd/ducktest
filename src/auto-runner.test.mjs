import test from "node:test";
import assert from "node:assert/strict";
import { runAutomaticSequence } from "./auto-runner.mjs";

test("automatically executes every configured round with the next parameters", async () => {
  const executed = [];
  const waits = [];
  const result = await runAutomaticSequence({
    initialConfig: { concurrency: 10, duration: 10 },
    options: { enabled: true, maxRounds: 3, cooldownSeconds: 2 },
    executeRound: async (config) => {
      executed.push({ ...config });
      return { stopped: false, summary: { completed: 1000 } };
    },
    getNextConfig: (_report, config) => ({ ...config, concurrency: config.concurrency + 2 }),
    onWaiting: ({ remaining }) => waits.push(remaining),
    sleep: async () => {},
  });

  assert.deepEqual(executed.map((config) => config.concurrency), [10, 12, 14]);
  assert.deepEqual(waits, [2, 1, 2, 1]);
  assert.equal(result.completedRounds, 3);
});

test("stops scheduling new rounds after cancellation", async () => {
  let cancelled = false;
  const result = await runAutomaticSequence({
    initialConfig: { concurrency: 10 },
    options: { enabled: true, maxRounds: 5, cooldownSeconds: 1 },
    executeRound: async () => {
      cancelled = true;
      return { stopped: true };
    },
    getNextConfig: (_report, config) => config,
    isCancelled: () => cancelled,
    sleep: async () => {},
  });

  assert.equal(result.completedRounds, 1);
  assert.equal(result.stopped, true);
});

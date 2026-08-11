const test = require("node:test");
const assert = require("node:assert/strict");
const { parseTracert } = require("./route-trace.cjs");

test("parses Windows tracert hops and timeouts", () => {
  const hops = parseTracert(`\nTracing route to example.com [93.184.216.34]\n\n  1     1 ms     2 ms     1 ms  192.168.1.1\n  2    14 ms    13 ms    15 ms  203.0.113.1\n  3     *        *        *     Request timed out.\n`);
  assert.equal(hops.length, 3);
  assert.deepEqual(hops[0], {
    hop: 1,
    ip: "192.168.1.1",
    timeout: false,
    averageMs: 1.3,
    samplesMs: [1, 2, 1],
    raw: "1 ms     2 ms     1 ms  192.168.1.1",
  });
  assert.equal(hops[2].timeout, true);
  assert.equal(hops[2].ip, null);
});

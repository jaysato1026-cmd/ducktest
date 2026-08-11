const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createHistoryStore, compareRuns } = require("./history-store.cjs");

test("stores and compares historical runs", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ducktest-history-"));
  const store = createHistoryStore(root);
  store.save({ id: "a", target: "https://example.test", summary: { requestsPerSecond: 100 } });
  store.save({ id: "b", target: "https://example.test", summary: { requestsPerSecond: 80 } });
  assert.equal(store.list().length, 2);
  assert.equal(compareRuns(store.get("a"), store.get("b")).metrics[0].delta, -20);
  store.log({ level: "ERROR", category: "nmap", action: "scan", target: "example.test", message: "測試失敗", detail: { code: "TIMEOUT" } });
  store.log({ level: "INFO", category: "iperf3", action: "throughput", target: "server.test", message: "測試完成" });
  assert.equal(store.logs({ level: "ERROR" }).length, 1);
  assert.equal(store.logs({ search: "server.test" })[0].category, "iperf3");
  assert.equal(store.databaseInfo().runCount, 2);
  assert.ok(fs.existsSync(store.databaseInfo().path));
  store.save({ id: "live-monitor", type: "uptime-monitor", checkpoint: true, result: { live: true, samples: [{ ok: true }] } });
  store.save({ id: "live-monitor", type: "uptime-monitor", checkpoint: false, result: { live: false, samples: [{ ok: true }, { ok: true }] } });
  assert.equal(store.get("live-monitor").checkpoint, false);
  assert.equal(store.get("live-monitor").result.samples.length, 2);
  assert.equal(store.databaseInfo().runCount, 3);
  store.close();
});

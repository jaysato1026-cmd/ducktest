const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const {
  checkUptime,
  beginsOutage,
  runUptimeMonitor,
  summarizeSamples,
  validateMonitorConfig,
} = require("./uptime-monitor.cjs");

test("accepts the supported monitoring durations", () => {
  for (const durationHours of [1, 8, 12, 24]) {
    assert.equal(validateMonitorConfig({
      authorized: true,
      url: "https://example.com/",
      durationHours,
      intervalSeconds: 60,
      timeoutMs: 5000,
    }).durationHours, durationHours);
  }
  assert.equal(validateMonitorConfig({
    authorized: true,
    url: "https://example.com/",
    mode: "month",
    intervalSeconds: 60,
    timeoutMs: 5000,
  }).durationHours, 720);
  assert.equal(validateMonitorConfig({
    authorized: true,
    url: "https://example.com/",
    mode: "continuous",
    intervalSeconds: 60,
    timeoutMs: 5000,
  }).durationHours, Infinity);
  const range = validateMonitorConfig({
    authorized: true,
    url: "https://example.com/",
    mode: "range",
    startAt: "2026-07-20T10:00",
    endAt: "2026-07-21T10:00",
    intervalSeconds: 60,
    timeoutMs: 5000,
  });
  assert.ok(Number.isFinite(range.rangeStartAt));
  assert.ok(range.rangeEndAt > range.rangeStartAt);
  assert.throws(() => validateMonitorConfig({
    authorized: true,
    url: "https://example.com/",
    mode: "range",
    startAt: "2026-07-21T10:00",
    endAt: "2026-07-20T10:00",
    intervalSeconds: 60,
    timeoutMs: 5000,
  }));
  assert.equal(validateMonitorConfig({
    authorized: true,
    url: "https://example.com/",
    durationHours: 1,
    intervalSeconds: 60,
    timeoutMs: 5000,
    routeTraceMode: "every-check",
  }).routeTraceMode, "every-check");
});

test("summarizes availability and outage incidents", () => {
  assert.deepEqual(summarizeSamples([
    { ok: true, reachable: true, latencyMs: 20, statusCode: 200 },
    { ok: false, reachable: true, latencyMs: 30, statusCode: 500 },
    { ok: false, reachable: false, latencyMs: 50, statusCode: 0 },
    { ok: true, reachable: true, latencyMs: 40, statusCode: 200 },
  ], 60), {
    total: 4,
    passed: 2,
    failed: 2,
    availability: 50,
    averageLatencyMs: 30,
    p95LatencyMs: 40,
    incidents: 1,
    estimatedDowntimeSeconds: 120,
    lastStatus: 200,
    lastOk: true,
  });
});

test("groups consecutive failures into one outage start", () => {
  assert.equal(beginsOutage({ ok: true }, { ok: false }), true);
  assert.equal(beginsOutage({ ok: false }, { ok: false }), false);
  assert.equal(beginsOutage(null, { ok: false }), true);
  assert.equal(beginsOutage({ ok: false }, { ok: true }), false);
});

test("checks a live HTTP endpoint without downloading its body", async (context) => {
  const server = http.createServer((_request, response) => {
    response.writeHead(204);
    response.end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  context.after(() => server.close());
  const address = server.address();
  const result = await checkUptime(`http://127.0.0.1:${address.port}/health`, 1000);
  assert.equal(result.ok, true);
  assert.equal(result.statusCode, 204);
  assert.ok(result.timings.ttfbMs >= 0);
  assert.equal(result.timeoutPhase, "");
});

test("records the request phase when an HTTP response times out", async (context) => {
  const server = http.createServer(() => {});
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  context.after(() => { server.closeAllConnections(); server.close(); });
  const result = await checkUptime(`http://127.0.0.1:${server.address().port}/slow`, 100);
  assert.equal(result.ok, false);
  assert.equal(result.error, "timeout");
  assert.equal(result.timeoutPhase, "http");
  assert.ok(result.timings.tcpMs >= 0);
  assert.ok(result.timings.totalMs >= 100);
});

test("starts immediately and returns a report when monitoring is stopped", async (context) => {
  const server = http.createServer((_request, response) => {
    response.writeHead(200);
    response.end("ok");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  context.after(() => server.close());
  let cancelled = false;
  let checkpoints = 0;
  const report = await runUptimeMonitor({
    authorized: true,
    url: `http://127.0.0.1:${server.address().port}/health`,
    durationHours: 1,
    intervalSeconds: 30,
    timeoutMs: 1000,
  }, {
    isCancelled: () => cancelled,
    onProgress: () => {
      cancelled = true;
    },
    onCheckpoint: (checkpoint) => {
      checkpoints += 1;
      assert.equal(checkpoint.live, true);
      assert.equal(checkpoint.samples.length, 1);
    },
  });
  assert.equal(report.stopped, true);
  assert.equal(report.samples.length, 1);
  assert.equal(report.summary.availability, 100);
  assert.equal(checkpoints, 1);
});

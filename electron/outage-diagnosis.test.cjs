const test = require("node:test");
const assert = require("node:assert/strict");
const { diagnoseTarget, diagnoseMonitor, diagnoseDisconnectEvent } = require("./outage-diagnosis.cjs");

test("explains DNS failure as the first broken layer", () => {
  const result = diagnoseTarget({ target: "https://bad.example", alive: false, dns: { resolved: false, error: "ENOTFOUND" }, addresses: [], tcp: { reachable: false, error: "ENOTFOUND" }, http: { reachable: false, error: "ENOTFOUND" }, networkScope: "unknown" });
  assert.equal(result.status, "offline");
  assert.equal(result.causes[0].code, "ENOTFOUND");
  assert.match(result.causes[0].title, /DNS/);
});

test("separates a live host from a broken HTTP service", () => {
  const result = diagnoseTarget({ target: "http://example.test", alive: true, dns: { resolved: true }, addresses: [{ address: "203.0.113.5" }], tcp: { reachable: true, latencyMs: 12 }, http: { reachable: true, status: 503, latencyMs: 70 }, networkScope: "public" });
  assert.equal(result.status, "degraded");
  assert.ok(result.causes.some((cause) => cause.code === "HTTP_5XX"));
});

test("summarizes repeated uptime errors", () => {
  const result = diagnoseMonitor({ summary: { availability: 80, failed: 2, p95LatencyMs: 900 }, samples: [{ ok: false, error: "timeout" }, { ok: false, error: "timeout" }] });
  assert.equal(result.status, "offline");
  assert.equal(result.causes[0].code, "timeout");
});

test("accepts the monitor payload shape sent by the renderer", () => {
  const result = diagnoseMonitor({ type: "uptime-monitor", summary: { availability: 50, failed: 1, p95LatencyMs: 900 }, samples: [{ ok: false, error: "ETIMEDOUT" }] });
  assert.equal(result.status, "offline");
  assert.equal(result.causes[0].code, "ETIMEDOUT");
});

test("captures route evidence with a timeout incident", () => {
  const diagnosis = diagnoseDisconnectEvent({
    target: "https://example.test/",
    sample: { ok: false, reachable: false, checkedAt: "2026-07-20T10:00:00.000Z", error: "timeout", statusCode: 0 },
    previousSample: { ok: true, statusCode: 200 },
    routeTrace: { hops: [{ hop: 1, ip: "192.168.1.1", timeout: false }, { hop: 2, ip: null, timeout: true }] },
  });
  assert.equal(diagnosis.status, "offline");
  assert.ok(diagnosis.causes.some((cause) => cause.code === "ROUTE_TIMEOUT"));
  assert.ok(diagnosis.evidence.some((item) => item.label === "tracert"));
});

test("identifies the timed out HTTP phase and does not blame filtered intermediate hops after the destination responds", () => {
  const diagnosis = diagnoseDisconnectEvent({
    target: "https://example.test/",
    sample: {
      ok: false, reachable: false, checkedAt: "2026-08-04T06:17:00.000Z", error: "timeout", statusCode: 0,
      timeoutPhase: "http", remoteAddress: "104.21.48.214", timings: { dnsMs: 3, tcpMs: 20, tlsMs: 30, ttfbMs: null },
    },
    previousSample: { ok: true, statusCode: 200 },
    routeTrace: {
      completed: true,
      hops: [{ hop: 1, ip: "192.168.1.1", timeout: false }, { hop: 2, ip: null, timeout: true }, { hop: 3, ip: "198.51.100.20", timeout: false }],
    },
  });
  assert.ok(diagnosis.causes.some((cause) => cause.code === "TIMEOUT_HTTP"));
  assert.ok(!diagnosis.causes.some((cause) => cause.code === "ROUTE_TIMEOUT"));
  assert.ok(diagnosis.evidence.some((item) => item.label === "逾時階段" && item.value === "HTTP"));
});

import test from "node:test";
import assert from "node:assert/strict";
import { buildDiagnosis, buildNextRunConfig, normalizeAutoTune } from "./diagnostics.mjs";

const thresholds = { minRps: 100, maxP95: 800, maxFailureRate: 1, minCompleted: 1000, maxAverageKb: 200 };
const config = { concurrency: 10, duration: 10 };

test("recommends backing off when failures exceed the threshold", () => {
  const diagnosis = buildDiagnosis({
    summary: { requestsPerSecond: 80, failureRate: 4, completed: 1200, averageResponseBytes: 1024 },
    latencyMs: { p50: 100, p95: 900, p99: 1200 },
    statusCodes: { 200: 1152, 500: 48 },
    errors: {},
  }, thresholds, config);

  assert.equal(diagnosis.status, "critical");
  assert.equal(diagnosis.nextRun.concurrency, 8);
  assert.match(diagnosis.findings[0].evidence, /5xx/);
});

test("recommends exploring more load after a healthy run", () => {
  const diagnosis = buildDiagnosis({
    summary: { requestsPerSecond: 140, failureRate: 0, completed: 1400, averageResponseBytes: 1024 },
    latencyMs: { p50: 90, p95: 180, p99: 220 },
    statusCodes: { 200: 1400 },
    errors: {},
  }, thresholds, config);

  assert.equal(diagnosis.status, "healthy");
  assert.equal(diagnosis.nextRun.concurrency, 12);
  assert.match(diagnosis.findings[0].title, /通過/);
});

test("extends short runs when the sample is too small", () => {
  const diagnosis = buildDiagnosis({
    summary: { requestsPerSecond: 120, failureRate: 0, completed: 300, averageResponseBytes: 1024 },
    latencyMs: { p50: 90, p95: 180, p99: 220 },
    statusCodes: { 200: 300 },
    errors: {},
  }, thresholds, config);

  assert.equal(diagnosis.nextRun.duration, 30);
  assert.ok(diagnosis.findings.some((item) => item.title.includes("樣本量")));
});

test("applies next-run parameters without losing target or authorization", () => {
  assert.deepEqual(buildNextRunConfig({
    url: "https://example.com/health",
    authorized: true,
    concurrency: 10,
    duration: 10,
    timeout: 5000,
  }, {
    concurrency: 12,
    duration: 30,
  }), {
    url: "https://example.com/health",
    authorized: true,
    concurrency: 12,
    duration: 30,
    timeout: 5000,
  });
});

test("bounds automatic tuning to safe round and cooldown limits", () => {
  assert.deepEqual(normalizeAutoTune({
    enabled: true,
    maxRounds: 99,
    cooldownSeconds: 0,
  }), {
    enabled: true,
    maxRounds: 10,
    cooldownSeconds: 5,
  });
});

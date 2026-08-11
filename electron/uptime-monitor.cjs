const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const { traceRoute } = require("./route-trace.cjs");
const { diagnoseDisconnectEvent } = require("./outage-diagnosis.cjs");

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const MAX_STORED_SAMPLES = 10000;
const MAX_STORED_ROUTE_TRACES = 500;

function percentile(values, p) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * p) - 1)];
}

function validateMonitorConfig(config) {
  if (!config?.authorized) throw new Error("請先確認已取得目標系統的監控授權");
  const url = new URL(config.url);
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("監控目標只支援 HTTP 或 HTTPS");
  const mode = ["duration", "month", "continuous", "range"].includes(config.mode) ? config.mode : "duration";
  const durationHours = mode === "month" ? 720 : mode === "continuous" ? Infinity : Number(config.durationHours);
  if (mode === "duration" && ![1, 8, 12, 24].includes(durationHours)) throw new Error("監控時間必須為 1、8、12 或 24 小時");
  const rangeStartAt = mode === "range" ? Date.parse(config.startAt) : null;
  const rangeEndAt = mode === "range" ? Date.parse(config.endAt) : null;
  if (mode === "range" && (!Number.isFinite(rangeStartAt) || !Number.isFinite(rangeEndAt) || rangeEndAt <= rangeStartAt)) throw new Error("指定日期區間必須有有效開始與結束時間，且結束必須晚於開始");
  const intervalSeconds = Number(config.intervalSeconds);
  if (!Number.isInteger(intervalSeconds) || intervalSeconds < 30 || intervalSeconds > 3600) {
    throw new Error("監控間隔必須為 30–3600 秒");
  }
  const timeoutMs = Number(config.timeoutMs);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 500 || timeoutMs > 30000) {
    throw new Error("監控逾時必須為 500–30000 毫秒");
  }
  const routeTraceMode = ["off", "every-check", "interval"].includes(config.routeTraceMode)
    ? config.routeTraceMode
    : "interval";
  const routeTraceIntervalSeconds = Number(config.routeTraceIntervalSeconds || 900);
  if (routeTraceMode === "interval" && (!Number.isInteger(routeTraceIntervalSeconds) || routeTraceIntervalSeconds < 300 || routeTraceIntervalSeconds > 86400)) {
    throw new Error("Route tracing interval must be between 5 minutes and 24 hours.");
  }
  return {
    url: url.href,
    mode,
    durationHours,
    rangeStartAt,
    rangeEndAt,
    intervalSeconds,
    timeoutMs,
    routeTraceMode,
    routeTraceIntervalSeconds,
    ignoreTlsErrors: Boolean(config.ignoreTlsErrors),
  };
}

function checkUptime(target, timeoutMs, ignoreTlsErrors = false) {
  return new Promise((resolve) => {
    const url = new URL(target);
    const transport = url.protocol === "https:" ? https : http;
    const startedAt = performance.now();
    const elapsed = () => Number((performance.now() - startedAt).toFixed(2));
    const timings = { dnsMs: null, tcpMs: null, tlsMs: null, ttfbMs: null, totalMs: null, reusedConnection: false };
    let phase = net.isIP(url.hostname) ? "tcp" : "dns";
    let resolvedAddress = net.isIP(url.hostname) ? url.hostname : "";
    let remoteAddress = "";
    let finished = false;
    const finish = (result) => {
      if (finished) return;
      finished = true;
      resolve({
        checkedAt: new Date().toISOString(),
        latencyMs: elapsed(),
        ...result,
      });
    };
    const request = transport.request(url, {
      method: "GET",
      headers: {
        "User-Agent": "DuckTest-Uptime-Monitor/1.15.1",
        "Cache-Control": "no-cache",
        Range: "bytes=0-0",
      },
      rejectUnauthorized: !ignoreTlsErrors,
    }, (response) => {
      const statusCode = response.statusCode || 0;
      const healthy = statusCode >= 200 && statusCode < 400;
      const socket = response.socket;
      timings.ttfbMs = elapsed();
      timings.totalMs = timings.ttfbMs;
      remoteAddress = socket.remoteAddress || remoteAddress;
      finish({
        ok: healthy,
        reachable: true,
        statusCode,
        statusName: response.statusMessage || "",
        server: String(response.headers.server || ""),
        tlsAuthorized: url.protocol === "https:" ? socket.authorized : null,
        tlsProtocol: url.protocol === "https:" ? socket.getProtocol() : null,
        resolvedAddress,
        remoteAddress,
        timeoutPhase: "",
        timings,
        cloudflare: {
          ray: String(response.headers["cf-ray"] || ""),
          cacheStatus: String(response.headers["cf-cache-status"] || ""),
          errorType: String(response.headers["cf-error-type"] || ""),
          errorOrigin: String(response.headers["cf-error-origin"] || ""),
        },
        error: healthy ? "" : `HTTP ${statusCode}`,
      });
      response.destroy();
    });
    request.once("socket", (socket) => {
      timings.reusedConnection = !socket.connecting;
      if (!socket.connecting) {
        phase = "http";
        remoteAddress = socket.remoteAddress || "";
        return;
      }
      socket.once("lookup", (_error, address) => {
        timings.dnsMs = elapsed();
        resolvedAddress = address || resolvedAddress;
        phase = "tcp";
      });
      socket.once("connect", () => {
        const connectedAt = elapsed();
        timings.tcpMs = Number((connectedAt - (timings.dnsMs || 0)).toFixed(2));
        remoteAddress = socket.remoteAddress || remoteAddress;
        phase = url.protocol === "https:" ? "tls" : "http";
      });
      socket.once("secureConnect", () => {
        const securedAt = elapsed();
        timings.tlsMs = Number((securedAt - (timings.dnsMs || 0) - (timings.tcpMs || 0)).toFixed(2));
        phase = "http";
      });
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error("timeout")));
    request.once("error", (error) => {
      timings.totalMs = elapsed();
      finish({
        ok: false,
        reachable: false,
        statusCode: 0,
        statusName: "",
        server: "",
        tlsAuthorized: null,
        tlsProtocol: null,
        resolvedAddress,
        remoteAddress,
        timeoutPhase: error.message === "timeout" ? phase : "",
        timings,
        cloudflare: { ray: "", cacheStatus: "", errorType: "", errorOrigin: "" },
        error: error.message === "timeout" ? "timeout" : (error.code || error.message),
      });
    });
    request.end();
  });
}

function summarizeSamples(samples, intervalSeconds) {
  const total = samples.length;
  const passed = samples.filter((sample) => sample.ok).length;
  const failed = total - passed;
  const latencies = samples.filter((sample) => sample.reachable).map((sample) => sample.latencyMs);
  let incidents = 0;
  let previousOk = true;
  for (const sample of samples) {
    if (!sample.ok && previousOk) incidents += 1;
    previousOk = sample.ok;
  }
  return {
    total,
    passed,
    failed,
    availability: total ? Number(((passed / total) * 100).toFixed(3)) : 0,
    averageLatencyMs: latencies.length
      ? Number((latencies.reduce((sum, value) => sum + value, 0) / latencies.length).toFixed(2))
      : 0,
    p95LatencyMs: Number(percentile(latencies, 0.95).toFixed(2)),
    incidents,
    estimatedDowntimeSeconds: failed * intervalSeconds,
    lastStatus: samples.at(-1)?.statusCode || 0,
    lastOk: samples.at(-1)?.ok ?? null,
  };
}

function beginsOutage(previousSample, sample) {
  return Boolean(sample && !sample.ok && previousSample?.ok !== false);
}

async function waitUntilNext(ms, isCancelled) {
  let remaining = ms;
  while (remaining > 0 && !isCancelled()) {
    const chunk = Math.min(1000, remaining);
    await sleep(chunk);
    remaining -= chunk;
  }
}

async function runUptimeMonitor(rawConfig, hooks = {}) {
  const config = validateMonitorConfig(rawConfig);
  const isCancelled = hooks.isCancelled || (() => false);
  const onProgress = hooks.onProgress || (() => {});
  const onCheckpoint = hooks.onCheckpoint || (() => {});
  const requestedAtMs = Date.now();
  const scheduledStartAtMs = config.rangeStartAt || requestedAtMs;
  const endsAtMs = config.mode === "continuous" ? Infinity : config.rangeEndAt || requestedAtMs + config.durationHours * 60 * 60 * 1000;
  const samples = [];
  const routeTraces = [];
  const incidentAnalyses = [];
  let samplesTruncated = false;
  let routeTracesTruncated = false;
  let lastRouteTraceAtMs = 0;
  let lastCheckpointAtMs = 0;

  if (scheduledStartAtMs > Date.now()) {
    onProgress({ target: config.url, mode: config.mode, pending: true, startedAt: new Date(scheduledStartAtMs).toISOString(), endsAt: Number.isFinite(endsAtMs) ? new Date(endsAtMs).toISOString() : null, remainingSeconds: Math.ceil((scheduledStartAtMs - Date.now()) / 1000), summary: summarizeSamples([], config.intervalSeconds) });
    await waitUntilNext(scheduledStartAtMs - Date.now(), isCancelled);
  }
  const startedAtMs = Date.now();

  while (!isCancelled() && Date.now() < endsAtMs) {
    const sample = await checkUptime(config.url, config.timeoutMs, config.ignoreTlsErrors);
    samples.push(sample);
    if (samples.length > MAX_STORED_SAMPLES) {
      samples.shift();
      samplesTruncated = true;
    }
    let routeTrace = null;
    const shouldTrace = !sample.ok || config.routeTraceMode === "every-check"
      || (config.routeTraceMode === "interval" && Date.now() - lastRouteTraceAtMs >= config.routeTraceIntervalSeconds * 1000);
    if (shouldTrace && !isCancelled()) {
      lastRouteTraceAtMs = Date.now();
      try {
        routeTrace = await traceRoute(config.url, { maxHops: 12, timeoutMs: Math.min(1500, config.timeoutMs) });
      } catch (error) {
        routeTrace = { target: config.url, checkedAt: new Date().toISOString(), hops: [], error: error.message || String(error) };
      }
      routeTraces.push({ sampleCheckedAt: sample.checkedAt, sampleOk: sample.ok, ...routeTrace });
      if (routeTraces.length > MAX_STORED_ROUTE_TRACES) {
        routeTraces.shift();
        routeTracesTruncated = true;
      }
    }
    const previousSample = samples.at(-2);
    const incident = beginsOutage(previousSample, sample)
      ? diagnoseDisconnectEvent({ target: config.url, sample, previousSample, routeTrace })
      : null;
    if (incident) {
      incidentAnalyses.push(incident);
      if (incidentAnalyses.length > MAX_STORED_ROUTE_TRACES) incidentAnalyses.shift();
    }
    const summary = summarizeSamples(samples, config.intervalSeconds);
    onProgress({
      target: config.url,
      mode: config.mode,
      startedAt: new Date(startedAtMs).toISOString(),
      endsAt: Number.isFinite(endsAtMs) ? new Date(endsAtMs).toISOString() : null,
      remainingSeconds: Number.isFinite(endsAtMs) ? Math.max(0, Math.ceil((endsAtMs - Date.now()) / 1000)) : null,
      sample,
      routeTrace,
      incident,
      summary,
    });
    const checkpointAtMs = Date.now();
    if (!sample.ok || lastCheckpointAtMs === 0 || checkpointAtMs - lastCheckpointAtMs >= 5 * 60 * 1000) {
      lastCheckpointAtMs = checkpointAtMs;
      onCheckpoint({
        type: "uptime-monitor",
        target: config.url,
        mode: config.mode,
        live: true,
        startedAt: new Date(startedAtMs).toISOString(),
        updatedAt: new Date(checkpointAtMs).toISOString(),
        intervalSeconds: config.intervalSeconds,
        routeTraceMode: config.routeTraceMode,
        routeTraceIntervalSeconds: config.routeTraceIntervalSeconds,
        samplesTruncated,
        routeTracesTruncated,
        samples: [...samples],
        routeTraces: [...routeTraces],
        incidentAnalyses: [...incidentAnalyses],
        summary,
      });
    }
    if (isCancelled() || Date.now() >= endsAtMs) break;
    await waitUntilNext(Math.min(config.intervalSeconds * 1000, endsAtMs - Date.now()), isCancelled);
  }

  return {
    type: "uptime-monitor",
    target: config.url,
    mode: config.mode,
    startedAt: new Date(startedAtMs).toISOString(),
    endedAt: new Date().toISOString(),
    scheduledHours: Number.isFinite(config.durationHours) ? config.durationHours : null,
    scheduledStartAt: new Date(scheduledStartAtMs).toISOString(),
    scheduledEndAt: Number.isFinite(endsAtMs) ? new Date(endsAtMs).toISOString() : null,
    intervalSeconds: config.intervalSeconds,
    stopped: isCancelled(),
    samplesTruncated,
    routeTraceMode: config.routeTraceMode,
    routeTraceIntervalSeconds: config.routeTraceIntervalSeconds,
    routeTracesTruncated,
    routeTraces,
    incidentAnalyses,
    summary: summarizeSamples(samples, config.intervalSeconds),
    samples,
  };
}

module.exports = {
  checkUptime,
  beginsOutage,
  runUptimeMonitor,
  summarizeSamples,
  validateMonitorConfig,
};

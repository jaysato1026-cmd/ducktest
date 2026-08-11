import http from "node:http";
import https from "node:https";
import dns from "node:dns";
import net from "node:net";

const port = Number(process.env.PORT || 8787);
const token = process.env.PROBE_TOKEN || "";
const allowedHosts = new Set(String(process.env.ALLOWED_TARGET_HOSTS || "").split(",").map((item) => item.trim()).filter(Boolean));

const percentile = (values, p) => {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * p) - 1)];
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function resolveTarget(hostname, dnsServer) {
  const startedAt = performance.now();
  if (net.isIP(hostname)) return { address: hostname, family: net.isIP(hostname), latencyMs: 0 };
  if (!dnsServer || dnsServer === "system") {
    const result = await dns.promises.lookup(hostname);
    return { ...result, latencyMs: performance.now() - startedAt };
  }
  const resolver = new dns.promises.Resolver();
  resolver.setServers([dnsServer]);
  try {
    const addresses = await resolver.resolve4(hostname);
    return { address: addresses[0], family: 4, latencyMs: performance.now() - startedAt };
  } catch (ipv4Error) {
    try {
      const addresses = await resolver.resolve6(hostname);
      return { address: addresses[0], family: 6, latencyMs: performance.now() - startedAt };
    } catch {
      throw ipv4Error;
    }
  }
}

function requestTarget(targetUrl, resolved, timeoutMs) {
  return new Promise((resolve, reject) => {
    const startedAt = performance.now();
    const transport = targetUrl.protocol === "https:" ? https : http;
    const request = transport.request({
      hostname: resolved.address,
      family: resolved.family,
      port: Number(targetUrl.port) || (targetUrl.protocol === "https:" ? 443 : 80),
      path: `${targetUrl.pathname}${targetUrl.search}`,
      method: "GET",
      servername: targetUrl.hostname,
      headers: {
        Host: targetUrl.host,
        "User-Agent": "YAT-Global-Probe-Agent/1.1",
      },
    }, (response) => {
      const latencyMs = performance.now() - startedAt;
      response.resume();
      response.on("end", () => resolve({ status: response.statusCode || 0, latencyMs }));
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error("timeout")));
    request.once("error", reject);
    request.end();
  });
}

async function measure({ target, samples, intervalMs, timeoutMs, dnsServer = "system" }) {
  const targetUrl = new URL(target);
  if (!["http:", "https:"].includes(targetUrl.protocol)) throw new Error("unsupported target protocol");
  if (allowedHosts.size && !allowedHosts.has(targetUrl.hostname)) throw new Error("target host is not allowed");
  const count = Math.min(30, Math.max(3, Number(samples) || 10));
  const interval = Math.min(5000, Math.max(100, Number(intervalMs) || 500));
  const timeout = Math.min(30000, Math.max(500, Number(timeoutMs) || 5000));
  const latencies = [];
  const dnsLatencies = [];
  const resolvedAddresses = new Set();
  const statuses = {};
  const errors = {};
  let dnsFailures = 0;

  for (let index = 0; index < count; index += 1) {
    try {
      const resolved = await resolveTarget(targetUrl.hostname, dnsServer);
      dnsLatencies.push(resolved.latencyMs);
      resolvedAddresses.add(resolved.address);
      const result = await requestTarget(targetUrl, resolved, timeout);
      latencies.push(result.latencyMs);
      statuses[result.status] = (statuses[result.status] || 0) + 1;
    } catch (error) {
      const code = error.message === "timeout" ? "timeout" : (error.cause?.code || error.code || error.name || "unknown");
      errors[code] = (errors[code] || 0) + 1;
      if (["ENOTFOUND", "ENODATA", "ETIMEOUT", "ESERVFAIL", "EREFUSED"].includes(code)) dnsFailures += 1;
    }
    if (index < count - 1) await sleep(interval);
  }

  const successes = Object.entries(statuses).filter(([status]) => Number(status) < 400).reduce((sum, [, value]) => sum + value, 0);
  const average = latencies.reduce((sum, value) => sum + value, 0) / Math.max(1, latencies.length);
  const variance = latencies.reduce((sum, value) => sum + ((value - average) ** 2), 0) / Math.max(1, latencies.length);
  const dnsAverage = dnsLatencies.reduce((sum, value) => sum + value, 0) / Math.max(1, dnsLatencies.length);
  return {
    availability: Number(((successes / count) * 100).toFixed(2)),
    latencyMs: {
      average: Number(average.toFixed(2)),
      p50: Number(percentile(latencies, 0.5).toFixed(2)),
      p95: Number(percentile(latencies, 0.95).toFixed(2)),
      jitter: Number(Math.sqrt(variance).toFixed(2)),
    },
    dns: {
      server: dnsServer,
      average: Number(dnsAverage.toFixed(2)),
      p95: Number(percentile(dnsLatencies, 0.95).toFixed(2)),
      failures: dnsFailures,
      addresses: [...resolvedAddresses],
    },
    statuses,
    errors,
    completed: count,
  };
}

const server = http.createServer(async (request, response) => {
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  if (request.method !== "POST" || request.url !== "/probe") {
    response.writeHead(404).end(JSON.stringify({ error: "not found" }));
    return;
  }
  if (token && request.headers.authorization !== `Bearer ${token}`) {
    response.writeHead(401).end(JSON.stringify({ error: "unauthorized" }));
    return;
  }
  let body = "";
  request.setEncoding("utf8");
  for await (const chunk of request) {
    body += chunk;
    if (body.length > 100000) {
      response.writeHead(413).end(JSON.stringify({ error: "payload too large" }));
      return;
    }
  }
  try {
    response.end(JSON.stringify(await measure(JSON.parse(body))));
  } catch (error) {
    response.writeHead(400).end(JSON.stringify({ error: error.message || String(error) }));
  }
});

server.listen(port, "0.0.0.0", () => {
  console.log(`YAT global probe agent listening on :${port}`);
});

const net = require("node:net");
const { isPrivateAddress, lookupGeo } = require("./target-probe.cjs");

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const percentile = (values, p) => {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * p) - 1)];
};

const finiteNumber = (value, fallback = 0) => {
  if (value === null || value === undefined || value === "") return fallback;
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
};

function isPrivateIp(address) {
  const parts = address.split(".").map(Number);
  if (parts.length === 4) {
    return parts[0] === 10 || parts[0] === 127 || (parts[0] === 192 && parts[1] === 168)
      || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31);
  }
  const normalized = address.toLowerCase();
  return normalized === "::1" || normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe80:");
}

function parseCountries(value) {
  const countries = [...new Set(String(value || "").split(/[,，\s]+/).map((item) => item.trim().toUpperCase()).filter(Boolean))];
  if (!countries.length) throw new Error("請至少輸入一個國家代碼");
  if (countries.length > 12) throw new Error("免部署模式單次最多 12 個國家");
  if (countries.some((code) => !/^[A-Z]{2}$/.test(code))) throw new Error("國家請使用兩碼代碼，例如 JP、SG、US、DE");
  return countries;
}

async function apiRequest(path, options, token) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(`https://api.globalping.io/v1${path}`, {
      ...options,
      signal: controller.signal,
      headers: {
        "User-Agent": "YAT-Load-Console/1.9",
        ...(options?.body ? { "Content-Type": "application/json" } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(options?.headers || {}),
      },
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || data.error?.message || `Globalping HTTP ${response.status}`);
    return data;
  } finally {
    clearTimeout(timer);
  }
}

async function createAndWait(payload, token) {
  const created = await apiRequest("/measurements", { method: "POST", body: JSON.stringify(payload) }, token);
  for (let attempt = 0; attempt < 24; attempt += 1) {
    await sleep(1200);
    const measurement = await apiRequest(`/measurements/${created.id}`, { method: "GET" }, token);
    if (measurement.status !== "in-progress") return measurement;
  }
  throw new Error("Globalping 測試逾時");
}

async function safeMeasurement(payload, token) {
  try {
    return await createAndWait(payload, token);
  } catch (cause) {
    return { id: null, results: [], error: cause.message || String(cause) };
  }
}

function classifyEndpoint({ httpReachable, statusCode, tlsAuthorized, pingAvailability }) {
  if (!httpReachable) {
    return pingAvailability > 0
      ? { label: "網路可達", className: "warn", reason: "ICMP 有回應，但 HTTP/HTTPS 服務沒有完成回應。" }
      : { label: "無法連線", className: "bad", reason: "HTTP/HTTPS 與 ICMP 都沒有確認目標可達。" };
  }
  if (statusCode >= 500) {
    return { label: "服務錯誤", className: "bad", reason: `主機可達，但服務回傳 HTTP ${statusCode}。` };
  }
  if (statusCode >= 400) {
    return {
      label: "網址異常",
      className: "warn",
      reason: `主機與 HTTPS 可達，但指定網址回傳 HTTP ${statusCode}；請確認路徑、Host 或存取權限。`,
    };
  }
  if (tlsAuthorized === false) {
    return { label: "TLS 異常", className: "bad", reason: "網站有回應，但 TLS 憑證驗證未通過。" };
  }
  return {
    label: "網站正常",
    className: "good",
    reason: pingAvailability === 0
      ? "HTTP/HTTPS 正常；ICMP 沒有回應，通常是主機或防火牆封鎖 Ping，不代表網站離線。"
      : "DNS、HTTP/HTTPS 與 ICMP 均可完成測試。",
  };
}

async function runGlobalping(config) {
  const url = new URL(config.target);
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("只支援公開 HTTP 或 HTTPS 目標");
  if (url.hostname === "localhost" || (net.isIP(url.hostname) && isPrivateIp(url.hostname))) {
    throw new Error("Globalping 公共節點不能存取 localhost 或私有 IP；請改用自架 Agent + VPN");
  }
  const countries = parseCountries(config.countries);
  const locations = countries.map((country) => ({ country, limit: 1 }));
  const packets = Math.min(16, Math.max(3, Number(config.packets) || 5));
  const dnsServer = config.dnsServer || "system";
  const token = String(config.token || "").trim();
  const protocol = url.protocol === "https:" ? "HTTPS" : "HTTP";
  const port = url.port ? Number(url.port) : (protocol === "HTTPS" ? 443 : 80);
  const request = {
    method: "GET",
    path: url.pathname || "/",
    ...(url.search ? { query: url.search.slice(1) } : {}),
  };
  const resolver = dnsServer === "system" ? {} : { resolver: dnsServer };
  const [ping, dns, http, traceroute] = await Promise.all([
    safeMeasurement({
      target: url.hostname,
      type: "ping",
      locations,
      measurementOptions: { packets },
    }, token),
    safeMeasurement({
      target: url.hostname,
      type: "dns",
      locations,
      measurementOptions: {
        query: { type: "A" },
        ...resolver,
      },
    }, token),
    safeMeasurement({
      target: url.hostname,
      type: "http",
      locations,
      measurementOptions: {
        request,
        protocol,
        ...(url.port ? { port } : {}),
        ...resolver,
      },
    }, token),
    safeMeasurement({
      target: url.hostname,
      type: "traceroute",
      locations,
      measurementOptions: { protocol: "TCP", port },
    }, token),
  ]);
  const dnsByCountry = new Map((dns.results || []).map((item) => [item.probe?.country, item]));
  const pingByCountry = new Map((ping.results || []).map((item) => [item.probe?.country, item]));
  const httpByCountry = new Map((http.results || []).map((item) => [item.probe?.country, item]));
  const traceByCountry = new Map((traceroute.results || []).map((item) => [item.probe?.country, item]));
  const results = countries.map((country, index) => {
    const item = pingByCountry.get(country);
    const httpItem = httpByCountry.get(country);
    const dnsItem = dnsByCountry.get(country);
    const traceItem = traceByCountry.get(country);
    const probe = httpItem?.probe || item?.probe || dnsItem?.probe || traceItem?.probe || {};
    const timings = (item?.result?.timings || []).map((timing) => Number(timing.rtt)).filter(Number.isFinite);
    const average = finiteNumber(item?.result?.stats?.avg);
    const variance = timings.reduce((sum, value) => sum + ((value - average) ** 2), 0) / Math.max(1, timings.length);
    const pingLoss = finiteNumber(item?.result?.stats?.loss, 100);
    const pingAvailability = Math.max(0, 100 - pingLoss);
    const dnsTotal = finiteNumber(dnsItem?.result?.timings?.total);
    const statusCode = finiteNumber(httpItem?.result?.statusCode, null);
    const httpReachable = Number.isFinite(statusCode);
    const httpTimings = httpItem?.result?.timings || {};
    const tls = httpItem?.result?.tls;
    const hops = traceItem?.result?.hops || [];
    const routeTimings = hops.flatMap((hop) => hop.timings || []).map((timing) => finiteNumber(timing.rtt)).filter((value) => value > 0);
    const verdict = classifyEndpoint({
      httpReachable,
      statusCode,
      tlsAuthorized: tls?.authorized,
      pingAvailability,
    });
    return {
      id: `globalping-${country}-${index}`,
      country,
      city: probe.city || probe.region || "--",
      endpoint: probe.network || "Globalping",
      asn: probe.asn || null,
      tags: probe.tags || [],
      ok: httpReachable || pingAvailability > 0,
      alive: httpReachable || pingAvailability > 0,
      availability: pingAvailability,
      latencyMs: {
        average: Number(average.toFixed(2)),
        p50: Number(percentile(timings, 0.5).toFixed(2)),
        p95: Number(percentile(timings, 0.95).toFixed(2)),
        jitter: Number(Math.sqrt(variance).toFixed(2)),
      },
      dns: {
        server: dnsItem?.result?.resolver || dnsServer,
        average: dnsTotal,
        p95: dnsTotal,
        failures: dnsItem?.result?.status === "finished" ? 0 : 1,
        addresses: (dnsItem?.result?.answers || []).map((answer) => answer.value),
      },
      ping: {
        protocol: "ICMP",
        loss: pingLoss,
        sent: finiteNumber(item?.result?.stats?.total, packets),
        received: finiteNumber(item?.result?.stats?.rcv),
        dropped: finiteNumber(item?.result?.stats?.drop),
        min: finiteNumber(item?.result?.stats?.min),
        max: finiteNumber(item?.result?.stats?.max),
        error: item?.result?.status === "finished" ? null : item?.result?.rawOutput || ping.error || "Ping 未完成",
      },
      http: {
        reachable: httpReachable,
        healthy: httpReachable && statusCode >= 200 && statusCode < 400 && tls?.authorized !== false,
        statusCode,
        statusName: httpItem?.result?.statusCodeName || "",
        resolvedAddress: httpItem?.result?.resolvedAddress || null,
        server: httpItem?.result?.headers?.server || "--",
        contentType: httpItem?.result?.headers?.["content-type"] || "--",
        timings: {
          total: finiteNumber(httpTimings.total),
          dns: finiteNumber(httpTimings.dns),
          tcp: finiteNumber(httpTimings.tcp),
          tls: finiteNumber(httpTimings.tls),
          firstByte: finiteNumber(httpTimings.firstByte),
          download: finiteNumber(httpTimings.download),
        },
        tls: tls ? {
          authorized: tls.authorized,
          protocol: tls.protocol,
          cipher: tls.cipherName,
          issuer: tls.issuer?.O || tls.issuer?.CN || "--",
          subject: tls.subject?.CN || "--",
          expiresAt: tls.expiresAt,
          error: tls.authorizationError || null,
        } : null,
        error: httpItem?.result?.status === "finished" ? null : httpItem?.result?.rawOutput || http.error || "HTTP 測試未完成",
      },
      route: {
        protocol: "TCP",
        port,
        hops: hops.length,
        responsiveHops: hops.filter((hop) => hop.resolvedAddress).length,
        lastAddress: [...hops].reverse().find((hop) => hop.resolvedAddress)?.resolvedAddress || null,
        maxRtt: routeTimings.length ? Math.max(...routeTimings) : 0,
        path: hops.map((hop, hopIndex) => {
          const timings = (hop.timings || []).map((timing) => finiteNumber(timing.rtt)).filter((value) => value > 0);
          return {
            hop: finiteNumber(hop.hop, hopIndex + 1),
            ip: hop.resolvedAddress || null,
            hostname: hop.resolvedHostname || "",
            averageMs: timings.length ? Number((timings.reduce((sum, value) => sum + value, 0) / timings.length).toFixed(1)) : null,
          };
        }),
        error: traceItem?.result?.status === "finished" ? null : traceItem?.result?.rawOutput || traceroute.error || "路由追蹤未完成",
      },
      verdict,
      errors: {
        ...(ping.error ? { ping: ping.error } : {}),
        ...(dns.error ? { dns: dns.error } : {}),
        ...(http.error ? { http: http.error } : {}),
        ...(traceroute.error ? { traceroute: traceroute.error } : {}),
      },
      completed: finiteNumber(item?.result?.stats?.total, packets),
    };
  });
  const publicHopIps = [...new Set(results.flatMap((item) => (item.route?.path || []).map((hop) => hop.ip)).filter((ip) => ip && !isPrivateAddress(ip)))].slice(0, 48);
  const geoEntries = await Promise.all(publicHopIps.map(async (ip) => [ip, await lookupGeo(ip, 3500)]));
  const geoByIp = Object.fromEntries(geoEntries);
  for (const result of results) {
    for (const hop of result.route?.path || []) hop.geo = hop.ip ? geoByIp[hop.ip] || null : null;
  }
  return {
    provider: "Globalping 公共節點",
    target: url.href,
    checkedAt: new Date().toISOString(),
    samples: packets,
    dnsServer,
    measurementIds: { ping: ping.id, dns: dns.id, http: http.id, traceroute: traceroute.id },
    results,
  };
}

module.exports = { classifyEndpoint, parseCountries, runGlobalping };

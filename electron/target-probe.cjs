const dns = require("node:dns").promises;
const net = require("node:net");
const http = require("node:http");
const https = require("node:https");

function isPrivateAddress(address) {
  if (!address) return false;
  if (address === "::1" || address === "0:0:0:0:0:0:0:1") return true;
  const normalized = address.toLowerCase();
  if (normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe80:")) return true;
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part))) return false;
  return parts[0] === 10
    || parts[0] === 127
    || (parts[0] === 169 && parts[1] === 254)
    || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
    || (parts[0] === 192 && parts[1] === 168);
}

function tcpConnect(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const startedAt = performance.now();
    const socket = net.createConnection({ host, port });
    const finish = (reachable, error = "") => {
      socket.destroy();
      resolve({
        reachable,
        latencyMs: reachable ? Number((performance.now() - startedAt).toFixed(2)) : null,
        error,
      });
    };
    socket.setTimeout(timeoutMs, () => finish(false, "timeout"));
    socket.once("connect", () => finish(true));
    socket.once("error", (error) => finish(false, error.code || error.message));
  });
}

function httpCheck(url, timeoutMs, options = {}) {
  return new Promise((resolve) => {
    const startedAt = performance.now();
    const transport = url.protocol === "https:" ? https : http;
    const method = String(options.method || "HEAD").toUpperCase();
    const request = transport.request(url, {
      method,
      headers: { "User-Agent": "YAT-Target-Probe/1.7", ...(options.headers || {}) },
      rejectUnauthorized: false,
    }, (response) => {
      const result = {
        reachable: true,
        status: response.statusCode || 0,
        latencyMs: Number((performance.now() - startedAt).toFixed(2)),
        server: String(response.headers.server || ""),
        tlsAuthorized: url.protocol === "https:" ? response.socket.authorized : null,
        tlsError: url.protocol === "https:" ? String(response.socket.authorizationError || "") : "",
        tlsProtocol: url.protocol === "https:" ? response.socket.getProtocol() : "",
        error: "",
      };
      response.resume();
      response.on("end", () => resolve(result));
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error("timeout")));
    request.once("error", (error) => resolve({
      reachable: false,
      status: 0,
      latencyMs: null,
      server: "",
      error: error.message === "timeout" ? "timeout" : (error.code || error.message),
    }));
    if (!["GET", "HEAD"].includes(method) && options.body) request.write(options.body);
    request.end();
  });
}

function lookupGeo(address, timeoutMs = 5000) {
  return new Promise((resolve) => {
    const request = https.get(
      `https://ipwho.is/${encodeURIComponent(address)}?fields=success,message,country,region,city,latitude,longitude,timezone,connection`,
      { headers: { "User-Agent": "YAT-Target-Probe/1.7" } },
      (response) => {
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          if (body.length < 100000) body += chunk;
        });
        response.on("end", () => {
          try {
            const data = JSON.parse(body);
            if (!data.success) return resolve({ available: false, error: data.message || "Geo lookup failed" });
            resolve({
              available: true,
              country: data.country || "",
              region: data.region || "",
              city: data.city || "",
              latitude: data.latitude ?? null,
              longitude: data.longitude ?? null,
              timezone: data.timezone?.id || "",
              isp: data.connection?.isp || "",
              organization: data.connection?.org || "",
            });
          } catch {
            resolve({ available: false, error: "Geo response invalid" });
          }
        });
      },
    );
    request.setTimeout(timeoutMs, () => request.destroy(new Error("timeout")));
    request.once("error", (error) => resolve({ available: false, error: error.message }));
  });
}

async function probeTarget(rawUrl, timeoutMs = 5000, requestOptions = {}) {
  const url = new URL(rawUrl);
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("目標網址只支援 HTTP 或 HTTPS");
  const timeout = Math.min(30000, Math.max(500, Number(timeoutMs) || 5000));
  const port = Number(url.port) || (url.protocol === "https:" ? 443 : 80);
  let addresses = [];
  let dnsError = "";

  try {
    addresses = net.isIP(url.hostname)
      ? [{ address: url.hostname, family: net.isIP(url.hostname) }]
      : await dns.lookup(url.hostname, { all: true, verbatim: true });
  } catch (error) {
    dnsError = error.code || error.message;
  }

  const primaryAddress = addresses[0]?.address || "";
  const networkScope = primaryAddress
    ? (isPrivateAddress(primaryAddress) ? "private" : "public")
    : "unknown";
  const [tcp, headProbe] = await Promise.all([
    primaryAddress
      ? tcpConnect(primaryAddress, port, timeout)
      : Promise.resolve({ reachable: false, latencyMs: null, error: dnsError || "unresolved" }),
    httpCheck(url, timeout),
  ]);
  const requestedMethod = String(requestOptions.method || "HEAD").toUpperCase();
  let web = headProbe;
  let methodFallback = null;
  if (headProbe.reachable && [404, 405, 501].includes(headProbe.status) && requestedMethod !== "HEAD") {
    const methodProbe = await httpCheck(url, timeout, {
      method: requestedMethod,
      headers: requestOptions.headers,
      body: requestOptions.body,
    });
    web = methodProbe;
    methodFallback = {
      headStatus: headProbe.status,
      method: requestedMethod,
      methodStatus: methodProbe.status,
      recovered: methodProbe.reachable && ![404, 405, 501].includes(methodProbe.status),
    };
  }
  let protocolHint = null;
  if (!web.reachable && web.error === "EPROTO" && url.protocol === "https:") {
    const alternateUrl = new URL(url.href);
    alternateUrl.protocol = "http:";
    const alternateResult = await httpCheck(alternateUrl, timeout);
    if (alternateResult.reachable) {
      protocolHint = {
        mismatch: true,
        suggestedUrl: alternateUrl.href,
        message: `Port ${port} 可連線，但不是 HTTPS；改用 HTTP 後收到 HTTP ${alternateResult.status}`,
        alternateResult,
      };
    }
  }
  const geo = networkScope === "public"
    ? await lookupGeo(primaryAddress)
    : {
      available: false,
      private: networkScope === "private",
      label: networkScope === "private" ? "私有網路／內部位址" : "無法判定",
    };

  return {
    target: url.href,
    hostname: url.hostname,
    port,
    checkedAt: new Date().toISOString(),
    alive: tcp.reachable || web.reachable,
    networkScope,
    addresses,
    dns: { resolved: addresses.length > 0, error: dnsError },
    tcp,
    http: web,
    headProbe,
    methodFallback,
    protocolHint,
    geo,
  };
}

module.exports = { isPrivateAddress, lookupGeo, probeTarget };

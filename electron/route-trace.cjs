const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const { isPrivateAddress, lookupGeo } = require("./target-probe.cjs");

const execFileAsync = promisify(execFile);
const IPV4_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

function parseLatency(line) {
  const values = [...String(line).matchAll(/<?(\d+)\s*ms/gi)].map((match) => Number(match[1]));
  if (!values.length) return { averageMs: null, samplesMs: [] };
  return {
    averageMs: Number((values.reduce((sum, value) => sum + value, 0) / values.length).toFixed(1)),
    samplesMs: values,
  };
}

function parseTracert(output) {
  return String(output || "").split(/\r?\n/).flatMap((line) => {
    const match = line.match(/^\s*(\d+)\s+(.+)$/);
    if (!match) return [];
    const hop = Number(match[1]);
    const detail = match[2];
    const ip = detail.match(IPV4_PATTERN)?.[0] || null;
    const latency = parseLatency(detail);
    return [{
      hop,
      ip,
      timeout: !ip && detail.includes("*"),
      ...latency,
      raw: detail.trim(),
    }];
  });
}

async function traceRoute(rawUrl, options = {}) {
  const url = new URL(rawUrl);
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only HTTP and HTTPS targets are supported.");
  const maxHops = Math.min(20, Math.max(1, Number(options.maxHops) || 12));
  const timeoutMs = Math.min(5000, Math.max(300, Number(options.timeoutMs) || 1200));
  const command = process.platform === "win32" ? "tracert" : "traceroute";
  const args = process.platform === "win32"
    ? ["-d", "-h", String(maxHops), "-w", String(timeoutMs), url.hostname]
    : ["-n", "-m", String(maxHops), "-w", String(Math.max(1, Math.ceil(timeoutMs / 1000))), url.hostname];
  let stdout = "";
  let stderr = "";
  try {
    const result = await execFileAsync(command, args, {
      windowsHide: true,
      timeout: maxHops * timeoutMs * 4 + 10000,
      maxBuffer: 256 * 1024,
    });
    stdout = result.stdout;
    stderr = result.stderr;
  } catch (error) {
    stdout = error.stdout || "";
    stderr = error.stderr || error.message || "";
  }
  const hops = parseTracert(stdout);
  const uniquePublicIps = [...new Set(hops.map((hop) => hop.ip).filter((ip) => ip && !isPrivateAddress(ip)))].slice(0, 12);
  const geoEntries = await Promise.all(uniquePublicIps.map(async (ip) => [ip, await lookupGeo(ip, 3500)]));
  const geoByIp = Object.fromEntries(geoEntries);
  return {
    target: url.href,
    hostname: url.hostname,
    checkedAt: new Date().toISOString(),
    maxHops,
    timeoutMs,
    hops: hops.map((hop) => ({ ...hop, geo: hop.ip ? geoByIp[hop.ip] || null : null })),
    completed: Boolean(hops.at(-1)?.ip),
    error: hops.length ? "" : String(stderr).trim() || "No traceroute hops returned.",
  };
}

module.exports = { parseTracert, traceRoute };

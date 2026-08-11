const http = require("node:http");
const https = require("node:https");

function parseNodes(text) {
  const nodes = String(text || "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line, index) => {
    const [country, city, endpoint] = line.split("|").map((part) => part?.trim());
    if (!country || !city || !endpoint) throw new Error(`節點第 ${index + 1} 行格式錯誤，請使用：國家|城市|Agent URL`);
    const url = new URL(endpoint);
    if (!["http:", "https:"].includes(url.protocol)) throw new Error(`節點 ${country}/${city} 只支援 HTTP 或 HTTPS Agent`);
    return { id: `${country}-${city}-${index}`, country, city, endpoint: url.href };
  });
  if (!nodes.length) throw new Error("請至少設定一個國家節點");
  if (nodes.length > 12) throw new Error("單次最多 12 個國家節點");
  return nodes;
}

function postJson(endpoint, payload, token, timeoutMs) {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint);
    const body = Buffer.from(JSON.stringify(payload));
    const transport = url.protocol === "https:" ? https : http;
    const request = transport.request(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": String(body.length),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    }, (response) => {
      let data = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => {
        if (data.length < 1000000) data += chunk;
      });
      response.on("end", () => {
        if (response.statusCode < 200 || response.statusCode >= 300) {
          return reject(new Error(`Agent HTTP ${response.statusCode}: ${data.slice(0, 160)}`));
        }
        try {
          resolve(JSON.parse(data));
        } catch {
          reject(new Error("Agent 回傳無效 JSON"));
        }
      });
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error("Agent timeout")));
    request.once("error", reject);
    request.end(body);
  });
}

async function runGlobalProbe(config) {
  const target = new URL(config.target);
  if (!["http:", "https:"].includes(target.protocol)) throw new Error("目標網址只支援 HTTP 或 HTTPS");
  const nodes = parseNodes(config.nodesText);
  const samples = Math.min(30, Math.max(3, Number(config.samples) || 10));
  const intervalMs = Math.min(5000, Math.max(100, Number(config.intervalMs) || 500));
  const timeoutMs = Math.min(30000, Math.max(500, Number(config.timeoutMs) || 5000));
  const agentTimeout = samples * (timeoutMs + intervalMs) + 5000;
  const results = await Promise.all(nodes.map(async (node) => {
    try {
      const result = await postJson(node.endpoint, {
        target: target.href,
        samples,
        intervalMs,
        timeoutMs,
        dnsServer: config.dnsServer || "system",
      }, config.token, agentTimeout);
      return { ...node, ok: true, ...result };
    } catch (error) {
      return { ...node, ok: false, error: error.message || String(error) };
    }
  }));
  return { target: target.href, checkedAt: new Date().toISOString(), samples, dnsServer: config.dnsServer || "system", results };
}

module.exports = { parseNodes, runGlobalProbe };

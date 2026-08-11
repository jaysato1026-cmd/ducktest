const http = require("node:http");
const https = require("node:https");

function sendWebhook(rawUrl, payload, timeoutMs = 8000) {
  const url = new URL(rawUrl);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error("Webhook 只支援 HTTP 或 HTTPS");
  const transport = url.protocol === "https:" ? https : http;
  const body = JSON.stringify(payload);
  return new Promise((resolve, reject) => {
    const request = transport.request(url, { method: "POST", headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body), "User-Agent": "DuckTest/1.13" } }, (response) => {
      response.resume();
      response.on("end", () => response.statusCode >= 200 && response.statusCode < 300 ? resolve({ ok: true, status: response.statusCode }) : reject(new Error(`Webhook HTTP ${response.statusCode}`)));
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error("Webhook timeout")));
    request.once("error", reject);
    request.end(body);
  });
}

module.exports = { sendWebhook };

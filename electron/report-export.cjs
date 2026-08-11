const escapeHtml = (value) => String(value ?? "")
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&#39;");

const labelMap = {
  loadTest: "壓力測試",
  uptimeMonitor: "存活監控",
  targetProbe: "目標偵測",
  globalProbe: "全球節點",
  securityBaseline: "資安基線",
  networkAnalysis: "Nmap／Wireshark 網路分析",
  summary: "摘要",
  latencyMs: "延遲（ms）",
  statusCodes: "HTTP 狀態碼",
  errors: "錯誤",
  configuration: "測試設定",
};

function renderValue(value, depth = 0) {
  if (value == null) return '<span class="empty">尚無資料</span>';
  if (Array.isArray(value)) {
    if (!value.length) return '<span class="empty">尚無資料</span>';
    return `<ol>${value.slice(0, 500).map((item) => `<li>${renderValue(item, depth + 1)}</li>`).join("")}</ol>`;
  }
  if (typeof value === "object") {
    return `<table>${Object.entries(value).map(([key, item]) => (
      `<tr><th>${escapeHtml(labelMap[key] || key)}</th><td>${depth > 4 ? `<pre>${escapeHtml(JSON.stringify(item, null, 2))}</pre>` : renderValue(item, depth + 1)}</td></tr>`
    )).join("")}</table>`;
  }
  if (typeof value === "boolean") return value ? "是" : "否";
  return escapeHtml(value);
}

function renderHtmlReport(report = {}) {
  const generatedAt = report.generatedAt || new Date().toISOString();
  const sections = [
    ["壓力測試", report.loadTest],
    ["存活監控", report.uptimeMonitor],
    ["目標偵測", report.targetProbe],
    ["全球節點", report.globalProbe],
    ["資安基線", report.securityBaseline],
    ["Nmap／Wireshark 網路分析", report.networkAnalysis],
    ["斷線根因分析", report.diagnosis],
    ["歷史基準線", report.history],
    ["主機資源", report.systemSamples],
    ["排程狀態", report.scheduler],
  ];
  return `<!doctype html>
<html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>鴨鴨測完整報告</title><style>
body{margin:0;background:#eef4f8;color:#173149;font:14px/1.55 "Segoe UI","Microsoft JhengHei",sans-serif}
header{padding:32px 7%;color:#fff;background:linear-gradient(135deg,#09233a,#12649a)}
header h1{margin:0 0 6px;font-size:30px}header p{margin:3px 0;color:#cde9fa}
main{max-width:1180px;margin:24px auto;padding:0 20px}.card{margin:0 0 18px;padding:22px;background:#fff;border:1px solid #d9e5ed;border-radius:12px;box-shadow:0 8px 24px #17314912}
h2{margin:0 0 14px;color:#12649a;border-bottom:2px solid #d9edf8;padding-bottom:8px}
table{width:100%;border-collapse:collapse;margin:4px 0}th,td{padding:8px 10px;border:1px solid #dce6ed;vertical-align:top;text-align:left}th{width:190px;background:#f1f7fa;color:#31566e}
ol{margin:4px 0;padding-left:22px}pre{white-space:pre-wrap;word-break:break-all}.empty{color:#8295a2}footer{text-align:center;padding:22px;color:#6c8494}
@media print{body{background:#fff}.card{box-shadow:none;break-inside:avoid}header{print-color-adjust:exact}}
</style></head><body>
<header><h1>鴨鴨測完整測試報告</h1><p>作者：王宥傑　版本：${escapeHtml(report.appVersion || "1.12.0")}</p><p>目標：${escapeHtml(report.target || "未設定")}　產生時間：${escapeHtml(new Date(generatedAt).toLocaleString("zh-TW"))}</p></header>
<main>${sections.map(([title, data]) => `<section class="card"><h2>${title}</h2>${renderValue(data)}</section>`).join("")}</main>
<footer>由鴨鴨測產生 · 王宥傑</footer></body></html>`;
}

function csvCell(value) {
  const text = typeof value === "object" ? JSON.stringify(value) : String(value ?? "");
  return "\"" + text.replaceAll("\"", "\"\"").replaceAll("\r", " ").replaceAll("\n", " ") + "\"";
}

function renderCsvReport(report = {}) {
  const rows = [["section", "field", "value"]];
  const walk = (section, value, prefix = "") => {
    if (value == null) return rows.push([section, prefix, ""]);
    if (typeof value !== "object") return rows.push([section, prefix, value]);
    if (Array.isArray(value)) return value.forEach((item, index) => walk(section, item, prefix + "[" + index + "]"));
    Object.entries(value).forEach(([key, item]) => walk(section, item, prefix ? prefix + "." + key : key));
  };
  ["loadTest", "uptimeMonitor", "targetProbe", "globalProbe", "securityBaseline", "networkAnalysis", "diagnosis", "history", "systemSamples", "scheduler"].forEach((section) => walk(section, report[section]));
  return rows.map((row) => row.map(csvCell).join(",")).join("\r\n") + "\r\n";
}

module.exports = { escapeHtml, renderHtmlReport, renderCsvReport };

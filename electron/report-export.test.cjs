const test = require("node:test");
const assert = require("node:assert/strict");
const { escapeHtml, renderHtmlReport, renderCsvReport } = require("./report-export.cjs");

test("escapes untrusted report content", () => {
  assert.equal(escapeHtml('<script>"x"</script>'), "&lt;script&gt;&quot;x&quot;&lt;/script&gt;");
});

test("renders branded complete report and every product section", () => {
  const html = renderHtmlReport({
    target: "https://example.com/?a=<b>",
    loadTest: { summary: { completed: 3 } },
    networkAnalysis: { type: "nmap-report", command: "nmap -sT example.com", plainSummary: ["檢查完成"] },
  });
  assert.match(html, /鴨鴨測完整測試報告/);
  assert.match(html, /作者：王宥傑/);
  assert.match(html, /壓力測試/);
  assert.match(html, /存活監控/);
  assert.doesNotMatch(html, /<b>/);
  assert.match(html, /nmap -sT example\.com/);
});

test("renders a flat CSV report for spreadsheet analysis", () => {
  const csv = renderCsvReport({ target: "https://example.com", loadTest: { summary: { completed: 3, failureRate: 0 } }, networkAnalysis: { type: "wireshark-report", packetCount: 20 } });
  assert.match(csv, /"section","field","value"/);
  assert.match(csv, /"loadTest","summary\.completed","3"/);
  assert.match(csv, /"networkAnalysis","packetCount","20"/);
});

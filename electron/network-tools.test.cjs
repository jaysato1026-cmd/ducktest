const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  MANAGED_IPERF3,
  configureNetworkTools,
  getManagedIperf3Path,
  calculateFileSha256,
  normalizeTarget,
  validatePortSpec,
  buildNmapArgs,
  validateExtraArgs,
  buildIperf3Args,
  createIperf3Error,
  parseIperf3Json,
  parseInterfaces,
  parseNmapXml,
  createNmapTimeoutReport,
  parseFieldLine,
  summarizeCapture,
  buildCaptureTrafficUrl,
} = require("./network-tools.cjs");

test("managed iPerf3 uses a per-user tool directory and verifies SHA-256", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ducktest-iperf-test-"));
  try {
    configureNetworkTools({ toolsDirectory: directory });
    assert.equal(getManagedIperf3Path(), path.join(directory, "iperf3", MANAGED_IPERF3.version, "iperf3.exe"));
    const fixture = path.join(directory, "fixture.bin");
    fs.writeFileSync(fixture, "ducktest", "utf8");
    assert.equal(await calculateFileSha256(fixture), "E1B64C86098CF4F1A879534F48312765D1D9AB913FBE93573F88D1140C4E9B17");
  } finally {
    configureNetworkTools({ toolsDirectory: "" });
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("validatePortSpec rejects invalid and out-of-range ports", () => {
  assert.equal(validatePortSpec("80,443,8000-8100"), "80,443,8000-8100");
  assert.throws(() => validatePortSpec("0"), /1.*65535/);
  assert.throws(() => validatePortSpec("65536"), /1.*65535/);
  assert.throws(() => validatePortSpec("9000-8000"), /起點/);
  assert.throws(() => validatePortSpec("80;whoami"), /數字、逗號與連字號/);
});

test("buildNmapArgs runs to completion by default and only limits time when explicitly selected", () => {
  const basic = buildNmapArgs({ mode: "basic", topPorts: 100, timeoutSeconds: 60 }, "example.com");
  assert.deepEqual(basic.args.slice(0, 7), ["-sT", "-Pn", "-n", "-T3", "--max-retries", "1", "--reason"]);
  assert.ok(!basic.args.includes("--host-timeout"));
  assert.equal(basic.completionMode, "complete");
  assert.equal(basic.timeoutSeconds, null);
  assert.ok(!basic.args.includes("--script"));
  const advanced = buildNmapArgs({ mode: "advanced", completionMode: "time_limit", ports: "80,443", timeoutSeconds: 600, osDetection: true }, "192.0.2.10");
  assert.ok(advanced.args.includes("default,safe"));
  assert.ok(advanced.args.includes("--traceroute"));
  assert.ok(advanced.args.includes("--osscan-limit"));
  assert.equal(advanced.timeoutSeconds, 600);
  assert.ok(advanced.args.includes("600s"));
  assert.equal(advanced.args.at(-1), "192.0.2.10");
  assert.throws(() => buildNmapArgs({ mode: "basic", completionMode: "time_limit", timeoutSeconds: 601 }, "example.com"), /10 到 600 秒/);
  assert.doesNotThrow(() => buildNmapArgs({ mode: "basic", completionMode: "complete", timeoutSeconds: 601 }, "example.com"));
});

test("custom command parameters allow useful flags and reject unsafe output or scripts", () => {
  assert.deepEqual(validateExtraArgs("nmap", "-sV --min-rate 50 --script default,safe"), ["-sV", "--min-rate", "50", "--script", "default,safe"]);
  assert.deepEqual(validateExtraArgs("wireshark", "-p -s 128"), ["-p", "-s", "128"]);
  assert.throws(() => validateExtraArgs("nmap", "-oX stolen.xml"), /不支援或不安全/);
  assert.throws(() => validateExtraArgs("nmap", "--script vuln"), /只允許/);
  assert.throws(() => validateExtraArgs("iperf3", '"unterminated'), /雙引號/);
});

test("iPerf3 command builder and parser produce a beginner-friendly report", () => {
  const built = buildIperf3Args({ role: "client", mode: "advanced", target: "server.example", direction: "download", protocol: "udp", durationSeconds: 12, parallelStreams: 2, bandwidthMbps: 50, port: 5201 });
  assert.ok(built.args.includes("-R"));
  assert.ok(built.args.includes("-u"));
  assert.ok(built.args.includes("50M"));
  assert.equal(built.args.at(1), "server.example");
  const report = parseIperf3Json(JSON.stringify({
    start: { connected: [{ local_host: "192.0.2.2", remote_host: "192.0.2.3" }] },
    intervals: [{ sum: { end: 1, bits_per_second: 50000000 } }],
    end: { sum_sent: { bits_per_second: 48000000, retransmits: 2, seconds: 10 }, sum_received: { bits_per_second: 47000000, seconds: 10 }, sum: { bits_per_second: 47000000, lost_percent: 0.5, jitter_ms: 1.2 } },
  }), { target: "server.example", mode: "advanced", protocol: "udp", direction: "download" });
  assert.equal(report.summary.measuredMbps, 47);
  assert.equal(report.summary.lossPercent, 0.5);
  assert.match(report.plainSummary.join(" "), /下載.*47 Mbps/);
});

test("iPerf3 connection failures are translated into actionable Chinese", () => {
  const error = createIperf3Error("unable to connect to server: Connection refused", { target: "192.168.1.50", port: 5201 });
  assert.equal(error.code, "IPERF3_CONNECTION_REFUSED");
  assert.match(error.message, /連線被接收端拒絕/);
  assert.match(error.message, /啟動一次性接收端/);
  assert.match(error.message, /Windows 防火牆/);
});

test("normalizeTarget accepts a URL, host name and IPv6 address without command fragments", () => {
  assert.equal(normalizeTarget("https://example.com/path?q=1"), "example.com");
  assert.equal(normalizeTarget("192.0.2.10"), "192.0.2.10");
  assert.equal(normalizeTarget("[2001:db8::1]"), "2001:db8::1");
  assert.throws(() => normalizeTarget("example.com; whoami"), /格式不正確|不允許/);
});

test("Wireshark target traffic preserves the requested web path", () => {
  assert.equal(buildCaptureTrafficUrl("https://example.com/health?q=1").href, "https://example.com/health?q=1");
  assert.equal(buildCaptureTrafficUrl("example.com").href, "https://example.com/");
  assert.equal(buildCaptureTrafficUrl("file:///etc/passwd"), null);
});

test("parseInterfaces converts TShark interface output into friendly choices", () => {
  const interfaces = parseInterfaces("1. \\Device\\NPF_{ABC} (乙太網路)\n2. \\Device\\NPF_{DEF} (Wi-Fi)\n");
  assert.deepEqual(interfaces.map(({ id, label }) => ({ id, label })), [
    { id: "1", label: "乙太網路" },
    { id: "2", label: "Wi-Fi" },
  ]);
});

test("parseNmapXml explains open ports in plain Chinese", () => {
  const xml = `<?xml version="1.0"?><nmaprun><host><status state="up" reason="syn-ack"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="nginx" version="1.24"/></port><port protocol="tcp" portid="3389"><state state="open" reason="syn-ack"/><service name="ms-wbt-server"/></port></ports><os><osmatch name="Windows Server" accuracy="96"/></os><trace><hop ttl="1" ipaddr="192.0.2.1" rtt="1.2"/></trace></host><runstats><finished elapsed="2.34"/></runstats></nmaprun>`;
  const report = parseNmapXml(xml, "192.0.2.10", "advanced", "nmap ...");
  assert.equal(report.summary.openPorts, 2);
  assert.equal(report.summary.highAttention, 1);
  assert.equal(report.hosts[0].ports[1].displayName, "Windows 遠端桌面 RDP");
  assert.match(report.plainSummary.join(" "), /不等於漏洞/);
  assert.equal(report.hosts[0].osMatches[0].accuracy, 96);
  assert.equal(report.hosts[0].hops[0].ttl, 1);
});

test("Nmap timeout becomes an incomplete report instead of a raw red error", () => {
  const report = createNmapTimeoutReport("example.com", "basic", "nmap ...", 60);
  assert.equal(report.type, "nmap-report");
  assert.equal(report.incomplete, true);
  assert.equal(report.status, "timeout");
  assert.equal(report.summary.elapsedSeconds, 60);
  assert.equal(report.summary.onlineHosts, null);
  assert.equal(report.summary.openPorts, null);
  assert.equal(report.summary.highAttention, null);
  assert.match(report.plainSummary.join(" "), /不代表目標一定離線/);
  assert.match(report.warnings.join(" "), /未完成/);
});

test("parseFieldLine and summarizeCapture produce understandable anomaly totals", () => {
  const fields = [
    "1", "1710000000.1", "192.0.2.10", "", "198.51.100.20", "", "TCP", "120", "52000", "443", "", "", "3",
    "1", "", "", "", "", "0.042", "1", "", "0", "GET", "example.com", "500", "example.com", "",
  ].join("\t");
  const packet = parseFieldLine(fields);
  assert.equal(packet.retransmission, true);
  assert.equal(packet.reset, true);
  assert.equal(packet.httpStatus, 500);
  const summary = summarizeCapture([packet], { durationSeconds: 15 });
  assert.equal(summary.anomalies.retransmissions, 1);
  assert.equal(summary.anomalies.resets, 1);
  assert.equal(summary.anomalies.httpErrors, 1);
  assert.match(summary.plainSummary.join(" "), /TCP 重傳/);
});

test("parseFieldLine does not treat TShark zero flags as TCP anomalies", () => {
  const fields = [
    "2", "1710000000.2", "192.0.2.10", "", "198.51.100.20", "", "TCP", "60", "52000", "443", "", "", "3",
    "0", "0", "0", "0", "0", "0.010", "0", "", "0", "", "", "", "", "",
  ].join("\t");
  const packet = parseFieldLine(fields);
  assert.equal(packet.retransmission, false);
  assert.equal(packet.lostSegment, false);
  assert.equal(packet.outOfOrder, false);
  assert.equal(packet.duplicateAck, false);
  assert.equal(packet.reset, false);
  const summary = summarizeCapture([packet], { durationSeconds: 15 });
  assert.equal(summary.anomalies.resets, 0);
  assert.equal(summary.anomalies.retransmissions, 0);
});

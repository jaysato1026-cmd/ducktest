const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const assert = require("node:assert/strict");
const modulePath = process.argv[2] ? path.resolve(process.argv[2]) : path.resolve(__dirname, "../electron/network-tools.cjs");
const { configureNetworkTools, getNetworkToolStatus, listCaptureInterfaces, runNmap, runWiresharkCapture, runIperf3 } = require(modulePath);

async function main() {
  configureNetworkTools({ toolsDirectory: path.join(process.env.APPDATA || os.tmpdir(), "duck-load-console", "tools") });
  const status = await getNetworkToolStatus();
  assert.equal(status.nmap.ready, true);
  assert.equal(status.wireshark.ready, true);
  assert.equal(status.iperf3.ready, true);

  const nmapProgress = [];
  const nmapReport = await runNmap({ authorized: true, target: "127.0.0.1", mode: "basic", completionMode: "time_limit", ports: "1", timeoutSeconds: 10 }, { onProgress: (item) => nmapProgress.push(item.phase) });
  assert.ok(nmapProgress.includes("preparing"));
  assert.ok(nmapProgress.includes("scanning"));
  assert.equal(nmapReport.incomplete, true);
  const nmapController = new AbortController();
  const stoppedNmap = runNmap({ authorized: true, target: "192.0.2.1", mode: "basic", completionMode: "time_limit", topPorts: 100, timeoutSeconds: 30 }, { signal: nmapController.signal });
  setTimeout(() => nmapController.abort(), 300);
  await assert.rejects(stoppedNmap, (error) => error?.code === "NMAP_STOPPED");

  const interfaces = await listCaptureInterfaces();
  const loopback = interfaces.find((item) => /loopback|npf_loopback/i.test(`${item.label} ${item.raw} ${item.description}`));
  assert.ok(loopback, "Npcap loopback interface is required");
  const wiresharkProgress = [];
  const traffic = setInterval(() => {
    const socket = net.connect({ host: "127.0.0.1", port: 9 });
    socket.on("error", () => {});
    socket.setTimeout(100, () => socket.destroy());
  }, 40);
  let capture;
  try {
    capture = await runWiresharkCapture({ authorized: true, target: "127.0.0.1", mode: "basic", interfaceId: loopback.id, durationSeconds: 5, maxPackets: 50 }, { onProgress: (item) => wiresharkProgress.push(item.phase) });
  } finally {
    clearInterval(traffic);
  }
  assert.ok(wiresharkProgress.includes("capturing"));
  assert.ok(wiresharkProgress.includes("analyzing"));
  assert.ok(capture.summary.packetCount > 0);
  fs.rmSync(capture.captureFile, { force: true });

  const port = 5218;
  const serverProgress = [];
  const clientProgress = [];
  const server = runIperf3({ authorized: true, role: "server", port, mode: "basic" }, { onProgress: (item) => serverProgress.push(item.phase) });
  await new Promise((resolve) => setTimeout(resolve, 500));
  await runIperf3({ authorized: true, role: "client", target: "127.0.0.1", port, mode: "basic", durationSeconds: 1, direction: "upload" }, { onProgress: (item) => clientProgress.push(item.phase) });
  await server;
  assert.ok(serverProgress.includes("waiting"));
  assert.ok(clientProgress.includes("testing"));
  assert.ok(clientProgress.includes("parsing"));

  const controller = new AbortController();
  const stoppedServer = runIperf3({ authorized: true, role: "server", port: 5219, mode: "basic" }, { signal: controller.signal });
  setTimeout(() => controller.abort(), 300);
  await assert.rejects(stoppedServer, (error) => error?.code === "IPERF3_STOPPED");

  console.log(JSON.stringify({ nmapProgress, nmapTimeoutReportPreserved: nmapReport.incomplete, wiresharkProgress, capturedPackets: capture.summary.packetCount, serverProgress, clientProgress, stopVerified: { nmap: true, iperf3: true } }, null, 2));
}

main().catch((error) => {
  console.error(error?.stack || error);
  process.exitCode = 1;
});

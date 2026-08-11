const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const {
  configureNetworkTools,
  getNetworkToolStatus,
  listCaptureInterfaces,
  runNmap,
  runWiresharkCapture,
} = require(process.argv[2] ? path.resolve(process.argv[2]) : path.resolve(__dirname, "../electron/network-tools.cjs"));

async function main() {
  configureNetworkTools({ toolsDirectory: path.join(process.env.APPDATA || os.tmpdir(), "duck-load-console", "tools") });
  const status = await getNetworkToolStatus();
  const interfaces = status.wireshark.installed ? await listCaptureInterfaces() : [];
  const nmap = status.nmap.ready
    ? await runNmap({ authorized: true, target: "127.0.0.1", mode: "basic", topPorts: 20, timeoutSeconds: 10 })
    : null;

  let wireshark = null;
  const loopback = interfaces.find((item) => /loopback|npf_loopback/i.test(`${item.label} ${item.raw} ${item.description}`));
  if (status.wireshark.ready && loopback) {
    const traffic = setInterval(() => {
      const socket = net.connect({ host: "127.0.0.1", port: 9 });
      socket.on("error", () => {});
      socket.setTimeout(100, () => socket.destroy());
    }, 40);
    try {
      const report = await runWiresharkCapture({ authorized: true, target: "127.0.0.1", mode: "basic", interfaceId: loopback.id, durationSeconds: 5, maxPackets: 50 });
      wireshark = { interface: loopback.label, packetCount: report.summary.packetCount, warnings: report.warnings };
      fs.rmSync(report.captureFile, { force: true });
    } finally {
      clearInterval(traffic);
    }
  }

  console.log(JSON.stringify({
    ready: { nmap: status.nmap.ready, wireshark: status.wireshark.ready, iperf3: status.iperf3.ready },
    health: { nmap: status.nmap.healthMessage, wireshark: status.wireshark.healthMessage, iperf3: status.iperf3.healthMessage },
    interfaceCount: interfaces.length,
    nmap: nmap && { status: nmap.status || "complete", openPorts: nmap.summary.openPorts, elapsedSeconds: nmap.summary.elapsedSeconds },
    wireshark: wireshark || { skipped: true, reason: loopback ? "擷取功能未通過健康檢查" : "沒有 Npcap loopback 介面" },
  }, null, 2));
}

main().catch((error) => {
  console.error(error?.stack || error);
  process.exitCode = 1;
});

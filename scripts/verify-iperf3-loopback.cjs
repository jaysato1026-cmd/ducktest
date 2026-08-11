const path = require("node:path");
const modulePath = process.argv[2]
  ? path.resolve(process.argv[2])
  : path.resolve(__dirname, "../electron/network-tools.cjs");
const { configureNetworkTools, runIperf3 } = require(modulePath);

async function main() {
  const toolsDirectory = path.join(process.env.APPDATA || "", "duck-load-console", "tools");
  configureNetworkTools({ toolsDirectory });
  const port = 5217;
  const server = runIperf3({ authorized: true, role: "server", port, mode: "basic" });
  await new Promise((resolve) => setTimeout(resolve, 600));
  const client = await runIperf3({
    authorized: true,
    role: "client",
    target: "127.0.0.1",
    port,
    mode: "basic",
    durationSeconds: 1,
    direction: "upload",
  });
  const serverReport = await server;
  console.log(JSON.stringify({
    clientMbps: client.summary.measuredMbps,
    clientConnections: client.connections.length,
    serverType: serverReport.type,
    serverRole: serverReport.role,
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const modulePath = process.argv[2]
  ? path.resolve(process.argv[2])
  : path.join(__dirname, "..", "electron", "network-tools.cjs");
const { configureNetworkTools, installNetworkTool } = require(modulePath);

async function main() {
  const toolsDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "ducktest-managed-iperf-"));
  try {
    configureNetworkTools({ toolsDirectory });
    const result = await installNetworkTool("iperf3");
    console.log(JSON.stringify({
      installed: result.installed,
      managed: result.managed,
      path: result.path,
      sha256: result.sha256,
      executableExists: fs.existsSync(result.path),
      sourceNoticeExists: fs.existsSync(path.join(path.dirname(result.path), "來源與驗證.txt")),
      message: result.message,
    }, null, 2));
  } finally {
    configureNetworkTools({ toolsDirectory: "" });
    fs.rmSync(toolsDirectory, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

const { spawn, spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const dns = require("node:dns").promises;
const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");

const MANAGED_IPERF3 = Object.freeze({
  version: "3.21",
  url: "https://github.com/ar51an/iperf3-win-builds/releases/download/3.21/iperf-3.21-win64.zip",
  sha256: "9B73B7E0E0326347B5F4AC4F6A1FC34FE60A5966E5FD172C7BFCD0E1CC93E709",
  maxDownloadBytes: 32 * 1024 * 1024,
});

let managedToolsDirectory = "";

function configureNetworkTools(options = {}) {
  managedToolsDirectory = options.toolsDirectory ? path.resolve(options.toolsDirectory) : "";
}

function getManagedIperf3Path() {
  return managedToolsDirectory
    ? path.join(managedToolsDirectory, "iperf3", MANAGED_IPERF3.version, "iperf3.exe")
    : "";
}

const WINDOWS_PATHS = {
  nmap: [
    "C:\\Program Files\\Nmap\\nmap.exe",
    "C:\\Program Files (x86)\\Nmap\\nmap.exe",
  ],
  tshark: [
    "C:\\Program Files\\Wireshark\\tshark.exe",
    "C:\\Program Files (x86)\\Wireshark\\tshark.exe",
  ],
  iperf3: [
    path.join(process.env.ProgramFiles || "C:\\Program Files", "iPerf3", "iperf3.exe"),
    path.join(process.env.ProgramFiles || "C:\\Program Files", "iperf3", "iperf3.exe"),
    path.join(process.env.LOCALAPPDATA || "", "Microsoft", "WinGet", "Links", "iperf3.exe"),
  ],
  winget: [
    path.join(process.env.LOCALAPPDATA || "", "Microsoft", "WindowsApps", "winget.exe"),
  ],
};

const TOOL_INSTALLERS = {
  nmap: {
    packageId: "Insecure.Nmap",
    officialUrl: "https://nmap.org/download.html#windows",
    displayName: "Nmap",
  },
  wireshark: {
    packageId: "WiresharkFoundation.Wireshark",
    officialUrl: "https://www.wireshark.org/download.html",
    displayName: "Wireshark、TShark 與 Npcap",
  },
  iperf3: {
    displayName: "iPerf3",
    packageId: "ar51an.iPerf3",
    officialUrl: "https://software.es.net/iperf/obtaining.html",
  },
};

const PORT_GUIDE = {
  21: ["FTP 檔案傳輸", "高", "FTP 常以明文傳送帳密；若非必要，建議停用或改用 SFTP。"],
  22: ["SSH 遠端管理", "中", "確認只允許管理來源連線，並使用金鑰及登入防護。"],
  23: ["Telnet 遠端管理", "高", "Telnet 是明文協定，建議停用並改用 SSH。"],
  25: ["SMTP 郵件傳送", "中", "郵件服務對外開放屬常見情況，仍應檢查轉寄與加密設定。"],
  53: ["DNS 網域查詢", "中", "若不是公開 DNS，應限制可查詢來源並避免開放遞迴。"],
  80: ["HTTP 網站", "低", "HTTP 未加密；登入或敏感內容建議導向 HTTPS。"],
  110: ["POP3 收信", "中", "傳統 POP3 可能未加密，建議使用 POP3S 或其他安全方式。"],
  135: ["Windows RPC", "高", "通常不應直接暴露於網際網路，建議由防火牆限制。"],
  139: ["Windows NetBIOS", "高", "通常只應存在於受控內網，避免暴露於網際網路。"],
  143: ["IMAP 收信", "中", "確認已啟用加密並限制不安全的驗證方式。"],
  443: ["HTTPS 網站", "低", "屬正常加密網站服務，仍需搭配憑證與 TLS 檢查。"],
  445: ["Windows SMB 檔案共享", "高", "不建議直接暴露於網際網路，應限制為可信內網或 VPN。"],
  1433: ["Microsoft SQL Server", "高", "資料庫通常不應直接公開，建議限制來源或僅允許內網。"],
  1521: ["Oracle Database", "高", "資料庫通常不應直接公開，建議限制來源或僅允許內網。"],
  3306: ["MySQL／MariaDB", "高", "資料庫通常不應直接公開，建議限制來源或僅允許內網。"],
  3389: ["Windows 遠端桌面 RDP", "高", "建議僅允許 VPN／可信來源，並啟用 NLA、MFA 與鎖定策略。"],
  5432: ["PostgreSQL", "高", "資料庫通常不應直接公開，建議限制來源或僅允許內網。"],
  5900: ["VNC 遠端桌面", "高", "建議僅透過 VPN 使用，並限制來源及強化驗證。"],
  6379: ["Redis", "高", "不應直接公開於網際網路，請限制網路並啟用驗證。"],
  8080: ["替代 HTTP 網站", "中", "常見於管理頁或測試服務；確認是否需要對外開放。"],
  8443: ["替代 HTTPS 網站", "中", "常見於管理頁或測試服務；確認憑證與存取限制。"],
  9200: ["Elasticsearch", "高", "搜尋資料服務不應直接公開，應限制來源並啟用驗證。"],
  27017: ["MongoDB", "高", "資料庫通常不應直接公開，建議限制來源並啟用驗證。"],
};

const XML_ENTITIES = { "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": "\"", "&apos;": "'" };
const decodeXml = (value = "") => String(value).replace(/&(amp|lt|gt|quot|apos);/g, (entity) => XML_ENTITIES[entity] || entity);
const attr = (source, name) => decodeXml(source.match(new RegExp(`${name}="([^"]*)"`))?.[1] || "");

function findExecutable(name) {
  const where = spawnSync(process.platform === "win32" ? "where.exe" : "which", [name], { encoding: "utf8", windowsHide: true });
  const fromPath = String(where.stdout || "").split(/\r?\n/).map((item) => item.trim()).find(Boolean);
  if (fromPath && fs.existsSync(fromPath)) return fromPath;
  const managedCandidates = name === "iperf3" ? [getManagedIperf3Path()].filter(Boolean) : [];
  return [...managedCandidates, ...(WINDOWS_PATHS[name] || [])].find((candidate) => fs.existsSync(candidate)) || null;
}

function runProcess(executable, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      cwd: options.cwd,
      windowsHide: true,
      shell: false,
      env: { ...process.env, LANG: "C", LC_ALL: "C", ...(options.env || {}) },
      signal: options.signal,
    });
    try { options.onSpawn?.(child); } catch { /* optional startup hook must not break the tool */ }
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    const maxBytes = options.maxBytes || 16 * 1024 * 1024;
    let timedOut = false;
    const timeoutMs = options.timeoutMs === 0 ? 0 : (options.timeoutMs || 120000);
    const timer = timeoutMs > 0 ? setTimeout(() => {
      timedOut = true;
      if (process.platform === "win32" && child.pid) {
        spawnSync("taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" });
      } else {
        child.kill("SIGKILL");
      }
    }, timeoutMs) : null;
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes <= maxBytes) stdout.push(chunk);
      try { options.onOutput?.("stdout", chunk.toString("utf8")); } catch { /* progress reporting is best effort */ }
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes <= maxBytes) stderr.push(chunk);
      try { options.onOutput?.("stderr", chunk.toString("utf8")); } catch { /* progress reporting is best effort */ }
    });
    child.once("error", (error) => {
      if (timer) clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code) => {
      if (timer) clearTimeout(timer);
      const result = {
        code: Number(code ?? -1),
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        timedOut,
      };
      if (timedOut) return reject(Object.assign(new Error("工具執行時間超過限制，已自動停止。"), { code: "TOOL_TIMEOUT", result }));
      resolve(result);
    });
  });
}

function downloadFile(url, destination, options = {}, redirectCount = 0) {
  const maxRedirects = options.maxRedirects ?? 5;
  const maxBytes = options.maxBytes ?? 32 * 1024 * 1024;
  const timeoutMs = options.timeoutMs ?? 120000;
  return new Promise((resolve, reject) => {
    if (redirectCount > maxRedirects) return reject(new Error("iPerf3 下載重新導向次數過多。"));
    const parsedUrl = new URL(url);
    const allowedHosts = new Set(["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"]);
    if (parsedUrl.protocol !== "https:" || !allowedHosts.has(parsedUrl.hostname)) {
      return reject(new Error("iPerf3 下載被導向未核准的來源，已取消安裝。"));
    }
    const request = https.get(url, {
      headers: {
        "User-Agent": "DuckTest-iPerf3-Installer/1.15.1",
        Accept: "application/octet-stream",
      },
    }, (response) => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        const nextUrl = new URL(response.headers.location, url).toString();
        return resolve(downloadFile(nextUrl, destination, options, redirectCount + 1));
      }
      if (response.statusCode !== 200) {
        response.resume();
        return reject(new Error(`iPerf3 下載失敗：伺服器回傳 HTTP ${response.statusCode || "未知"}。`));
      }
      const expectedLength = Number(response.headers["content-length"] || 0);
      if (expectedLength > maxBytes) {
        response.resume();
        return reject(new Error("iPerf3 下載檔案超過安全大小限制。"));
      }
      const output = fs.createWriteStream(destination, { flags: "wx" });
      let receivedBytes = 0;
      response.on("data", (chunk) => {
        receivedBytes += chunk.length;
        if (receivedBytes > maxBytes) request.destroy(new Error("iPerf3 下載檔案超過安全大小限制。"));
      });
      response.pipe(output);
      output.once("finish", () => output.close(() => resolve({ receivedBytes })));
      output.once("error", reject);
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error("iPerf3 下載逾時，請檢查網路後再試一次。")));
    request.once("error", reject);
  });
}

async function calculateFileSha256(filePath) {
  const hash = crypto.createHash("sha256");
  await new Promise((resolve, reject) => {
    const input = fs.createReadStream(filePath);
    input.on("data", (chunk) => hash.update(chunk));
    input.once("end", resolve);
    input.once("error", reject);
  });
  return hash.digest("hex").toUpperCase();
}

async function installManagedIperf3() {
  if (process.platform !== "win32") throw new Error("自動下載 iPerf3 目前只支援 Windows 64 位元。");
  if (!managedToolsDirectory) throw new Error("iPerf3 工具儲存位置尚未初始化。");
  const executable = getManagedIperf3Path();
  if (fs.existsSync(executable)) {
    return { installed: true, managed: true, path: executable, message: `iPerf3 ${MANAGED_IPERF3.version} 已可使用，不需要重複下載。` };
  }

  const toolRoot = path.join(managedToolsDirectory, "iperf3");
  const finalDirectory = path.dirname(executable);
  const stagingDirectory = path.join(toolRoot, `.staging-${process.pid}-${Date.now()}`);
  const archivePath = path.join(toolRoot, `.iperf3-${process.pid}-${Date.now()}.zip`);
  await fs.promises.mkdir(toolRoot, { recursive: true });
  try {
    await downloadFile(MANAGED_IPERF3.url, archivePath, { maxBytes: MANAGED_IPERF3.maxDownloadBytes });
    const actualSha256 = await calculateFileSha256(archivePath);
    if (actualSha256 !== MANAGED_IPERF3.sha256) {
      throw new Error(`iPerf3 安全驗證失敗：SHA-256 不相符，已取消安裝。實際值 ${actualSha256}`);
    }
    await fs.promises.mkdir(stagingDirectory, { recursive: true });
    const powershell = path.join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
    if (!fs.existsSync(powershell)) throw new Error("找不到 Windows PowerShell，無法解壓 iPerf3。");
    const extraction = await runProcess(powershell, [
      "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
      "Expand-Archive -LiteralPath $env:DUCKTEST_IPERF_ARCHIVE -DestinationPath $env:DUCKTEST_IPERF_DEST -Force",
    ], {
      timeoutMs: 120000,
      maxBytes: 2 * 1024 * 1024,
      env: { DUCKTEST_IPERF_ARCHIVE: archivePath, DUCKTEST_IPERF_DEST: stagingDirectory },
    });
    if (extraction.code !== 0 || !fs.existsSync(path.join(stagingDirectory, "iperf3.exe"))) {
      throw new Error(`iPerf3 解壓失敗：${extraction.stderr.trim() || extraction.stdout.trim() || `代碼 ${extraction.code}`}`);
    }
    await fs.promises.rm(finalDirectory, { recursive: true, force: true });
    await fs.promises.rename(stagingDirectory, finalDirectory);
    await fs.promises.writeFile(path.join(finalDirectory, "來源與驗證.txt"), [
      `iPerf3 Windows binary ${MANAGED_IPERF3.version}`,
      `下載來源：${MANAGED_IPERF3.url}`,
      `SHA-256：${MANAGED_IPERF3.sha256}`,
      "上游原始碼：https://github.com/esnet/iperf",
      "Windows binary 專案：https://github.com/ar51an/iperf3-win-builds",
      "請參閱上述專案的授權與聲明。",
      "",
    ].join("\r\n"), "utf8");
    const versionCheck = await runProcess(executable, ["--version"], { timeoutMs: 10000, maxBytes: 256 * 1024 });
    if (versionCheck.code !== 0) throw new Error("iPerf3 已下載，但啟動驗證失敗。");
    return {
      installed: true,
      managed: true,
      path: executable,
      sourceUrl: MANAGED_IPERF3.url,
      sha256: MANAGED_IPERF3.sha256,
      message: `iPerf3 ${MANAGED_IPERF3.version} 已自動下載並安裝到鴨鴨測的工具目錄，不需要 winget 或系統管理員權限。`,
    };
  } finally {
    await fs.promises.rm(archivePath, { force: true }).catch(() => {});
    await fs.promises.rm(stagingDirectory, { recursive: true, force: true }).catch(() => {});
  }
}

function commandText(executable, args) {
  const quote = (value) => /[\s"&|<>]/.test(String(value)) ? `"${String(value).replaceAll('"', '\\"')}"` : String(value);
  return [quote(executable), ...args.map(quote)].join(" ");
}

function tokenizeExtraArgs(input) {
  const text = String(input || "").trim();
  if (!text) return [];
  if (text.length > 500 || /[\r\n\0]/.test(text)) throw new Error("自訂參數過長或含有不允許的換行字元。");
  const tokens = [];
  let current = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (character === '"') { quoted = !quoted; continue; }
    if (/\s/.test(character) && !quoted) {
      if (current) { tokens.push(current); current = ""; }
    } else current += character;
  }
  if (quoted) throw new Error("自訂參數的雙引號沒有成對結束。");
  if (current) tokens.push(current);
  return tokens;
}

const EXTRA_ARG_RULES = {
  nmap: {
    flags: new Set(["-Pn", "-n", "--reason", "-sV", "-O", "--osscan-limit", "--traceroute", "-T0", "-T1", "-T2", "-T3", "-T4"]),
    values: new Set(["-p", "--top-ports", "--max-retries", "--host-timeout", "--min-rate", "--max-rate", "--version-intensity", "--script-timeout", "--script"]),
  },
  wireshark: {
    flags: new Set(["-n", "-p"]),
    values: new Set(["-s", "-B"]),
  },
  iperf3: {
    flags: new Set(["-R", "-u", "--get-server-output", "--timestamps"]),
    values: new Set(["-P", "-b", "-l", "-w", "-M", "--connect-timeout", "--fq-rate"]),
  },
};

function validateExtraArgs(tool, input) {
  const rules = EXTRA_ARG_RULES[tool];
  if (!rules) return [];
  const tokens = tokenizeExtraArgs(input);
  const result = [];
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (rules.flags.has(token)) { result.push(token); continue; }
    if (!rules.values.has(token)) throw new Error(`不支援或不安全的自訂參數：${token}`);
    const value = tokens[index + 1];
    if (!value || value.startsWith("-")) throw new Error(`自訂參數 ${token} 缺少設定值。`);
    if (tool === "nmap" && token === "-p") validatePortSpec(value);
    if (tool === "nmap" && token === "--script" && !["default", "safe", "default,safe", "safe,default"].includes(value)) {
      throw new Error("自訂 Nmap 腳本只允許 default 與 safe 類別。");
    }
    result.push(token, value);
    index += 1;
  }
  return result;
}

function normalizeTarget(input) {
  const value = String(input || "").trim();
  if (!value || value.length > 253) throw new Error("請輸入要檢查的網址、主機名稱或 IP 位址。");
  let hostname = value;
  try {
    const parsed = new URL(value.includes("://") ? value : `http://${value}`);
    hostname = parsed.hostname;
  } catch {
    throw new Error("目標格式不正確，請輸入網址、主機名稱或 IP 位址。");
  }
  hostname = hostname.replace(/^\[|\]$/g, "");
  if (!hostname || /[\s/@?#]/.test(hostname)) throw new Error("目標主機名稱包含不允許的字元。");
  return hostname;
}

function validatePortSpec(input) {
  const value = String(input || "").trim();
  if (!value) return "";
  if (!/^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*$/.test(value)) {
    throw new Error("自訂連接埠只可使用數字、逗號與連字號，例如 80,443,8000-8100。");
  }
  for (const part of value.split(",")) {
    const [startText, endText = startText] = part.split("-");
    const start = Number(startText);
    const end = Number(endText);
    if (start < 1 || start > 65535 || end < 1 || end > 65535 || start > end) {
      throw new Error("連接埠必須介於 1 到 65535，且範圍起點不可大於終點。");
    }
  }
  return value;
}

function buildNmapArgs(config, target) {
  const mode = config.mode === "advanced" ? "advanced" : "basic";
  const completionMode = config.completionMode === "time_limit" ? "time_limit" : "complete";
  const timeoutSeconds = completionMode === "time_limit" ? Number(config.timeoutSeconds ?? (mode === "advanced" ? 180 : 60)) : null;
  if (completionMode === "time_limit" && (!Number.isFinite(timeoutSeconds) || timeoutSeconds < 10 || timeoutSeconds > 600)) throw new Error("Nmap 單一主機最長時間必須介於 10 到 600 秒，程式不會自動改寫輸入值。");
  const topPorts = Math.max(20, Math.min(1000, Number(config.topPorts) || (mode === "advanced" ? 1000 : 100)));
  const portText = validatePortSpec(config.ports);
  const args = ["-sT", "-Pn", "-n", "-T3", "--max-retries", "1", "--reason"];
  if (portText) args.push("-p", portText);
  else args.push("--top-ports", String(topPorts));
  if (mode === "advanced") {
    args.push("-sV", "--version-light", "--script", "default,safe", "--traceroute");
    if (config.osDetection) args.push("-O", "--osscan-limit");
  }
  args.push(...validateExtraArgs("nmap", config.extraArgs));
  if (completionMode === "time_limit") args.push("--host-timeout", `${timeoutSeconds}s`);
  args.push("-oX", "-", target);
  return { args, mode, completionMode, timeoutSeconds };
}

function validateAuthorized(config, action) {
  if (!config?.authorized) throw new Error(`執行${action}前，請先勾選「已取得目標系統授權」。`);
}

async function getNetworkToolStatus() {
  const nmapPath = findExecutable("nmap");
  const tsharkPath = findExecutable("tshark");
  const iperf3Path = findExecutable("iperf3");
  const inspectVersion = async (executable, args) => {
    if (!executable) return { version: "", ready: false, error: "尚未安裝" };
    try {
      const result = await runProcess(executable, args, { timeoutMs: 10000, maxBytes: 256 * 1024 });
      const version = `${result.stdout}\n${result.stderr}`.split(/\r?\n/).find((line) => /Nmap|TShark|iperf/i.test(line))?.trim() || "已安裝";
      return result.code === 0
        ? { version, ready: true, error: "" }
        : { version, ready: false, error: `版本檢查失敗（代碼 ${result.code}）` };
    } catch (error) {
      return { version: "已安裝，但無法啟動", ready: false, error: error?.message || "無法啟動" };
    }
  };
  const nmapCheck = await inspectVersion(nmapPath, ["--version"]);
  const tsharkCheck = await inspectVersion(tsharkPath, ["--version"]);
  const iperf3Check = await inspectVersion(iperf3Path, ["--version"]);
  let captureInterfaceCount = 0;
  let captureHealth = "";
  if (tsharkCheck.ready) {
    try {
      const interfaces = await runProcess(tsharkPath, ["-D"], { timeoutMs: 12000, maxBytes: 1024 * 1024 });
      captureInterfaceCount = parseInterfaces(`${interfaces.stdout}\n${interfaces.stderr}`).length;
      if (!captureInterfaceCount) captureHealth = "TShark 可啟動，但沒有取得 Npcap 擷取介面";
    } catch (error) {
      captureHealth = `無法檢查 Npcap 擷取介面：${error?.message || "未知錯誤"}`;
    }
  }
  const result = {
    installerAvailable: Boolean(findExecutable("winget")),
    localIpv4Addresses: Object.values(os.networkInterfaces()).flat().filter((item) => item?.family === "IPv4" && !item.internal).map((item) => item.address).filter(Boolean),
    nmap: {
      installed: Boolean(nmapPath),
      ready: nmapCheck.ready,
      path: nmapPath,
      version: nmapCheck.version,
      healthMessage: nmapCheck.ready ? "執行檔與版本檢查通過" : nmapCheck.error,
      installHint: "請從 nmap.org 下載 Windows 安裝程式，安裝時保留 Npcap 選項，完成後重新開啟鴨鴨測。",
    },
    wireshark: {
      installed: Boolean(tsharkPath),
      ready: tsharkCheck.ready && captureInterfaceCount > 0,
      path: tsharkPath,
      version: tsharkCheck.version,
      interfaceCount: captureInterfaceCount,
      healthMessage: tsharkCheck.ready && captureInterfaceCount > 0 ? `已偵測 ${captureInterfaceCount} 個 Npcap 擷取介面` : captureHealth || tsharkCheck.error,
      installHint: "請安裝 Wireshark 並勾選 TShark 與 Npcap；封包擷取若失敗，請以系統管理員身分開啟鴨鴨測。",
    },
  };
  result.iperf3 = {
    installed: Boolean(iperf3Path),
    ready: iperf3Check.ready,
    path: iperf3Path,
    version: iperf3Check.version,
    healthMessage: iperf3Check.ready ? "執行檔與版本檢查通過；測速前仍需啟動接收端" : iperf3Check.error,
    installHint: "可由鴨鴨測自動下載到使用者工具目錄，不需要 winget 或系統管理員權限；測速時仍需要另一台電腦當接收端。",
  };
  return result;
}

async function installNetworkTool(tool) {
  if (tool === "iperf3") return installManagedIperf3();
  const definition = TOOL_INSTALLERS[tool];
  if (!definition) throw new Error("不支援的工具安裝要求。");
  const winget = findExecutable("winget");
  if (!winget) {
    return {
      installed: false,
      needsManualInstall: true,
      officialUrl: definition.officialUrl,
      message: `此電腦沒有 Windows 套件管理員，請從 ${definition.displayName} 官方網站完成安裝。`,
    };
  }
  const args = [
    "install", "--id", definition.packageId, "--exact", "--source", "winget", "--silent",
    "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity",
  ];
  const result = await runProcess(winget, args, { timeoutMs: 15 * 60 * 1000, maxBytes: 8 * 1024 * 1024 });
  if (result.code !== 0) {
    throw new Error(`${definition.displayName} 安裝失敗（代碼 ${result.code}）。${result.stderr.trim() || result.stdout.trim() || "請改用官方下載頁安裝。"}`);
  }
  return {
    installed: true,
    command: commandText(winget, args),
    message: `${definition.displayName} 已完成安裝。若狀態尚未更新，請重新啟動鴨鴨測。`,
  };
}

function parseNmapXml(xml, target, mode, executedCommand) {
  const hosts = [];
  for (const match of xml.matchAll(/<host\b[^>]*>([\s\S]*?)<\/host>/g)) {
    const block = match[1];
    const statusAttrs = block.match(/<status\b([^>]*)\/?\s*>/)?.[1] || "";
    const addresses = [...block.matchAll(/<address\b([^>]*)\/?\s*>/g)].map((item) => ({ address: attr(item[1], "addr"), type: attr(item[1], "addrtype") }));
    const hostnames = [...block.matchAll(/<hostname\b([^>]*)\/?\s*>/g)].map((item) => attr(item[1], "name")).filter(Boolean);
    const ports = [...block.matchAll(/<port\b([^>]*)>([\s\S]*?)<\/port>/g)].map((item) => {
      const portAttrs = item[1];
      const portBlock = item[2];
      const stateAttrs = portBlock.match(/<state\b([^>]*)\/?\s*>/)?.[1] || "";
      const serviceAttrs = portBlock.match(/<service\b([^>]*)\/?\s*>/)?.[1] || "";
      const port = Number(attr(portAttrs, "portid"));
      const guide = PORT_GUIDE[port] || [attr(serviceAttrs, "name") || "未辨識服務", "資訊", "確認此服務是否為預期用途，並限制不必要的對外存取。"];
      return {
        port,
        protocol: attr(portAttrs, "protocol") || "tcp",
        state: attr(stateAttrs, "state") || "unknown",
        reason: attr(stateAttrs, "reason") || "",
        service: attr(serviceAttrs, "name") || "unknown",
        product: attr(serviceAttrs, "product"),
        version: attr(serviceAttrs, "version"),
        tunnel: attr(serviceAttrs, "tunnel"),
        displayName: guide[0],
        attention: guide[1],
        explanation: guide[2],
      };
    });
    const osMatches = [...block.matchAll(/<osmatch\b([^>]*)>/g)].map((item) => ({ name: attr(item[1], "name"), accuracy: Number(attr(item[1], "accuracy")) || 0 })).slice(0, 5);
    const hops = [...block.matchAll(/<hop\b([^>]*)\/?\s*>/g)].map((item) => ({ ttl: Number(attr(item[1], "ttl")), ip: attr(item[1], "ipaddr"), rttMs: Number(attr(item[1], "rtt")) || null, host: attr(item[1], "host") }));
    hosts.push({ status: attr(statusAttrs, "state") || "unknown", reason: attr(statusAttrs, "reason"), addresses, hostnames, ports, osMatches, hops });
  }
  const openPorts = hosts.flatMap((host) => host.ports.filter((port) => port.state === "open"));
  const highAttention = openPorts.filter((port) => port.attention === "高");
  const plainSummary = [];
  if (!hosts.length || hosts.every((host) => host.status !== "up")) {
    plainSummary.push("沒有確認到主機回應。這不一定代表主機關機，也可能是防火牆丟棄掃描封包。可搭配存活監控與 tracert 再判斷。");
  } else if (!openPorts.length) {
    plainSummary.push("主機有回應，但本次範圍內沒有找到開放連接埠。可能是服務未啟動、被防火牆阻擋，或服務使用未掃描的連接埠。");
  } else {
    plainSummary.push(`找到 ${openPorts.length} 個可連線的服務入口。開放連接埠本身不等於漏洞，重點是確認每個服務是否真的需要對外開放。`);
  }
  if (highAttention.length) plainSummary.push(`其中 ${highAttention.length} 個屬於需要優先確認的管理、檔案共享或資料庫類服務：${highAttention.map((port) => `${port.port}/${port.protocol}`).join("、")}。`);
  else if (openPorts.length) plainSummary.push("目前未看到常見的高注意服務入口；仍需定期更新服務並限制允許連線的來源。");
  const runStatsAttrs = xml.match(/<finished\b([^>]*)\/?\s*>/)?.[1] || "";
  return {
    type: "nmap-report",
    target,
    mode,
    checkedAt: new Date().toISOString(),
    command: executedCommand,
    hosts,
    summary: {
      hostCount: hosts.length,
      onlineHosts: hosts.filter((host) => host.status === "up").length,
      openPorts: openPorts.length,
      highAttention: highAttention.length,
      elapsedSeconds: Number(attr(runStatsAttrs, "elapsed")) || null,
    },
    plainSummary,
    glossary: [
      { term: "連接埠 Port", meaning: "像建築物的門牌；不同號碼通常代表不同網路服務。" },
      { term: "Open 開放", meaning: "該入口有程式正在接聽，不代表一定有漏洞。" },
      { term: "Filtered 被過濾", meaning: "防火牆可能擋住探測，因此無法判斷入口是否開放。" },
      { term: "服務版本", meaning: "進階模式嘗試辨認軟體名稱與版本，結果可能因代理或防護設備而不完整。" },
    ],
  };
}

function createNmapTimeoutReport(target, mode, executedCommand, timeoutSeconds) {
  return {
    type: "nmap-report",
    target,
    mode,
    checkedAt: new Date().toISOString(),
    command: executedCommand,
    incomplete: true,
    status: "timeout",
    hosts: [],
    summary: { hostCount: null, onlineHosts: null, openPorts: null, highAttention: null, elapsedSeconds: timeoutSeconds },
    plainSummary: [
      `掃描已達 ${timeoutSeconds} 秒上限並安全停止；這不代表目標一定離線。`,
      "常見原因是目標或防火牆不回覆探測封包、路徑延遲較高，或掃描範圍太大。",
      "可縮小連接埠範圍後重試；若仍超時，請搭配目標偵測與 tracert 判斷。",
    ],
    warnings: [`Nmap 未在 ${timeoutSeconds} 秒內完成，本次結果標示為未完成。`],
    glossary: [
      { term: "掃描逾時", meaning: "在設定時間內沒有完成全部探測；可能是封包被過濾或目標回覆很慢，不等於主機一定離線。" },
    ],
  };
}

async function runNmap(config, options = {}) {
  validateAuthorized(config, "Nmap 掃描");
  options.onProgress?.({ phase: "preparing", progress: 8, message: "正在檢查 Nmap 與目標格式。" });
  const executable = findExecutable("nmap");
  if (!executable) throw Object.assign(new Error("找不到 Nmap。請先安裝 Nmap，完成後重新開啟鴨鴨測。"), { code: "NMAP_NOT_FOUND" });
  const target = normalizeTarget(config.target);
  const { args, mode, timeoutSeconds } = buildNmapArgs(config, target);
  const executedCommand = commandText(executable, args);
  options.onProgress?.({ phase: "scanning", progress: 18, message: timeoutSeconds ? `正在掃描 ${target}；你設定的上限是 ${timeoutSeconds} 秒。` : `正在掃描 ${target}；將執行到 Nmap 自行完成或你手動停止。`, detail: executedCommand });
  let result;
  try {
    result = await runProcess(executable, args, { timeoutMs: timeoutSeconds ? (timeoutSeconds + 3) * 1000 : 0, maxBytes: 24 * 1024 * 1024, signal: options.signal });
  } catch (error) {
    if (error?.name === "AbortError" || error?.code === "ABORT_ERR") throw Object.assign(new Error("Nmap 掃描已由使用者停止。"), { code: "NMAP_STOPPED" });
    if (error?.code === "TOOL_TIMEOUT" && timeoutSeconds) return createNmapTimeoutReport(target, mode, executedCommand, timeoutSeconds);
    throw new Error(`Nmap 無法啟動掃描：${error?.message || "未知錯誤"}`);
  }
  if (!result.stdout.includes("<nmaprun")) {
    const detail = result.stderr.trim() || result.stdout.trim() || `結束代碼 ${result.code}`;
    throw new Error(`Nmap 沒有產生可讀取的報告。請確認目標格式、防火牆與執行權限。原因：${detail}`);
  }
  options.onProgress?.({ phase: "parsing", progress: 92, message: "掃描完成，正在整理主機與連接埠結果。" });
  return { ...parseNmapXml(result.stdout, target, mode, executedCommand), warnings: result.stderr.trim() ? [result.stderr.trim()] : [] };
}

function parseInterfaces(output) {
  return String(output || "").split(/\r?\n/).map((line) => {
    const match = line.match(/^\s*(\d+)\.\s+(.+?)(?:\s+\((.*)\))?\s*$/);
    if (!match) return null;
    const raw = match[2].trim();
    const label = (match[3] || raw).trim();
    return { id: match[1], raw, label: label === raw ? `網路介面 ${match[1]}` : label, description: raw };
  }).filter(Boolean);
}

async function listCaptureInterfaces() {
  const executable = findExecutable("tshark");
  if (!executable) throw Object.assign(new Error("找不到 Wireshark 的 TShark。請重新安裝 Wireshark 並勾選 TShark 與 Npcap。"), { code: "TSHARK_NOT_FOUND" });
  try {
    const result = await runProcess(executable, ["-D"], { timeoutMs: 12000, maxBytes: 1024 * 1024 });
    const interfaces = parseInterfaces(`${result.stdout}\n${result.stderr}`);
    if (interfaces.length) return interfaces;
  } catch {
    // Some locked-down Windows builds cannot enumerate Npcap adapters through
    // dumpcap. Friendly OS interface names still work as TShark -i arguments.
  }
  const fallback = Object.entries(os.networkInterfaces()).filter(([, addresses]) => Array.isArray(addresses) && addresses.length).map(([name, addresses]) => ({
    id: name,
    raw: name,
    label: name,
    description: `${addresses.filter((item) => !item.internal).map((item) => item.address).join("、") || "僅本機介面"}（系統介面清單）`,
    fallback: true,
  }));
  if (!fallback.length) throw new Error("找不到可擷取的網路介面。請確認 Npcap 已安裝，或以系統管理員身分開啟鴨鴨測。");
  return fallback;
}

function parseFieldLine(line) {
  const values = line.split("\t");
  const [number, epoch, ipv4Source, ipv6Source, ipv4Destination, ipv6Destination, protocol, length, tcpSourcePort, tcpDestinationPort, udpSourcePort, udpDestinationPort, stream, retransmission, fastRetransmission, lostSegment, outOfOrder, duplicateAck, ackRtt, reset, dnsName, dnsRcode, httpMethod, httpHost, httpStatus, tlsServerName, icmpType] = values;
  return {
    number: Number(number) || 0,
    time: epoch ? new Date(Number(epoch) * 1000).toISOString() : "",
    source: ipv4Source || ipv6Source || "未知",
    destination: ipv4Destination || ipv6Destination || "未知",
    protocol: protocol || "其他",
    bytes: Number(length) || 0,
    sourcePort: Number(tcpSourcePort || udpSourcePort) || null,
    destinationPort: Number(tcpDestinationPort || udpDestinationPort) || null,
    stream: stream === "" ? null : Number(stream),
    retransmission: [retransmission, fastRetransmission].some((value) => String(value || "").trim() === "1"),
    lostSegment: String(lostSegment || "").trim() === "1",
    outOfOrder: String(outOfOrder || "").trim() === "1",
    duplicateAck: String(duplicateAck || "").trim() === "1",
    ackRttMs: ackRtt ? Number(ackRtt) * 1000 : null,
    reset: String(reset || "").trim() === "1",
    dnsName: dnsName || "",
    dnsRcode: dnsRcode === "" ? null : Number(dnsRcode),
    httpMethod: httpMethod || "",
    httpHost: httpHost || "",
    httpStatus: httpStatus === "" ? null : Number(httpStatus),
    tlsServerName: tlsServerName || "",
    icmpType: icmpType === "" ? null : Number(icmpType),
  };
}

function countBy(items, keyFn) {
  const counts = new Map();
  for (const item of items) {
    const key = keyFn(item);
    if (!key) continue;
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return [...counts.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);
}

function summarizeCapture(packets, metadata) {
  const totalBytes = packets.reduce((sum, packet) => sum + packet.bytes, 0);
  const protocols = countBy(packets, (packet) => packet.protocol);
  const endpoints = countBy(packets.flatMap((packet) => [packet.source, packet.destination]), (value) => value);
  const conversations = countBy(packets, (packet) => {
    const left = `${packet.source}${packet.sourcePort ? `:${packet.sourcePort}` : ""}`;
    const right = `${packet.destination}${packet.destinationPort ? `:${packet.destinationPort}` : ""}`;
    return [left, right].sort().join(" ↔ ");
  });
  const retransmissions = packets.filter((packet) => packet.retransmission).length;
  const resets = packets.filter((packet) => packet.reset).length;
  const dnsErrors = packets.filter((packet) => packet.dnsRcode != null && packet.dnsRcode !== 0).length;
  const httpErrors = packets.filter((packet) => packet.httpStatus >= 400).length;
  const outOfOrder = packets.filter((packet) => packet.outOfOrder).length;
  const duplicateAcks = packets.filter((packet) => packet.duplicateAck).length;
  const rtts = packets.map((packet) => packet.ackRttMs).filter((value) => Number.isFinite(value));
  const averageRttMs = rtts.length ? rtts.reduce((sum, value) => sum + value, 0) / rtts.length : null;
  const plainSummary = [];
  if (!packets.length) {
    plainSummary.push("擷取期間沒有看到符合條件的封包。請確認選對網卡，並在擷取期間實際操作網站或服務。");
  } else {
    plainSummary.push(`本次看到 ${packets.length} 個封包，共 ${formatBytes(totalBytes)}；最常見協定是 ${protocols[0]?.name || "未辨識"}。`);
    const retransmissionRate = retransmissions / packets.length * 100;
    plainSummary.push(retransmissions
      ? `發現 ${retransmissions} 個 TCP 重傳（約 ${retransmissionRate.toFixed(2)}%）。少量重傳可能是正常波動；比例持續升高才代表壅塞、訊號不佳或路徑丟包。`
      : "沒有發現 TCP 重傳跡象，擷取範圍內未看到明顯的傳輸丟包訊號。");
    if (resets) plainSummary.push(`看到 ${resets} 個 TCP 連線被重設（RST），可能是服務主動拒絕、程式中止連線或中間設備切斷。`);
    if (dnsErrors) plainSummary.push(`看到 ${dnsErrors} 個 DNS 錯誤回覆，可能包含網域不存在或 DNS 伺服器處理失敗。`);
    if (httpErrors) plainSummary.push(`看到 ${httpErrors} 個 HTTP 4xx/5xx 回應；4xx 多半是請求或權限問題，5xx 多半是伺服器端問題。`);
    if (!resets && !dnsErrors && !httpErrors && !retransmissions) plainSummary.push("本次沒有看到常見的重傳、重設、DNS 錯誤或 HTTP 錯誤跡象。");
  }
  return {
    packetCount: packets.length,
    totalBytes,
    protocols: protocols.slice(0, 20),
    endpoints: endpoints.slice(0, 20),
    conversations: conversations.slice(0, 30),
    anomalies: { retransmissions, resets, dnsErrors, httpErrors, outOfOrder, duplicateAcks, averageRttMs },
    plainSummary,
    ...metadata,
  };
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
}

function buildCaptureTrafficUrl(rawTarget) {
  const value = String(rawTarget || "").trim();
  if (!value) return null;
  try {
    const url = new URL(/^https?:\/\//i.test(value) ? value : `https://${normalizeTarget(value)}/`);
    if (!["http:", "https:"].includes(url.protocol)) return null;
    url.hash = "";
    return url;
  } catch {
    return null;
  }
}

function generateCaptureTraffic(rawTarget) {
  const url = buildCaptureTrafficUrl(rawTarget);
  if (!url) return Promise.resolve(false);
  return new Promise((resolve) => {
    const client = url.protocol === "http:" ? http : https;
    const request = client.get(url, {
      headers: { "User-Agent": "DuckTest-Capture-Probe/1.15.1", Accept: "*/*", Connection: "close" },
      timeout: 5000,
    }, (response) => {
      response.resume();
      response.once("end", () => resolve(true));
    });
    request.once("timeout", () => request.destroy());
    request.once("error", () => resolve(false));
  });
}

async function runWiresharkCapture(config, options = {}) {
  validateAuthorized(config, "Wireshark 封包擷取");
  options.onProgress?.({ phase: "preparing", progress: 8, message: "正在檢查 TShark、Npcap 與擷取網卡。" });
  const executable = findExecutable("tshark");
  if (!executable) throw Object.assign(new Error("找不到 Wireshark 的 TShark。請先安裝 Wireshark、TShark 與 Npcap。"), { code: "TSHARK_NOT_FOUND" });
  const target = normalizeTarget(config.target);
  const mode = config.mode === "advanced" ? "advanced" : "basic";
  const durationSeconds = Math.max(5, Math.min(120, Number(config.durationSeconds) || (mode === "advanced" ? 30 : 15)));
  const maxPackets = Math.max(50, Math.min(5000, Number(config.maxPackets) || (mode === "advanced" ? 2000 : 500)));
  const interfaceId = String(config.interfaceId || "").trim();
  if (!interfaceId || interfaceId.length > 200 || /[\r\n]/.test(interfaceId)) throw new Error("請先選擇要擷取的網路介面。");
  let addresses = [];
  try {
    options.onProgress?.({ phase: "resolving", progress: 14, message: `正在解析 ${target} 的 IP 位址。` });
    addresses = (await dns.lookup(target, { all: true })).map((item) => item.address);
  } catch {
    throw new Error(`無法解析目標 ${target}，請先確認 DNS 或改用 IP 位址。`);
  }
  const automaticFilter = addresses.map((address) => `host ${address}`).join(" or ");
  const customCaptureFilter = String(config.captureFilter || "").trim();
  if (customCaptureFilter.length > 300 || /[\r\n]/.test(customCaptureFilter)) throw new Error("擷取篩選器過長或包含換行，請重新輸入。");
  const captureFilter = mode === "advanced" && customCaptureFilter ? `(${automaticFilter}) and (${customCaptureFilter})` : automaticFilter;
  const filePath = path.join(options.tempDir || os.tmpdir(), `ducktest-${Date.now()}-${Math.random().toString(16).slice(2)}.pcapng`);
  const captureArgs = ["-i", interfaceId, "-a", `duration:${durationSeconds}`, "-c", String(maxPackets), "-f", captureFilter, ...validateExtraArgs("wireshark", config.extraArgs), "-w", filePath, "-q"];
  const captureCommand = commandText(executable, captureArgs);
  let captured;
  const trafficTimers = [];
  try {
    options.onProgress?.({ phase: "capturing", progress: 20, message: `正在擷取 ${durationSeconds} 秒封包，並主動產生目標流量。`, detail: captureCommand });
    captured = await runProcess(executable, captureArgs, {
      timeoutMs: 0,
      maxBytes: 4 * 1024 * 1024,
      signal: options.signal,
      onSpawn: () => {
        for (const delay of [800, 2500, 4500].filter((value) => value < durationSeconds * 1000)) {
          trafficTimers.push(setTimeout(() => { generateCaptureTraffic(config.target); }, delay));
        }
      },
    });
  } catch (error) {
    if (error?.name === "AbortError" || error?.code === "ABORT_ERR") throw Object.assign(new Error("Wireshark 封包擷取已由使用者停止。"), { code: "WIRESHARK_STOPPED" });
    if (error?.code === "TOOL_TIMEOUT") throw new Error(`Wireshark 封包擷取超過 ${durationSeconds + 25} 秒，已安全停止。請改選正確網卡或縮短擷取時間。`);
    throw new Error(`Wireshark 無法啟動封包擷取：${error?.message || "未知錯誤"}`);
  } finally {
    trafficTimers.forEach(clearTimeout);
  }
  const captureExists = fs.existsSync(filePath);
  const captureBytes = captureExists ? fs.statSync(filePath).size : 0;
  if (!captureExists || captureBytes < 24) {
    const detail = captured.stderr.trim() || captured.stdout.trim() || "請確認 Npcap 已安裝、已選擇正確網卡，必要時以系統管理員身分執行。";
    throw new Error(`Wireshark 沒有取得可分析的封包檔。原因：${detail}`);
  }
  const displayFilter = String(config.displayFilter || "").trim();
  if (displayFilter.length > 500 || /[\r\n]/.test(displayFilter)) throw new Error("顯示篩選器過長或包含換行，請重新輸入。");
  const fields = [
    "frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "_ws.col.Protocol", "frame.len",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.stream",
    "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission", "tcp.analysis.lost_segment", "tcp.analysis.out_of_order", "tcp.analysis.duplicate_ack", "tcp.analysis.ack_rtt", "tcp.flags.reset",
    "dns.qry.name", "dns.flags.rcode", "http.request.method", "http.host", "http.response.code", "tls.handshake.extensions_server_name", "icmp.type",
  ];
  const analyzeArgs = ["-r", filePath, "-n"];
  if (displayFilter) analyzeArgs.push("-Y", displayFilter);
  analyzeArgs.push("-T", "fields", "-E", "separator=\t", "-E", "occurrence=f");
  for (const field of fields) analyzeArgs.push("-e", field);
  const analyzeCommand = commandText(executable, analyzeArgs);
  let analyzed;
  try {
    options.onProgress?.({ phase: "analyzing", progress: 78, message: `已取得 ${formatBytes(captureBytes)}，正在分析封包與異常訊號。`, detail: analyzeCommand });
    analyzed = await runProcess(executable, analyzeArgs, { timeoutMs: 0, maxBytes: 32 * 1024 * 1024, signal: options.signal });
  } catch (error) {
    if (error?.name === "AbortError" || error?.code === "ABORT_ERR") throw Object.assign(new Error("Wireshark 封包分析已由使用者停止。"), { code: "WIRESHARK_STOPPED" });
    if (error?.code === "TOOL_TIMEOUT") throw new Error("Wireshark 已完成擷取，但分析封包超過 60 秒。請降低封包上限後重試；原始封包仍保留在暫存目錄。");
    throw new Error(`Wireshark 無法分析封包：${error?.message || "未知錯誤"}`);
  }
  if (analyzed.code !== 0 && !analyzed.stdout.trim()) {
    throw new Error(`封包已擷取，但分析失敗：${analyzed.stderr.trim() || "未知錯誤"}`);
  }
  const packets = analyzed.stdout.split(/\r?\n/).filter(Boolean).map(parseFieldLine);
  const summary = summarizeCapture(packets, { durationSeconds, captureFilter, displayFilter, resolvedAddresses: addresses });
  const warnings = [];
  const meaningfulToolLines = (text) => String(text || "")
    .replace(/Capturing on\s+['\"].*?['\"]\s*/gi, "")
    .replace(/\d+\s+packets captured\s*/gi, "")
    .split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const captureErrors = meaningfulToolLines(captured.stderr);
  if (captured.code !== 0 && captureErrors.length) warnings.push(`TShark 擷取結束代碼 ${captured.code}：${captureErrors.join("；")}`);
  const analyzeErrors = meaningfulToolLines(analyzed.stderr);
  if (analyzeErrors.length) warnings.push(analyzeErrors.join("；"));
  return {
    type: "wireshark-report",
    target,
    mode,
    checkedAt: new Date().toISOString(),
    captureCommand,
    analyzeCommand,
    captureFile: filePath,
    summary,
    packets: packets.slice(0, mode === "advanced" ? 1000 : 200),
    dnsQueries: countBy(packets, (packet) => packet.dnsName).slice(0, 30),
    tlsHosts: countBy(packets, (packet) => packet.tlsServerName).slice(0, 30),
    httpTransactions: packets.filter((packet) => packet.httpMethod || packet.httpStatus).slice(0, 100),
    warnings,
    glossary: [
      { term: "封包 Packet", meaning: "網路傳輸切成的小段資料，像物流中的一個個包裹。" },
      { term: "TCP 重傳", meaning: "資料沒有如期被確認，因此再次傳送；持續偏高才可能表示丟包或壅塞。" },
      { term: "RST 重設", meaning: "某一端立即終止連線，可能是服務拒絕、程式關閉或防火牆介入。" },
      { term: "DNS", meaning: "把網域名稱翻譯成 IP 位址的查詢。" },
      { term: "往返延遲 RTT", meaning: "封包送出到收到確認所需時間，越低通常代表互動越快。" },
    ],
  };
}

function buildIperf3Args(config) {
  const role = config.role === "server" ? "server" : "client";
  const mode = config.mode === "advanced" ? "advanced" : "basic";
  const port = Number(config.port) || 5201;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("iPerf3 連接埠必須介於 1 到 65535。");
  if (role === "server") return { args: ["-s", "-1", "-J", "-p", String(port)], role, mode, port, timeoutSeconds: 600 };
  const target = normalizeTarget(config.target);
  const durationSeconds = Math.max(1, Math.min(60, Number(config.durationSeconds) || 10));
  const omitSeconds = mode === "advanced" ? Math.max(0, Math.min(10, Number(config.omitSeconds) || 0)) : 0;
  const streams = mode === "advanced" ? Math.max(1, Math.min(16, Number(config.parallelStreams) || 1)) : 1;
  const protocol = mode === "advanced" && config.protocol === "udp" ? "udp" : "tcp";
  const args = ["-c", target, "-J", "-p", String(port), "-t", String(durationSeconds), "--connect-timeout", "5000"];
  if (config.direction === "download") args.push("-R");
  if (streams > 1) args.push("-P", String(streams));
  if (omitSeconds > 0) args.push("-O", String(omitSeconds));
  if (protocol === "udp") {
    const bandwidthMbps = Math.max(1, Math.min(10000, Number(config.bandwidthMbps) || 100));
    args.push("-u", "-b", `${bandwidthMbps}M`);
  }
  args.push(...validateExtraArgs("iperf3", config.extraArgs));
  return { args, role, mode, protocol, target, port, durationSeconds, timeoutSeconds: durationSeconds + omitSeconds + 30 };
}

function createIperf3Error(message, metadata = {}) {
  const raw = String(message || "").trim();
  const text = raw.toLowerCase();
  const endpoint = metadata.target ? `${metadata.target}:${metadata.port || 5201}` : `連接埠 ${metadata.port || 5201}`;
  let code = "IPERF3_FAILED";
  let friendly = "iPerf3 測試未完成。請確認兩台電腦的角色、IP 與連接埠設定後再試一次。";
  if (/connection refused|actively refused|server may have stopped/.test(text)) {
    code = "IPERF3_CONNECTION_REFUSED";
    friendly = `連線被接收端拒絕（${endpoint}）。請先在另一台電腦開啟鴨鴨測，選「接收端｜等待另一台測試一次」並按「啟動一次性接收端」；再確認兩台都是連接埠 ${metadata.port || 5201}，以及接收端的 Windows 防火牆允許 iPerf3。`;
  } else if (/timed out|timeout|unable to connect/.test(text)) {
    code = "IPERF3_CONNECTION_TIMEOUT";
    friendly = `接收端沒有回應（${endpoint}）。請確認接收端 IP 正確、兩台電腦能互相連線，並檢查路由器或防火牆是否封鎖連接埠 ${metadata.port || 5201}。`;
  } else if (/no route to host|network is unreachable|host is unreachable/.test(text)) {
    code = "IPERF3_NO_ROUTE";
    friendly = `找不到前往接收端的網路路徑（${endpoint}）。請確認兩台位於相同區域網路或 VPN，且 IP 位址沒有填錯。`;
  } else if (/address already in use|bind failed/.test(text)) {
    code = "IPERF3_PORT_IN_USE";
    friendly = `連接埠 ${metadata.port || 5201} 已被其他程式占用。可能已有 iPerf3 接收端在執行；請先停止舊程序，或讓兩台電腦改用同一個其他連接埠。`;
  } else if (/permission denied|access is denied/.test(text)) {
    code = "IPERF3_PERMISSION_DENIED";
    friendly = `Windows 不允許 iPerf3 使用${endpoint}。請允許防火牆存取，必要時以系統管理員身分執行接收端。`;
  } else if (/server is busy|another test is in progress/.test(text)) {
    code = "IPERF3_SERVER_BUSY";
    friendly = "接收端正在進行另一個 iPerf3 測試。請等待該測試結束後再試一次。";
  }
  return Object.assign(new Error(friendly), { code, rawMessage: raw });
}

function parseIperf3Json(text, metadata = {}) {
  let data;
  try { data = JSON.parse(String(text || "").trim()); } catch { throw createIperf3Error(text, metadata); }
  if (data.error) throw createIperf3Error(data.error, metadata);
  const end = data.end || {};
  const sent = end.sum_sent || end.sum || {};
  const received = end.sum_received || end.sum || {};
  const udp = end.sum || received || sent;
  const toMbps = (value) => Number.isFinite(Number(value)) ? Number((Number(value) / 1_000_000).toFixed(2)) : null;
  const uploadMbps = toMbps(sent.bits_per_second);
  const downloadMbps = toMbps(received.bits_per_second);
  const measuredMbps = metadata.direction === "download" ? downloadMbps : uploadMbps;
  const retransmits = Number(sent.retransmits) || 0;
  const lossPercent = Number.isFinite(Number(udp.lost_percent)) ? Number(Number(udp.lost_percent).toFixed(3)) : null;
  const jitterMs = Number.isFinite(Number(udp.jitter_ms)) ? Number(Number(udp.jitter_ms).toFixed(3)) : null;
  const plainSummary = [];
  plainSummary.push(`這次${metadata.direction === "download" ? "下載" : "上傳"}方向的實測速度約為 ${measuredMbps ?? 0} Mbps。這是兩台 iPerf3 電腦之間的網路能力，不等同電信方案標示速度。`);
  if (metadata.protocol === "udp") {
    plainSummary.push(lossPercent > 1 ? `封包遺失率 ${lossPercent}% 偏高，語音、視訊或即時控制可能卡頓。` : `封包遺失率 ${lossPercent ?? 0}% 尚在低檔，UDP 傳輸相對穩定。`);
    plainSummary.push(`抖動約 ${jitterMs ?? 0} ms；數字越小，聲音與影像到達時間越整齊。`);
  } else {
    plainSummary.push(retransmits ? `TCP 發生 ${retransmits} 次重傳，代表部分資料需要再送一次；可再檢查 Wi-Fi 訊號、網路壅塞或線材。` : "本次沒有觀察到 TCP 重傳，傳輸過程相對乾淨。" );
  }
  return {
    type: "iperf3-report",
    checkedAt: new Date().toISOString(),
    target: metadata.target || data.start?.connecting_to?.host || "本機接收端",
    mode: metadata.mode || "basic",
    role: metadata.role || "client",
    protocol: metadata.protocol || (data.start?.test_start?.protocol || "TCP").toLowerCase(),
    direction: metadata.direction || "upload",
    summary: { measuredMbps, uploadMbps, downloadMbps, retransmits, lossPercent, jitterMs, seconds: Number(sent.seconds || received.seconds) || null },
    cpu: end.cpu_utilization_percent || null,
    connections: data.start?.connected || [],
    intervals: Array.isArray(data.intervals) ? data.intervals.slice(0, 120).map((item) => ({
      seconds: Number(item.sum?.end) || 0,
      mbps: toMbps(item.sum?.bits_per_second),
      retransmits: Number(item.sum?.retransmits) || 0,
    })) : [],
    plainSummary,
    glossary: [
      { term: "Mbps", meaning: "每秒可傳送多少百萬位元；數字越大，傳輸容量通常越高。" },
      { term: "TCP 重傳", meaning: "資料沒有順利抵達而再送一次；過多時通常代表干擾、壅塞或線路品質問題。" },
      { term: "UDP 遺失率", meaning: "送出的封包有多少比例沒有抵達；即時語音與視訊特別在意這個數字。" },
      { term: "抖動 Jitter", meaning: "封包抵達時間忽快忽慢的程度；越低通常越適合通話、直播與遠端操作。" },
    ],
  };
}

async function runIperf3(config, options = {}) {
  validateAuthorized(config, "iPerf3 網路效能測試");
  options.onProgress?.({ phase: "preparing", progress: 8, message: "正在檢查 iPerf3 與連線參數。" });
  const executable = findExecutable("iperf3");
  if (!executable) throw Object.assign(new Error("此電腦尚未安裝 iPerf3，請先安裝後再重新執行。"), { code: "IPERF3_NOT_FOUND" });
  const built = buildIperf3Args(config);
  const command = commandText(executable, built.args);
  options.onProgress?.({
    phase: built.role === "server" ? "waiting" : "testing",
    progress: built.role === "server" ? 18 : 22,
    message: built.role === "server" ? `接收端已啟動，正在等待測試端連入 Port ${built.port}。` : `正在連線到 ${built.target}:${built.port} 並測量 ${built.direction === "download" ? "下載" : "上傳"}速度。`,
    detail: command,
  });
  let result;
  try {
    result = await runProcess(executable, built.args, { timeoutMs: 0, maxBytes: 24 * 1024 * 1024, signal: options.signal });
  } catch (error) {
    if (error?.name === "AbortError" || error?.code === "ABORT_ERR") {
      throw Object.assign(new Error("iPerf3 測試已由使用者停止。"), { code: "IPERF3_STOPPED" });
    }
    if (error?.code === "TOOL_TIMEOUT") {
      throw Object.assign(new Error(`iPerf3 測試超過 ${built.timeoutSeconds} 秒，已安全停止。請確認接收端仍在執行，或縮短測試時間。`), { code: "IPERF3_TIMEOUT" });
    }
    throw createIperf3Error(error?.message || error, built);
  }
  let report;
  try {
    options.onProgress?.({ phase: "parsing", progress: 92, message: "傳輸測試完成，正在計算頻寬、重傳與遺失率。" });
    report = parseIperf3Json(result.stdout, { ...built, direction: config.direction === "download" ? "download" : "upload" });
  } catch (error) {
    if (error?.code && error.code !== "IPERF3_FAILED") throw error;
    throw createIperf3Error(`${result.stdout}\n${result.stderr}\n${error?.message || ""}`, built);
  }
  return { ...report, command, warnings: result.stderr.trim() ? [result.stderr.trim()] : [] };
}

module.exports = {
  MANAGED_IPERF3,
  configureNetworkTools,
  getManagedIperf3Path,
  calculateFileSha256,
  normalizeTarget,
  validatePortSpec,
  buildNmapArgs,
  tokenizeExtraArgs,
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
  getNetworkToolStatus,
  listCaptureInterfaces,
  runNmap,
  runWiresharkCapture,
  runIperf3,
  installNetworkTool,
};

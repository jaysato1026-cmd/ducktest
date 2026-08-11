const { app, BrowserWindow, ipcMain, dialog, powerSaveBlocker, shell } = require("electron");
const path = require("node:path");
const fs = require("node:fs");
const https = require("node:https");
const http = require("node:http");
const os = require("node:os");
const { probeTarget } = require("./target-probe.cjs");
const { traceRoute } = require("./route-trace.cjs");
const { runGlobalProbe } = require("./global-probe.cjs");
const { runGlobalping } = require("./globalping.cjs");
const { runUptimeMonitor } = require("./uptime-monitor.cjs");
const { renderHtmlReport, renderCsvReport } = require("./report-export.cjs");
const { runScenario } = require("./scenario-runner.cjs");
const { diagnoseTarget, diagnoseMonitor, diagnoseDisconnectEvent } = require("./outage-diagnosis.cjs");
const { createHistoryStore, compareRuns } = require("./history-store.cjs");
const { createSystemMonitor } = require("./system-monitor.cjs");
const { sendWebhook } = require("./webhook-alert.cjs");
const {
  getNetworkToolStatus,
  listCaptureInterfaces,
  runNmap,
  runWiresharkCapture,
  runIperf3,
  installNetworkTool,
  configureNetworkTools,
} = require("./network-tools.cjs");

// Electron/Chromium hardware acceleration can trigger a Windows GPU-driver
// access violation while the final BrowserWindow is being destroyed.
app.disableHardwareAcceleration();
app.commandLine.appendSwitch("disable-gpu");
app.commandLine.appendSwitch("disable-gpu-compositing");

const smokeMode = process.argv.includes("--smoke-test");
const smokeLogPath = path.join(os.tmpdir(), "ducktest-smoke.log");
const smokeLog = (message) => {
  if (!smokeMode) return;
  fs.appendFileSync(smokeLogPath, `${new Date().toISOString()} ${message}\n`, "utf8");
};
process.on("uncaughtException", (error) => {
  smokeLog(`uncaughtException ${error?.stack || error}`);
  app.exit(70);
});
process.on("unhandledRejection", (error) => {
  smokeLog(`unhandledRejection ${error?.stack || error}`);
  app.exit(71);
});
smokeLog(`main-loaded electron=${process.versions.electron} chrome=${process.versions.chrome}`);

let mainWindow;
let currentRun = null;
let currentMonitor = null;
let currentSchedule = null;
const currentNetworkControllers = new Map();
let currentManagedIperfInstall = null;
let historyStore;
const systemSample = createSystemMonitor();

async function loggedOperation(category, action, target, operation) {
  historyStore?.log({ category, action: `${action}:start`, target, message: "開始執行。" });
  try {
    const result = await operation();
    historyStore?.log({ category, action: `${action}:success`, target, message: "執行完成。", detail: { type: result?.type, summary: result?.summary } });
    return result;
  } catch (error) {
    historyStore?.log({ level: "ERROR", category, action: `${action}:error`, target, message: error?.message || "執行失敗。", detail: { code: error?.code || "" } });
    throw error;
  }
}

function emitNetworkProgress(event, tool, config, payload) {
  if (!event?.sender || event.sender.isDestroyed()) return;
  event.sender.send("network-tools:progress", {
    tool,
    runId: String(config?.runId || ""),
    at: new Date().toISOString(),
    ...payload,
  });
}

async function runNetworkToolOperation(event, tool, config, action, operation) {
  if (currentNetworkControllers.has(tool)) throw new Error(`${tool === "nmap" ? "Nmap" : tool === "wireshark" ? "Wireshark" : "iPerf3"} 已有一個測試正在執行。`);
  const controller = new AbortController();
  currentNetworkControllers.set(tool, { controller, runId: String(config?.runId || "") });
  emitNetworkProgress(event, tool, config, { phase: "starting", progress: 3, message: "已收到執行要求，正在啟動工具。" });
  try {
    const result = await loggedOperation(tool, action, config?.target || "本機接收端", () => operation({
      signal: controller.signal,
      onProgress: (progress) => emitNetworkProgress(event, tool, config, progress),
    }));
    emitNetworkProgress(event, tool, config, { phase: "completed", progress: 100, message: result?.incomplete ? "測試已停止在時間上限，已保留可用診斷資訊。" : "測試完成，報告已產生。" });
    return result;
  } catch (error) {
    emitNetworkProgress(event, tool, config, { phase: error?.code?.endsWith("_STOPPED") ? "stopped" : "error", progress: 100, message: error?.message || "工具執行失敗。" });
    throw error;
  } finally {
    const current = currentNetworkControllers.get(tool);
    if (current?.controller === controller) currentNetworkControllers.delete(tool);
  }
}

function createWindow() {
  smokeLog("create-window");
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1080,
    minHeight: 760,
    backgroundColor: "#071420",
    title: "鴨鴨測",
    icon: path.join(__dirname, "..", "assets", "icon.ico"),
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  if (!app.isPackaged && process.env.VITE_DEV_SERVER_URL) {
    mainWindow.loadURL(process.env.VITE_DEV_SERVER_URL);
  } else if (!app.isPackaged) {
    mainWindow.loadURL("http://127.0.0.1:5173");
  } else {
    mainWindow.loadFile(path.join(__dirname, "..", "dist", "index.html"));
  }
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  if (smokeMode) mainWindow.webContents.on("did-fail-load", (_event, errorCode, errorDescription, validatedURL) => smokeLog(`did-fail-load ${errorCode} ${errorDescription} ${validatedURL}`));
  mainWindow.webContents.on("will-navigate", (event, targetUrl) => {
    const allowed = app.isPackaged
      ? targetUrl.startsWith("file:")
      : /^http:\/\/127\.0\.0\.1:(5173|4173)\//.test(targetUrl);
    if (!allowed) event.preventDefault();
  });
  if (smokeMode) {
    mainWindow.webContents.once("did-finish-load", () => {
      smokeLog("did-finish-load");
      // Exercise the same close path as the window's X button.
      setTimeout(() => mainWindow?.close(), 2500);
    });
  }
}

app.whenReady().then(() => {
  smokeLog("app-ready");
  configureNetworkTools({ toolsDirectory: path.join(app.getPath("userData"), "tools") });
  historyStore = createHistoryStore(app.getPath("userData"));
  historyStore.log({ category: "system", action: "app:start", message: `鴨鴨測 v${app.getVersion()} 已啟動。` });
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  smokeLog("window-all-closed");
  if (currentRun) currentRun.stopRequested = true;
  if (currentMonitor) currentMonitor.cancelled = true;
  currentNetworkControllers.forEach(({ controller }) => controller.abort());
  if (currentSchedule) {
    clearInterval(currentSchedule.timer);
    currentSchedule = null;
  }
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => {
  if (historyStore) {
    historyStore.close();
    historyStore = null;
  }
});

function percentile(values, p) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)];
}

function minMax(values) {
  if (!values.length) return { min: 0, max: 0 };
  let min = values[0];
  let max = values[0];
  for (let index = 1; index < values.length; index += 1) {
    if (values[index] < min) min = values[index];
    if (values[index] > max) max = values[index];
  }
  return { min, max };
}

function validateConfig(config) {
  if (!config?.authorized) throw new Error("請先確認已取得目標系統的測試授權");
  const url = new URL(config.url);
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("目標網址只支援 HTTP 或 HTTPS");
  const concurrency = Number(config.concurrency);
  const duration = Number(config.duration);
  const mode = config.mode === "spike" ? "spike" : "ramp";
  const ramp = mode === "spike" ? 0 : Number(config.ramp);
  const timeout = Number(config.timeout);
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 500) throw new Error("最大併發必須為 1–500");
  if (!Number.isFinite(duration) || duration < 1 || duration > 3600) throw new Error("測試時間必須為 1–3600 秒");
  if (!Number.isFinite(ramp) || ramp < 0 || ramp > duration) throw new Error("漸增時間不可大於測試時間");
  if (!Number.isInteger(timeout) || timeout < 100 || timeout > 120000) throw new Error("逾時必須為 100–120000 毫秒");
  const method = String(config.method || "GET").toUpperCase();
  if (!["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"].includes(method)) throw new Error("不支援此請求方法");
  let headers = {};
  if (config.headers?.trim()) {
    try {
      headers = JSON.parse(config.headers);
    } catch {
      throw new Error("Headers 必須是有效的 JSON 物件");
    }
    if (!headers || Array.isArray(headers) || typeof headers !== "object") throw new Error("Headers 必須是 JSON 物件");
  }
  const generatePayload = Boolean(config.generatePayload) && !["GET", "HEAD"].includes(method);
  const payloadBytes = Number(config.payloadBytes);
  if (generatePayload && (!Number.isInteger(payloadBytes) || payloadBytes < 1 || payloadBytes > 10485760)) {
    throw new Error("自動 Payload 大小必須是 1–10,485,760 bytes");
  }
  const body = generatePayload ? Buffer.alloc(payloadBytes, 0x41) : (config.body || "");
  if (generatePayload && !Object.keys(headers).some((name) => name.toLowerCase() === "content-length")) {
    headers["Content-Length"] = String(payloadBytes);
  }
  return {
    url: url.href,
    concurrency,
    duration,
    ramp,
    timeout,
    method,
    mode,
    headers,
    body,
    generatePayload,
    payloadBytes: Buffer.byteLength(body),
    ignoreTlsErrors: Boolean(config.ignoreTlsErrors),
  };
}

function requestIgnoringTls(config, signal) {
  return new Promise((resolve, reject) => {
    const request = https.request(config.url, {
      method: config.method,
      headers: config.headers,
      rejectUnauthorized: false,
      signal,
    }, (response) => {
      let bytes = 0;
      response.on("data", (chunk) => { bytes += chunk.length; });
      response.on("end", () => resolve({
        status: response.statusCode || 0,
        statusText: response.statusMessage || "",
        bytes,
      }));
    });
    request.on("error", reject);
    if (!["GET", "HEAD"].includes(config.method) && config.body) request.write(config.body);
    request.end();
  });
}

ipcMain.handle("load-test:start", async (_event, rawConfig) => {
  if (currentRun) throw new Error("已有測試正在執行");
  const config = validateConfig(rawConfig);
  const run = {
    stopRequested: false,
    controllers: new Set(),
    latencies: [],
    recentLatencies: [],
    latencyMin: Number.POSITIVE_INFINITY,
    latencyMax: 0,
    statuses: {},
    errors: {},
    completed: 0,
    bytes: 0,
    startedAt: Date.now(),
    active: 0,
    samples: [],
    logs: [],
  };
  currentRun = run;
  const endAt = run.startedAt + config.duration * 1000;

  const log = (level, message, status = "") => {
    run.logs.unshift({ time: new Date().toLocaleTimeString("zh-TW", { hour12: false }), level, status, message });
    run.logs = run.logs.slice(0, 80);
  };
  const recordLatency = (latency) => {
    run.latencyMin = Math.min(run.latencyMin, latency);
    run.latencyMax = Math.max(run.latencyMax, latency);
    run.recentLatencies.push(latency);
    if (run.recentLatencies.length > 4000) run.recentLatencies.splice(0, 2000);
    const seen = run.completed + 1;
    if (run.latencies.length < 100000) {
      run.latencies.push(latency);
    } else {
      const replacement = Math.floor(Math.random() * seen);
      if (replacement < run.latencies.length) run.latencies[replacement] = latency;
    }
  };
  log("INFO", `開始測試 ${config.method} ${config.url}`);

  const requestOnce = async () => {
    const controller = new AbortController();
    run.controllers.add(controller);
    run.active += 1;
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, config.timeout);
    const started = performance.now();
    try {
      let result;
      if (config.ignoreTlsErrors && config.url.startsWith("https:")) {
        result = await requestIgnoringTls(config, controller.signal);
      } else {
        const response = await fetch(config.url, {
          method: config.method,
          headers: config.headers,
          body: ["GET", "HEAD"].includes(config.method) ? undefined : config.body,
          signal: controller.signal,
          redirect: "follow",
        });
        const buffer = await response.arrayBuffer();
        result = { status: response.status, statusText: response.statusText, bytes: buffer.byteLength };
      }
      run.bytes += result.bytes;
      run.statuses[result.status] = (run.statuses[result.status] || 0) + 1;
      if (result.status >= 400) log("ERROR", result.statusText || "HTTP 錯誤", result.status);
    } catch (error) {
      if (!run.stopRequested) {
        const code = timedOut ? "timeout" : (error.cause?.code || error.code || error.name || "unknown");
        run.errors[code] = (run.errors[code] || 0) + 1;
        log("ERROR", code);
      }
    } finally {
      clearTimeout(timer);
      run.controllers.delete(controller);
      recordLatency(performance.now() - started);
      run.completed += 1;
      run.active -= 1;
    }
  };

  const worker = async (index) => {
    let delay = config.ramp === 0 ? 0 : (index / config.concurrency) * config.ramp * 1000;
    while (delay > 0 && !run.stopRequested) {
      const slice = Math.min(100, delay);
      await new Promise((resolve) => setTimeout(resolve, slice));
      delay -= slice;
    }
    while (!run.stopRequested && Date.now() < endAt) await requestOnce();
  };

  let previousCompleted = 0;
  let previousBytes = 0;
  const progressTimer = setInterval(() => {
    const now = Date.now();
    const elapsed = (now - run.startedAt) / 1000;
    const rps = (run.completed - previousCompleted) * 2;
    const bytesPerSecond = (run.bytes - previousBytes) * 2;
    previousCompleted = run.completed;
    previousBytes = run.bytes;
    const failures = Object.values(run.errors).reduce((a, b) => a + b, 0) +
      Object.entries(run.statuses).filter(([code]) => Number(code) >= 400).reduce((sum, [, count]) => sum + count, 0);
    const sample = {
      elapsed: Number(elapsed.toFixed(1)),
      rps,
      p50: Number(percentile(run.recentLatencies.slice(-2000), 50).toFixed(1)),
      p95: Number(percentile(run.recentLatencies.slice(-2000), 95).toFixed(1)),
      p99: Number(percentile(run.recentLatencies.slice(-2000), 99).toFixed(1)),
      completed: run.completed,
      active: run.active,
      responseBytes: run.bytes,
      bytesPerSecond,
      averageResponseBytes: Math.round(run.bytes / Math.max(1, run.completed)),
      failureRate: Number(((failures / Math.max(1, run.completed)) * 100).toFixed(2)),
      statuses: run.statuses,
      errors: run.errors,
      logs: run.logs.slice(0, 12),
    };
    run.samples.push(sample);
    mainWindow?.webContents.send("load-test:progress", sample);
  }, 500);

  try {
    await Promise.all(Array.from({ length: config.concurrency }, (_, index) => worker(index)));
  } finally {
    clearInterval(progressTimer);
  }

  const elapsedSeconds = (Date.now() - run.startedAt) / 1000;
  const latencyRange = run.completed
    ? { min: run.latencyMin, max: run.latencyMax }
    : minMax([]);
  const failures = Object.values(run.errors).reduce((a, b) => a + b, 0) +
    Object.entries(run.statuses).filter(([code]) => Number(code) >= 400).reduce((sum, [, count]) => sum + count, 0);
  const result = {
    target: config.url,
    method: config.method,
    stopped: run.stopRequested,
    configuration: {
      concurrency: config.concurrency,
      mode: config.mode,
      duration: config.duration,
      ramp: config.ramp,
      timeout: config.timeout,
      ignoreTlsErrors: config.ignoreTlsErrors,
      headerNames: Object.keys(config.headers),
      generatedPayload: config.generatePayload,
      bodyBytes: config.payloadBytes,
    },
    generatedAt: new Date().toISOString(),
    summary: {
      elapsedSeconds: Number(elapsedSeconds.toFixed(2)),
      completed: run.completed,
      requestsPerSecond: Number((run.completed / Math.max(0.001, elapsedSeconds)).toFixed(2)),
      failureRate: Number(((failures / Math.max(1, run.completed)) * 100).toFixed(2)),
      responseBytes: run.bytes,
      averageResponseBytes: Math.round(run.bytes / Math.max(1, run.completed)),
    },
    latencyMs: {
      min: Number(latencyRange.min.toFixed(2)),
      p50: Number(percentile(run.latencies, 50).toFixed(2)),
      p95: Number(percentile(run.latencies, 95).toFixed(2)),
      p99: Number(percentile(run.latencies, 99).toFixed(2)),
      max: Number(latencyRange.max.toFixed(2)),
    },
    statusCodes: run.statuses,
    errors: run.errors,
    samples: run.samples,
  };
  currentRun = null;
  return result;
});

ipcMain.handle("load-test:stop", async () => {
  if (!currentRun) return false;
  currentRun.stopRequested = true;
  for (const controller of currentRun.controllers) controller.abort();
  return true;
});

ipcMain.handle("load-test:save-report", async (_event, payload) => {
  const report = payload?.report ?? payload;
  const format = ["html", "csv"].includes(payload?.format) ? payload.format : "json";
  const isComplete = report?.type === "ducktest-complete-report";
  const choice = await dialog.showSaveDialog(mainWindow, {
    title: isComplete ? "匯出鴨鴨測完整報告" : "匯出測試報告",
    defaultPath: `鴨鴨測-${new Date().toISOString().replaceAll(":", "-").slice(0, 19)}.${format}`,
    filters: format === "html"
      ? [{ name: "HTML 報告", extensions: ["html"] }]
      : format === "csv"
        ? [{ name: "CSV 表格", extensions: ["csv"] }]
        : [{ name: "JSON 原始資料", extensions: ["json"] }],
  });
  if (choice.canceled || !choice.filePath) return null;
  const content = format === "html" ? renderHtmlReport(report) : format === "csv" ? renderCsvReport(report) : JSON.stringify(report, null, 2);
  fs.writeFileSync(choice.filePath, content, "utf8");
  return choice.filePath;
});

ipcMain.handle("outage:diagnose", async (_event, payload) => {
  if (payload?.type === "uptime-monitor") return diagnoseMonitor(payload);
  if (payload?.type === "disconnect-event") return diagnoseDisconnectEvent(payload);
  return diagnoseTarget(payload);
});
ipcMain.handle("scenario:run", async (_event, config) => runScenario(config));

ipcMain.handle("history:list", async (_event, limit) => historyStore?.list(limit) || []);
ipcMain.handle("history:save", async (_event, record) => historyStore?.save(record) || null);
ipcMain.handle("history:get", async (_event, id) => historyStore?.get(id) || null);
ipcMain.handle("history:clear", async () => historyStore?.clear() || false);
ipcMain.handle("history:compare", async (_event, payload) => {
  const left = historyStore?.get(payload?.leftId);
  const right = historyStore?.get(payload?.rightId);
  if (!left || !right) throw new Error("找不到要比較的歷史紀錄");
  return compareRuns(left, right);
});
ipcMain.handle("logs:list", async (_event, options) => historyStore?.logs(options || {}) || []);
ipcMain.handle("logs:clear", async () => historyStore?.clearLogs() || false);
ipcMain.handle("logs:database-info", async () => historyStore?.databaseInfo() || null);
ipcMain.handle("logs:export", async (_event, options) => {
  const logs = historyStore?.logs({ ...(options || {}), limit: 1000 }) || [];
  const choice = await dialog.showSaveDialog(mainWindow, {
    title: "匯出系統活動紀錄",
    defaultPath: `鴨鴨測-活動紀錄-${new Date().toISOString().replaceAll(":", "-").slice(0, 19)}.csv`,
    filters: [{ name: "CSV 試算表", extensions: ["csv"] }],
  });
  if (choice.canceled || !choice.filePath) return null;
  const csvCell = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
  const rows = [["時間", "等級", "分類", "動作", "目標", "訊息"], ...logs.map((item) => [item.createdAt, item.level, item.category, item.action, item.target, item.message])];
  fs.writeFileSync(choice.filePath, `\uFEFF${rows.map((row) => row.map(csvCell).join(",")).join("\r\n")}\r\n`, "utf8");
  return choice.filePath;
});

ipcMain.handle("system:sample", async () => systemSample());
ipcMain.handle("alert:webhook", async (_event, payload) => sendWebhook(payload?.url, payload?.payload));

ipcMain.handle("schedule:start", async (_event, config) => {
  if (currentSchedule) throw new Error("已有排程監控正在執行");
  if (!config?.authorized) throw new Error("排程監控需要先確認測試授權");
  const intervalMs = Math.max(10000, Math.min(86400000, Number(config.intervalMs) || 300000));
  const schedule = { cancelled: false, running: false, runs: 0, last: null, config };
  const execute = async () => {
    if (schedule.cancelled || schedule.running) return;
    schedule.running = true;
    try {
      const result = await probeTarget(config.url, config.timeoutMs, { method: config.method || "GET", headers: config.headers, body: config.body });
      schedule.runs += 1;
      const diagnosis = diagnoseTarget(result);
      schedule.last = { ...result, diagnosis, scheduleRun: schedule.runs };
      historyStore?.save({ type: "scheduled-probe", target: result.target, summary: { status: result.alive ? "online" : "offline", httpStatus: result.http?.status }, result, diagnosis });
      mainWindow?.webContents.send("schedule:progress", schedule.last);
      if (config.webhookUrl && (!result.alive || !result.http?.reachable || result.http.status >= 500)) {
        await sendWebhook(config.webhookUrl, { source: "鴨鴨測", event: "website-outage", target: result.target, diagnosis: diagnoseTarget(result), result });
      }
    } catch (error) {
      schedule.last = { error: error.message, checkedAt: new Date().toISOString() };
      mainWindow?.webContents.send("schedule:progress", schedule.last);
    } finally { schedule.running = false; }
  };
  currentSchedule = { ...schedule, timer: setInterval(execute, intervalMs) };
  await execute();
  return { started: true, intervalMs };
});
ipcMain.handle("schedule:stop", async () => {
  if (!currentSchedule) return false;
  currentSchedule.cancelled = true;
  clearInterval(currentSchedule.timer);
  currentSchedule = null;
  return true;
});
ipcMain.handle("schedule:status", async () => currentSchedule ? { running: true, runs: currentSchedule.runs, last: currentSchedule.last, intervalMs: currentSchedule.config.intervalMs } : { running: false });

ipcMain.handle("uptime-monitor:start", async (_event, config) => {
  if (currentMonitor) throw new Error("已有存活監控正在執行");
  const monitor = { cancelled: false, blockerId: null, historyId: `uptime-live-${Date.now()}` };
  currentMonitor = monitor;
  try {
    monitor.blockerId = powerSaveBlocker.start("prevent-app-suspension");
    const result = await runUptimeMonitor(config, {
      isCancelled: () => monitor.cancelled,
      onProgress: (progress) => {
        if (!mainWindow?.isDestroyed()) mainWindow.webContents.send("uptime-monitor:progress", progress);
      },
      onCheckpoint: (checkpoint) => {
        try {
          historyStore?.save({
            id: monitor.historyId,
            type: "uptime-monitor",
            target: checkpoint.target,
            summary: { status: "running", availability: checkpoint.summary?.availability, failed: checkpoint.summary?.failed },
            result: checkpoint,
            checkpoint: true,
          });
        } catch (error) {
          historyStore?.log({ level: "ERROR", category: "uptime-monitor", action: "checkpoint:error", target: checkpoint.target, message: error?.message || "監控 checkpoint 寫入失敗。" });
        }
      },
    });
    return { ...result, historyId: monitor.historyId };
  } finally {
    if (monitor.blockerId != null && powerSaveBlocker.isStarted(monitor.blockerId)) {
      powerSaveBlocker.stop(monitor.blockerId);
    }
    if (currentMonitor === monitor) currentMonitor = null;
  }
});

ipcMain.handle("uptime-monitor:stop", async () => {
  if (!currentMonitor) return false;
  currentMonitor.cancelled = true;
  return true;
});

ipcMain.handle("target-probe:run", async (_event, config) => {
  if (!config?.authorized) throw new Error("請先確認已取得目標系統的偵測授權");
  let headers = {};
  if (config.headers?.trim()) {
    try {
      headers = JSON.parse(config.headers);
    } catch {
      throw new Error("Headers 必須是有效的 JSON 物件");
    }
  }
  return probeTarget(config.url, config.timeout, {
    method: config.method,
    headers,
    body: config.body,
  });
});

ipcMain.handle("route-trace:run", async (_event, config) => {
  if (!config?.authorized) throw new Error("Authorization is required before tracing a network route.");
  return traceRoute(config.url, { maxHops: config.maxHops, timeoutMs: config.timeoutMs });
});

ipcMain.handle("global-probe:run", async (_event, config) => {
  if (!config?.authorized) throw new Error("請先確認已取得目標系統與遠端節點的測試授權");
  return runGlobalProbe(config);
});

ipcMain.handle("globalping:run", async (_event, config) => {
  if (!config?.authorized) throw new Error("請先確認已取得公開目標的測試授權");
  return runGlobalping(config);
});

ipcMain.handle("network-tools:status", async () => getNetworkToolStatus());

ipcMain.handle("network-tools:ensure-iperf3", async () => {
  if (currentManagedIperfInstall) return currentManagedIperfInstall;
  const status = await getNetworkToolStatus();
  if (status.iperf3?.installed) return { installed: true, alreadyInstalled: true, path: status.iperf3.path, message: "iPerf3 已安裝，可以直接使用。" };
  if (currentManagedIperfInstall) return currentManagedIperfInstall;
  currentManagedIperfInstall = (async () => {
    historyStore?.log({ category: "installer", action: "install:iperf3:auto-start", message: "偵測到缺少 iPerf3，開始背景自動下載。" });
    try {
      const result = await installNetworkTool("iperf3");
      historyStore?.log({ category: "installer", action: "install:iperf3:auto-success", message: result.message, detail: { path: result.path, sourceUrl: result.sourceUrl, sha256: result.sha256 } });
      return result;
    } catch (error) {
      historyStore?.log({ level: "ERROR", category: "installer", action: "install:iperf3:auto-error", message: error?.message || "iPerf3 自動下載失敗。" });
      throw error;
    } finally {
      currentManagedIperfInstall = null;
    }
  })();
  return currentManagedIperfInstall;
});

ipcMain.handle("network-tools:interfaces", async () => listCaptureInterfaces());

ipcMain.handle("network-tools:nmap", async (event, config) => runNetworkToolOperation(event, "nmap", config, "scan", (options) => runNmap(config, options)));

ipcMain.handle("network-tools:wireshark", async (event, config) => runNetworkToolOperation(event, "wireshark", config, "capture", (options) => runWiresharkCapture(config, { ...options, tempDir: app.getPath("temp") })));

ipcMain.handle("network-tools:iperf3", async (event, config) => runNetworkToolOperation(event, "iperf3", config, config?.role === "server" ? "server" : "client", (options) => runIperf3(config, options)));
ipcMain.handle("network-tools:iperf3-stop", async () => {
  const current = currentNetworkControllers.get("iperf3");
  if (!current) return false;
  current.controller.abort();
  return true;
});
ipcMain.handle("network-tools:stop", async (_event, tool) => {
  const current = currentNetworkControllers.get(String(tool || ""));
  if (!current) return false;
  current.controller.abort();
  return true;
});

ipcMain.handle("network-tools:install", async (_event, tool) => {
  const displayName = tool === "nmap" ? "Nmap" : tool === "wireshark" ? "Wireshark、TShark 與 Npcap" : tool === "iperf3" ? "iPerf3" : "";
  if (!displayName) throw new Error("不支援的工具安裝要求。");
  const confirmation = await dialog.showMessageBox(mainWindow, {
    type: "question",
    title: `安裝 ${displayName}`,
    message: tool === "iperf3" ? "是否要自動下載 iPerf3？" : `是否要安裝 ${displayName}？`,
    detail: tool === "iperf3"
      ? "鴨鴨測會下載已鎖定版本，核對 SHA-256 後解壓到目前使用者的工具目錄。免安裝版不需要 winget 或系統管理員權限。"
      : "將使用 Windows 套件管理員從官方發行來源下載。過程需要網路，Windows 可能要求系統管理員權限。",
    buttons: ["取消", tool === "iperf3" ? "自動下載安裝" : "開始安裝"],
    defaultId: 1,
    cancelId: 0,
    noLink: true,
  });
  if (confirmation.response !== 1) return { cancelled: true };
  historyStore?.log({ category: "installer", action: `install:${tool}:start`, message: `開始安裝 ${displayName}。` });
  try {
    const result = await installNetworkTool(tool);
    historyStore?.log({ category: "installer", action: `install:${tool}:success`, message: result.message || `${displayName} 安裝流程完成。`, detail: { installed: result.installed, manual: result.needsManualInstall, managed: result.managed, path: result.path, sourceUrl: result.sourceUrl, sha256: result.sha256 } });
    if (result.needsManualInstall && result.officialUrl) await shell.openExternal(result.officialUrl);
    return result;
  } catch (error) {
    historyStore?.log({ level: "ERROR", category: "installer", action: `install:${tool}:error`, message: error?.message || `${displayName} 安裝失敗。` });
    throw error;
  }
});

ipcMain.handle("network-tools:save-capture", async (_event, sourcePath) => {
  const resolvedSource = path.resolve(String(sourcePath || ""));
  const tempRoot = `${path.resolve(app.getPath("temp"))}${path.sep}`.toLowerCase();
  if (!resolvedSource.toLowerCase().startsWith(tempRoot) || !/^ducktest-[\w-]+\.pcapng$/i.test(path.basename(resolvedSource)) || !fs.existsSync(resolvedSource)) {
    throw new Error("找不到可匯出的封包擷取檔案。");
  }
  const choice = await dialog.showSaveDialog(mainWindow, {
    title: "儲存 Wireshark 封包檔",
    defaultPath: `鴨鴨測-封包-${new Date().toISOString().replaceAll(":", "-").slice(0, 19)}.pcapng`,
    filters: [{ name: "Wireshark 封包檔", extensions: ["pcapng"] }],
  });
  if (choice.canceled || !choice.filePath) return null;
  fs.copyFileSync(resolvedSource, choice.filePath);
  return choice.filePath;
});

function inspectEndpoint(targetUrl, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const url = new URL(targetUrl);
    const transport = url.protocol === "https:" ? https : http;
    const request = transport.request(url, {
      method: "GET",
      headers: { "User-Agent": "YAT-Security-Baseline/1.4" },
      rejectUnauthorized: false,
    }, (response) => {
      const socket = response.socket;
      const certificate = url.protocol === "https:" ? socket.getPeerCertificate() : null;
      const result = {
        status: response.statusCode || 0,
        headers: response.headers,
        tlsAuthorized: url.protocol === "https:" ? socket.authorized : null,
        tlsError: url.protocol === "https:" ? socket.authorizationError : null,
        tlsProtocol: url.protocol === "https:" ? socket.getProtocol() : null,
        certificate: certificate && Object.keys(certificate).length ? {
          subject: certificate.subject?.CN || "",
          issuer: certificate.issuer?.CN || "",
          validFrom: certificate.valid_from,
          validTo: certificate.valid_to,
        } : null,
      };
      response.resume();
      response.on("end", () => resolve(result));
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error("timeout")));
    request.on("error", reject);
    request.end();
  });
}

ipcMain.handle("security-check:run", async (_event, config) => {
  if (!config?.authorized) throw new Error("請先確認已取得目標系統的測試授權");
  const url = new URL(config.url);
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("目標網址只支援 HTTP 或 HTTPS");
  const response = await inspectEndpoint(url.href);
  const findings = [];
  const add = (name, status, detail) => findings.push({ name, status, detail });

  add("HTTPS 傳輸", url.protocol === "https:" ? "pass" : "fail",
    url.protocol === "https:" ? "使用 HTTPS" : "仍使用明文 HTTP");
  if (url.protocol === "https:") {
    add("TLS 憑證驗證", response.tlsAuthorized ? "pass" : "fail",
      response.tlsAuthorized ? "憑證鏈與主機名稱有效" : String(response.tlsError || "憑證無法驗證"));
    add("TLS 協定", ["TLSv1.2", "TLSv1.3"].includes(response.tlsProtocol) ? "pass" : "warn",
      response.tlsProtocol || "無法判定");
    if (response.certificate?.validTo) {
      const remainingDays = Math.floor((Date.parse(response.certificate.validTo) - Date.now()) / 86400000);
      add("憑證有效期限", remainingDays >= 30 ? "pass" : remainingDays >= 0 ? "warn" : "fail",
        remainingDays >= 0 ? `剩餘 ${remainingDays} 天` : `已過期 ${Math.abs(remainingDays)} 天`);
    }
  }

  const headers = response.headers;
  const headerChecks = [
    ["Strict-Transport-Security", "strict-transport-security", url.protocol === "https:"],
    ["Content-Security-Policy", "content-security-policy", true],
    ["X-Content-Type-Options", "x-content-type-options", true],
    ["X-Frame-Options", "x-frame-options", true],
    ["Referrer-Policy", "referrer-policy", true],
    ["Permissions-Policy", "permissions-policy", true],
  ];
  for (const [label, key, applicable] of headerChecks) {
    if (!applicable) continue;
    add(label, headers[key] ? "pass" : "warn", headers[key] ? String(headers[key]) : "未設定");
  }

  const cookies = Array.isArray(headers["set-cookie"]) ? headers["set-cookie"] : [];
  if (cookies.length) {
    const secure = cookies.every((cookie) => /;\s*secure\b/i.test(cookie));
    const httpOnly = cookies.every((cookie) => /;\s*httponly\b/i.test(cookie));
    const sameSite = cookies.every((cookie) => /;\s*samesite=/i.test(cookie));
    add("Cookie Secure", secure ? "pass" : "warn", secure ? "全部具備 Secure" : "部分 Cookie 缺少 Secure");
    add("Cookie HttpOnly", httpOnly ? "pass" : "warn", httpOnly ? "全部具備 HttpOnly" : "部分 Cookie 缺少 HttpOnly");
    add("Cookie SameSite", sameSite ? "pass" : "warn", sameSite ? "全部具備 SameSite" : "部分 Cookie 缺少 SameSite");
  } else {
    add("Cookie 屬性", "pass", "此回應未設定 Cookie");
  }

  const disclosures = [headers.server && `Server: ${headers.server}`, headers["x-powered-by"] && `X-Powered-By: ${headers["x-powered-by"]}`].filter(Boolean);
  add("伺服器資訊揭露", disclosures.length ? "warn" : "pass", disclosures.length ? disclosures.join("；") : "未發現常見版本揭露標頭");

  const weights = { pass: 1, warn: 0.5, fail: 0 };
  const score = Math.round(findings.reduce((sum, finding) => sum + weights[finding.status], 0) / findings.length * 100);
  return {
    target: url.href,
    checkedAt: new Date().toISOString(),
    httpStatus: response.status,
    tlsProtocol: response.tlsProtocol,
    certificate: response.certificate,
    score,
    findings,
  };
});

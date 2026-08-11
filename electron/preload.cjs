const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("loadTest", {
  start: (config) => ipcRenderer.invoke("load-test:start", config),
  stop: () => ipcRenderer.invoke("load-test:stop"),
  saveReport: (report, format = "json") => ipcRenderer.invoke("load-test:save-report", { report, format }),
  diagnose: (payload) => ipcRenderer.invoke("outage:diagnose", payload),
  runScenario: (config) => ipcRenderer.invoke("scenario:run", config),
  historyList: (limit) => ipcRenderer.invoke("history:list", limit),
  historySave: (record) => ipcRenderer.invoke("history:save", record),
  historyGet: (id) => ipcRenderer.invoke("history:get", id),
  historyClear: () => ipcRenderer.invoke("history:clear"),
  historyCompare: (payload) => ipcRenderer.invoke("history:compare", payload),
  systemSample: () => ipcRenderer.invoke("system:sample"),
  alertWebhook: (payload) => ipcRenderer.invoke("alert:webhook", payload),
  scheduleStart: (config) => ipcRenderer.invoke("schedule:start", config),
  scheduleStop: () => ipcRenderer.invoke("schedule:stop"),
  scheduleStatus: () => ipcRenderer.invoke("schedule:status"),
  securityCheck: (config) => ipcRenderer.invoke("security-check:run", config),
  targetProbe: (config) => ipcRenderer.invoke("target-probe:run", config),
  traceRoute: (config) => ipcRenderer.invoke("route-trace:run", config),
  globalProbe: (config) => ipcRenderer.invoke("global-probe:run", config),
  globalping: (config) => ipcRenderer.invoke("globalping:run", config),
  uptimeStart: (config) => ipcRenderer.invoke("uptime-monitor:start", config),
  uptimeStop: () => ipcRenderer.invoke("uptime-monitor:stop"),
  networkToolsStatus: () => ipcRenderer.invoke("network-tools:status"),
  ensureIperf3: () => ipcRenderer.invoke("network-tools:ensure-iperf3"),
  networkInterfaces: () => ipcRenderer.invoke("network-tools:interfaces"),
  runNmap: (config) => ipcRenderer.invoke("network-tools:nmap", config),
  runWireshark: (config) => ipcRenderer.invoke("network-tools:wireshark", config),
  runIperf3: (config) => ipcRenderer.invoke("network-tools:iperf3", config),
  stopIperf3: () => ipcRenderer.invoke("network-tools:iperf3-stop"),
  stopNetworkTool: (tool) => ipcRenderer.invoke("network-tools:stop", tool),
  installNetworkTool: (tool) => ipcRenderer.invoke("network-tools:install", tool),
  saveCapture: (sourcePath) => ipcRenderer.invoke("network-tools:save-capture", sourcePath),
  logsList: (options) => ipcRenderer.invoke("logs:list", options),
  logsClear: () => ipcRenderer.invoke("logs:clear"),
  logsDatabaseInfo: () => ipcRenderer.invoke("logs:database-info"),
  logsExport: (options) => ipcRenderer.invoke("logs:export", options),
  onProgress: (callback) => {
    const listener = (_event, data) => callback(data);
    ipcRenderer.on("load-test:progress", listener);
    return () => ipcRenderer.removeListener("load-test:progress", listener);
  },
  onUptimeProgress: (callback) => {
    const listener = (_event, data) => callback(data);
    ipcRenderer.on("uptime-monitor:progress", listener);
    return () => ipcRenderer.removeListener("uptime-monitor:progress", listener);
  },
  onScheduleProgress: (callback) => {
    const listener = (_event, data) => callback(data);
    ipcRenderer.on("schedule:progress", listener);
    return () => ipcRenderer.removeListener("schedule:progress", listener);
  },
  onNetworkProgress: (callback) => {
    const listener = (_event, data) => callback(data);
    ipcRenderer.on("network-tools:progress", listener);
    return () => ipcRenderer.removeListener("network-tools:progress", listener);
  },
});

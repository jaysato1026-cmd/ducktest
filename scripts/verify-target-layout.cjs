const { app, BrowserWindow } = require("electron");
const fs = require("node:fs");
const path = require("node:path");

app.disableHardwareAcceleration();
app.commandLine.appendSwitch("disable-gpu");

const projectRoot = path.join(__dirname, "..");
const viewportWidth = Math.max(1080, Number(process.argv[2] || 1560));
const cssFile = fs.readdirSync(path.join(projectRoot, "dist", "assets"))
  .find((name) => /^index-.*\.css$/.test(name));
const css = fs.readFileSync(path.join(projectRoot, "dist", "assets", cssFile), "utf8");
const outputPath = path.join(projectRoot, "outputs", `target-probe-layout-1.12.6-${viewportWidth}px.png`);
const diagnosisOutputPath = path.join(projectRoot, "outputs", `target-probe-layout-1.12.6-${viewportWidth}px-diagnosis.png`);

const html = `<!doctype html>
<html lang="zh-Hant">
<head><meta charset="UTF-8"><style>${css}</style></head>
<body>
  <section class="dashboard probe-dashboard" style="height:875px;width:100vw">
    <div class="summary-bar">
      <div><h2>目標偵測</h2><p>解析名稱、測試服務連線，並判斷網路位置與 HTTP/TLS 狀態。</p></div>
      <div class="probe-state alive"><i></i>機器存活</div>
    </div>
    <div class="probe-cards">
      <article><span>DNS / IP</span><strong>已解析</strong><small>127.0.0.1</small></article>
      <article><span>TCP 連線</span><strong class="good">可連線</strong><small>1.73 ms · Port 17891</small></article>
      <article><span>HTTP 服務</span><strong class="good">200</strong><small>17.45 ms · HTTPD</small></article>
      <article><span>網路範圍</span><strong>私有</strong><small>localhost</small></article>
    </div>
    <div class="probe-grid">
      <section class="panel probe-detail">
        <div class="panel-head"><h3>服務健康狀態</h3><span>2026/7/20 下午2:53:13</span></div>
        <div class="probe-rows">
          <div><span>目標</span><strong>http://127.0.0.1:17891/</strong></div>
          <div><span>機器存活</span><strong class="good">是</strong></div>
          <div><span>TCP</span><strong>Port 17891 可連線</strong></div>
          <div><span>HTTP</span><strong>HTTP 200</strong></div>
          <div><span>TLS</span><strong>未使用 TLS</strong></div>
        </div>
      </section>
      <section class="panel geo-detail">
        <div class="panel-head"><h3>Geo 與網路資訊</h3><span>IP 推估位置</span></div>
        <div class="geo-content">
          <div class="geo-pin">◎</div>
          <div><span>位置</span><strong>私有網路</strong></div>
          <div><span>ISP</span><strong>本機測試服務</strong></div>
          <div><span>組織</span><strong>Loopback</strong></div>
          <div><span>時區</span><strong>Asia/Taipei</strong></div>
          <small>私有 IP 不會送往外部 Geo 服務。</small>
        </div>
      </section>
    </div>
    <section class="panel outage-diagnosis online">
      <div class="panel-head"><h3>為什麼斷線？</h3><span>分層證據分析</span></div>
      <h4>目前沒有偵測到斷線原因</h4>
      <div class="cause-list"></div>
      <div class="evidence-row">
        <span><b>目標</b><strong>http://127.0.0.1:17891/</strong></span>
        <span><b>DNS</b><strong>1 個位址</strong></span>
        <span><b>TCP</b><strong>1.73 ms</strong></span>
        <span><b>HTTP</b><strong>HTTP 200 · 17.45 ms</strong></span>
        <span><b>IP 範圍</b><strong>private</strong></span>
      </div>
    </section>
    <section class="panel route-trace-panel">
      <div class="panel-head">
        <div><h3>斷線路徑分析（tracert）</h3><span>從此電腦追蹤至目標，每跳帶入 Geo 與營運商資料</span></div>
        <button>追蹤網路路徑</button>
      </div>
      <div class="empty-state">先完成目標偵測，再按「追蹤網路路徑」。</div>
    </section>
  </section>
</body>
</html>`;

app.whenReady().then(async () => {
  const window = new BrowserWindow({
    show: false,
    width: viewportWidth,
    height: 875,
    webPreferences: { contextIsolation: true, nodeIntegration: false },
  });
  await window.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`);

  const layout = await window.webContents.executeJavaScript(`(() => {
    const rect = (selector) => {
      const value = document.querySelector(selector).getBoundingClientRect();
      return { top: value.top, bottom: value.bottom, height: value.height };
    };
    const diagnosis = rect(".outage-diagnosis");
    const evidence = rect(".evidence-row");
    const route = rect(".route-trace-panel");
    return {
      diagnosis,
      evidence,
      route,
      evidenceClipped: evidence.bottom > diagnosis.bottom + 0.5,
      routeOverlap: diagnosis.bottom > route.top + 0.5,
      evidenceRows: Math.round(evidence.height / 61),
      gap: route.top - diagnosis.bottom,
    };
  })()`);

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, (await window.webContents.capturePage()).toPNG());
  await window.webContents.executeJavaScript(`document.querySelector(".probe-dashboard").scrollTop = document.querySelector(".probe-dashboard").scrollHeight`);
  await new Promise((resolve) => setTimeout(resolve, 100));
  fs.writeFileSync(diagnosisOutputPath, (await window.webContents.capturePage()).toPNG());
  console.log(JSON.stringify({ viewportWidth, outputPath, diagnosisOutputPath, ...layout }));
  app.exit(layout.evidenceClipped || layout.routeOverlap ? 1 : 0);
});

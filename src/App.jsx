import { useEffect, useMemo, useRef, useState } from "react";
import { buildDiagnosis, buildNextRunConfig, normalizeAutoTune } from "./diagnostics.mjs";
import { runAutomaticSequence } from "./auto-runner.mjs";
import { TEST_TEMPLATES, getTemplate } from "./templates.mjs";
import NetworkToolsPanel from "./NetworkToolsPanel.jsx";
import { buildNetworkToolRequest, readableRemoteError } from "./network-request.mjs";
import { applyNetworkResult, createEmptyNetworkResultStates, hydrateNetworkResultStates } from "./network-results.mjs";

const APP_VERSION = "1.15.1";

const createEmptyNetworkRuns = () => Object.fromEntries(["nmap", "wireshark", "iperf3"].map((tool) => [tool, {
  running: false,
  runId: "",
  phase: "idle",
  progress: 0,
  message: "尚未開始測試。",
  detail: "",
  startedAt: 0,
  elapsedSeconds: 0,
  logs: [],
}]));

const initialConfig = {
  url: "https://example.com/",
  method: "GET",
  mode: "ramp",
  concurrency: 10,
  duration: 10,
  ramp: 3,
  timeout: 5000,
  headers: "{\n  \"Accept\": \"application/json\"\n}",
  body: "",
  generatePayload: false,
  payloadBytes: 1024,
  ignoreTlsErrors: false,
  authorized: false,
};

const formatNumber = (value) => new Intl.NumberFormat("zh-TW").format(Number(value) || 0);
const formatBytes = (value) => {
  const bytes = Number(value) || 0;
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
};
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const formatDuration = (seconds) => {
  const value = Math.max(0, Number(seconds) || 0);
  const hours = Math.floor(value / 3600);
  const minutes = Math.floor((value % 3600) / 60);
  const secs = Math.floor(value % 60);
  return [hours ? `${hours}時` : "", minutes ? `${minutes}分` : "", `${secs}秒`].filter(Boolean).join(" ");
};

function ThresholdInput({ label, value, unit, onChange }) {
  return (
    <label className="threshold-input">
      <span>{label}</span>
      <div>
        <input type="number" min="0" value={value} onChange={(event) => onChange(event.target.value)} />
        <em>{unit}</em>
      </div>
    </label>
  );
}

function MetricCard({ label, value, unit, targetLabel, passed, accent = "green" }) {
  return (
    <section className={`metric-card ${passed === true ? "pass" : passed === false ? "fail" : ""}`}>
      <span className="metric-label">{label}</span>
      <strong className={`metric-value ${accent}`}>{value}<small>{unit}</small></strong>
      <span className="metric-actual">實際值</span>
      <span className="metric-target">{targetLabel}</span>
      {passed !== undefined && <span className={`metric-badge ${passed ? "pass" : "fail"}`}>{passed ? "✓ 通過" : "× 未通過"}</span>}
    </section>
  );
}

function LineChart({ samples, maxP95 }) {
  const width = 900;
  const height = 250;
  const pad = { left: 62, right: 22, top: 18, bottom: 42 };
  const visible = samples.slice(-90);
  const max = Math.max(100, Number(maxP95) || 0, ...visible.flatMap((s) => [s.p50, s.p95, s.p99])) * 1.15;
  const plotWidth = width - pad.left - pad.right;
  const plotHeight = height - pad.top - pad.bottom;
  const xAt = (index) => pad.left + (index / Math.max(1, visible.length - 1)) * plotWidth;
  const yAt = (value) => pad.top + (1 - (Number(value) || 0) / max) * plotHeight;
  const points = (key) => visible.map((sample, index) => {
    return `${xAt(index)},${yAt(sample[key])}`;
  }).join(" ");
  const targetY = yAt(maxP95);
  const xTicks = visible.length
    ? [...new Set([0, Math.floor((visible.length - 1) / 2), visible.length - 1])]
    : [];
  return (
    <div className="chart-wrap">
      <svg viewBox={`0 0 ${width} ${height}`} aria-label="即時延遲圖，Y 軸為毫秒，X 軸為經過秒數">
        {[0, 1, 2, 3, 4].map((i) => {
          const y = pad.top + (i / 4) * plotHeight;
          const value = Math.round(max * (1 - i / 4));
          return <g key={i}><line x1={pad.left} x2={width - pad.right} y1={y} y2={y} className="grid" /><text x={pad.left - 10} y={y + 4} className="axis-label y-label">{value}</text></g>;
        })}
        <line x1={pad.left} x2={pad.left} y1={pad.top} y2={height - pad.bottom} className="axis-line" />
        <line x1={pad.left} x2={width - pad.right} y1={height - pad.bottom} y2={height - pad.bottom} className="axis-line" />
        {xTicks.map((index) => <text key={index} x={xAt(index)} y={height - 17} className="axis-label x-label">{visible[index]?.elapsed != null ? `${Number(visible[index].elapsed).toFixed(0)}s` : `${index + 1}`}</text>)}
        <text x={12} y={16} className="axis-title">ms</text>
        <text x={width - 22} y={height - 7} className="axis-title">時間</text>
        {Number(maxP95) > 0 && <line x1={pad.left} x2={width - pad.right} y1={targetY} y2={targetY} className="target-line" />}
        {visible.length > 1 && <>
          <polyline points={points("p50")} className="line p50" />
          <polyline points={points("p95")} className="line p95" />
          <polyline points={points("p99")} className="line p99" />
        </>}
        {visible.length === 1 && <circle cx={xAt(0)} cy={yAt(visible[0].p95)} r="4" className="single-point" />}
      </svg>
      {!visible.length && <div className="chart-empty">開始測試後會顯示 P50 / P95 / P99 延遲趨勢</div>}
      <span className="target-label">目標 P95 {formatNumber(maxP95)}ms</span>
    </div>
  );
}

function StatusDonut({ statuses = {}, completed = 0, failureRate = 0 }) {
  const hasTraffic = Number(completed) > 0;
  const total = Math.max(1, Number(completed) || 0);
  const groups = Object.entries(statuses).reduce((acc, [code, count]) => {
    const bucket = `${String(code).slice(0, 1)}xx`;
    acc[bucket] = (acc[bucket] || 0) + count;
    return acc;
  }, {});
  const ok = ((groups["2xx"] || 0) / total) * 100;
  const warn = (((groups["3xx"] || 0) + (groups["4xx"] || 0)) / total) * 100;
  const bad = Math.max(0, 100 - ok - warn);
  const donutStyle = hasTraffic
    ? { background: `conic-gradient(#72d36f 0 ${ok}%, #f3ad31 ${ok}% ${ok + warn}%, #ff5d61 ${ok + warn}% ${ok + warn + bad}%, #748496 0)` }
    : { background: "#50677b" };
  return (
    <section className="panel status-visual">
      <div className="panel-head"><h3>HTTP 狀態</h3><span>{formatNumber(completed)} 總請求</span></div>
      <div className="donut-grid">
        <div className="donut" style={donutStyle}><strong>{formatNumber(completed)}</strong><span>總請求</span></div>
        <div className="status-table">
          {["2xx", "3xx", "4xx", "5xx"].map((bucket) => (
            <div className="status-line" key={bucket}>
              <i className={`status-${bucket}`} />
              <span>{bucket}</span>
              <strong>{formatNumber(groups[bucket] || 0)}</strong>
              <em>{(((groups[bucket] || 0) / total) * 100).toFixed(2)}%</em>
            </div>
          ))}
          <div className="failure-note">失敗率 <strong>{failureRate}%</strong></div>
        </div>
      </div>
    </section>
  );
}

function SecurityPanel({ result, running }) {
  return (
    <section className="dashboard security-dashboard">
      <div className="summary-bar">
        <div><h2>資安基線</h2><p>非破壞性被動檢查 TLS、憑證、安全標頭、Cookie 與資訊揭露</p></div>
        {result && <strong className={`score ${result.score >= 80 ? "good" : result.score >= 60 ? "warn" : "bad"}`}>{result.score}<span>/100</span></strong>}
      </div>
      <div className="security-summary">
        <div><span>目標</span><strong>{result?.target || "尚未檢查"}</strong></div>
        <div><span>HTTP 狀態</span><strong>{result?.httpStatus || "--"}</strong></div>
        <div><span>TLS 版本</span><strong>{result?.tlsProtocol || "--"}</strong></div>
        <div><span>檢查項目</span><strong>{result?.findings?.length || 0}</strong></div>
      </div>
      <section className="panel security-findings">
        <div className="panel-head"><h3>檢查結果</h3><span>{running ? "檢查中" : "被動基線"}</span></div>
        {!result && <div className="empty-state">{running ? "正在讀取目標回應與 TLS 資訊…" : "確認授權後，按左側「執行資安基線」開始。"}</div>}
        {result && <div className="finding-table">
          <div className="finding-row finding-header"><span>狀態</span><span>項目</span><span>說明</span></div>
          {result.findings.map((finding) => <div className="finding-row" key={finding.name}>
            <span className={`finding-status ${finding.status}`}>{finding.status === "pass" ? "通過" : finding.status === "warn" ? "注意" : "失敗"}</span>
            <strong>{finding.name}</strong><span>{finding.detail}</span>
          </div>)}
        </div>}
      </section>
    </section>
  );
}

function OutageDiagnosisPanel({ diagnosis }) {
  if (!diagnosis) return null;
  const evidenceRows = Array.isArray(diagnosis.evidence)
    ? diagnosis.evidence
    : Object.entries(diagnosis.evidence || {}).map(([label, value]) => ({ label, value }));
  return <section className={`panel outage-diagnosis ${diagnosis.status || "unknown"}`}>
    <div className="panel-head"><h3>為什麼斷線？</h3><span>分層證據分析</span></div>
    <h4>{diagnosis.headline}</h4>
    <div className="cause-list">{(diagnosis.causes || []).map((cause, index) => <article key={`${cause.title}-${index}`}><strong>{cause.title}</strong><span>{cause.detail}</span>{cause.action && <small>{cause.action}</small>}</article>)}</div>
    {evidenceRows.length > 0 && <div className="evidence-row">{evidenceRows.map((row, index) => <span key={`${row.label || "evidence"}-${index}`}><b>{row.label || "證據"}</b><strong>{String(row.value ?? "--")}</strong></span>)}</div>}
  </section>;
}

function ActivityLogPanel() {
  const [logs, setLogs] = useState([]);
  const [databaseInfo, setDatabaseInfo] = useState(null);
  const [filters, setFilters] = useState({ level: "", category: "", search: "" });
  const load = async () => {
    const options = { ...filters, limit: 300 };
    const [items, info] = await Promise.all([window.loadTest?.logsList?.(options) || [], window.loadTest?.logsDatabaseInfo?.() || null]);
    setLogs(items || []);
    setDatabaseInfo(info);
  };
  useEffect(() => { load().catch(() => {}); }, [filters.level, filters.category]);
  const clear = async () => { await window.loadTest?.logsClear?.(); await load(); };
  const exportLogs = async () => window.loadTest?.logsExport?.(filters);
  return <section className="panel activity-log-panel">
    <div className="panel-head"><div><h3>SQLite 系統活動紀錄</h3><p>安裝、掃描、封包與測速結果都會保留，重新開機後仍可查詢</p></div><span>{databaseInfo ? `${databaseInfo.logCount} 筆 Log` : "讀取中…"}</span></div>
    <div className="log-toolbar">
      <select aria-label="Log 等級" value={filters.level} onChange={(event) => setFilters((current) => ({ ...current, level: event.target.value }))}><option value="">全部等級</option><option value="INFO">一般 INFO</option><option value="WARN">注意 WARN</option><option value="ERROR">錯誤 ERROR</option></select>
      <select aria-label="Log 分類" value={filters.category} onChange={(event) => setFilters((current) => ({ ...current, category: event.target.value }))}><option value="">全部工具</option><option value="nmap">Nmap</option><option value="wireshark">Wireshark</option><option value="iperf3">iPerf3</option><option value="installer">軟體安裝</option><option value="database">資料庫</option></select>
      <input aria-label="搜尋 Log" value={filters.search} onChange={(event) => setFilters((current) => ({ ...current, search: event.target.value }))} onKeyDown={(event) => event.key === "Enter" && load()} placeholder="搜尋目標、動作或訊息" />
      <button onClick={load}>搜尋／更新</button><button onClick={exportLogs}>匯出 CSV</button><button className="danger-lite" onClick={clear}>清除 Log</button>
    </div>
    <div className="activity-log-table">
      <div className="activity-log-row header"><span>時間</span><span>等級</span><span>工具／動作</span><span>目標</span><span>白話訊息</span></div>
      {!logs.length && <div className="empty-state">目前沒有符合條件的活動紀錄。</div>}
      {logs.map((item) => <div className="activity-log-row" key={item.id}><span>{new Date(item.createdAt).toLocaleString("zh-TW")}</span><strong className={`level ${item.level.toLowerCase()}`}>{item.level}</strong><span><b>{item.category}</b><small>{item.action}</small></span><span title={item.target}>{item.target || "--"}</span><span>{item.message}</span></div>)}
    </div>
    {databaseInfo?.path && <p className="database-path">SQLite 檔案位置：{databaseInfo.path}</p>}
  </section>;
}

function ReliabilityPanel({ history, compare, systemSamples, scheduleRunning, scheduleLast, onRefresh, onClear }) {
  const latest = systemSamples[systemSamples.length - 1];
  return <section className="dashboard reliability-dashboard">
    <div className="summary-bar"><div><h2>可靠性中心</h2><p>歷史基準線、排程監控、主機資源與斷線證據集中檢視。</p></div><div className={`probe-state ${scheduleRunning ? "alive" : "offline"}`}><i />{scheduleRunning ? "排程執行中" : "排程未啟動"}</div></div>
    <div className="resource-cards"><article><span>CPU</span><strong>{latest ? `${latest.cpuPercent}%` : "--"}</strong></article><article><span>記憶體</span><strong>{latest ? `${latest.memoryPercent}%` : "--"}</strong></article><article><span>程序 RSS</span><strong>{latest ? formatBytes(latest.processRssBytes) : "--"}</strong></article><article><span>最近排程</span><strong>{scheduleLast ? (scheduleLast.ok ? "正常" : "異常") : "--"}</strong></article></div>
    <section className="panel history-panel"><div className="panel-head"><h3>歷史基準線</h3><div><button onClick={onRefresh}>重新整理</button><button onClick={onClear}>清除歷史</button></div></div>{!history.length ? <div className="empty-state">尚未保存測試結果。</div> : <div className="history-table">{history.map((item) => <div className="history-row" key={item.id}><span>{new Date(item.savedAt).toLocaleString("zh-TW")}</span><strong>{item.type}</strong><span>{item.target || "--"}</span><em>{item.summary?.status || item.summary?.failureRate != null ? JSON.stringify(item.summary) : "已保存"}</em></div>)}</div>}{compare && <div className="compare-box"><strong>與上一筆比較</strong>{(compare.metrics || []).slice(0, 3).map((metric) => <span key={metric.label}>{metric.label}: {metric.delta >= 0 ? "+" : ""}{metric.delta} {metric.unit}</span>)}</div>}</section>
    <ActivityLogPanel />
  </section>;
}

function TargetProbePanel({ result, running, diagnosis, routeTrace, routeTraceRunning, onRunRouteTrace, onApplySuggestedUrl }) {
  const location = result?.geo?.available
    ? [result.geo.country, result.geo.region, result.geo.city].filter(Boolean).join(" / ")
    : result?.geo?.label || "尚無資料";
  return (
    <section className="dashboard probe-dashboard">
      <div className="summary-bar">
        <div><h2>目標偵測</h2><p>解析名稱、測試服務連線，並判斷網路位置與 HTTP/TLS 狀態。</p></div>
        {result && <div className={`probe-state ${result.alive ? "alive" : "offline"}`}><i />{result.alive ? "機器存活" : "無法連線"}</div>}
      </div>
      <div className="probe-cards">
        <article><span>DNS / IP</span><strong>{result?.dns.resolved ? "已解析" : running ? "偵測中…" : "--"}</strong><small>{result?.addresses?.map((item) => item.address).join(", ") || "等待執行"}</small></article>
        <article><span>TCP 連線</span><strong className={result?.tcp.reachable ? "good" : result ? "bad" : ""}>{result?.tcp.reachable ? "可連線" : result ? "失敗" : "--"}</strong><small>{result?.tcp.reachable ? `${result.tcp.latencyMs} ms · Port ${result.port}` : result?.tcp.error || "服務層存活檢查"}</small></article>
        <article><span>HTTP 服務</span><strong className={result?.http.reachable ? "good" : result ? "bad" : ""}>{result?.http.reachable ? result.http.status : result ? "失敗" : "--"}</strong><small>{result?.methodFallback?.recovered ? `HEAD ${result.methodFallback.headStatus} → ${result.methodFallback.method} ${result.methodFallback.methodStatus}` : result?.http.reachable ? `${result.http.latencyMs} ms${result.http.server ? ` · ${result.http.server}` : ""}` : result?.http.error || "HEAD 回應檢查"}</small></article>
        <article><span>網路範圍</span><strong>{result ? (result.networkScope === "private" ? "私有網路" : result.networkScope === "public" ? "公網" : "未知") : "--"}</strong><small>{result?.hostname || "依解析 IP 判定"}</small></article>
      </div>
      <div className="probe-grid">
        <section className="panel probe-detail">
          <div className="panel-head"><h3>服務健康狀態</h3><span>{result?.checkedAt ? new Date(result.checkedAt).toLocaleString("zh-TW") : "尚未偵測"}</span></div>
          {!result && <div className="empty-state">{running ? "正在執行 DNS、TCP、HTTP 與 Geo 偵測…" : "確認授權後，按左側「開始目標偵測」。"}</div>}
          {result && <div className="probe-rows">
            <div><span>目標</span><strong>{result.target}</strong></div>
            <div><span>機器存活</span><strong className={result.alive ? "good" : "bad"}>{result.alive ? "是" : "否"}</strong></div>
            <div><span>TCP</span><strong>{result.tcp.reachable ? `Port ${result.port} 可連線` : result.tcp.error}</strong></div>
            <div><span>HTTP</span><strong>{result.methodFallback?.recovered ? `HEAD ${result.methodFallback.headStatus} 不支援；${result.methodFallback.method} 實測為 HTTP ${result.methodFallback.methodStatus}` : result.http.reachable ? `HTTP ${result.http.status}` : result.http.error}</strong></div>
            <div><span>TLS</span><strong>{result.http.tlsAuthorized == null ? "未建立 TLS" : result.http.tlsAuthorized ? `${result.http.tlsProtocol} · 憑證有效` : `憑證錯誤：${result.http.tlsError || "無法驗證"}`}</strong></div>
            {result.protocolHint && <div className="protocol-hint"><span>協定修正</span><strong>{result.protocolHint.message}<button onClick={() => onApplySuggestedUrl(result.protocolHint.suggestedUrl)}>套用 {result.protocolHint.suggestedUrl}</button></strong></div>}
          </div>}
        </section>
        <section className="panel geo-detail">
          <div className="panel-head"><h3>Geo 與網路資訊</h3><span>IP 推估位置</span></div>
          {!result && <div className="empty-state">公網 IP 才會查詢 Geo；私有 IP 不會傳送給外部服務。</div>}
          {result && <div className="geo-content">
            <div className="geo-pin">◎</div>
            <div><span>位置</span><strong>{location}</strong></div>
            <div><span>ISP</span><strong>{result.geo?.isp || "不適用／無資料"}</strong></div>
            <div><span>組織</span><strong>{result.geo?.organization || "不適用／無資料"}</strong></div>
            <div><span>時區</span><strong>{result.geo?.timezone || "不適用／無資料"}</strong></div>
            {result.geo?.available && <small>座標約 {result.geo.latitude}, {result.geo.longitude}；Geo 僅為 IP 推估，非設備精確位置。</small>}
          </div>}
        </section>
      </div>
      <OutageDiagnosisPanel diagnosis={diagnosis} />
      <section className="panel route-trace-panel">
        <div className="panel-head">
          <div><h3>斷線路徑分析（tracert）</h3><span>從此電腦追蹤至目標，每跳帶入 Geo 與營運商資料</span></div>
          <button disabled={!result || routeTraceRunning} onClick={onRunRouteTrace}>{routeTraceRunning ? "追蹤中…" : "追蹤網路路徑"}</button>
        </div>
        {!routeTrace && <div className="empty-state">先完成目標偵測，再按「追蹤網路路徑」。此功能可協助判斷斷線發生在本地網路、ISP、中繼路由或目標端附近。</div>}
        {routeTrace?.error && <div className="route-trace-error">{routeTrace.error}</div>}
        {routeTrace?.hops?.length > 0 && <div className="route-trace-table">
          <div className="route-trace-row route-trace-header"><span>跳數</span><span>IP / 延遲</span><span>Geo 位置</span><span>營運商 / 組織</span><span>判讀</span></div>
          {routeTrace.hops.map((hop) => {
            const geoLocation = hop.geo?.available ? [hop.geo.country, hop.geo.region, hop.geo.city].filter(Boolean).join(" / ") : hop.ip ? (hop.geo?.private ? "私有網路" : "尚無 Geo 資料") : "未回應";
            const network = hop.geo?.isp || hop.geo?.organization || "--";
            return <div className="route-trace-row" key={`${hop.hop}-${hop.ip || "timeout"}`}>
              <strong>{hop.hop}</strong>
              <span><b>{hop.ip || "* * *"}</b><small>{hop.timeout ? "此跳未回應" : hop.averageMs == null ? "--" : `${hop.averageMs} ms`}</small></span>
              <span>{geoLocation}</span>
              <span>{network}</span>
              <em className={hop.timeout ? "warn" : "good"}>{hop.timeout ? "可能被過濾" : "已回應"}</em>
            </div>;
          })}
        </div>}
        {routeTrace?.hops?.length > 0 && <p className="route-trace-note">注意：路由器不回 ICMP / TTL 回覆不等於網站故障；需搭配 HTTP、TCP 與存活監控的結果判讀。</p>}
      </section>
    </section>
  );
}

function GlobalProbePanel({ result, running, mode }) {
  const isDetailed = mode === "public" && Boolean(result);
  const successful = result?.results?.filter((item) => isDetailed ? item.http?.healthy : item.ok) || [];
  const best = successful.length
    ? [...successful].sort((a, b) => isDetailed
      ? (a.http?.timings?.total || Infinity) - (b.http?.timings?.total || Infinity)
      : a.latencyMs.p95 - b.latencyMs.p95)[0]
    : null;
  const grade = (item) => {
    if (!item.ok || item.availability < 95) return { label: "不穩定", className: "bad" };
    if (item.availability < 99.9 || item.latencyMs.jitter > 80) return { label: "需注意", className: "warn" };
    return { label: "穩定", className: "good" };
  };
  return (
    <section className="dashboard global-dashboard">
      <div className="summary-bar">
        <div><h2>全球節點穩定性</h2><p>{result ? `${result.provider || "自架 Agent"} · ${result.target} · DNS ${result.dnsServer}` : "可使用免部署公共節點，或由各國自架 Agent 實際連向目標。"}</p></div>
        {best && <div className="global-best"><span>最佳節點</span><strong>{best.country}・{best.city}</strong><small>{isDetailed ? `HTTP ${best.http.timings.total} ms` : `P95 ${best.latencyMs.p95} ms`}</small></div>}
      </div>
      <section className="panel global-results">
        <div className={`global-row global-header ${mode === "public" ? "global-row-detailed" : ""}`}>
          {mode === "public" ? <>
            <span>國家／探針</span><span>機器</span><span>HTTP</span><span>總耗時／TTFB</span><span>DNS</span><span>TCP／TLS</span><span>ICMP Ping</span><span>TCP 路由</span><span>判定</span>
          </> : <>
            <span>國家／城市</span><span>可用率</span><span>平均</span><span>P50</span><span>P95</span><span>抖動</span><span>DNS 平均／P95</span><span>判定</span>
          </>}
        </div>
        {!result && <div className="empty-state">{running
          ? mode === "public" ? "正在執行 DNS、HTTP、TLS、Ping 與 TCP 路由測試…" : "各國節點測試中，等待所有 Agent 回傳…"
          : mode === "public" ? "選擇國家與 DNS 後即可免部署測試。" : "設定至少一個遠端 Agent 後開始測試。"}</div>}
        {isDetailed && result.results.map((item) => (
          <article className="global-node" key={item.id}>
            <div className="global-row global-row-detailed">
              <span><strong>{item.country}・{item.city}</strong><small>{item.endpoint}{item.asn ? ` · AS${item.asn}` : ""}</small></span>
              <span><strong className={item.alive ? "good" : "bad"}>{item.alive ? "存活" : "未確認"}</strong><small>{item.http?.resolvedAddress || item.dns?.addresses?.[0] || "--"}</small></span>
              <span><strong className={item.http?.healthy ? "good" : item.http?.reachable ? "warn" : "bad"}>{item.http?.statusCode || "--"}</strong><small>{item.http?.statusName || item.http?.error || "無回應"}</small></span>
              <span><strong>{item.http?.timings?.total || "--"} ms</strong><small>首位元組 {item.http?.timings?.firstByte || "--"} ms</small></span>
              <span><strong>{item.dns?.average ?? "--"} ms</strong><small>{item.dns?.server || "--"}</small></span>
              <span><strong>{item.http?.timings?.tcp || "--"}／{item.http?.timings?.tls || "--"} ms</strong><small>{item.http?.tls ? `${item.http.tls.protocol} ${item.http.tls.authorized ? "✓" : "✕"}` : "無 TLS"}</small></span>
              <span><strong className={item.ping?.loss === 100 ? "warn" : "good"}>{item.ping?.loss ?? 100}% loss</strong><small>{item.availability > 0 ? `平均 ${item.latencyMs.average} ms` : "可能封鎖 ICMP"}</small></span>
              <span><strong>{item.route?.hops || "--"} hops</strong><small>TCP :{item.route?.port || "--"} · max {item.route?.maxRtt || "--"} ms</small></span>
              <em className={item.verdict?.className || "bad"}>{item.verdict?.label || "測試失敗"}</em>
            </div>
            <div className={`global-diagnostic ${item.verdict?.className || "bad"}`}>
              <strong>診斷</strong>
              <span>{item.verdict?.reason || "無法完成節點測試。"}
                {item.http?.tls?.expiresAt ? ` 憑證有效至 ${new Date(item.http.tls.expiresAt).toLocaleDateString("zh-TW")}。` : ""}
                {item.http?.server && item.http.server !== "--" ? ` Server: ${item.http.server}。` : ""}
              </span>
            </div>
            {item.route?.path?.length > 0 && <div className="global-route-path">
              <strong>TCP traceroute</strong>
              <span>來源 Geo／營運商：{item.country} / {item.city} · {item.endpoint}{item.asn ? ` · AS${item.asn}` : ""}</span>
              <div>{item.route.path.map((hop) => {
                const geo = hop.geo?.available ? [hop.geo.country, hop.geo.city, hop.geo.isp].filter(Boolean).join(" / ") : "";
                return <small key={`${hop.hop}-${hop.ip || "timeout"}`}>#{hop.hop} {hop.ip || "*"}{hop.averageMs == null ? "" : ` (${hop.averageMs} ms)`}{geo ? ` · ${geo}` : ""}</small>;
              })}</div>
            </div>}
          </article>
        ))}
        {!isDetailed && result?.results?.map((item) => {
          const stability = grade(item);
          return <div className="global-row" key={item.id}>
            <span><strong>{item.country}</strong><small>{item.city}</small></span>
            {item.ok ? <>
              <strong>{item.availability}%</strong>
              <span>{item.latencyMs.average} ms</span>
              <span>{item.latencyMs.p50} ms</span>
              <span>{item.latencyMs.p95} ms</span>
              <span>{item.latencyMs.jitter} ms</span>
              <span>{item.dns?.average ?? "--"} / {item.dns?.p95 ?? "--"} ms<small>{item.dns?.addresses?.join(", ")}</small></span>
              <em className={stability.className}>{stability.label}</em>
            </> : <>
              <span className="global-error">{item.error}</span>
              <span>--</span><span>--</span><span>--</span><span>--</span><span>--</span>
              <em className="bad">測試失敗</em>
            </>}
          </div>;
        })}
      </section>
      <section className="global-notes">
        <strong>判讀方式</strong>
        <span>{mode === "public"
          ? "機器存活以 HTTP/HTTPS、TCP 或 ICMP 任一可達為準；HTTP 2xx/3xx 才判定網址正常。Ping 100% loss 但 HTTPS 正常時，會標示可能封鎖 ICMP，不再誤判離線。"
          : "可用率低於 95% 為不穩定；抖動大於 80 ms 或可用率未達 99.9% 顯示需注意。DNS 數據由每個國家節點使用同一組指定 DNS 實測。"}</span>
      </section>
    </section>
  );
}

function UptimeChart({ samples }) {
  const visible = samples.slice(-180);
  const width = 900;
  const height = 230;
  const pad = { left: 62, right: 22, top: 18, bottom: 42 };
  const max = Math.max(100, ...visible.map((sample) => Number(sample.latencyMs) || 0)) * 1.15;
  const plotWidth = width - pad.left - pad.right;
  const plotHeight = height - pad.top - pad.bottom;
  const xAt = (index) => pad.left + (index / Math.max(1, visible.length - 1)) * plotWidth;
  const yAt = (value) => pad.top + (1 - (Number(value) || 0) / max) * plotHeight;
  const points = visible.map((sample, index) => {
    return `${xAt(index)},${yAt(sample.latencyMs)}`;
  }).join(" ");
  const xTicks = visible.length
    ? [...new Set([0, Math.floor((visible.length - 1) / 2), visible.length - 1])]
    : [];
  return (
    <div className="uptime-chart">
      <svg viewBox={`0 0 ${width} ${height}`} aria-label="存活監控延遲圖，Y 軸為毫秒，X 軸為檢查時間">
        {[0, 1, 2, 3, 4].map((index) => {
          const y = pad.top + (index / 4) * plotHeight;
          return <g key={index}><line x1={pad.left} x2={width - pad.right} y1={y} y2={y} className="grid" /><text x={pad.left - 10} y={y + 4} className="axis-label y-label">{Math.round(max * (1 - index / 4))}</text></g>;
        })}
        <line x1={pad.left} x2={pad.left} y1={pad.top} y2={height - pad.bottom} className="axis-line" />
        <line x1={pad.left} x2={width - pad.right} y1={height - pad.bottom} y2={height - pad.bottom} className="axis-line" />
        {xTicks.map((index) => <text key={index} x={xAt(index)} y={height - 17} className="axis-label x-label">{visible[index]?.checkedAt ? new Date(visible[index].checkedAt).toLocaleTimeString("zh-TW", { hour: "2-digit", minute: "2-digit" }) : "--:--"}</text>)}
        <text x={12} y={16} className="axis-title">ms</text>
        <text x={width - 22} y={height - 7} className="axis-title">時間</text>
        {visible.length > 1 && <polyline points={points} className="uptime-line" />}
        {visible.map((sample, index) => {
          const x = xAt(index);
          const y = yAt(sample.latencyMs);
          return <circle key={`${sample.checkedAt}-${index}`} cx={x} cy={y} r={sample.ok ? 3 : 5} className={sample.ok ? "uptime-ok" : "uptime-fail"} />;
        })}
      </svg>
      {!visible.length && <div className="empty-state">開始監控後會顯示回應時間與中斷點。</div>}
    </div>
  );
}

function UptimePanel({ progress, report, samples, routeTraces, incidents, running, onExport }) {
  const summary = progress?.summary || report?.summary || {
    availability: 0,
    averageLatencyMs: 0,
    p95LatencyMs: 0,
    incidents: 0,
    total: 0,
    failed: 0,
    lastStatus: 0,
    lastOk: null,
  };
  const failures = samples.filter((sample) => !sample.ok).slice(-50).reverse();
  const target = progress?.target || report?.target || "";
  const remainingLabel = progress?.pending
    ? "等待開始"
    : progress?.mode === "continuous"
      ? "永久監控"
      : progress?.remainingSeconds == null
        ? "--"
        : formatDuration(progress.remainingSeconds);
  return (
    <section className="dashboard uptime-dashboard">
      <div className="summary-bar">
        <div><h2>存活監控</h2><p>{target || "以本機定時檢查 HTTP/HTTPS；程式需保持開啟。"}</p></div>
        {running && <div className="monitor-remaining"><span>監控狀態</span><strong>{remainingLabel}</strong></div>}
        {report && <button className="export-button" onClick={onExport}>↓ 匯出 JSON</button>}
      </div>
      <div className="uptime-cards">
        <article><span>可用率</span><strong className={summary.availability >= 99.9 ? "good" : summary.total ? "warn" : ""}>{summary.total ? `${summary.availability}%` : "--"}</strong><small>{summary.passed || 0} / {summary.total || 0} 次成功</small></article>
        <article><span>目前狀態</span><strong className={summary.lastOk === true ? "good" : summary.lastOk === false ? "bad" : ""}>{summary.lastOk == null ? "--" : summary.lastOk ? "正常" : "中斷"}</strong><small>{summary.lastStatus ? `HTTP ${summary.lastStatus}` : "等待第一次檢查"}</small></article>
        <article><span>平均／P95</span><strong>{summary.total ? `${summary.averageLatencyMs} ms` : "--"}</strong><small>P95 {summary.p95LatencyMs || 0} ms</small></article>
        <article><span>中斷事件</span><strong className={summary.incidents ? "bad" : "good"}>{summary.incidents || 0}</strong><small>估計中斷 {formatDuration(summary.estimatedDowntimeSeconds)}</small></article>
      </div>
      <div className="uptime-grid">
        <section className="panel">
          <div className="panel-head"><h3>回應時間趨勢</h3><span>最近 {Math.min(180, samples.length)} 筆</span></div>
          <UptimeChart samples={samples} />
        </section>
        <section className="panel">
          <div className="panel-head"><h3>中斷紀錄</h3><span>{failures.length} 筆</span></div>
          <div className="uptime-events">
            {!failures.length && <div className="empty-state">{running ? "目前沒有中斷事件" : "尚未開始監控"}</div>}
            {failures.map((sample, index) => <div className="uptime-event" key={`${sample.checkedAt}-${index}`}>
              <span>{new Date(sample.checkedAt).toLocaleString("zh-TW")}</span>
              <strong>{sample.statusCode ? `HTTP ${sample.statusCode}` : `${sample.error}${sample.timeoutPhase ? ` · ${sample.timeoutPhase.toUpperCase()}` : ""}`}</strong>
              <em>{sample.latencyMs} ms</em>
            </div>)}
          </div>
        </section>
      </div>
      {incidents.length > 0 && <section className="monitor-incident-analysis">
        <div className="panel-head"><h3>最新斷線原因分析</h3><span>{incidents.length} 件斷線事件</span></div>
        <OutageDiagnosisPanel diagnosis={incidents.at(-1)} />
      </section>}
      <section className="panel monitor-route-history">
        <div className="panel-head"><h3>監控期間的 tracert</h3><span>{routeTraces.length} 次追蹤</span></div>
        {!routeTraces.length && <div className="empty-state">尚未執行路徑追蹤；可在左側選擇每次檢查或固定間隔。</div>}
        {routeTraces.length > 0 && <div className="monitor-route-list">{routeTraces.slice(-6).reverse().map((trace, index) => <div className="monitor-route-entry" key={`${trace.checkedAt || trace.sampleCheckedAt}-${index}`}>
          <span>{new Date(trace.checkedAt || trace.sampleCheckedAt).toLocaleString("zh-TW")}</span>
          <strong className={trace.error ? "bad" : "good"}>{trace.error ? "追蹤失敗" : `${trace.hops?.length || 0} hops`}</strong>
          <em title={trace.hops?.map((hop) => hop.ip || "*").join(" → ") || trace.error || "--"}>{trace.hops?.map((hop) => hop.ip || "*").join(" → ") || trace.error || "--"}</em>
        </div>)}</div>}
      </section>
      <section className="monitor-note">
        <strong>{running ? "監控執行中" : report ? (report.stopped ? "已手動停止" : "監控完成") : "等待開始"}</strong>
        <span>監控會阻止 Windows 暫停此程式，但關機、重開機、網路中斷或關閉鴨鴨測仍會停止監控。</span>
      </section>
    </section>
  );
}

function DiagnosisPanel({ diagnosis, onRunNext, running }) {
  if (!diagnosis) return null;
  return (
    <section className={`panel diagnosis-panel ${diagnosis.status}`}>
      <div className="diagnosis-summary">
        <span className="diagnosis-kicker">自動診斷</span>
        <h3>{diagnosis.headline}</h3>
        <p>根據本輪門檻與測試數據產生；下一輪會先重新預檢目標再開始。</p>
        <button disabled={running} onClick={() => onRunNext(diagnosis.nextRun)}>{running ? "自動流程執行中" : "套用並執行下一輪"}</button>
        <small>併發 {diagnosis.nextRun.concurrency} · {diagnosis.nextRun.duration} 秒</small>
      </div>
      <div className="diagnosis-findings">
        {diagnosis.findings.map((finding) => (
          <article className={finding.level} key={`${finding.title}-${finding.evidence}`}>
            <i />
            <div><strong>{finding.title}</strong><span>{finding.evidence}</span><p>{finding.action}</p></div>
          </article>
        ))}
      </div>
    </section>
  );
}

export default function App() {
  const [activeTab, setActiveTab] = useState("load");
  const [openMenu, setOpenMenu] = useState("");
  const [aboutOpen, setAboutOpen] = useState(false);
  const [config, setConfig] = useState(initialConfig);
  const [templateId, setTemplateId] = useState("health");
  const [thresholds, setThresholds] = useState({ minRps: 100, maxP95: 800, maxFailureRate: 1, minCompleted: 1000, maxAverageKb: 200 });
  const [running, setRunning] = useState(false);
  const [sample, setSample] = useState({ rps: 0, p50: 0, p95: 0, p99: 0, completed: 0, failureRate: 0, active: 0, responseBytes: 0, bytesPerSecond: 0, averageResponseBytes: 0, statuses: {}, errors: {}, logs: [] });
  const [samples, setSamples] = useState([]);
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  const [advanced, setAdvanced] = useState(false);
  const [securityResult, setSecurityResult] = useState(null);
  const [securityRunning, setSecurityRunning] = useState(false);
  const [targetResult, setTargetResult] = useState(null);
  const [targetDiagnosis, setTargetDiagnosis] = useState(null);
  const [targetRunning, setTargetRunning] = useState(false);
  const [routeTrace, setRouteTrace] = useState(null);
  const [routeTraceRunning, setRouteTraceRunning] = useState(false);
  const [globalResult, setGlobalResult] = useState(null);
  const [globalRunning, setGlobalRunning] = useState(false);
  const [networkTool, setNetworkTool] = useState("nmap");
  const [networkMode, setNetworkMode] = useState("basic");
  const [networkToolStatus, setNetworkToolStatus] = useState(null);
  const [networkInterfaces, setNetworkInterfaces] = useState([]);
  const [networkRuns, setNetworkRuns] = useState(createEmptyNetworkRuns);
  const [networkInstalling, setNetworkInstalling] = useState("");
  const [networkResultStates, setNetworkResultStates] = useState(createEmptyNetworkResultStates);
  const [networkNotice, setNetworkNotice] = useState("");
  const [networkConfig, setNetworkConfig] = useState({
    preset: "quick",
    nmapCompletionMode: "complete",
    extraArgs: "",
    topPorts: 100,
    ports: "",
    timeoutSeconds: 60,
    osDetection: false,
    interfaceId: "",
    durationSeconds: 15,
    maxPackets: 500,
    captureFilter: "",
    displayFilter: "",
    iperfRole: "client",
    iperfTarget: "",
    iperfPort: 5201,
    iperfDirection: "upload",
    iperfProtocol: "tcp",
    iperfParallelStreams: 1,
    iperfBandwidthMbps: 100,
    iperfOmitSeconds: 0,
  });
  const startLock = useRef(false);
  const autoCancel = useRef(false);
  const [autoTune, setAutoTune] = useState({ enabled: true, maxRounds: 5, cooldownSeconds: 5 });
  const [autoStatus, setAutoStatus] = useState({ phase: "idle", round: 0, total: 0, countdown: 0 });
  const [monitorConfig, setMonitorConfig] = useState({ mode: "duration", durationHours: 1, intervalSeconds: 60, timeoutMs: 5000, startAt: "", endAt: "", routeTraceMode: "interval", routeTraceIntervalSeconds: 900 });
  const [monitorRunning, setMonitorRunning] = useState(false);
  const [monitorProgress, setMonitorProgress] = useState(null);
  const [monitorSamples, setMonitorSamples] = useState([]);
  const [monitorRouteTraces, setMonitorRouteTraces] = useState([]);
  const [monitorIncidents, setMonitorIncidents] = useState([]);
  const [monitorReport, setMonitorReport] = useState(null);
  const [monitorDiagnosis, setMonitorDiagnosis] = useState(null);
  const [history, setHistory] = useState([]);
  const [historyCompare, setHistoryCompare] = useState(null);
  const [systemSamples, setSystemSamples] = useState([]);
  const [scheduleRunning, setScheduleRunning] = useState(false);
  const [scheduleLast, setScheduleLast] = useState(null);
  const [scheduleConfig, setScheduleConfig] = useState({ intervalMs: 300000, webhookUrl: "" });
  const [globalConfig, setGlobalConfig] = useState({
    mode: "public",
    nodesText: "台灣|台北|http://127.0.0.1:8787/probe",
    token: "",
    countries: "JP, SG, US, DE, AU",
    apiToken: "",
    packets: 5,
    samples: 10,
    intervalMs: 500,
    timeoutMs: 5000,
    dnsPreset: "system",
    customDns: "",
  });
  const networkRunning = Boolean(networkRuns[networkTool]?.running);
  const anyNetworkRunning = Object.values(networkRuns).some((run) => run.running);

  useEffect(() => {
    const disposeLoad = window.loadTest?.onProgress((next) => {
      setSample(next);
      setSamples((current) => [...current, next].slice(-240));
    });
    const disposeMonitor = window.loadTest?.onUptimeProgress?.((next) => {
      setMonitorProgress(next);
      if (next.sample) setMonitorSamples((current) => [...current, next.sample].slice(-5000));
      if (next.routeTrace) setMonitorRouteTraces((current) => [...current, next.routeTrace].slice(-500));
      if (next.incident) setMonitorIncidents((current) => [...current, next.incident].slice(-500));
    });
    const disposeSchedule = window.loadTest?.onScheduleProgress?.((next) => { setScheduleLast(next); setScheduleRunning(true); window.loadTest?.historyList?.(50).then((items) => setHistory(items || [])).catch(() => {}); });
    const disposeNetwork = window.loadTest?.onNetworkProgress?.((next) => {
      if (!next?.tool) return;
      setNetworkRuns((current) => {
        const previous = current[next.tool] || createEmptyNetworkRuns()[next.tool];
        if (previous.runId && next.runId && previous.runId !== next.runId) return current;
        const log = { at: next.at || new Date().toISOString(), phase: next.phase, message: next.message, detail: next.detail || "" };
        return { ...current, [next.tool]: { ...previous, ...next, logs: [...(previous.logs || []), log].slice(-20) } };
      });
    });
    window.loadTest?.historyList?.(50).then((items) => {
      const records = items || [];
      setHistory(records);
      setNetworkResultStates(hydrateNetworkResultStates(records));
    }).catch(() => {});
    const collectSystemSample = () => window.loadTest?.systemSample?.().then((item) => item && setSystemSamples((current) => [...current, item].slice(-120))).catch(() => {});
    collectSystemSample();
    const timer = setInterval(collectSystemSample, 10000);
    return () => {
      disposeLoad?.();
      disposeMonitor?.();
      disposeSchedule?.();
      disposeNetwork?.();
      clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    const timer = setInterval(() => setNetworkRuns((current) => Object.fromEntries(Object.entries(current).map(([tool, run]) => [tool, run.running && run.startedAt ? { ...run, elapsedSeconds: Math.max(0, Math.floor((Date.now() - run.startedAt) / 1000)) } : run]))), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (activeTab !== "network") return;
    let cancelled = false;
    window.loadTest?.networkToolsStatus?.().then(async (status) => {
      if (cancelled) return;
      setNetworkToolStatus(status);
      if (!status?.iperf3?.installed) {
        setNetworkInstalling("iperf3");
        setNetworkNotice("偵測到缺少 iPerf3，正在背景自動下載、驗證並安裝…");
        try {
          const result = await window.loadTest.ensureIperf3();
          if (cancelled) return;
          setNetworkNotice(result?.message || "iPerf3 已自動下載安裝完成。");
          setNetworkToolStatus(await window.loadTest.networkToolsStatus());
        } catch (cause) {
          if (!cancelled) setError(`iPerf3 自動下載失敗：${cause.message || String(cause)}；可按工具卡片重新嘗試。`);
        } finally {
          setNetworkInstalling("");
        }
      }
    }).catch((cause) => {
      if (!cancelled) setError(cause.message || String(cause));
    });
    if (networkTool === "wireshark") window.loadTest?.networkInterfaces?.().then((interfaces) => {
      if (cancelled) return;
      setNetworkInterfaces(interfaces || []);
      setNetworkConfig((current) => current.interfaceId || !interfaces?.length ? current : { ...current, interfaceId: interfaces[0].id });
    }).catch((cause) => {
      if (!cancelled) setNetworkNotice(`網卡列舉提示：${cause.message || String(cause)}`);
    });
    return () => { cancelled = true; };
  }, [activeTab, networkTool]);

  const update = (key, value) => setConfig((current) => ({ ...current, [key]: value }));
  const applyTemplate = (id) => { setTemplateId(id); const template = getTemplate(id); setConfig((current) => ({ ...current, ...template })); };
  const updateThreshold = (key, value) => setThresholds((current) => ({ ...current, [key]: value }));
  const elapsed = sample.elapsed || 0;
  const progress = running ? Math.min(100, (elapsed / Number(config.duration)) * 100) : report ? 100 : 0;
  const statusRows = useMemo(() => Object.entries(sample.statuses || {}).sort(([a], [b]) => Number(a) - Number(b)), [sample.statuses]);

  const metricPass = report ? {
    rps: report.summary.requestsPerSecond >= Number(thresholds.minRps),
    p95: report.latencyMs.p95 <= Number(thresholds.maxP95),
    failure: report.summary.failureRate <= Number(thresholds.maxFailureRate),
    completed: report.summary.completed >= Number(thresholds.minCompleted),
    size: report.summary.averageResponseBytes <= Number(thresholds.maxAverageKb) * 1024,
  } : {};
  const overallPassed = report && Object.values(metricPass).every(Boolean);
  const networkResult = networkResultStates[networkTool]?.latest || networkResultStates[networkTool]?.lastSuccess || null;
  const hasNetworkReportData = Object.values(networkResultStates).some((state) => state.latest || state.lastSuccess);
  const hasReportData = Boolean(report || monitorReport || targetResult || globalResult || securityResult || hasNetworkReportData);
  const diagnosis = useMemo(
    () => buildDiagnosis(report, thresholds, config),
    [report, thresholds, config],
  );

  const runLoadRound = async (runConfig) => {
    const preflight = await window.loadTest.targetProbe({
      url: runConfig.url,
      timeout: runConfig.timeout,
      authorized: runConfig.authorized,
      method: runConfig.method,
      headers: runConfig.headers,
      body: runConfig.body,
    });
    setTargetResult(preflight);
    if (!preflight.alive) {
      throw new Error(`壓測前預檢失敗：${preflight.tcp.error || preflight.http.error || "目標無法連線"}`);
    }
    if (preflight.protocolHint) {
      throw new Error(`網址協定錯誤：${preflight.protocolHint.message}。請到「目標偵測」一鍵套用 ${preflight.protocolHint.suggestedUrl}`);
    }
    if (!preflight.http.reachable) {
      throw new Error(`HTTP 服務預檢失敗：${preflight.http.error || "無法取得回應"}。TCP 存活不代表網址協定與服務可用。`);
    }
    if (preflight.http.tlsAuthorized === false && !runConfig.ignoreTlsErrors) {
      throw new Error(`HTTPS 憑證驗證失敗：${preflight.http.tlsError || "憑證無法驗證"}。請改用憑證主機名，或僅在內部測試環境啟用「忽略 HTTPS 憑證錯誤」。`);
    }
    return window.loadTest.start(runConfig);
  };

  const start = async (runConfig = config) => {
    if (startLock.current) return;
    startLock.current = true;
    autoCancel.current = false;
    setError("");
    setRunning(true);
    const autoOptions = normalizeAutoTune(autoTune);
    try {
      await runAutomaticSequence({
        initialConfig: runConfig,
        options: autoOptions,
        executeRound: runLoadRound,
        isCancelled: () => autoCancel.current,
        getNextConfig: (result, currentConfig) => {
          const nextDiagnosis = buildDiagnosis(result, thresholds, currentConfig);
          return buildNextRunConfig(currentConfig, nextDiagnosis.nextRun);
        },
        onRoundStart: ({ config: currentConfig, round, totalRounds }) => {
          setConfig(currentConfig);
          setReport(null);
          setSamples([]);
          setSample({ rps: 0, p50: 0, p95: 0, p99: 0, completed: 0, failureRate: 0, active: 0, responseBytes: 0, bytesPerSecond: 0, averageResponseBytes: 0, statuses: {}, errors: {}, logs: [] });
          setAutoStatus({ phase: "running", round, total: totalRounds, countdown: 0 });
        },
        onRoundComplete: ({ result, reports: roundReports, round, totalRounds }) => {
          setReport({
            ...result,
            autoRun: {
              enabled: autoOptions.enabled,
              round,
              totalRounds,
              rounds: roundReports.map((item, index) => ({
                round: index + 1,
                configuration: item.configuration,
                summary: item.summary,
                latencyMs: item.latencyMs,
                statusCodes: item.statusCodes,
              })),
            },
          });
          setSample((current) => ({
            ...current,
            rps: result.summary.requestsPerSecond,
            p50: result.latencyMs.p50,
            p95: result.latencyMs.p95,
            p99: result.latencyMs.p99,
            completed: result.summary.completed,
            failureRate: result.summary.failureRate,
            active: 0,
            responseBytes: result.summary.responseBytes,
            bytesPerSecond: 0,
            averageResponseBytes: result.summary.averageResponseBytes,
            statuses: result.statusCodes,
            errors: result.errors,
          }));
        },
        onWaiting: ({ round, totalRounds, remaining }) => {
          setAutoStatus({ phase: "waiting", round, total: totalRounds, countdown: remaining });
        },
        sleep: wait,
      });
      setAutoStatus((current) => ({ ...current, phase: autoCancel.current ? "stopped" : "completed", countdown: 0 }));
    } catch (cause) {
      setError(cause.message || String(cause));
      setAutoStatus((current) => ({ ...current, phase: "error", countdown: 0 }));
    } finally {
      startLock.current = false;
      setRunning(false);
    }
  };

  const stop = async () => {
    autoCancel.current = true;
    setAutoStatus((current) => ({ ...current, phase: "stopping", countdown: 0 }));
    await window.loadTest.stop();
  };
  const exportReport = async () => {
    if (report) await window.loadTest.saveReport(report);
  };
  const buildCompleteReport = () => ({
    type: "ducktest-complete-report",
    appName: "鴨鴨測",
    appVersion: APP_VERSION,
    author: "王宥傑",
    generatedAt: new Date().toISOString(),
    target: config.url,
    thresholds,
    loadTest: report,
    uptimeMonitor: monitorReport,
    targetProbe: targetResult,
    globalProbe: globalResult,
    securityBaseline: securityResult,
    networkAnalysis: networkResult,
    networkAnalyses: networkResultStates,
    diagnosis: targetDiagnosis || monitorDiagnosis,
    history,
    systemSamples,
    scheduler: { running: scheduleRunning, last: scheduleLast },
  });
  const exportCompleteReport = async (format) => {
    if (!hasReportData) return;
    setOpenMenu("");
    await window.loadTest.saveReport(buildCompleteReport(), format);
  };
  const clearResults = () => {
    if (running || monitorRunning || securityRunning || targetRunning || globalRunning || scheduleRunning || anyNetworkRunning) return;
    if (hasReportData && !window.confirm("確定清除目前所有測試結果？此動作不會刪除已匯出的報告。")) return;
    setSample({ rps: 0, p50: 0, p95: 0, p99: 0, completed: 0, failureRate: 0, active: 0, responseBytes: 0, bytesPerSecond: 0, averageResponseBytes: 0, statuses: {}, errors: {}, logs: [] });
    setSamples([]);
    setReport(null);
    setMonitorProgress(null);
    setMonitorSamples([]);
    setMonitorRouteTraces([]);
    setMonitorIncidents([]);
    setMonitorReport(null);
    setTargetResult(null);
    setTargetDiagnosis(null);
    setRouteTrace(null);
    setGlobalResult(null);
    setSecurityResult(null);
    setNetworkResultStates(createEmptyNetworkResultStates());
    setNetworkRuns(createEmptyNetworkRuns());
    setNetworkNotice("");
    setMonitorDiagnosis(null);
    setError("");
    setOpenMenu("");
  };
  const runNextSuggested = async (nextRun) => {
    if (running) return;
    const nextConfig = buildNextRunConfig(config, nextRun);
    setConfig(nextConfig);
    await start(nextConfig);
  };
  const startMonitor = async () => {
    if (monitorRunning) return;
    setError("");
    setMonitorReport(null);
    setMonitorProgress(null);
    setMonitorSamples([]);
    setMonitorRouteTraces([]);
    setMonitorIncidents([]);
    setMonitorRunning(true);
    try {
      const result = await window.loadTest.uptimeStart({
        url: config.url,
        authorized: config.authorized,
        mode: monitorConfig.mode,
        durationHours: monitorConfig.durationHours,
        startAt: monitorConfig.startAt,
        endAt: monitorConfig.endAt,
        intervalSeconds: monitorConfig.intervalSeconds,
        timeoutMs: monitorConfig.timeoutMs,
        routeTraceMode: monitorConfig.routeTraceMode,
        routeTraceIntervalSeconds: monitorConfig.routeTraceIntervalSeconds,
        ignoreTlsErrors: config.ignoreTlsErrors,
      });
      setMonitorReport(result);
      const diagnosis = await window.loadTest.diagnose({ type: "uptime-monitor", ...result });
      setMonitorDiagnosis(diagnosis);
      const saved = await window.loadTest.historySave({ id: result.historyId, type: "uptime-monitor", target: config.url, summary: { status: result.stopped ? "stopped" : "completed", availability: result.summary?.availability, failed: result.summary?.failed }, result, diagnosis, checkpoint: false });
      const nextHistory = await window.loadTest.historyList(50);
      setHistory(nextHistory);
      setHistoryCompare(saved && nextHistory[1]
        ? await window.loadTest.historyCompare({ leftId: nextHistory[1].id, rightId: saved.id })
        : null);
    } catch (cause) {
      setError(cause.message || String(cause));
    } finally {
      setMonitorRunning(false);
    }
  };
  const stopMonitor = async () => window.loadTest.uptimeStop();
  const exportMonitor = async () => {
    if (monitorReport) await window.loadTest.saveReport(monitorReport);
  };
  const runSecurityCheck = async () => {
    setError("");
    setSecurityRunning(true);
    setSecurityResult(null);
    try {
      setSecurityResult(await window.loadTest.securityCheck({ url: config.url, authorized: config.authorized }));
    } catch (cause) {
      setError(cause.message || String(cause));
    } finally {
      setSecurityRunning(false);
    }
  };
  const runTargetProbe = async () => {
    setError("");
    setTargetRunning(true);
    setTargetResult(null);
    setTargetDiagnosis(null);
    setRouteTrace(null);
    try {
      const result = await window.loadTest.targetProbe({
        url: config.url,
        timeout: config.timeout,
        authorized: config.authorized,
        method: config.method,
        headers: config.headers,
        body: config.body,
      });
      const needsDisconnectAnalysis = !result.alive || !result.http?.reachable || result.http?.status >= 500;
      let trace = null;
      if (needsDisconnectAnalysis) {
        trace = await window.loadTest.traceRoute({ url: config.url, authorized: config.authorized, maxHops: 12, timeoutMs: 1200 });
        setRouteTrace(trace);
      }
      setTargetResult({ ...result, routeTrace: trace });
      const diagnosis = needsDisconnectAnalysis
        ? await window.loadTest.diagnose({
          type: "disconnect-event",
          target: result.target,
          sample: {
            ok: false,
            reachable: Boolean(result.http?.reachable || result.tcp?.reachable),
            checkedAt: result.checkedAt,
            statusCode: result.http?.status || 0,
            error: result.http?.error || result.tcp?.error || result.dns?.error || "unknown",
          },
          routeTrace: trace,
        })
        : await window.loadTest.diagnose(result);
      setTargetDiagnosis(diagnosis);
      const saved = await window.loadTest.historySave({ type: "target-probe", target: result.target, summary: { status: result.alive ? "online" : "offline", httpStatus: result.http?.status }, result, diagnosis });
      const nextHistory = await window.loadTest.historyList(50);
      setHistory(nextHistory);
      setHistoryCompare(saved && nextHistory[1]
        ? await window.loadTest.historyCompare({ leftId: nextHistory[1].id, rightId: saved.id })
        : null);
    } catch (cause) {
      setError(cause.message || String(cause));
    } finally {
      setTargetRunning(false);
    }
  };
  const runRouteTrace = async () => {
    if (routeTraceRunning || !targetResult) return;
    setError("");
    setRouteTrace(null);
    setRouteTraceRunning(true);
    try {
      setRouteTrace(await window.loadTest.traceRoute({
        url: config.url,
        authorized: config.authorized,
        maxHops: 12,
        timeoutMs: 1200,
      }));
    } catch (cause) {
      setError(cause.message || String(cause));
    } finally {
      setRouteTraceRunning(false);
    }
  };
  const refreshHistory = async () => setHistory(await window.loadTest.historyList(50));
  const clearHistory = async () => { await window.loadTest.historyClear(); setHistory([]); setHistoryCompare(null); };
  const startSchedule = async () => { setError(""); try { await window.loadTest.scheduleStart({ url: config.url, intervalMs: scheduleConfig.intervalMs, timeoutMs: config.timeout, authorized: config.authorized, webhookUrl: scheduleConfig.webhookUrl }); setScheduleRunning(true); } catch (cause) { setError(cause.message || String(cause)); } };
  const stopSchedule = async () => { await window.loadTest.scheduleStop(); setScheduleRunning(false); };
  const runGlobalProbe = async () => {
    setError("");
    setGlobalRunning(true);
    setGlobalResult(null);
    try {
      const dnsServer = globalConfig.dnsPreset === "custom"
        ? globalConfig.customDns.trim()
        : globalConfig.dnsPreset;
      if (!dnsServer) throw new Error("請輸入自訂 DNS 伺服器");
      if (globalConfig.mode === "public") {
        setGlobalResult(await window.loadTest.globalping({
          target: config.url,
          authorized: config.authorized,
          countries: globalConfig.countries,
          token: globalConfig.apiToken,
          packets: globalConfig.packets,
          dnsServer,
        }));
      } else {
        setGlobalResult(await window.loadTest.globalProbe({
          target: config.url,
          authorized: config.authorized,
          nodesText: globalConfig.nodesText,
          token: globalConfig.token,
          samples: globalConfig.samples,
          intervalMs: globalConfig.intervalMs,
          timeoutMs: globalConfig.timeoutMs,
          dnsServer,
        }));
      }
    } catch (cause) {
      setError(readableRemoteError(cause));
    } finally {
      setGlobalRunning(false);
    }
  };
  const updateGlobal = (key, value) => setGlobalConfig((current) => ({ ...current, [key]: value }));
  const updateNetwork = (key, value) => setNetworkConfig((current) => ({ ...current, [key]: value }));
  const applyNetworkPreset = (preset) => {
    setNetworkConfig((current) => {
      const common = { ...current, preset, extraArgs: "" };
      if (networkTool === "nmap") {
        if (preset === "web") return { ...common, ports: "80,443,8080,8443", topPorts: 100, timeoutSeconds: 90, osDetection: false };
        if (preset === "complete") return { ...common, ports: "", topPorts: 1000, timeoutSeconds: 180, osDetection: networkMode === "advanced" };
        return { ...common, ports: "", topPorts: 100, timeoutSeconds: 60, osDetection: false };
      }
      if (networkTool === "wireshark") {
        if (preset === "quality") return { ...common, durationSeconds: 30, maxPackets: 2000, captureFilter: "", displayFilter: "tcp.analysis.retransmission or tcp.flags.reset == 1" };
        if (preset === "web") return { ...common, durationSeconds: 30, maxPackets: 2000, captureFilter: "tcp port 80 or tcp port 443", displayFilter: "http or tls or dns" };
        return { ...common, durationSeconds: 15, maxPackets: 500, captureFilter: "", displayFilter: "" };
      }
      if (preset === "download") return { ...common, iperfRole: "client", iperfDirection: "download", iperfProtocol: "tcp", durationSeconds: 10, iperfParallelStreams: 1 };
      if (preset === "udp") return { ...common, iperfRole: "client", iperfDirection: "upload", iperfProtocol: "udp", durationSeconds: 20, iperfParallelStreams: 1, iperfBandwidthMbps: 100 };
      if (preset === "server") return { ...common, iperfRole: "server" };
      return { ...common, iperfRole: "client", iperfDirection: "upload", iperfProtocol: "tcp", durationSeconds: 10, iperfParallelStreams: 1 };
    });
  };
  const runNetworkAnalysis = async () => {
    if (networkRunning) return;
    const tool = networkTool;
    const runId = globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const startedAt = Date.now();
    setError("");
    setNetworkNotice("");
    const estimatedTotalSeconds = tool === "nmap"
      ? (networkConfig.nmapCompletionMode === "time_limit" ? Number(networkConfig.timeoutSeconds) : 0)
      : tool === "wireshark"
        ? Number(networkConfig.durationSeconds) + 15
        : networkConfig.iperfRole === "server"
          ? 0
          : Number(networkConfig.durationSeconds) + Number(networkConfig.iperfOmitSeconds || 0) + 10;
    setNetworkRuns((current) => ({ ...current, [tool]: { running: true, runId, phase: "starting", progress: 2, message: "準備啟動工具…", detail: "", startedAt, elapsedSeconds: 0, estimatedTotalSeconds, logs: [{ at: new Date().toISOString(), phase: "starting", message: "使用者已開始測試。" }] } }));
    try {
      let result;
      const request = { ...buildNetworkToolRequest(tool, {
        targetUrl: config.url,
        authorized: config.authorized,
        mode: networkMode,
        config: networkConfig,
      }), runId };
      if (tool === "nmap") result = await window.loadTest.runNmap(request);
      else if (tool === "wireshark") result = await window.loadTest.runWireshark(request);
      else result = await window.loadTest.runIperf3(request);
      setNetworkResultStates((current) => applyNetworkResult(current, tool, result));
      await window.loadTest.historySave({ type: result.type, target: result.target, summary: result.summary, result });
      setHistory(await window.loadTest.historyList(50));
      setNetworkRuns((current) => ({ ...current, [tool]: { ...current[tool], running: false, phase: result.incomplete ? "incomplete" : "completed", progress: 100, message: result.incomplete ? "測試達到時間上限；已保留診斷資訊，未知數值不會顯示為 0。" : "測試完成，結果已保存。" } }));
    } catch (cause) {
      const message = readableRemoteError(cause);
      const stopped = /停止/.test(message);
      const phase = stopped ? "stopped" : "incomplete";
      setNetworkNotice(stopped ? "測試已停止，已保留本次執行紀錄。" : "測試未完成，已產生可判讀的診斷結果。");
      setNetworkRuns((current) => ({ ...current, [tool]: {
        ...current[tool],
        running: false,
        phase,
        progress: 100,
        message: stopped ? message : `測試未完成：${message}`,
        diagnostic: {
          outcome: stopped ? "使用者停止" : "未完成",
          reason: message,
          tool,
          endedAt: new Date().toISOString(),
        },
        logs: [...(current[tool]?.logs || []), { at: new Date().toISOString(), phase, message }].slice(-20),
      } }));
    } finally {
      setNetworkRuns((current) => current[tool]?.runId !== runId ? current : ({ ...current, [tool]: { ...current[tool], running: false } }));
    }
  };
  const stopNetworkAnalysis = async () => {
    const tool = networkTool;
    const stopped = await window.loadTest?.stopNetworkTool?.(tool);
    if (stopped) {
      setNetworkRuns((current) => ({ ...current, [tool]: { ...current[tool], phase: "stopping", message: "正在停止工具並回收程序，請稍候…" } }));
      setNetworkNotice(`已要求停止 ${tool === "nmap" ? "Nmap" : tool === "wireshark" ? "Wireshark" : "iPerf3"}。`);
    }
  };
  const installNetworkTool = async (tool) => {
    setError("");
    setNetworkNotice("");
    setNetworkInstalling(tool);
    try {
      const result = await window.loadTest.installNetworkTool(tool);
      if (!result?.cancelled) setNetworkNotice(result?.message || "安裝流程已完成。");
      setNetworkToolStatus(await window.loadTest.networkToolsStatus());
      if (tool === "wireshark") {
        const interfaces = await window.loadTest.networkInterfaces().catch(() => []);
        setNetworkInterfaces(interfaces);
        setNetworkConfig((current) => current.interfaceId || !interfaces.length ? current : { ...current, interfaceId: interfaces[0].id });
      }
    } catch (cause) {
      setError(cause.message || String(cause));
    } finally {
      setNetworkInstalling("");
    }
  };
  const saveNetworkCapture = async (captureFile) => {
    setError("");
    try {
      const saved = await window.loadTest.saveCapture(captureFile);
      if (saved) setNetworkNotice(`封包檔已儲存：${saved}`);
    } catch (cause) {
      setError(cause.message || String(cause));
    }
  };
  const networkBlockReason = !config.authorized
    ? "請先勾選授權確認。"
    : networkTool === "nmap" && networkConfig.nmapCompletionMode === "time_limit" && (!Number.isFinite(Number(networkConfig.timeoutSeconds)) || Number(networkConfig.timeoutSeconds) < 10 || Number(networkConfig.timeoutSeconds) > 600)
      ? "Nmap 單一主機最長時間必須介於 10 到 600 秒；程式不會偷偷改成其他數值。"
    : networkTool === "nmap" && !networkToolStatus?.nmap?.installed
      ? "尚未安裝或找不到 Nmap。"
      : networkTool === "wireshark" && !networkToolStatus?.wireshark?.installed
        ? "尚未安裝或找不到 Wireshark／TShark。"
        : networkTool === "wireshark" && !networkConfig.interfaceId
          ? "請先選擇目前正在使用的網路介面。"
          : networkTool === "iperf3" && !networkToolStatus?.iperf3?.installed
            ? "尚未安裝或找不到 iPerf3。"
            : networkTool === "iperf3" && networkConfig.iperfRole === "client" && !networkConfig.iperfTarget.trim()
              ? "請先填寫另一台已啟動 iPerf3 接收端的 IP 或主機名。"
              : "";

  return (
    <main className="app-shell">
      <div className="menu-bar">
        <div className="menu-group">
          <button className={openMenu === "file" ? "active" : ""} onClick={() => setOpenMenu((current) => current === "file" ? "" : "file")}>檔案</button>
          {openMenu === "file" && <div className="menu-popover">
            <button disabled={running || monitorRunning} onClick={clearResults}><span>建立新工作區</span><small>清除畫面上的測試結果</small></button>
          </div>}
        </div>
        <div className="menu-group">
          <button className={openMenu === "export" ? "active" : ""} onClick={() => setOpenMenu((current) => current === "export" ? "" : "export")}>匯出</button>
          {openMenu === "export" && <div className="menu-popover">
            <button disabled={!hasReportData} onClick={() => exportCompleteReport("html")}><span>完整 HTML 報告</span><small>可瀏覽、列印與轉存 PDF</small></button>
            <button disabled={!hasReportData} onClick={() => exportCompleteReport("json")}><span>JSON 原始資料</span><small>保留全部檢測資料</small></button>
            <button disabled={!hasReportData} onClick={() => exportCompleteReport("csv")}><span>CSV 報告</span><small>可直接匯入 Excel</small></button>
            {!hasReportData && <p>完成任一項測試後即可匯出</p>}
          </div>}
        </div>
        <button onClick={() => { setAboutOpen(true); setOpenMenu(""); }}>關於</button>
        <span className="menu-caption">鴨鴨測 v{APP_VERSION} · 王宥傑</span>
      </div>
      <header className="titlebar">
        <div className="product-title"><span className="brand-dot">鴨</span><strong>鴨鴨測</strong><small>網站品質工作台</small></div>
        <nav className="tabs">
          <button className={activeTab === "load" ? "active" : ""} onClick={() => setActiveTab("load")}>壓力測試</button>
          <button className={activeTab === "probe" ? "active" : ""} onClick={() => setActiveTab("probe")}>目標偵測</button>
          <button className={activeTab === "monitor" ? "active" : ""} onClick={() => setActiveTab("monitor")}>存活監控</button>
          <button className={activeTab === "global" ? "active" : ""} onClick={() => setActiveTab("global")}>全球節點</button>
          <button className={activeTab === "network" ? "active" : ""} onClick={() => setActiveTab("network")}>網路透視</button>
          <button className={activeTab === "security" ? "active" : ""} onClick={() => setActiveTab("security")}>資安基線</button>
          <button className={activeTab === "reliability" ? "active" : ""} onClick={() => setActiveTab("reliability")}>可靠性中心</button>
        </nav>
        <div className={`run-indicator ${running || monitorRunning || securityRunning || targetRunning || globalRunning || anyNetworkRunning ? "busy" : ""}`}><i />{[running && `自動壓測 ${autoStatus.round}/${autoStatus.total}`, monitorRunning && "存活監控", securityRunning && "基線檢查", targetRunning && "目標偵測", globalRunning && "全球測試", ...Object.entries(networkRuns).filter(([, run]) => run.running).map(([tool]) => `${tool === "nmap" ? "Nmap" : tool === "wireshark" ? "Wireshark" : "iPerf3"} 執行中`)].filter(Boolean).join("＋") || (report ? "測試完成" : "準備就緒")}</div>
      </header>

      <div className="workspace">
        <aside className={`settings ${activeTab === "load" ? "load-mode-settings" : activeTab === "global" ? "global-mode-settings" : activeTab === "monitor" ? "monitor-mode-settings" : ""}`}>
          <div className="section-title"><h2>{activeTab === "reliability" ? "可靠性設定" : activeTab === "security" ? "檢查設定" : activeTab === "network" ? "網路分析設定" : activeTab === "probe" ? "偵測設定" : activeTab === "monitor" ? "監控設定" : activeTab === "global" ? "全球節點設定" : "測試設定"}</h2><span>v{APP_VERSION}</span></div>
          <label>目標 URL<input value={config.url} disabled={running || monitorRunning || networkRunning} onChange={(e) => update("url", e.target.value)} placeholder="https://api.example.com/health" /></label>
          {activeTab === "load" && <>
          <label>測試模板<select value={templateId} disabled={running} onChange={(e) => applyTemplate(e.target.value)}>{Object.entries(TEST_TEMPLATES).map(([id, template]) => <option value={id} key={id}>{template.label}</option>)}</select></label>
          <label>HTTP 方法<select value={config.method} disabled={running} onChange={(e) => update("method", e.target.value)}>{["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"].map((m) => <option key={m}>{m}</option>)}</select></label>
          <label>測試模式<select value={config.mode} disabled={running} onChange={(e) => update("mode", e.target.value)}><option value="ramp">漸進加壓</option><option value="spike">瞬間突增 Spike Test</option></select></label>
          <div className="form-row two">
            <label>並發數<input type="number" min="1" max="500" value={config.concurrency} disabled={running} onChange={(e) => update("concurrency", e.target.value)} /></label>
            <label>測試時間<input type="number" min="1" max="3600" value={config.duration} disabled={running} onChange={(e) => update("duration", e.target.value)} /><small>秒</small></label>
          </div>
          <div className="form-row two">
            <label>Ramp Up<input type="number" min="0" value={config.mode === "spike" ? 0 : config.ramp} disabled={running || config.mode === "spike"} onChange={(e) => update("ramp", e.target.value)} /><small>秒</small></label>
            <label>逾時<input type="number" min="100" value={config.timeout} disabled={running} onChange={(e) => update("timeout", e.target.value)} /><small>ms</small></label>
          </div>
          <section className="auto-tune-card">
            <label className="auto-tune-toggle">
              <input type="checkbox" checked={autoTune.enabled} disabled={running} onChange={(event) => setAutoTune((current) => ({ ...current, enabled: event.target.checked }))} />
              <span><strong>自動執行下一輪</strong><small>依診斷自動調整併發與測試時間</small></span>
            </label>
            {autoTune.enabled && <div className="form-row two">
              <label>最大輪數<input type="number" min="2" max="10" value={autoTune.maxRounds} disabled={running} onChange={(event) => setAutoTune((current) => ({ ...current, maxRounds: event.target.value }))} /></label>
              <label>輪次間隔<input type="number" min="1" max="300" value={autoTune.cooldownSeconds} disabled={running} onChange={(event) => setAutoTune((current) => ({ ...current, cooldownSeconds: event.target.value }))} /><small>秒</small></label>
            </div>}
          </section>

          <button className="advanced-toggle" onClick={() => setAdvanced(!advanced)} disabled={running}>進階設定 <span>{advanced ? "−" : "+"}</span></button>
          {advanced && <div className="advanced">
            <label>Headers（JSON）<textarea value={config.headers} disabled={running} onChange={(e) => update("headers", e.target.value)} /></label>
            {!["GET", "HEAD"].includes(config.method) && <>
              <label className="payload-generator">
                <input type="checkbox" checked={config.generatePayload} disabled={running} onChange={(e) => update("generatePayload", e.target.checked)} />
                <span><strong>自動產生固定大小 Payload</strong><small>可調整每次 HTTP Request Body 的封包/內容大小。</small></span>
              </label>
              {config.generatePayload && <label>Payload 大小（bytes）<input type="number" min="1" max="10485760" value={config.payloadBytes} disabled={running} onChange={(e) => update("payloadBytes", e.target.value)} /><small className="payload-size">每次送出：{formatBytes(config.payloadBytes)}，上限 10 MB</small></label>}
              {!config.generatePayload && <label>Request Body<textarea value={config.body} disabled={running} onChange={(e) => update("body", e.target.value)} placeholder='{"scenario":"pre-release"}' /><small className="payload-size">每次送出：{formatBytes(new TextEncoder().encode(config.body).byteLength)}</small></label>}
            </>}
            <label className="tls-option">
              <input type="checkbox" checked={config.ignoreTlsErrors} disabled={running} onChange={(e) => update("ignoreTlsErrors", e.target.checked)} />
              <span><strong>忽略 HTTPS 憑證錯誤</strong><small>只建議在內部測試環境使用，正式環境仍應修正憑證。</small></span>
            </label>
          </div>}
          </>}
          {activeTab === "probe" && <label>偵測逾時<input type="number" min="500" max="30000" value={config.timeout} disabled={targetRunning} onChange={(e) => update("timeout", e.target.value)} /><small>ms</small></label>}
          {activeTab === "monitor" && <div className="monitor-settings">
            <label>監控時間<select
              value={monitorConfig.mode === "duration" ? `duration:${monitorConfig.durationHours}` : monitorConfig.mode}
              disabled={monitorRunning}
              onChange={(event) => {
                const [mode, durationHours] = event.target.value.split(":");
                setMonitorConfig((current) => ({
                  ...current,
                  mode,
                  ...(mode === "duration" ? { durationHours } : {}),
                }));
              }}
            >
              <option value="duration:1">1 小時</option>
              <option value="duration:8">8 小時</option>
              <option value="duration:12">12 小時</option>
              <option value="duration:24">24 小時／1 天</option>
              <option value="month">一個月（30 天）</option>
              <option value="continuous">永久監控（手動停止）</option>
              <option value="range">指定日期區間</option>
            </select></label>
            {monitorConfig.mode === "range" && <>
              <label>開始時間<input type="datetime-local" value={monitorConfig.startAt} disabled={monitorRunning} onChange={(event) => setMonitorConfig((current) => ({ ...current, startAt: event.target.value }))} /></label>
              <label>結束時間<input type="datetime-local" value={monitorConfig.endAt} disabled={monitorRunning} onChange={(event) => setMonitorConfig((current) => ({ ...current, endAt: event.target.value }))} /></label>
            </>}
            {monitorConfig.mode === "continuous" && <p className="payload-size">永久監控會持續到你按下「停止監控並結算」；請保持鴨鴨測開啟。</p>}
            <label>檢查間隔<select value={monitorConfig.intervalSeconds} disabled={monitorRunning} onChange={(event) => setMonitorConfig((current) => ({ ...current, intervalSeconds: event.target.value }))}>
              <option value="30">每 30 秒</option>
              <option value="60">每 1 分鐘</option>
              <option value="300">每 5 分鐘</option>
              <option value="600">每 10 分鐘</option>
            </select></label>
            <label>tracert 模式<select value={monitorConfig.routeTraceMode} disabled={monitorRunning} onChange={(event) => setMonitorConfig((current) => ({ ...current, routeTraceMode: event.target.value }))}>
              <option value="off">不追蹤路徑</option>
              <option value="every-check">每次存活檢查都追蹤</option>
              <option value="interval">固定間隔追蹤</option>
            </select></label>
            {monitorConfig.routeTraceMode === "interval" && <label>追蹤間隔<select value={monitorConfig.routeTraceIntervalSeconds} disabled={monitorRunning} onChange={(event) => setMonitorConfig((current) => ({ ...current, routeTraceIntervalSeconds: event.target.value }))}>
              <option value="300">每 5 分鐘</option>
              <option value="900">每 15 分鐘</option>
              <option value="1800">每 30 分鐘</option>
              <option value="3600">每 1 小時</option>
            </select></label>}
            <label>單次逾時<input type="number" min="500" max="30000" value={monitorConfig.timeoutMs} disabled={monitorRunning} onChange={(event) => setMonitorConfig((current) => ({ ...current, timeoutMs: event.target.value }))} /><small>ms</small></label>
          </div>}
          {activeTab === "global" && <div className="global-settings">
            <label>節點來源<select value={globalConfig.mode} disabled={globalRunning} onChange={(e) => updateGlobal("mode", e.target.value)}>
              <option value="public">免部署 · Globalping 公共節點</option>
              <option value="agents">自架 Agent · 支援私網/VPN</option>
            </select></label>
            {globalConfig.mode === "public" ? <>
              <label>國家代碼<input value={globalConfig.countries} disabled={globalRunning} onChange={(e) => updateGlobal("countries", e.target.value)} placeholder="JP, SG, US, DE, AU" /><small className="payload-size">兩碼國家代碼，最多 12 國</small></label>
              <label>Globalping API Token（選填）<input type="password" value={globalConfig.apiToken} disabled={globalRunning} onChange={(e) => updateGlobal("apiToken", e.target.value)} placeholder="未填仍可使用免費額度" /></label>
              <label>Ping 封包數<input type="number" min="3" max="16" value={globalConfig.packets} disabled={globalRunning} onChange={(e) => updateGlobal("packets", e.target.value)} /><small className="payload-size">3–16；超過會自動限制為 16</small></label>
            </> : <>
              <label>國家節點（每行一個）<textarea value={globalConfig.nodesText} disabled={globalRunning} onChange={(e) => updateGlobal("nodesText", e.target.value)} placeholder="日本|東京|https://jp-probe.example.com/probe" /></label>
              <label>共用 Agent Token<input type="password" value={globalConfig.token} disabled={globalRunning} onChange={(e) => updateGlobal("token", e.target.value)} placeholder="不會儲存於磁碟" /></label>
            </>}
            <label>DNS<select value={globalConfig.dnsPreset} disabled={globalRunning} onChange={(e) => updateGlobal("dnsPreset", e.target.value)}>
              <option value="system">系統預設</option>
              <option value="1.1.1.1">Cloudflare · 1.1.1.1</option>
              <option value="8.8.8.8">Google · 8.8.8.8</option>
              <option value="9.9.9.9">Quad9 · 9.9.9.9</option>
              <option value="custom">自訂 DNS</option>
            </select></label>
            {globalConfig.dnsPreset === "custom" && <label>自訂 DNS IP<input value={globalConfig.customDns} disabled={globalRunning} onChange={(e) => updateGlobal("customDns", e.target.value)} placeholder="例如 168.95.1.1" /></label>}
            {globalConfig.mode === "agents" && <><div className="form-row two">
              <label>每節點樣本<input type="number" min="3" max="30" value={globalConfig.samples} disabled={globalRunning} onChange={(e) => updateGlobal("samples", e.target.value)} /></label>
              <label>間隔<input type="number" min="100" max="5000" value={globalConfig.intervalMs} disabled={globalRunning} onChange={(e) => updateGlobal("intervalMs", e.target.value)} /><small>ms</small></label>
            </div>
            <label>單次逾時<input type="number" min="500" max="30000" value={globalConfig.timeoutMs} disabled={globalRunning} onChange={(e) => updateGlobal("timeoutMs", e.target.value)} /><small>ms</small></label>
            </>}
          </div>}

          {activeTab === "network" && <div className="network-settings">
            <div className="network-tool-switch" role="group" aria-label="網路工具">
              <button className={networkTool === "nmap" ? "active" : ""} onClick={() => { setNetworkTool("nmap"); setNetworkConfig((current) => ({ ...current, preset: "quick", extraArgs: "" })); }}>Nmap<span>{networkRuns.nmap.running ? "執行中" : "服務入口"}</span></button>
              <button className={networkTool === "wireshark" ? "active" : ""} onClick={() => { setNetworkTool("wireshark"); setNetworkConfig((current) => ({ ...current, preset: "quick", extraArgs: "" })); }}>Wireshark<span>{networkRuns.wireshark.running ? "執行中" : "封包品質"}</span></button>
              <button className={networkTool === "iperf3" ? "active" : ""} onClick={() => { setNetworkTool("iperf3"); setNetworkConfig((current) => ({ ...current, preset: "quick", extraArgs: "" })); }}>iPerf3<span>{networkRuns.iperf3.running ? "執行中" : "傳輸測速"}</span></button>
            </div>
            <label>功能層級<select value={networkMode} disabled={networkRunning} onChange={(event) => {
              const mode = event.target.value;
              setNetworkMode(mode);
              setNetworkConfig((current) => ({
                ...current,
                topPorts: mode === "advanced" ? 1000 : 100,
                timeoutSeconds: mode === "advanced" ? 180 : 60,
                durationSeconds: mode === "advanced" ? (networkTool === "iperf3" ? 20 : 30) : (networkTool === "iperf3" ? 10 : 15),
                maxPackets: mode === "advanced" ? 2000 : 500,
              }));
            }}><option value="basic">基礎｜快速、白話</option><option value="advanced">進階｜完整證據</option></select></label>
            <label>懶人測試範本<select value={networkConfig.preset} disabled={networkRunning} onChange={(event) => applyNetworkPreset(event.target.value)}>
              {networkTool === "nmap" && <><option value="quick">快速檢查常用入口</option><option value="web">網站服務入口</option><option value="complete">較完整服務盤點</option></>}
              {networkTool === "wireshark" && <><option value="quick">快速擷取</option><option value="quality">連線不穩／重傳</option><option value="web">網站 DNS／HTTP／TLS</option></>}
              {networkTool === "iperf3" && <><option value="quick">上傳速度（TCP）</option><option value="download">下載速度（TCP）</option><option value="udp">語音視訊品質（UDP）</option><option value="server">本機當一次性接收端</option></>}
            </select><small className="payload-size">選一個使用情境，相關參數會自動填好。</small></label>
            {networkTool === "nmap" ? <>
              <label>常用連接埠數<select value={networkConfig.topPorts} disabled={networkRunning || Boolean(networkConfig.ports)} onChange={(event) => updateNetwork("topPorts", event.target.value)}><option value="100">前 100 個（較快）</option><option value="200">前 200 個</option><option value="1000">前 1,000 個（較完整）</option></select></label>
              <label>自訂連接埠（選填）<input value={networkConfig.ports} disabled={networkRunning} onChange={(event) => updateNetwork("ports", event.target.value)} placeholder="例如 80,443,8000-8100" /><small className="payload-size">填寫後會取代上方常用連接埠範圍</small></label>
              <label>完成方式<select value={networkConfig.nmapCompletionMode} disabled={networkRunning} onChange={(event) => updateNetwork("nmapCompletionMode", event.target.value)}><option value="complete">執行到掃描完成（建議）</option><option value="time_limit">設定最長時間</option></select><small className="payload-size">完整模式不會被秒數中止；需要時可按「停止 Nmap」。</small></label>
              {networkConfig.nmapCompletionMode === "time_limit" && <label>單一主機最長時間<input type="number" min="10" max="600" value={networkConfig.timeoutSeconds} disabled={networkRunning} onChange={(event) => updateNetwork("timeoutSeconds", event.target.value)} /><small>秒</small><span className="payload-size">只有選擇時間上限時才會生效，輸入值不會被偷偷改寫。</span></label>}
              {networkMode === "advanced" && <label className="network-option"><input type="checkbox" checked={networkConfig.osDetection} disabled={networkRunning} onChange={(event) => updateNetwork("osDetection", event.target.checked)} /><span><strong>推測作業系統</strong><small>可能需要系統管理員權限；結果僅供參考。</small></span></label>}
            </> : networkTool === "wireshark" ? <>
              <label>擷取網卡<select value={networkConfig.interfaceId} disabled={networkRunning} onChange={(event) => updateNetwork("interfaceId", event.target.value)}><option value="">請選擇網卡</option>{networkInterfaces.map((item) => <option key={item.id} value={item.id}>{item.label}{item.fallback ? "（系統清單）" : ""}</option>)}</select><small className="payload-size">請選擇目前實際上網的乙太網路或 Wi-Fi</small></label>
              <div className="form-row two"><label>擷取時間<input type="number" min="5" max="120" value={networkConfig.durationSeconds} disabled={networkRunning} onChange={(event) => updateNetwork("durationSeconds", event.target.value)} /><small>秒</small></label><label>封包上限<input type="number" min="50" max="5000" value={networkConfig.maxPackets} disabled={networkRunning} onChange={(event) => updateNetwork("maxPackets", event.target.value)} /></label></div>
              {networkMode === "advanced" && <div className="network-filter-box"><label>擷取篩選器（選填）<input value={networkConfig.captureFilter} disabled={networkRunning} onChange={(event) => updateNetwork("captureFilter", event.target.value)} placeholder="例如 tcp port 443" /><small className="payload-size">會自動再加上目標 IP，不會擷取其他主機</small></label><label>顯示篩選器（選填）<input value={networkConfig.displayFilter} disabled={networkRunning} onChange={(event) => updateNetwork("displayFilter", event.target.value)} placeholder="例如 tcp.analysis.retransmission" /><small className="payload-size">只影響畫面報告，完整封包仍保留</small></label></div>}
            </> : <>
              <label>這台電腦的角色<select value={networkConfig.iperfRole} disabled={networkRunning} onChange={(event) => updateNetwork("iperfRole", event.target.value)}><option value="client">測試端｜連到另一台電腦</option><option value="server">接收端｜等待另一台測試一次</option></select><small className="payload-size">先在一台選「接收端」，再到另一台輸入接收端 IP 並開始。</small></label>
              <label>iPerf3 連接埠<input type="number" min="1" max="65535" value={networkConfig.iperfPort} disabled={networkRunning} onChange={(event) => updateNetwork("iperfPort", event.target.value)} /><small className="payload-size">兩台電腦必須相同；預設是 5201，防火牆需允許。</small></label>
              {networkConfig.iperfRole === "client" && <>
                <label>接收端 IP 或主機名<input value={networkConfig.iperfTarget} disabled={networkRunning} onChange={(event) => updateNetwork("iperfTarget", event.target.value)} placeholder="例如 192.168.1.50" /><small className="payload-size">請填另一台已啟動接收端的電腦，不要填一般網站網址。</small></label>
                <label>測試方向<select value={networkConfig.iperfDirection} disabled={networkRunning} onChange={(event) => updateNetwork("iperfDirection", event.target.value)}><option value="upload">上傳｜本機傳到接收端</option><option value="download">下載｜接收端傳回本機（-R）</option></select></label>
                <div className="form-row two"><label>測試時間<input type="number" min="1" max="60" value={networkConfig.durationSeconds} disabled={networkRunning} onChange={(event) => updateNetwork("durationSeconds", event.target.value)} /><small>秒</small></label><label>平行連線<input type="number" min="1" max="16" value={networkConfig.iperfParallelStreams} disabled={networkRunning || networkMode !== "advanced"} onChange={(event) => updateNetwork("iperfParallelStreams", event.target.value)} /><small>條</small></label></div>
                {networkMode === "advanced" && <><label>傳輸協定<select value={networkConfig.iperfProtocol} disabled={networkRunning} onChange={(event) => updateNetwork("iperfProtocol", event.target.value)}><option value="tcp">TCP｜一般檔案與網站</option><option value="udp">UDP｜語音、視訊與即時傳輸</option></select></label>{networkConfig.iperfProtocol === "udp" && <label>目標頻寬<input type="number" min="1" max="10000" value={networkConfig.iperfBandwidthMbps} disabled={networkRunning} onChange={(event) => updateNetwork("iperfBandwidthMbps", event.target.value)} /><small>Mbps</small><span className="payload-size">iPerf3 會嘗試用此速度送出 UDP，再觀察遺失率。</span></label>}<label>暖機時間<input type="number" min="0" max="10" value={networkConfig.iperfOmitSeconds} disabled={networkRunning} onChange={(event) => updateNetwork("iperfOmitSeconds", event.target.value)} /><small>秒</small></label></>}
              </>}
              {networkConfig.iperfRole === "server" && <div className="iperf-server-guide"><strong>請讓另一台電腦連到這台</strong><span>可嘗試的本機 IP：{networkToolStatus?.localIpv4Addresses?.join("、") || "請用 ipconfig 查詢 IPv4 位址"}</span><small>按下方「啟動一次性接收端」後保持此畫面開啟，再到另一台電腦輸入上述 IP。</small></div>}
            </>}
            <label>自訂安全參數（選填）<input value={networkConfig.extraArgs} disabled={networkRunning} onChange={(event) => updateNetwork("extraArgs", event.target.value)} placeholder={networkTool === "nmap" ? "例如 --min-rate 50 -sV" : networkTool === "wireshark" ? "例如 -p -s 128" : "例如 -P 4 --get-server-output"} /><small className="payload-size">可自行輸入參數；程式只接受本工具的安全白名單，不執行外部命令。</small></label>
            <div className="parameter-cheatsheet">
              <strong>常用參數白話說明</strong>
              {networkTool === "nmap" && <><span><code>-sV</code> 看服務名稱與版本</span><span><code>--min-rate 50</code> 每秒至少嘗試 50 次</span><span><code>--max-rate 200</code> 限制掃描速度</span><span><code>--script default,safe</code> 只跑安全腳本</span></>}
              {networkTool === "wireshark" && <><span><code>-p</code> 不開啟混雜模式</span><span><code>-s 128</code> 每包只保留前 128 bytes</span><span><code>-B 4</code> 使用 4 MB 擷取緩衝區</span></>}
              {networkTool === "iperf3" && <><span><code>-R</code> 測下載方向</span><span><code>-P 4</code> 同時四條連線</span><span><code>-u</code> 改測 UDP</span><span><code>-b 100M</code> UDP 目標 100 Mbps</span></>}
            </div>
            {networkNotice && <div className="network-notice">{networkNotice}</div>}
          </div>}

          {activeTab === "reliability" && <div className="reliability-settings">
            <label>排程間隔<select value={scheduleConfig.intervalMs} disabled={scheduleRunning} onChange={(e) => setScheduleConfig((current) => ({ ...current, intervalMs: Number(e.target.value) }))}><option value="60000">每 1 分鐘</option><option value="300000">每 5 分鐘</option><option value="900000">每 15 分鐘</option><option value="3600000">每 1 小時</option></select></label>
            <label>Webhook 告警（選填）<input value={scheduleConfig.webhookUrl} disabled={scheduleRunning} onChange={(e) => setScheduleConfig((current) => ({ ...current, webhookUrl: e.target.value }))} placeholder="https://hooks.example.com/..." /></label>
            <p className="payload-size">排程只會測試你已授權的 URL；異常或 HTTP 5xx 時送出 JSON 告警。</p>
          </div>}
          <label className="authorization">
            <input type="checkbox" checked={config.authorized} disabled={running || monitorRunning || networkRunning} onChange={(e) => update("authorized", e.target.checked)} />
            <span>授權確認<br /><small>已取得目標系統授權，允許執行壓力測試或被動檢查。</small></span>
          </label>
          {error && <div className="error-banner">{error}</div>}
          {activeTab === "network" && networkBlockReason && !networkRunning && <div className="network-action-required"><strong>目前不能開始</strong><span>{networkBlockReason}</span></div>}
          {activeTab === "network" ? (
            networkRunning
              ? <button className="stop-button" onClick={stopNetworkAnalysis}><span>■</span>停止 {networkTool === "nmap" ? "Nmap" : networkTool === "wireshark" ? "Wireshark" : "iPerf3"}</button>
              : <button className="start-button network-run-button" disabled={Boolean(networkBlockReason)} onClick={runNetworkAnalysis}><span>⌁</span>{networkBlockReason ? "尚缺必要設定" : networkTool === "nmap" ? `執行 ${networkMode === "advanced" ? "進階盤點" : "基礎掃描"}` : networkTool === "wireshark" ? `開始 ${networkMode === "advanced" ? "進階封包分析" : "基礎封包擷取"}` : networkConfig.iperfRole === "server" ? "啟動一次性接收端" : `開始 ${networkMode === "advanced" ? "進階效能分析" : "基礎網路測速"}`}</button>
          ) : activeTab === "monitor" ? (
            !monitorRunning
              ? <button className="start-button monitor-button" disabled={!config.authorized} onClick={startMonitor}><span>●</span>開始存活監控</button>
              : <button className="stop-button" onClick={stopMonitor}><span>■</span>停止監控並結算</button>
          ) : activeTab === "security" ? (
            <button className="start-button security-button" disabled={!config.authorized || securityRunning} onClick={runSecurityCheck}><span>◇</span>{securityRunning ? "檢查中…" : "執行資安基線"}</button>
          ) : activeTab === "probe" ? (
            <button className="start-button probe-button" disabled={!config.authorized || targetRunning} onClick={runTargetProbe}><span>⌖</span>{targetRunning ? "偵測中…" : "開始目標偵測"}</button>
          ) : activeTab === "global" ? (
            <button className="start-button global-button" disabled={!config.authorized || globalRunning} onClick={runGlobalProbe}><span>◎</span>{globalRunning ? "各國測試中…" : globalConfig.mode === "public" ? "開始免部署全球測試" : "開始自架節點測試"}</button>
          ) : activeTab === "reliability" ? (
            !scheduleRunning ? <button className="start-button" disabled={!config.authorized} onClick={startSchedule}><span>▶</span>開始排程監控</button> : <button className="stop-button" onClick={stopSchedule}><span>■</span>停止排程監控</button>
          ) : !running ? (
            <button className="start-button" disabled={!config.authorized} onClick={() => start()}><span>▶</span>{autoTune.enabled ? `開始自動壓測（${normalizeAutoTune(autoTune).maxRounds} 輪）` : "開始壓測"}</button>
          ) : (
            <button className="stop-button" onClick={stop}><span>■</span>緊急停止</button>
          )}

          {activeTab === "load" && <section className="threshold-card">
            <div className="threshold-title"><strong>驗收門檻</strong><span>全部可調整</span></div>
            <ThresholdInput label="最低請求/秒" value={thresholds.minRps} unit="req/s" onChange={(value) => updateThreshold("minRps", value)} />
            <ThresholdInput label="最大 P95 延遲" value={thresholds.maxP95} unit="ms" onChange={(value) => updateThreshold("maxP95", value)} />
            <ThresholdInput label="最大失敗率" value={thresholds.maxFailureRate} unit="%" onChange={(value) => updateThreshold("maxFailureRate", value)} />
            <ThresholdInput label="最低完成請求" value={thresholds.minCompleted} unit="req" onChange={(value) => updateThreshold("minCompleted", value)} />
            <ThresholdInput label="最大平均回應大小" value={thresholds.maxAverageKb} unit="KB" onChange={(value) => updateThreshold("maxAverageKb", value)} />
          </section>}
          <p className="legal">{activeTab === "network"
            ? "只可分析你擁有或已獲授權的系統。進階 Nmap 使用 default,safe 腳本，不執行漏洞利用；封包檔可能含敏感資料，請妥善保存。"
            : activeTab === "security"
            ? "資安基線只做非破壞性被動檢查，不執行漏洞利用。"
            : activeTab === "probe"
              ? "公網 Geo 由 ipwho.is 推估；私有 IP 不會送往外部服務。存活以 DNS、TCP 與 HTTP 服務為準。"
              : activeTab === "monitor"
                ? "監控從這台電腦發出低頻 HTTP/HTTPS 請求；鴨鴨測需保持開啟。24 小時與 1 天為相同時長。"
              : activeTab === "global"
                ? globalConfig.mode === "public"
                  ? "公開目標與國家會送至 Globalping；每國執行 DNS、HTTP/TLS、Ping、TCP Traceroute 共 4 項。匿名額度目前為每小時 250 次測試。"
                  : "目標 URL 會傳送給你設定的遠端 Agent。私網目標需要 Agent 已連入相同 VPN；單次最多 12 個節點。"
              : "壓測前會先檢查 TLS、授權與路徑，避免無效請求造成 100% 失敗率。僅可對已授權系統執行。"}</p>
        </aside>

        {activeTab === "network"
          ? <NetworkToolsPanel tool={networkTool} mode={networkMode} config={networkConfig} status={networkToolStatus} result={networkResult} resultStates={networkResultStates} runStates={networkRuns} running={networkRunning} installing={networkInstalling} onInstall={installNetworkTool} onSaveCapture={saveNetworkCapture} />
          : activeTab === "reliability"
          ? <ReliabilityPanel history={history} compare={historyCompare} systemSamples={systemSamples} scheduleRunning={scheduleRunning} scheduleLast={scheduleLast} onRefresh={refreshHistory} onClear={clearHistory} />
          : activeTab === "security"
          ? <SecurityPanel result={securityResult} running={securityRunning} />
          : activeTab === "probe"
            ? <TargetProbePanel
              result={targetResult}
              running={targetRunning}
              diagnosis={targetDiagnosis}
              routeTrace={routeTrace}
              routeTraceRunning={routeTraceRunning}
              onRunRouteTrace={runRouteTrace}
              onApplySuggestedUrl={(url) => {
                update("url", url);
                setTargetResult(null);
                setRouteTrace(null);
                setError("");
              }}
            />
            : activeTab === "monitor"
              ? <UptimePanel progress={monitorProgress} report={monitorReport} samples={monitorSamples} routeTraces={monitorRouteTraces} incidents={monitorIncidents} running={monitorRunning} onExport={exportMonitor} />
            : activeTab === "global"
              ? <GlobalProbePanel result={globalResult} running={globalRunning} mode={globalConfig.mode} />
            : <section className={`dashboard load-dashboard ${diagnosis ? "has-diagnosis" : ""}`}>
          <div className="summary-bar">
            <div>
              <h2>測試總覽</h2>
              <p>{running
                ? autoStatus.phase === "waiting"
                  ? `第 ${autoStatus.round} 輪完成，${autoStatus.countdown} 秒後自動執行第 ${autoStatus.round + 1} 輪`
                  : `${config.url} · 第 ${autoStatus.round}/${autoStatus.total} 輪 · ${sample.active || 0} workers`
                : report ? `${report.stopped ? "已停止" : "已完成"} · ${report.target}` : "設定參數後勾選授權即可開始"}</p>
            </div>
            {report && <div className={`overall ${overallPassed ? "pass" : "fail"}`}><span>{overallPassed ? "✓" : "!"}</span>{overallPassed ? "通過" : "需調整"}</div>}
            {report && <button className="export-button" onClick={exportReport}>↓ 匯出 JSON</button>}
          </div>
          <div className="progress-track"><span style={{ width: `${progress}%` }} /></div>
          <div className="metrics">
            <MetricCard label="最低請求/秒 (req/s)" value={running ? formatNumber(sample.rps) : report?.summary.requestsPerSecond || "--"} targetLabel={`目標 ${formatNumber(thresholds.minRps)}`} passed={report ? metricPass.rps : undefined} />
            <MetricCard label="最大 P95 延遲 (ms)" value={running ? formatNumber(sample.p95) : report?.latencyMs.p95 || "--"} targetLabel={`目標 ≤ ${formatNumber(thresholds.maxP95)}`} passed={report ? metricPass.p95 : undefined} />
            <MetricCard label="最大失敗率 (%)" value={running ? sample.failureRate : report?.summary.failureRate ?? "--"} targetLabel={`目標 ≤ ${thresholds.maxFailureRate}%`} passed={report ? metricPass.failure : undefined} accent={Number(sample.failureRate || report?.summary.failureRate) > 0 ? "red" : "green"} />
            <MetricCard label="最低完成請求 (req)" value={formatNumber(running ? sample.completed : report?.summary.completed)} targetLabel={`目標 ${formatNumber(thresholds.minCompleted)}`} passed={report ? metricPass.completed : undefined} />
            <MetricCard label="最大平均回應大小 (KB)" value={formatBytes(running ? sample.averageResponseBytes : report?.summary.averageResponseBytes)} targetLabel={`目標 ≤ ${thresholds.maxAverageKb} KB`} passed={report ? metricPass.size : undefined} accent="orange" />
          </div>

          <DiagnosisPanel diagnosis={diagnosis} onRunNext={runNextSuggested} running={running} />

          <div className="analysis-grid">
            <section className="panel chart-panel">
              <div className="panel-head"><h3>即時延遲</h3><div className="legend"><span className="green">P50</span><span className="blue">P95</span><span className="purple">P99</span><em>單位：ms</em></div></div>
              <LineChart samples={samples} maxP95={thresholds.maxP95} />
            </section>
            <StatusDonut statuses={sample.statuses} completed={sample.completed} failureRate={sample.failureRate} />
          </div>

          <section className="panel log-panel">
            <div className="panel-head"><h3>事件紀錄</h3><span>最近事件</span></div>
            <div className="log-table">
              <div className="log-row log-header"><span>時間</span><span>等級</span><span>狀態</span><span>事件</span></div>
              {!sample.logs?.length && <div className="empty-state">尚無事件紀錄</div>}
              {sample.logs?.map((item, index) => <div className="log-row" key={`${item.time}-${index}`}><span>{item.time}</span><span className={`level ${item.level.toLowerCase()}`}>{item.level}</span><span>{item.status}</span><span>{item.message}</span></div>)}
            </div>
          </section>
        </section>}
      </div>
      {aboutOpen && <div className="modal-backdrop" role="presentation" onMouseDown={() => setAboutOpen(false)}>
        <section className="about-dialog" role="dialog" aria-modal="true" aria-labelledby="about-title" onMouseDown={(event) => event.stopPropagation()}>
          <button className="modal-close" aria-label="關閉" onClick={() => setAboutOpen(false)}>×</button>
          <div className="about-mark">鴨</div>
          <h2 id="about-title">鴨鴨測</h2>
          <p className="about-version">版本 {APP_VERSION}</p>
          <p>整合壓力測試、目標偵測、24 小時存活監控、全球節點與資安基線的桌面檢測工具。</p>
          <dl><div><dt>作者</dt><dd>王宥傑</dd></div><div><dt>報告</dt><dd>HTML / JSON</dd></div><div><dt>平台</dt><dd>Windows</dd></div></dl>
          <button className="primary-dialog-button" onClick={() => setAboutOpen(false)}>完成</button>
        </section>
      </div>}
    </main>
  );
}

import React from "react";

const formatNumber = (value) => new Intl.NumberFormat("zh-TW").format(Number(value) || 0);
const formatBytes = (value) => {
  const bytes = Number(value) || 0;
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
};

const NMAP_COMMANDS = {
  basic: {
    label: "基礎掃描",
    command: "nmap -sT -Pn -n -T3 --max-retries 1 --reason --top-ports 100 --host-timeout 60s -oX - <目標>",
    description: "找出常用連接埠是否開放，速度適中，不執行漏洞利用。",
    flags: [
      ["-sT", "使用完整 TCP 連線測試，適合一般 Windows 電腦。"],
      ["-Pn", "即使目標不回 Ping，也繼續檢查服務入口。"],
      ["-n", "不反查主機名稱，減少 DNS 等待與不必要的外部查詢。"],
      ["-T3", "使用平衡速度，避免過快造成誤判或過度流量。"],
      ["--max-retries 1", "每次探測最多重試一次，避免無回應目標拖住整個流程。"],
      ["--top-ports 100", "檢查最常見的 100 個服務入口。"],
      ["--reason", "記錄為什麼判定入口開放、關閉或被過濾。"],
    ],
  },
  advanced: {
    label: "進階盤點",
    command: "nmap -sT -Pn -n -T3 --max-retries 1 --reason --top-ports 1000 -sV --version-light --script default,safe --traceroute --host-timeout 180s -oX - <目標>",
    description: "除連接埠外，也辨識服務版本、執行官方安全腳本並追蹤路由。",
    flags: [
      ["-sV --version-light", "辨識服務名稱與版本，使用較輕量的探測強度。"],
      ["-n --max-retries 1", "略過 DNS 反查並限制重試，讓掃描時間可預期。"],
      ["--script default,safe", "只執行 Nmap 標記為預設或安全的腳本，不包含漏洞利用。"],
      ["--traceroute", "記錄到目標途中經過的路由節點。"],
      ["-O --osscan-limit", "選配：推測作業系統；需要較高權限，結果不保證百分之百準確。"],
      ["--top-ports 1000", "擴大檢查最常見的 1,000 個入口，時間會比基礎模式長。"],
    ],
  },
};

const WIRESHARK_COMMANDS = {
  basic: {
    label: "基礎擷取",
    command: "tshark -i <網卡> -a duration:15 -c 500 -f \"host <目標 IP>\" -w <封包檔.pcapng>",
    description: "只擷取指定目標的短時間流量，整理協定、流量與常見異常。",
    flags: [
      ["-i", "指定要觀察的網卡，例如乙太網路或 Wi-Fi。"],
      ["-a duration:15", "15 秒後自動停止，不會一直占用磁碟。"],
      ["-c 500", "最多擷取 500 個封包，達到上限就停止。"],
      ["-f host …", "在擷取階段只保留與目標 IP 有關的流量。"],
      ["-w", "保存為 Wireshark 可開啟的 pcapng 證據檔。"],
    ],
  },
  advanced: {
    label: "進階分析",
    command: "tshark -i <網卡> -a duration:30 -c 2000 -f \"host <目標 IP> and <自訂條件>\" -w <封包檔.pcapng>",
    description: "延長擷取並加入篩選條件，分析 TCP 重傳、RST、DNS、HTTP、TLS 與連線對話。",
    flags: [
      ["Capture Filter", "擷取前就排除無關封包，例如 tcp port 443；可降低檔案大小。"],
      ["Display Filter", "擷取後再篩選報告，例如 tcp.analysis.retransmission；原始封包仍保留。"],
      ["tcp.analysis.*", "由 Wireshark 判讀重傳、亂序、重複 ACK 等傳輸跡象。"],
      ["dns / http / tls", "整理網域查詢、網站狀態碼與 TLS 主機名稱。"],
      ["Conversations", "統計哪些端點彼此傳輸最多封包，協助找出主要流量。"],
    ],
  },
};

const IPERF3_COMMANDS = {
  basic: {
    label: "基礎測速",
    command: "iperf3 -c <接收端 IP> -J -p 5201 -t 10 --connect-timeout 5000",
    description: "用一條 TCP 連線測量兩台電腦之間的實際傳輸能力，適合第一次使用。",
    flags: [
      ["-c", "連到另一台已啟動 iPerf3 接收端的電腦。"],
      ["-J", "用 JSON 格式輸出，讓鴨鴨測能翻譯成中文報告。"],
      ["-p 5201", "使用 iPerf3 預設連接埠 5201；兩端必須相同。"],
      ["-t 10", "連續傳送 10 秒，避免只看瞬間數字。"],
      ["--connect-timeout 5000", "5 秒連不上就停止，避免畫面一直等待。"],
    ],
  },
  advanced: {
    label: "進階效能分析",
    command: "iperf3 -c <接收端 IP> -J -p 5201 -t 20 -P 4 -R",
    description: "可選上下行、TCP/UDP、多條平行連線、目標頻寬與暖機時間。",
    flags: [
      ["-R", "反向測試：由接收端傳回本機，代表下載方向。"],
      ["-P 4", "同時開四條資料流，觀察多連線時能否用滿頻寬。"],
      ["-u -b 100M", "改用 UDP 並以 100 Mbps 傳送，可觀察遺失率與抖動。"],
      ["-O 2", "前兩秒只暖機、不列入統計，降低剛連線時的誤差。"],
      ["-1（接收端）", "接收端完成一輪後自動結束，不會永久開著服務。"],
    ],
  },
};

function CopyButton({ text }) {
  const copy = async () => {
    try { await navigator.clipboard.writeText(text); } catch { /* clipboard may be restricted */ }
  };
  return <button className="copy-command" onClick={copy}>複製指令</button>;
}

const formatResultTime = (result) => result?.checkedAt ? new Date(result.checkedAt).toLocaleString("zh-TW", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }) : "";

function resultSnapshot(key, state) {
  const latest = state?.latest;
  const lastSuccess = state?.lastSuccess;
  if (!latest) return { value: "尚未執行測試", detail: "執行後會在這裡保留最後數值" };
  if (key === "nmap") {
    if (latest.incomplete || latest.status === "timeout") {
      return {
        value: "本次掃描未完成",
        detail: lastSuccess ? `上次成功 ${lastSuccess.summary?.openPorts ?? "--"} 個入口 · ${formatResultTime(lastSuccess)}` : `已達時間上限 · ${formatResultTime(latest)}`,
        warning: true,
      };
    }
    return { value: `${latest.summary?.openPorts ?? "--"} 個開放入口`, detail: `${latest.summary?.onlineHosts ?? "--"} 台有回應 · ${formatResultTime(latest)}` };
  }
  if (key === "wireshark") {
    const packets = latest.summary?.packetCount ?? "--";
    return { value: `${formatNumber(packets)} 個封包`, detail: `${packets === 0 ? "未觀察到符合流量" : `TCP 重傳 ${latest.summary?.anomalies?.retransmissions ?? 0}`} · ${formatResultTime(latest)}`, warning: packets === 0 };
  }
  return { value: `${latest.summary?.measuredMbps ?? "--"} Mbps`, detail: `${latest.direction === "download" ? "下載" : "上傳"} · ${formatResultTime(latest)}` };
}

function ToolStatus({ status, resultStates, runStates, onInstall, installing }) {
  const cards = [
    ["nmap", "Nmap", "掃描連接埠、服務版本與路由"],
    ["wireshark", "Wireshark / TShark", "擷取封包並分析連線品質"],
    ["iperf3", "iPerf3", "測量兩台電腦之間的實際頻寬"],
  ];
  return <div className="tool-status-grid">
    {cards.map(([key, title, subtitle]) => {
      const item = status?.[key];
      const run = runStates?.[key];
      const state = run?.running ? "running" : !item?.installed ? "missing" : item.ready === false ? "warning" : "ready";
      const snapshot = run?.running
        ? { value: `${run.message || "執行中"}`, detail: `已執行 ${run.elapsedSeconds || 0} 秒 · 可切換頁面查看其他工具`, warning: false }
        : resultSnapshot(key, resultStates?.[key]);
      return <article className={`tool-status-card ${state}`} key={key}>
        <div className="tool-icon">{key === "nmap" ? "N" : key === "wireshark" ? "W" : "i"}</div>
        <div className="tool-status-copy">
          <span>{title}</span>
          <strong>{run?.running ? `執行中 · ${run.elapsedSeconds || 0} 秒` : !item?.installed ? (status ? "尚未安裝" : "正在檢查…") : item.ready === false ? "已安裝，但需要確認" : "執行檢查通過"}</strong>
          <small>{item?.healthMessage || item?.version || subtitle}</small>
          <div className={`tool-last-result ${snapshot.warning ? "warning" : ""}`}><b>{snapshot.value}</b><small>{snapshot.detail}</small></div>
        </div>
        {item && !item.installed && <button disabled={installing === key} onClick={() => onInstall(key)}>{installing === key ? "安裝中…" : key === "iperf3" ? "自動下載安裝" : status?.installerAvailable ? "一鍵安裝" : "開啟官方下載"}</button>}
      </article>;
    })}
  </div>;
}

const PHASE_LABELS = {
  idle: "尚未執行", starting: "啟動工具", preparing: "檢查環境", resolving: "解析目標", scanning: "掃描服務",
  capturing: "擷取封包", analyzing: "分析封包", waiting: "等待測試端", testing: "傳輸測速", parsing: "整理結果",
  stopping: "正在停止", stopped: "已停止", completed: "已完成", incomplete: "未完整完成", error: "執行失敗",
};

function NetworkRunProgress({ tool, run }) {
  if (!run || run.phase === "idle") return null;
  const hasEstimate = Number(run.estimatedTotalSeconds) > 0;
  const movingProgress = run.running && hasEstimate
    ? Math.min(90, Math.max(run.progress || 0, (run.progress || 0) + ((run.elapsedSeconds || 0) / Math.max(1, run.estimatedTotalSeconds || 60)) * (90 - (run.progress || 0))))
    : run.progress || 100;
  const tone = run.phase === "error" ? "error" : run.phase === "incomplete" || run.phase === "stopped" ? "warning" : run.phase === "completed" ? "complete" : "running";
  return <section className={`network-run-progress ${tone}`}>
    <div className="network-run-head">
      <div><span>{tool === "nmap" ? "Nmap" : tool === "wireshark" ? "Wireshark / TShark" : "iPerf3"} 執行流程</span><strong>{PHASE_LABELS[run.phase] || run.phase}</strong></div>
      <b>{run.elapsedSeconds || 0} 秒</b>
    </div>
    <div className={`network-progress-track ${run.running && !hasEstimate ? "indeterminate" : ""}`}><i style={{ width: `${movingProgress}%` }} /></div>
    <p>{run.message}</p>
    {run.detail && <code>{run.detail}</code>}
    <div className="network-progress-log">
      {(run.logs || []).slice(-5).map((item, index) => <div key={`${item.at}-${index}`}><time>{new Date(item.at).toLocaleTimeString("zh-TW", { hour12: false })}</time><b>{PHASE_LABELS[item.phase] || item.phase}</b><span>{item.message}</span></div>)}
    </div>
  </section>;
}

function ReportWarnings({ items = [] }) {
  if (!items.length) return null;
  return <section className="network-report-warnings"><strong>本次測試需要注意</strong>{items.map((item, index) => <p key={index}>{item}</p>)}</section>;
}

function IncompleteRunReport({ tool, run }) {
  if (!run || run.running || !["stopped", "incomplete", "error"].includes(run.phase)) return null;
  const toolName = tool === "nmap" ? "Nmap" : tool === "wireshark" ? "Wireshark / TShark" : "iPerf3";
  const suggestions = tool === "nmap"
    ? ["保留目前連接埠範圍重試，或先改成網站服務入口範本。", "完整模式可持續等待；若目標長時間不回覆，可手動停止並查看本次原因。"]
    : tool === "wireshark"
      ? ["確認選到正在使用的網卡，且 Npcap 擷取介面可用。", "即使沒有符合篩選條件的封包，也會保留擷取階段與實際指令。"]
      : ["接收端必須先啟動，兩台電腦的連接埠與防火牆規則必須一致。", "接收端會持續等待到測試端連入，可使用停止按鈕結束等待。"];
  return <div className="network-report-body incomplete-run-report">
    <ReportWarnings items={[run.diagnostic?.reason || run.message]} />
    <div className="network-metrics">
      <article><span>本次結果</span><strong className="warn">{run.diagnostic?.outcome || "未完成"}</strong><small>{toolName}</small></article>
      <article><span>已執行時間</span><strong>{run.elapsedSeconds ?? 0}<em> 秒</em></strong><small>實際經過時間</small></article>
      <article><span>最後階段</span><strong>{PHASE_LABELS[run.phase] || run.phase}</strong><small>不是空白結果</small></article>
      <article><span>過程紀錄</span><strong>{run.logs?.length || 0}<em> 筆</em></strong><small>可供後續判讀</small></article>
    </div>
    <PlainSummary items={[`本次 ${toolName} 沒有產生可量測數值，因此不會用 0 假裝測試成功。`, ...suggestions]} />
    {run.detail && <ExecutedCommands commands={[run.detail]} />}
  </div>;
}

function CommandGuide({ tool, mode, config }) {
  const guide = tool === "nmap" ? NMAP_COMMANDS[mode] : tool === "wireshark" ? WIRESHARK_COMMANDS[mode] : IPERF3_COMMANDS[mode];
  const displayedCommand = tool === "nmap"
    ? (config?.nmapCompletionMode === "time_limit"
      ? guide.command.replace(/--host-timeout \d+s/, `--host-timeout ${config?.timeoutSeconds || (mode === "advanced" ? 180 : 60)}s`)
      : guide.command.replace(/\s*--host-timeout \d+s/, ""))
    : guide.command;
  return <section className="network-guide panel">
    <div className="panel-head">
      <div><h3>{guide.label}會執行什麼？</h3><p>{guide.description}</p></div>
      <span>指令逐項說明</span>
    </div>
    <div className="command-box"><code>{displayedCommand}</code><CopyButton text={displayedCommand} /></div>
    <div className="command-flags">
      {guide.flags.map(([flag, explanation]) => <article key={flag}><code>{flag}</code><p>{explanation}</p></article>)}
    </div>
  </section>;
}

function PlainSummary({ items = [] }) {
  return <section className="plain-summary">
    <div className="plain-summary-title"><span>白話</span><div><h3>先看結論</h3><p>不熟網路也能直接閱讀的重點</p></div></div>
    <div className="plain-summary-list">{items.map((item, index) => <p key={index}><b>{index + 1}</b>{item}</p>)}</div>
  </section>;
}

function NmapReport({ result, lastSuccessfulResult }) {
  const ports = result.hosts?.flatMap((host) => host.ports || []).filter((port) => port.state === "open") || [];
  const firstHost = result.hosts?.[0];
  const incomplete = result.incomplete || result.status === "timeout";
  return <div className="network-report-body">
    <ReportWarnings items={result.warnings} />
    {incomplete && lastSuccessfulResult && <section className="network-last-success"><span>上次成功結果</span><strong>{lastSuccessfulResult.summary?.openPorts ?? "--"} 個開放入口 · {lastSuccessfulResult.summary?.onlineHosts ?? "--"} 台主機有回應</strong><small>{formatResultTime(lastSuccessfulResult)}；本次逾時不會覆蓋這筆有效數值。</small></section>}
    <div className="network-metrics">
      <article><span>主機狀態</span><strong className={incomplete ? "warn" : result.summary.onlineHosts ? "good" : "bad"}>{incomplete ? "掃描未完成" : result.summary.onlineHosts ? "有回應" : "未確認"}</strong><small>{firstHost?.addresses?.map((item) => item.address).join("、") || result.target}</small></article>
      <article><span>開放入口</span><strong>{incomplete ? "--" : result.summary.openPorts}</strong><small>{incomplete ? "未完成，不能判定" : "本次掃描範圍"}</small></article>
      <article><span>優先確認</span><strong className={incomplete ? "warn" : result.summary.highAttention ? "warn" : "good"}>{incomplete ? "--" : result.summary.highAttention}</strong><small>{incomplete ? "未完成，不能判定" : "管理、共享或資料庫服務"}</small></article>
      <article><span>掃描耗時</span><strong>{result.summary.elapsedSeconds?.toFixed(1) || "--"}<em> 秒</em></strong><small>{result.mode === "advanced" ? "進階盤點" : "基礎掃描"}</small></article>
    </div>
    <PlainSummary items={result.plainSummary} />
    <section className="panel network-table-panel">
      <div className="panel-head"><div><h3>開放連接埠</h3><p>開放不等於有漏洞；先確認是否為預期服務</p></div><span>{ports.length} 個入口</span></div>
      {ports.length ? <div className="network-table port-table">
        <div className="network-table-head"><span>入口</span><span>用途</span><span>辨識結果</span><span>注意程度</span><span>白話建議</span></div>
        {ports.map((port) => <div className="network-table-row" key={`${port.protocol}-${port.port}`}>
          <strong>{port.port}/{port.protocol}</strong>
          <span>{port.displayName}</span>
          <span>{[port.product || port.service, port.version].filter(Boolean).join(" ") || "未辨識"}</span>
          <span><i className={`attention ${port.attention === "高" ? "high" : port.attention === "中" ? "medium" : "low"}`}>{port.attention}</i></span>
          <p>{port.explanation}</p>
        </div>)}
      </div> : <div className="empty-state compact">{incomplete ? "掃描未完成，無法判定是否有開放連接埠。" : "本次範圍內沒有找到開放連接埠。"}</div>}
    </section>
    {result.mode === "advanced" && <div className="network-advanced-grid">
      <section className="panel"><div className="panel-head"><h3>作業系統推測</h3><span>僅供參考</span></div><div className="simple-list">{firstHost?.osMatches?.length ? firstHost.osMatches.map((item) => <p key={item.name}><strong>{item.name}</strong><span>信心 {item.accuracy}%</span></p>) : <p>沒有足夠證據判斷作業系統。</p>}</div></section>
      <section className="panel"><div className="panel-head"><h3>路由節點</h3><span>{firstHost?.hops?.length || 0} hops</span></div><div className="simple-list">{firstHost?.hops?.length ? firstHost.hops.map((hop) => <p key={`${hop.ttl}-${hop.ip}`}><strong>第 {hop.ttl} 跳 · {hop.ip}</strong><span>{hop.rttMs == null ? "未回覆延遲" : `${hop.rttMs} ms`}</span></p>) : <p>沒有取得路由節點；路由器不回覆不等於斷線。</p>}</div></section>
    </div>}
    <ExecutedCommands commands={[result.command]} />
    <Glossary items={result.glossary} />
  </div>;
}

function ProtocolBars({ items = [], total = 0 }) {
  return <div className="protocol-bars">{items.slice(0, 10).map((item) => <div key={item.name}><span>{item.name}</span><div><i style={{ width: `${Math.max(2, item.count / Math.max(1, total) * 100)}%` }} /></div><strong>{formatNumber(item.count)}</strong></div>)}</div>;
}

function WiresharkReport({ result, onSaveCapture }) {
  const { summary } = result;
  const anomalyCards = [
    ["TCP 重傳", summary.anomalies.retransmissions, "資料未被確認而再次傳送"],
    ["RST 重設", summary.anomalies.resets, "連線被其中一端立即終止"],
    ["DNS 錯誤", summary.anomalies.dnsErrors, "網域不存在或查詢處理失敗"],
    ["HTTP 錯誤", summary.anomalies.httpErrors, "網站回覆 4xx 或 5xx"],
  ];
  return <div className="network-report-body">
    <ReportWarnings items={result.warnings} />
    <div className="network-metrics">
      <article><span>封包數</span><strong>{formatNumber(summary.packetCount)}</strong><small>符合目前篩選條件</small></article>
      <article><span>資料量</span><strong>{formatBytes(summary.totalBytes)}</strong><small>擷取檔實際流量</small></article>
      <article><span>平均往返</span><strong>{summary.anomalies.averageRttMs == null ? "--" : summary.anomalies.averageRttMs.toFixed(1)}<em> ms</em></strong><small>有 TCP ACK 樣本時顯示</small></article>
      <article><span>主要協定</span><strong>{summary.protocols[0]?.name || "--"}</strong><small>{summary.durationSeconds} 秒擷取</small></article>
    </div>
    <PlainSummary items={summary.plainSummary} />
    <div className="network-analysis-grid">
      <section className="panel"><div className="panel-head"><div><h3>協定分布</h3><p>這段流量主要在做什麼</p></div><span>{summary.protocols.length} 種</span></div><ProtocolBars items={summary.protocols} total={summary.packetCount} /></section>
      <section className="panel"><div className="panel-head"><div><h3>異常訊號</h3><p>數字為 0 通常代表未看到該跡象</p></div><span>自動判讀</span></div><div className="anomaly-grid">{anomalyCards.map(([name, value, help]) => <article className={value ? "has-value" : ""} key={name}><span>{name}</span><strong>{formatNumber(value)}</strong><small>{help}</small></article>)}</div></section>
    </div>
    <section className="panel network-table-panel">
      <div className="panel-head"><div><h3>主要連線對話</h3><p>哪兩個端點之間出現最多封包</p></div><span>Top {Math.min(20, summary.conversations.length)}</span></div>
      <div className="conversation-list">{summary.conversations.slice(0, 20).map((item) => <p key={item.name}><span>{item.name}</span><strong>{formatNumber(item.count)} 個封包</strong></p>)}</div>
    </section>
    {result.mode === "advanced" && <section className="panel network-table-panel">
      <div className="panel-head"><div><h3>封包明細</h3><p>保留前 {Math.min(1000, result.packets.length)} 筆，完整內容在 pcapng</p></div><span>{result.packets.length} 筆</span></div>
      <div className="network-table packet-table"><div className="network-table-head"><span>時間</span><span>來源</span><span>目的地</span><span>協定</span><span>大小</span><span>判讀</span></div>{result.packets.slice(0, 300).map((packet) => <div className="network-table-row" key={packet.number}><span>{packet.time ? new Date(packet.time).toLocaleTimeString("zh-TW", { hour12: false }) : "--"}</span><span>{packet.source}{packet.sourcePort ? `:${packet.sourcePort}` : ""}</span><span>{packet.destination}{packet.destinationPort ? `:${packet.destinationPort}` : ""}</span><strong>{packet.protocol}</strong><span>{packet.bytes} B</span><span>{packet.retransmission ? "TCP 重傳" : packet.reset ? "RST 重設" : packet.httpStatus ? `HTTP ${packet.httpStatus}` : "一般封包"}</span></div>)}</div>
    </section>}
    <section className="capture-evidence"><div><span>PCAPNG 原始證據</span><strong>可用 Wireshark 開啟，保留完整封包供後續追查</strong><small>封包可能包含敏感資料，分享前請確認內容與存取權限。</small></div><button onClick={() => onSaveCapture(result.captureFile)}>儲存封包檔</button></section>
    <ExecutedCommands commands={[result.captureCommand, result.analyzeCommand]} />
    <Glossary items={result.glossary} />
  </div>;
}

function Iperf3Report({ result }) {
  const summary = result.summary || {};
  return <div className="network-report-body">
    <ReportWarnings items={result.warnings} />
    <div className="network-metrics">
      <article><span>本次實測</span><strong>{summary.measuredMbps ?? 0}<em> Mbps</em></strong><small>{result.direction === "download" ? "下載方向" : "上傳方向"}</small></article>
      <article><span>測試協定</span><strong>{String(result.protocol || "tcp").toUpperCase()}</strong><small>{result.mode === "advanced" ? "進階分析" : "基礎測速"}</small></article>
      <article><span>TCP 重傳</span><strong className={summary.retransmits ? "warn" : "good"}>{summary.retransmits ?? 0}</strong><small>資料重新傳送次數</small></article>
      <article><span>UDP 遺失／抖動</span><strong className={(summary.lossPercent || 0) > 1 ? "warn" : "good"}>{summary.lossPercent ?? 0}%</strong><small>{summary.jitterMs ?? 0} ms jitter</small></article>
    </div>
    <PlainSummary items={result.plainSummary} />
    {result.intervals?.length > 0 && <section className="panel network-table-panel">
      <div className="panel-head"><div><h3>每秒速度變化</h3><p>觀察速度是否忽高忽低；越平穩通常越好</p></div><span>{result.intervals.length} 個區間</span></div>
      <div className="protocol-bars">{result.intervals.slice(0, 30).map((item, index) => <div className="protocol-row" key={`${item.seconds}-${index}`}><span>{item.seconds.toFixed(1)} 秒</span><div><i style={{ width: `${Math.max(2, Math.min(100, (item.mbps / Math.max(...result.intervals.map((entry) => entry.mbps || 1))) * 100))}%` }} /></div><strong>{item.mbps ?? 0} Mbps</strong></div>)}</div>
    </section>}
    <section className="panel command-evidence"><div className="panel-head"><div><h3>本次實際指令</h3><p>可複製到命令提示字元重現測試</p></div><CopyButton text={result.command} /></div><code>{result.command}</code></section>
    <Glossary items={result.glossary} />
  </div>;
}

function ExecutedCommands({ commands = [] }) {
  return <section className="panel executed-commands"><div className="panel-head"><div><h3>本次實際執行指令</h3><p>完整保留，方便進階人員重現與稽核</p></div><span>{commands.length} 段</span></div>{commands.map((command, index) => <div className="command-box" key={index}><code>{command}</code><CopyButton text={command} /></div>)}</section>;
}

function Glossary({ items = [] }) {
  return <section className="panel glossary"><div className="panel-head"><div><h3>名詞翻譯</h3><p>看不懂技術名詞時先看這裡</p></div><span>新手友善</span></div><div>{items.map((item) => <article key={item.term}><strong>{item.term}</strong><p>{item.meaning}</p></article>)}</div></section>;
}

export default function NetworkToolsPanel({ tool, mode, config, status, result, resultStates, runStates, running, installing, onInstall, onSaveCapture }) {
  const statusItems = status ? [status.nmap, status.wireshark, status.iperf3] : [];
  const readinessLabel = !status ? "正在檢查工具" : statusItems.every((item) => item?.ready) ? "三項工具檢查完成" : "部分工具需要確認";
  return <section className="dashboard network-dashboard">
    <div className="summary-bar network-hero">
      <div><span className="eyebrow">NETWORK LAB</span><h2>網路透視</h2><p>Nmap 盤點服務入口、Wireshark 解讀封包、iPerf3 測量兩台電腦的實際頻寬；技術資料自動翻成中文白話。</p></div>
      <div className={`probe-state ${running ? "offline" : status && statusItems.every((item) => item?.ready) ? "alive" : "caution"}`}><i />{running ? "分析執行中" : readinessLabel}</div>
    </div>
    <ToolStatus status={status} resultStates={resultStates} runStates={runStates} onInstall={onInstall} installing={installing} />
    <NetworkRunProgress tool={tool} run={runStates?.[tool]} />
    {!result && !running && (!runStates?.[tool] || runStates[tool].phase === "idle") && <CommandGuide tool={tool} mode={mode} config={config} />}
    {!result && <IncompleteRunReport tool={tool} run={runStates?.[tool]} />}
    {!running && result?.type === "nmap-report" && <NmapReport result={result} lastSuccessfulResult={resultStates?.nmap?.lastSuccess === result ? null : resultStates?.nmap?.lastSuccess} />}
    {!running && result?.type === "wireshark-report" && <WiresharkReport result={result} onSaveCapture={onSaveCapture} />}
    {!running && result?.type === "iperf3-report" && <Iperf3Report result={result} />}
  </section>;
}

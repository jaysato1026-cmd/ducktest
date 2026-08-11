const ERROR_LABELS = {
  ENOTFOUND: ["DNS 解析失敗", "確認網域名稱、DNS 伺服器與 DNS 記錄是否存在。"],
  EAI_AGAIN: ["DNS 暫時失敗", "DNS 伺服器可能忙碌或網路不穩，稍後重試並比較其他 DNS。"],
  ECONNREFUSED: ["服務拒絕連線", "主機可達，但目標 Port 沒有服務監聽或被防火牆拒絕。"],
  ETIMEDOUT: ["連線逾時", "檢查防火牆、WAF、路由、服務負載與回程路徑。"],
  timeout: ["服務回應逾時", "TCP 或 HTTP 建立後未在逾時內完成，應檢查伺服器負載與上游依賴。"],
  ECONNRESET: ["連線被重置", "可能是服務重啟、代理／WAF 中斷、TLS 協商或上游連線被關閉。"],
  EPROTO: ["TLS／協定不相容", "確認網址協定、Port、TLS 版本與憑證主機名稱。"],
  ECONNABORTED: ["連線被中止", "檢查中間代理、WAF 或服務端是否主動中止請求。"],
};

function evidence(label, value) {
  return { label, value: value == null || value === "" ? "未取得" : String(value) };
}

const TIMEOUT_PHASES = {
  dns: ["DNS 查詢逾時", "DNS 查詢在設定時間內沒有完成；請比較其他 DNS，並檢查本機或閘道器的 DNS 紀錄。"],
  tcp: ["TCP 連線逾時", "目標 IP 已取得，但 TCP 連線沒有及時建立；請檢查防火牆、NAT、Cloudflare 到來源站與回程路徑。"],
  tls: ["TLS 交握逾時", "TCP 已連線，但 TLS 交握沒有及時完成；請檢查憑證、SNI、反向代理與 TLS 負載。"],
  http: ["HTTP 回應逾時", "TLS／TCP 已建立，但沒有及時收到 HTTP 回應標頭；請檢查 Web 服務、WAF、反向代理、應用程式與上游依賴。"],
};

function addTimedOutPhase(causes, sample) {
  const phase = sample?.timeoutPhase;
  if (!TIMEOUT_PHASES[phase]) return addCause(causes, "timeout", `TCP/HTTP 在設定逾時內未完成：${sample?.error || "timeout"}`);
  const [title, action] = TIMEOUT_PHASES[phase];
  causes.push({ code: `TIMEOUT_${phase.toUpperCase()}`, title, detail: `${phase.toUpperCase()} 階段超過監控逾時門檻`, action, confidence: "高" });
}

function addCause(causes, code, detail, confidence = "高") {
  const [title, action] = ERROR_LABELS[code] || ["網路連線失敗", "比對 DNS、TCP、TLS 與 HTTP 各層結果，確認失敗發生在哪一層。"];
  causes.push({ code, title, detail: detail || code, action, confidence });
}

function diagnoseTarget(result) {
  if (!result) return { status: "unknown", headline: "尚未取得診斷資料", causes: [], evidence: [], actions: [] };
  const causes = [];
  const evidenceRows = [
    evidence("目標", result.target),
    evidence("DNS", result.dns?.resolved ? `${result.addresses?.length || 0} 個位址` : result.dns?.error || "未解析"),
    evidence("TCP", result.tcp?.reachable ? `${result.tcp.latencyMs} ms` : result.tcp?.error),
    evidence("HTTP", result.http?.reachable ? `HTTP ${result.http.status} · ${result.http.latencyMs} ms` : result.http?.error),
    evidence("IP 範圍", result.networkScope),
  ];
  if (!result.dns?.resolved) addCause(causes, result.dns?.error || "ENOTFOUND", result.dns?.error || "找不到 DNS 位址");
  else if (!result.tcp?.reachable && !result.http?.reachable) addCause(causes, result.tcp?.error || result.http?.error || "ETIMEDOUT", `DNS 已解析到 ${result.addresses?.map((item) => item.address).join(", ") || "位址"}，但 TCP 與 HTTP 都不可達`);
  else if (!result.tcp?.reachable && result.http?.reachable) addCause(causes, result.tcp?.error || "ETIMEDOUT", "HTTP 可以回應但直接 TCP 探測失敗，可能是代理、IPv4/IPv6 路徑或 Port 探測差異", "中");
  if (result.tcp?.reachable && !result.http?.reachable) addCause(causes, result.http?.error || "timeout", `Port ${result.port} 可連線，但 HTTP 服務沒有在逾時內完成`);
  if (result.http?.tlsAuthorized === false) addCause(causes, "EPROTO", result.http.tlsError || "TLS 憑證未通過驗證");
  if (result.protocolHint) causes.unshift({ code: "PROTOCOL_MISMATCH", title: "網址協定或 Port 不符", detail: result.protocolHint.message, action: `改用建議網址：${result.protocolHint.suggestedUrl}`, confidence: "高" });
  if (result.http?.reachable && result.http.status >= 500) causes.push({ code: "HTTP_5XX", title: "服務端錯誤", detail: `伺服器回傳 HTTP ${result.http.status}`, action: "查閱伺服器應用程式、反向代理與上游服務日誌。", confidence: "高" });
  if (result.http?.reachable && result.http.status >= 400 && result.http.status < 500) causes.push({ code: "HTTP_4XX", title: "請求或權限被拒絕", detail: `伺服器回傳 HTTP ${result.http.status}`, action: "確認路徑、授權、Host、Headers 與 WAF 規則。", confidence: "高" });
  const status = result.alive && !causes.length ? "healthy" : result.alive ? "degraded" : "offline";
  const headline = status === "healthy" ? "目前沒有偵測到斷線原因" : status === "degraded" ? "主機存活，但服務層有異常" : "已定位到連線失敗層級";
  return { status, headline, causes, evidence: evidenceRows, actions: [...new Set(causes.map((item) => item.action))], checkedAt: result.checkedAt, target: result.target };
}

function diagnoseMonitor(report) {
  if (!report?.summary) return { status: "unknown", headline: "尚未取得監控資料", causes: [], evidence: [], actions: [] };
  const summary = report.summary;
  const failures = report.samples?.filter((sample) => !sample.ok) || [];
  const causes = [];
  const byError = new Map();
  for (const sample of failures) byError.set(sample.error || `HTTP_${sample.statusCode || 0}`, (byError.get(sample.error || `HTTP_${sample.statusCode || 0}`) || 0) + 1);
  for (const [code, count] of [...byError.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5)) addCause(causes, code, `${count} 次監控失敗`);
  if (!causes.length && summary.availability >= 99.9) return { status: "healthy", headline: "監控期間穩定", causes: [], evidence: [evidence("可用率", `${summary.availability}%`)], actions: [] };
  return { status: summary.availability >= 95 ? "degraded" : "offline", headline: summary.availability >= 95 ? "網站偶發中斷，建議比對時間與錯誤類型" : "網站可用率不足，已整理主要失敗原因", causes, evidence: [evidence("可用率", `${summary.availability}%`), evidence("失敗次數", summary.failed), evidence("P95", `${summary.p95LatencyMs} ms`)], actions: [...new Set(causes.map((item) => item.action))] };
}

function diagnoseDisconnectEvent({ target = "", sample, previousSample = null, routeTrace = null }) {
  if (!sample || sample.ok) return null;
  const errorCode = sample.error || (sample.statusCode ? `HTTP_${sample.statusCode}` : "unknown");
  const causes = [];
  const evidenceRows = [
    evidence("發生時間", sample.checkedAt),
    evidence("監控結果", sample.statusCode ? `HTTP ${sample.statusCode}` : errorCode),
    evidence("前一次結果", previousSample ? (previousSample.ok ? "正常" : previousSample.error || `HTTP ${previousSample.statusCode || 0}`) : "沒有前一筆資料"),
  ];
  if (sample.timeoutPhase) evidenceRows.push(evidence("逾時階段", sample.timeoutPhase.toUpperCase()));
  if (sample.resolvedAddress || sample.remoteAddress) evidenceRows.push(evidence("連線位址", sample.remoteAddress || sample.resolvedAddress));
  if (sample.timings) {
    const timingText = [["DNS", sample.timings.dnsMs], ["TCP", sample.timings.tcpMs], ["TLS", sample.timings.tlsMs], ["TTFB", sample.timings.ttfbMs]]
      .filter(([, value]) => Number.isFinite(value)).map(([label, value]) => `${label} ${value} ms`).join(" · ");
    if (timingText) evidenceRows.push(evidence("階段耗時", timingText));
  }
  if (sample.cloudflare?.ray) evidenceRows.push(evidence("Cloudflare Ray ID", sample.cloudflare.ray));
  if (["ENOTFOUND", "EAI_AGAIN"].includes(errorCode)) {
    addCause(causes, errorCode, "DNS 無法解析目標名稱；這次請求尚未進入 TCP 或 HTTP 階段");
  } else if (sample.statusCode >= 500) {
    causes.push({ code: "HTTP_5XX", title: "目標服務端回應異常", detail: `服務可連到，但回傳 HTTP ${sample.statusCode}`, action: "檢查 Web 伺服器、反向代理、應用程式與上游服務日誌。", confidence: "高" });
  } else if (sample.statusCode >= 400) {
    causes.push({ code: "HTTP_4XX", title: "請求被目標端拒絕", detail: `服務回傳 HTTP ${sample.statusCode}`, action: "確認路徑、帳號授權、Host、Headers 與 WAF 規則。", confidence: "高" });
  } else if (["EPROTO", "CERT_HAS_EXPIRED", "DEPTH_ZERO_SELF_SIGNED_CERT"].includes(errorCode)) {
    addCause(causes, "EPROTO", "TLS 交握或憑證驗證失敗");
  } else if (errorCode === "ECONNREFUSED") {
    addCause(causes, "ECONNREFUSED", "主機可達但服務 Port 拒絕連線");
  } else if (errorCode === "timeout") {
    addTimedOutPhase(causes, sample);
  } else {
    addCause(causes, "ETIMEDOUT", `TCP/HTTP 在設定逾時內未完成：${errorCode}`);
  }
  if (routeTrace) {
    const responsive = (routeTrace.hops || []).filter((hop) => hop.ip);
    const timeouts = (routeTrace.hops || []).filter((hop) => hop.timeout).length;
    const last = responsive.at(-1);
    evidenceRows.push(evidence("tracert", routeTrace.error || `${responsive.length} 個可回應跳點，${timeouts} 個未回應跳點`));
    if (last?.geo?.available) evidenceRows.push(evidence("最後可回應節點", `${last.ip} · ${[last.geo.country, last.geo.city, last.geo.isp].filter(Boolean).join(" / ")}`));
    if (routeTrace.error || !responsive.length) {
      causes.push({ code: "TRACE_UNAVAILABLE", title: "路徑追蹤未取得可用結果", detail: routeTrace.error || "tracert 沒有回傳任何可回應節點", action: "確認本機防火牆、路由器與 ISP 是否允許 ICMP/TTL 回覆；仍需以 TCP/HTTP 結果為主。", confidence: "低" });
    } else if (timeouts > 0 && !routeTrace.completed) {
      causes.push({ code: "ROUTE_TIMEOUT", title: "路徑中有未回應節點", detail: `已回應至第 ${last.hop} 跳；共有 ${timeouts} 跳未回應`, action: "比對後續監控是否持續失敗，並將此時間點與 ISP、路由器或防火牆紀錄交叉比對。", confidence: "低" });
    }
  }
  const status = sample.statusCode >= 500 || !sample.reachable ? "offline" : "degraded";
  return { status, headline: `偵測到斷線／異常：${errorCode}`, target, checkedAt: sample.checkedAt, causes, evidence: evidenceRows, actions: [...new Set(causes.map((item) => item.action))] };
}

module.exports = { diagnoseTarget, diagnoseMonitor, diagnoseDisconnectEvent, ERROR_LABELS };

const asNumber = (value) => Number(value) || 0;

const countStatusFamily = (statuses, family) => Object.entries(statuses || {})
  .filter(([code]) => String(code).startsWith(family))
  .reduce((total, [, count]) => total + asNumber(count), 0);

export function buildNextRunConfig(config, nextRun) {
  return {
    ...config,
    concurrency: Math.max(1, asNumber(nextRun?.concurrency)),
    duration: Math.max(1, asNumber(nextRun?.duration)),
  };
}

export function normalizeAutoTune(options = {}) {
  return {
    enabled: Boolean(options.enabled),
    maxRounds: Math.min(10, Math.max(2, Math.round(asNumber(options.maxRounds) || 5))),
    cooldownSeconds: Math.min(300, Math.max(1, Math.round(asNumber(options.cooldownSeconds) || 5))),
  };
}

export function buildDiagnosis(report, thresholds, config) {
  if (!report) return null;

  const rps = asNumber(report.summary?.requestsPerSecond);
  const failureRate = asNumber(report.summary?.failureRate);
  const completed = asNumber(report.summary?.completed);
  const averageBytes = asNumber(report.summary?.averageResponseBytes);
  const p50 = asNumber(report.latencyMs?.p50);
  const p95 = asNumber(report.latencyMs?.p95);
  const p99 = asNumber(report.latencyMs?.p99);
  const maxP95 = asNumber(thresholds.maxP95);
  const minRps = asNumber(thresholds.minRps);
  const maxFailureRate = asNumber(thresholds.maxFailureRate);
  const maxAverageBytes = asNumber(thresholds.maxAverageKb) * 1024;
  const errors = report.errors || {};
  const timeouts = asNumber(errors.timeout) + asNumber(errors.AbortError);
  const serverErrors = countStatusFamily(report.statusCodes, "5");
  const unauthorized = asNumber(report.statusCodes?.[401]) + asNumber(report.statusCodes?.[403]);
  const notFound = asNumber(report.statusCodes?.[404]);
  const tlsErrorKeys = [
    "DEPTH_ZERO_SELF_SIGNED_CERT",
    "SELF_SIGNED_CERT_IN_CHAIN",
    "ERR_TLS_CERT_ALTNAME_INVALID",
    "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
    "CERT_HAS_EXPIRED",
  ];
  const tlsFailures = tlsErrorKeys.reduce((total, key) => total + asNumber(errors[key]), 0);
  const findings = [];

  if (tlsFailures > 0) {
    findings.push({
      level: "critical",
      title: "HTTPS 憑證驗證失敗",
      evidence: `${tlsFailures} 筆請求在 TLS 階段中止`,
      action: "優先改用憑證上的主機名稱或安裝正確憑證；僅限已授權的內部測試環境，才啟用「忽略 HTTPS 憑證錯誤」。",
    });
  }

  if (unauthorized > 0) {
    findings.push({
      level: "critical",
      title: "目標需要身分驗證或拒絕存取",
      evidence: `${unauthorized} 筆 401/403 回應`,
      action: "在進階設定加入測試專用 Authorization Header，並確認測試帳號具備目標端點權限。",
    });
  }

  if (notFound > 0) {
    findings.push({
      level: "critical",
      title: "壓測網址不是有效端點",
      evidence: `${notFound} 筆 404 回應`,
      action: "確認 URL 路徑與反向代理設定；建議改用專用 health 或 API 端點後再測。",
    });
  }

  if ((failureRate > maxFailureRate || serverErrors > 0 || timeouts > 0)
      && tlsFailures === 0 && unauthorized === 0 && notFound === 0) {
    const evidence = [
      `失敗率 ${failureRate.toFixed(2)}%`,
      serverErrors ? `${serverErrors} 筆 5xx` : null,
      timeouts ? `${timeouts} 筆逾時` : null,
    ].filter(Boolean).join("、");
    findings.push({
      level: "critical",
      title: "先處理可靠性，再提高負載",
      evidence,
      action: "檢查伺服器錯誤與逾時紀錄；下一輪先降低 20% 併發，確認錯誤是否隨負載消失。",
    });
  }

  if (p95 > maxP95) {
    findings.push({
      level: "warning",
      title: "P95 延遲超出服務目標",
      evidence: `P95 ${Math.round(p95)}ms，高於門檻 ${Math.round(maxP95)}ms`,
      action: "優先檢查慢查詢、下游 API 與連線池；用較小併發重跑以區分基礎延遲與飽和延遲。",
    });
  } else if (p50 > 0 && p99 / p50 >= 3) {
    findings.push({
      level: "warning",
      title: "尾端延遲波動偏大",
      evidence: `P99 約為 P50 的 ${(p99 / p50).toFixed(1)} 倍`,
      action: "檢查偶發 GC、冷快取、鎖競爭或下游重試，並延長測試時間確認尖峰是否持續。",
    });
  }

  if (rps < minRps) {
    findings.push({
      level: "warning",
      title: "吞吐量未達目標",
      evidence: `${rps.toFixed(1)} req/s，目標 ${minRps} req/s`,
      action: failureRate > maxFailureRate
        ? "先排除失敗請求；錯誤會消耗容量並扭曲有效吞吐量。"
        : "逐步增加併發並觀察 P95；若吞吐不再上升，即接近目前容量上限。",
    });
  }

  if (averageBytes > maxAverageBytes && maxAverageBytes > 0) {
    findings.push({
      level: "info",
      title: "平均回應內容偏大",
      evidence: `${(averageBytes / 1024).toFixed(1)} KB，高於門檻 ${thresholds.maxAverageKb} KB`,
      action: "檢查欄位裁切、分頁、壓縮與靜態資源快取，避免網路傳輸成為瓶頸。",
    });
  }

  if (completed < asNumber(thresholds.minCompleted)) {
    findings.push({
      level: "info",
      title: "樣本量不足以支撐穩定判讀",
      evidence: `${completed} 筆完成請求，目標 ${thresholds.minCompleted} 筆`,
      action: "延長測試時間，讓百分位延遲與錯誤率建立在更多樣本上。",
    });
  }

  if (!findings.length) {
    findings.push({
      level: "success",
      title: "本輪所有驗收門檻皆通過",
      evidence: `P95 ${Math.round(p95)}ms、失敗率 ${failureRate.toFixed(2)}%、${rps.toFixed(1)} req/s`,
      action: "下一輪可將併發提高 20%，尋找性能轉折點並建立容量安全邊界。",
    });
  }

  const currentConcurrency = Math.max(1, asNumber(config.concurrency));
  const shouldBackOff = failureRate > maxFailureRate || serverErrors > 0 || timeouts > 0
    || tlsFailures > 0 || unauthorized > 0 || notFound > 0;
  const nextConcurrency = shouldBackOff
    ? Math.max(1, Math.floor(currentConcurrency * 0.8))
    : Math.ceil(currentConcurrency * 1.2);

  return {
    status: findings.some((item) => item.level === "critical")
      ? "critical"
      : findings.some((item) => item.level === "warning") ? "warning" : "healthy",
    headline: shouldBackOff ? "可靠性風險需要優先處理" : findings[0].title,
    findings: findings.slice(0, 4),
    nextRun: {
      concurrency: nextConcurrency,
      duration: completed < asNumber(thresholds.minCompleted)
        ? Math.max(30, Math.ceil(asNumber(config.duration) * 1.5))
        : Math.max(10, asNumber(config.duration)),
    },
  };
}

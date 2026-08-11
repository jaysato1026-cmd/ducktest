export function readableRemoteError(cause) {
  return String(cause?.message || cause || "發生未預期錯誤。")
    .replace(/^Error invoking remote method '[^']+':\s*Error:\s*/i, "")
    .replace(/^Error:\s*/i, "")
    .trim();
}

export function buildNetworkToolRequest(tool, { targetUrl, authorized, mode, config }) {
  const common = { authorized: Boolean(authorized), mode };
  if (tool === "nmap") {
    return {
      ...common,
      target: targetUrl,
      completionMode: config.nmapCompletionMode,
      topPorts: config.topPorts,
      ports: config.ports,
      timeoutSeconds: config.timeoutSeconds,
      osDetection: config.osDetection,
      extraArgs: config.extraArgs,
    };
  }
  if (tool === "wireshark") {
    return {
      ...common,
      target: targetUrl,
      interfaceId: config.interfaceId,
      durationSeconds: config.durationSeconds,
      maxPackets: config.maxPackets,
      captureFilter: config.captureFilter,
      displayFilter: config.displayFilter,
      extraArgs: config.extraArgs,
    };
  }
  if (tool === "iperf3") {
    return {
      ...common,
      target: config.iperfRole === "server" ? "" : String(config.iperfTarget || "").trim(),
      role: config.iperfRole,
      port: config.iperfPort,
      direction: config.iperfDirection,
      protocol: config.iperfProtocol,
      durationSeconds: config.durationSeconds,
      parallelStreams: config.iperfParallelStreams,
      bandwidthMbps: config.iperfBandwidthMbps,
      omitSeconds: config.iperfOmitSeconds,
      extraArgs: config.extraArgs,
    };
  }
  throw new Error(`不支援的網路工具：${tool}`);
}

export const NETWORK_TOOL_KEYS = ["nmap", "wireshark", "iperf3"];

export function createEmptyNetworkResultStates() {
  return Object.fromEntries(NETWORK_TOOL_KEYS.map((key) => [key, { latest: null, lastSuccess: null }]));
}

export function networkToolKeyForResult(result) {
  if (result?.type === "nmap-report") return "nmap";
  if (result?.type === "wireshark-report") return "wireshark";
  if (result?.type === "iperf3-report") return "iperf3";
  return null;
}

export function isCompleteNetworkResult(result) {
  return Boolean(result) && result.incomplete !== true && result.status !== "timeout";
}

export function applyNetworkResult(states, tool, result) {
  if (!NETWORK_TOOL_KEYS.includes(tool) || !result) return states;
  const current = states?.[tool] || { latest: null, lastSuccess: null };
  return {
    ...states,
    [tool]: {
      latest: result,
      lastSuccess: isCompleteNetworkResult(result) ? result : current.lastSuccess,
    },
  };
}

export function hydrateNetworkResultStates(records = []) {
  const states = createEmptyNetworkResultStates();
  for (const record of records) {
    const result = record?.result || (String(record?.type || "").endsWith("-report") ? record : null);
    const tool = networkToolKeyForResult(result);
    if (!tool) continue;
    if (!states[tool].latest) states[tool].latest = result;
    if (!states[tool].lastSuccess && isCompleteNetworkResult(result)) states[tool].lastSuccess = result;
  }
  return states;
}

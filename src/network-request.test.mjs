import test from "node:test";
import assert from "node:assert/strict";
import { buildNetworkToolRequest, readableRemoteError } from "./network-request.mjs";

const config = {
  nmapCompletionMode: "complete",
  topPorts: 100,
  ports: "",
  timeoutSeconds: 60,
  osDetection: false,
  interfaceId: "2",
  durationSeconds: 15,
  maxPackets: 500,
  captureFilter: "",
  displayFilter: "",
  extraArgs: "",
  iperfRole: "client",
  iperfTarget: " 192.168.1.50 ",
  iperfPort: 5201,
  iperfDirection: "upload",
  iperfProtocol: "tcp",
  iperfParallelStreams: 1,
  iperfBandwidthMbps: 100,
  iperfOmitSeconds: 0,
};

test("network requests keep website targets separate from the iPerf3 receiver", () => {
  const input = { targetUrl: "https://example.com/health", authorized: true, mode: "basic", config };
  assert.equal(buildNetworkToolRequest("nmap", input).target, "https://example.com/health");
  assert.equal(buildNetworkToolRequest("nmap", input).completionMode, "complete");
  assert.equal(buildNetworkToolRequest("wireshark", input).target, "https://example.com/health");
  assert.equal(buildNetworkToolRequest("iperf3", input).target, "192.168.1.50");
  assert.equal(buildNetworkToolRequest("iperf3", { ...input, config: { ...config, iperfRole: "server" } }).target, "");
});

test("remote Electron errors are reduced to the actionable message", () => {
  assert.equal(
    readableRemoteError(new Error("Error invoking remote method 'network-tools:nmap': Error: Nmap 已達掃描時間上限。")),
    "Nmap 已達掃描時間上限。",
  );
});

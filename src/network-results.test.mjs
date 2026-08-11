import test from "node:test";
import assert from "node:assert/strict";
import {
  applyNetworkResult,
  createEmptyNetworkResultStates,
  hydrateNetworkResultStates,
} from "./network-results.mjs";

const successfulNmap = {
  type: "nmap-report",
  checkedAt: "2026-07-23T01:00:00.000Z",
  summary: { onlineHosts: 1, openPorts: 6, highAttention: 1 },
};
const timedOutNmap = {
  type: "nmap-report",
  checkedAt: "2026-07-27T01:00:00.000Z",
  incomplete: true,
  status: "timeout",
  summary: { onlineHosts: null, openPorts: null, highAttention: null },
};

test("each network tool keeps an independent latest result", () => {
  let states = createEmptyNetworkResultStates();
  states = applyNetworkResult(states, "nmap", successfulNmap);
  states = applyNetworkResult(states, "wireshark", { type: "wireshark-report", summary: { packetCount: 42 } });
  assert.equal(states.nmap.latest.summary.openPorts, 6);
  assert.equal(states.wireshark.latest.summary.packetCount, 42);
  assert.equal(states.iperf3.latest, null);
});

test("an incomplete scan does not erase the previous successful measurement", () => {
  let states = applyNetworkResult(createEmptyNetworkResultStates(), "nmap", successfulNmap);
  states = applyNetworkResult(states, "nmap", timedOutNmap);
  assert.equal(states.nmap.latest.status, "timeout");
  assert.equal(states.nmap.lastSuccess.summary.openPorts, 6);
});

test("history hydration restores latest and last successful results separately", () => {
  const states = hydrateNetworkResultStates([
    { type: "nmap-report", result: timedOutNmap },
    { type: "wireshark-report", result: { type: "wireshark-report", summary: { packetCount: 9 } } },
    { type: "nmap-report", result: successfulNmap },
  ]);
  assert.equal(states.nmap.latest.status, "timeout");
  assert.equal(states.nmap.lastSuccess.summary.openPorts, 6);
  assert.equal(states.wireshark.latest.summary.packetCount, 9);
});

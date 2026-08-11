const { probeTarget } = require("./target-probe.cjs");

function interpolate(value, variables) {
  return typeof value === "string" ? value.replace(/\{\{\s*([\w.-]+)\s*\}\}/g, (_, key) => variables[key] ?? "") : value;
}

async function runScenario(config = {}) {
  if (!config.authorized) throw new Error("Scenario tests require explicit authorization");
  const steps = Array.isArray(config.steps) ? config.steps.slice(0, 20) : [];
  if (!steps.length) throw new Error("Scenario requires at least one step");
  const variables = { ...(config.variables || {}) };
  const results = [];
  for (const [index, step] of steps.entries()) {
    const result = await probeTarget(interpolate(step.url, variables), Math.min(30000, Number(step.timeoutMs) || 5000), { method: step.method || "GET", headers: interpolate(step.headers, variables), body: interpolate(step.body, variables) });
    results.push({ index, name: step.name || `step-${index + 1}`, result });
    if (step.capture && result.http?.status) variables[step.capture] = String(result.http.status);
    if (!result.alive || !result.http?.reachable || result.http.status >= 500) break;
  }
  return { ok: results.length === steps.length && results.every((item) => item.result.alive && item.result.http?.status < 500), variables, results, completedAt: new Date().toISOString() };
}

module.exports = { interpolate, runScenario };

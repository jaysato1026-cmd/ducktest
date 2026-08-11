#!/usr/bin/env node
const { probeTarget } = require('./target-probe.cjs');
const { diagnoseTarget } = require('./outage-diagnosis.cjs');

function parseArgs(argv) {
  const out = { timeout: 5000, json: false, authorized: false };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--json') out.json = true;
    else if (token === '--authorized') out.authorized = true;
    else if (token === '--url') out.url = argv[++i];
    else if (token === '--timeout') out.timeout = Number(argv[++i]);
  }
  return out;
}

async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (!args.url) throw new Error('Usage: npm run cli -- --url https://example.com --authorized [--timeout 5000] [--json]');
  if (!args.authorized) throw new Error('Explicit authorization is required: add --authorized for a target you own or are permitted to test');
  const result = await probeTarget(args.url, args.timeout);
  const diagnosis = diagnoseTarget(result);
  const payload = { result, diagnosis };
  if (args.json) console.log(JSON.stringify(payload, null, 2));
  else console.log(`${result.alive ? 'ONLINE' : 'OFFLINE'} ${result.target}\n${diagnosis.headline}`);
  return result.alive && (!result.http?.status || result.http.status < 500) ? 0 : 1;
}

if (require.main === module) main().then((code) => process.exitCode = code).catch((error) => { console.error(error.message); process.exitCode = 2; });
module.exports = { parseArgs, main };

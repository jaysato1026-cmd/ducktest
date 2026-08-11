const test = require("node:test");
const assert = require("node:assert/strict");
const { classifyEndpoint, parseCountries } = require("./globalping.cjs");

test("parses unique two-letter country codes", () => {
  assert.deepEqual(parseCountries("jp, SG,us,JP"), ["JP", "SG", "US"]);
});

test("rejects invalid or excessive country selections", () => {
  assert.throws(() => parseCountries("Japan,US"), /兩碼/);
  assert.throws(() => parseCountries("AA,BB,CC,DD,EE,FF,GG,HH,II,JJ,KK,LL,MM"), /最多 12/);
});

test("does not treat blocked ICMP as an offline website", () => {
  assert.deepEqual(classifyEndpoint({
    httpReachable: true,
    statusCode: 200,
    tlsAuthorized: true,
    pingAvailability: 0,
  }), {
    label: "網站正常",
    className: "good",
    reason: "HTTP/HTTPS 正常；ICMP 沒有回應，通常是主機或防火牆封鎖 Ping，不代表網站離線。",
  });
});

test("separates reachable hosts from broken URL paths", () => {
  assert.equal(classifyEndpoint({
    httpReachable: true,
    statusCode: 404,
    tlsAuthorized: true,
    pingAvailability: 0,
  }).label, "網址異常");
});

const test = require("node:test");
const assert = require("node:assert/strict");
const { parseNodes } = require("./global-probe.cjs");

test("parses country agent lines", () => {
  const nodes = parseNodes("日本|東京|https://jp.example.com/probe\n美國|維吉尼亞|https://us.example.com/probe");
  assert.equal(nodes.length, 2);
  assert.equal(nodes[0].country, "日本");
  assert.equal(nodes[1].city, "維吉尼亞");
});

test("rejects malformed agent lines", () => {
  assert.throws(() => parseNodes("日本|東京"), /格式錯誤/);
  assert.throws(() => parseNodes("日本|東京|ftp://example.com"), /HTTP/);
});

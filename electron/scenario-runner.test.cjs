const test = require("node:test");
const assert = require("node:assert/strict");
const { interpolate } = require("./scenario-runner.cjs");

test("interpolates scenario variables without evaluating code", () => {
  assert.equal(interpolate("https://example.test/{{ token }}", { token: "abc" }), "https://example.test/abc");
  assert.equal(interpolate("{{missing}}", {}), "");
});

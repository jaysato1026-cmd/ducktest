const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { isPrivateAddress, probeTarget } = require("./target-probe.cjs");

test("detects private and loopback IPv4 ranges", () => {
  assert.equal(isPrivateAddress("10.20.30.40"), true);
  assert.equal(isPrivateAddress("172.16.0.1"), true);
  assert.equal(isPrivateAddress("172.31.255.254"), true);
  assert.equal(isPrivateAddress("192.168.50.25"), true);
  assert.equal(isPrivateAddress("127.0.0.1"), true);
});

test("does not classify public IPv4 addresses as private", () => {
  assert.equal(isPrivateAddress("8.8.8.8"), false);
  assert.equal(isPrivateAddress("172.32.0.1"), false);
});

test("detects private IPv6 ranges", () => {
  assert.equal(isPrivateAddress("::1"), true);
  assert.equal(isPrivateAddress("fd12:3456::1"), true);
  assert.equal(isPrivateAddress("fe80::1"), true);
  assert.equal(isPrivateAddress("2001:4860:4860::8888"), false);
});

test("falls back to the real method when HEAD returns 404", async (t) => {
  const server = http.createServer((request, response) => {
    response.statusCode = request.method === "HEAD" ? 404 : 200;
    response.end(request.method === "HEAD" ? "" : "ok");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const { port } = server.address();

  const result = await probeTarget(`http://127.0.0.1:${port}/`, 2000, { method: "GET" });

  assert.equal(result.headProbe.status, 404);
  assert.equal(result.http.status, 200);
  assert.equal(result.methodFallback.recovered, true);
});

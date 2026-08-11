const http = require("node:http");

const port = Number(process.argv[2] || 17891);
http.createServer((_request, response) => {
  response.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
  response.end("ducktest-ui-fixture");
}).listen(port, "127.0.0.1");

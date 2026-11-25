import { createServer } from "node:http";
import { once } from "node:events";
import next from "next";

// Isolated test process. Only the signing-key transport is a fixture.
// The built application verifies the signed assertion and its allowlisted identity.
const server = createServer();
server.listen(0, "127.0.0.1");
await once(server, "listening");
const { port } = server.address();
const origin = `http://127.0.0.1:${port}`;
const fetchLocal = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const url = new URL(input instanceof Request ? input.url : input);
  if (url.href === "https://receipt-fixture.cloudflareaccess.com/cdn-cgi/access/certs") {
    return Promise.resolve(Response.json({ keys: [JSON.parse(process.env.FIXTURE_PUBLIC_JWK)] }));
  }
  if (url.origin !== origin) throw new Error("Unexpected external request");
  return fetchLocal(input, init);
};

const app = next({ dev: false, hostname: "127.0.0.1", port });
await app.prepare();
server.on("request", app.getRequestHandler());
process.send(port);

import { randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, rmdir } from "node:fs/promises";
import net, { type Socket } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";

export type Lifetime = { endpoint: string; token: string };

/** Launcher-owned teardown pipe. It carries no ownership or termination evidence. */
export async function openLifetime() {
  const directory = process.platform === "win32" ? undefined : await mkdtemp(path.join(tmpdir(), "lm-ipc-"));
  const endpoint = directory ? path.join(directory, "lifetime") : `\\\\.\\pipe\\limitmark-${randomUUID()}`;
  const token = randomBytes(32).toString("base64url");
  const sockets = new Set<Socket>();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    socket.on("error", () => socket.destroy());
    socket.setTimeout(5_000, () => socket.destroy());
    socket.setEncoding("utf8");
    let input = "";
    const authenticate = (part: string) => {
      input += part;
      if (input.length < token.length) return;
      if (input !== token) { socket.destroy(); return; }
      socket.off("data", authenticate);
      socket.once("data", () => socket.destroy());
      socket.setTimeout(0);
      socket.write("ok");
    };
    socket.on("data", authenticate);
  });
  server.maxConnections = 16;
  try {
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen({ path: endpoint }, resolve); });
  } catch (error) {
    if (directory) await rmdir(directory);
    throw error;
  }
  return {
    descriptor: { endpoint, token },
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      if (directory) await rmdir(directory);
    },
  };
}

export function connectLifetime({ endpoint, token }: Lifetime): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: endpoint }, () => socket.write(token));
    socket.setEncoding("utf8");
    const fail = () => { socket.destroy(); reject(new Error("launcher lifetime channel unavailable")); };
    socket.once("close", fail);
    socket.on("error", fail);
    socket.setTimeout(5_000, fail);
    let reply = "";
    const read = (part: string) => {
      reply += part;
      if (reply.length < 2) return;
      if (reply !== "ok") { fail(); return; }
      socket.off("data", read);
      socket.setTimeout(0);
      resolve(socket);
    };
    socket.on("data", read);
  });
}

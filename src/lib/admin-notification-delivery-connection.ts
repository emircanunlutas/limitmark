import "server-only";

import { once } from "node:events";
import { createConnection, type Socket } from "node:net";
import postgres, { type Sql } from "postgres";
import { getDatabaseClientOptions } from "./db/database.server";

type OpenSocket = (options: postgres.ParsedOptions, index: number) => Socket;

function openSocket(options: postgres.ParsedOptions, index: number): Socket {
  const { path } = options;
  const host = options.host[index];
  const port = options.port[index];
  const socket = createConnection(path ? { path } : { host, port });
  // postgres.js uses this property to preserve the hostname for TLS SNI.
  return Object.assign(socket, { host });
}

export type NotificationDeliveryConnection = {
  client: Sql;
  close(): Promise<void>;
};

/**
 * One disposable postgres.js client per read. Aborting closes its transport directly, including
 * during startup or transaction cleanup. No CancelRequest or application pool slot is involved.
 */
export function openNotificationDeliveryConnection(
  databaseUrl: string,
  signal: AbortSignal,
  dial: OpenSocket = openSocket,
): NotificationDeliveryConnection {
  signal.throwIfAborted();
  let socket: Socket | undefined;
  let closing: Promise<void> | undefined;
  const connectionOptions = {
    ...getDatabaseClientOptions(1),
    fetch_types: false,
    onnotice: () => {},
    async socket(options: postgres.ParsedOptions) {
      signal.throwIfAborted();
      if (closing) throw new Error("delivery connection is closed");
      // A replacement connection would lack the read-only transaction and its local limits.
      if (socket) throw new Error("delivery connection cannot reconnect");
      const endpoints = options.path ? 1 : options.host.length;
      for (let index = 0; index < endpoints; index += 1) {
        socket = dial(options, index);
        try {
          if (socket.connecting) await once(socket, "connect", { signal });
          signal.throwIfAborted();
          return socket;
        } catch (error) {
          socket.destroy();
          if (signal.aborted || index + 1 === endpoints) throw error;
        }
      }
      throw new Error("delivery connection has no database endpoint");
    },
  };
  const client = postgres(databaseUrl, connectionOptions);
  function close() {
    if (!closing) {
      signal.removeEventListener("abort", abort);
      // Stop the driver before destroying the socket it owns, even if the peer ignores shutdown.
      closing = client.end({ timeout: 0 }).finally(() => { socket?.destroy(); });
    }
    return closing;
  }
  function abort() {
    // The repository also awaits close() in its finally block.
    void close().catch(() => {});
  }
  signal.addEventListener("abort", abort, { once: true });
  return { client, close };
}

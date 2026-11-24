import assert from "node:assert/strict";
import { once } from "node:events";
import type { Socket } from "node:net";
import { Duplex } from "node:stream";
import test from "node:test";
import { loadNotificationDeliveryHealth } from "../src/lib/admin-notification-delivery";
import { openNotificationDeliveryConnection } from "../src/lib/admin-notification-delivery-connection";
import { PostgresAdminNotificationDeliveryReadRepository } from "../src/lib/admin-notification-delivery-repository";

const url = "postgres://synthetic:synthetic@offline.example.test/notifications";
const now = new Date("2026-11-24T12:00:00.000Z");

function int32(value: number): Buffer {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
}

function packet(type: string, body: Buffer = Buffer.alloc(0)): Buffer {
  return Buffer.concat([Buffer.from(type), int32(4 + body.length), body]);
}

const ready = (state: string) => packet("Z", Buffer.from(state));
const complete = (command: string) => packet("C", Buffer.from(command + "\0"));

type Scenario = "startup" | "begin" | "read" | "success" | "statement error" | "disconnect";

/** Minimal PostgreSQL wire peer for the real postgres.js driver, without a listening socket. */
function memoryPeer(scenario: Scenario) {
  let reached!: () => void;
  const waiting = new Promise<void>((resolve) => { reached = resolve; });
  const commands: string[] = [];
  const sockets: Duplex[] = [];

  function dial(): Socket {
    let phase = "startup";
    const socket = new Duplex({
      read() {},
      final() {
        // Simulate a peer that leaves the connection open after receiving Terminate.
      },
      write(bytes: Buffer, _encoding, next) {
        next();
        if (bytes.length === 16 && bytes.readUInt32BE(4) === 80877102) {
          commands.push("CancelRequest");
          // The old path left this separate transport's rejection unhandled.
          setImmediate(() => socket.destroy(new Error("cancel transport failed")));
          return;
        }
        if (bytes[0] === 88) return; // Terminate, with no acknowledgment
        if (phase === "startup") {
          commands.push("startup");
          if (scenario === "startup") return reached();
          phase = "begin";
          reply(packet("R", int32(0)), packet("K", Buffer.concat([int32(31), int32(99)])), ready("I"));
        } else if (phase === "begin") {
          assert.match(bytes.toString(), /begin read only/);
          commands.push("begin");
          if (scenario === "begin") return reached();
          phase = "setup";
          reply(packet("1"), packet("2"), complete("BEGIN"), ready("T"));
        } else if (phase === "setup") {
          assert.match(bytes.toString(), /set_config/);
          if (scenario === "disconnect") {
            commands.push("disconnect");
            setImmediate(() => socket.destroy());
            return;
          }
          const textParameters = Buffer.concat([Buffer.from([0, 3]), int32(25), int32(25), int32(25)]);
          phase = "setup-bind";
          reply(packet("1"), packet("t", textParameters), packet("n"));
        } else if (phase === "setup-bind") {
          commands.push("setup");
          phase = "read";
          reply(packet("2"), complete("SELECT 1"), ready("T"));
        } else if (phase === "read") {
          assert.match(bytes.toString(), /from notification_outbox/);
          commands.push("read");
          if (scenario === "read") return reached();
          if (scenario === "statement error") {
            phase = "done";
            reply(packet("E", Buffer.from("SERROR\0C57014\0Mstatement timeout\0\0")), ready("E"));
          } else {
            phase = "read-bind";
            const parameters = Buffer.concat([Buffer.from([0, 2]), int32(2950), int32(23)]);
            reply(packet("1"), packet("t", parameters), packet("n"));
          }
        } else if (phase === "read-bind") {
          phase = "done";
          reply(packet("2"), complete("SELECT 0"), ready("T"));
        } else {
          assert.fail(`unexpected command after the read: ${bytes.toString()}`);
        }
      },
    });
    Object.defineProperty(socket, "readyState", { get: () => socket.destroyed ? "closed" : "open" });
    function reply(...messages: Buffer[]) {
      setImmediate(() => { if (!socket.destroyed) socket.push(Buffer.concat(messages)); });
    }
    sockets.push(socket);
    return socket as unknown as Socket;
  }

  const repository = new PostgresAdminNotificationDeliveryReadRepository((signal) =>
    openNotificationDeliveryConnection(url, signal, dial));
  return { repository, waiting, commands, sockets };
}

test("the page deadline closes a stalled postgres.js read without a CancelRequest or late rejection", { timeout: 3_000 }, async () => {
  const peer = memoryPeer("read");
  const view = loadNotificationDeliveryHealth(async () => peer.repository, now, { deadlineMs: 300 });
  await peer.waiting;
  const closed = once(peer.sockets[0], "close");
  assert.deepEqual(await view, { kind: "unavailable" });
  await closed;
  assert.deepEqual(peer.commands, ["startup", "begin", "setup", "read"]);
  assert.equal(peer.sockets.length, 1);
});

for (const phase of ["startup", "begin"] as const) {
  test(`abort closes a postgres.js socket stalled during ${phase}`, { timeout: 2_000 }, async () => {
    const peer = memoryPeer(phase);
    const controller = new AbortController();
    const pending = peer.repository.listInquiryDeliveries("00000000-0000-4000-8000-000000000042", 1, controller.signal);
    const rejected = assert.rejects(pending);
    await peer.waiting;
    const closed = once(peer.sockets[0], "close");
    controller.abort();
    await Promise.all([rejected, closed]);
    assert.equal(peer.commands.at(-1), phase);
    assert.equal(peer.sockets.length, 1);
    assert.equal(peer.sockets[0].destroyed, true);
  });
}

for (const scenario of ["success", "statement error"] as const) {
  test(`postgres.js disposes the read-only transaction after ${scenario} without waiting for transaction cleanup`, { timeout: 2_000 }, async () => {
    const peer = memoryPeer(scenario);
    const pending = peer.repository.listInquiryDeliveries("00000000-0000-4000-8000-000000000042", 1, new AbortController().signal);
    if (scenario === "success") assert.deepEqual(await pending, []);
    else await assert.rejects(pending, /statement timeout/);
    assert.equal(peer.sockets[0].destroyed, true);
    assert.deepEqual(peer.commands, ["startup", "begin", "setup", "read"]);
  });
}

test("postgres.js cannot reconnect and continue on a connection without the read-only transaction", { timeout: 2_000 }, async () => {
  const peer = memoryPeer("disconnect");
  await assert.rejects(peer.repository.getDeliveryCounts(now, new AbortController().signal), /closed/i);
  assert.deepEqual(peer.commands, ["startup", "begin", "disconnect"]);
  assert.equal(peer.sockets.length, 1);
});

test("aborting during TCP connect also releases the delivery slot", { timeout: 2_000 }, async () => {
  const controller = new AbortController();
  const socket = new Duplex({ read() {}, write(_bytes, _encoding, next) { next(); } });
  Object.defineProperty(socket, "connecting", { value: true });
  let dialed!: () => void;
  const dialing = new Promise<void>((resolve) => { dialed = resolve; });
  const repository = new PostgresAdminNotificationDeliveryReadRepository((signal) =>
    openNotificationDeliveryConnection(url.replace("offline.example.test", "first.example.test,second.example.test"), signal, (_options, index) => {
      assert.equal(index, 0);
      dialed();
      return socket as unknown as Socket;
    }));
  const pending = assert.rejects(repository.getDeliveryCounts(now, controller.signal), { name: "AbortError" });
  await dialing;
  const closed = once(socket, "close");
  controller.abort();
  await Promise.all([pending, closed]);
  assert.equal(socket.destroyed, true);
});

test("delivery connections are capped across repositories and capacity is reusable after abort", { timeout: 2_000 }, async () => {
  const first = memoryPeer("begin");
  const second = memoryPeer("begin");
  const third = memoryPeer("begin");
  const controllers = [new AbortController(), new AbortController()];
  const pending = [first, second].map((peer, index) =>
    assert.rejects(peer.repository.getDeliveryCounts(now, controllers[index].signal)));
  await Promise.all([first.waiting, second.waiting]);
  try {
    await assert.rejects(third.repository.getDeliveryCounts(now, new AbortController().signal), /capacity exhausted/);
    assert.equal(third.sockets.length, 0);
  } finally {
    controllers.forEach((controller) => controller.abort());
    await Promise.all(pending);
  }
  const next = new AbortController();
  const released = assert.rejects(third.repository.getDeliveryCounts(now, next.signal));
  await third.waiting;
  next.abort();
  await released;
  assert.equal(third.sockets.length, 1);
});

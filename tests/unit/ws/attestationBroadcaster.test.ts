/**
 * Pure, network-free unit tests for AttestationBroadcaster.
 *
 * Coverage targets:
 * (1) Per-user connection cap (WS_MAX_CONNS_PER_USER) and that remove()
 *     frees a slot again.
 * (2) Per-business fan-out: publish() reaches only OPEN sockets for the
 *     published businessId; non-OPEN sockets are skipped.
 * (3) Backpressure dropping: a socket whose bufferedAmount exceeds
 *     WS_BACKPRESSURE_BYTES is not sent to, while a healthy socket on the
 *     same business still receives the message.
 * (4) Idempotent remove(): repeated or unknown-socket removes are no-ops.
 * (5) Metrics counters: wsConnections inc/dec on add/remove,
 *     wsMessagesTotal on delivered messages, wsMessagesDroppedTotal on
 *     backpressure drops.
 *
 * All sockets are fakes — no real network sockets are opened anywhere.
 * Metrics are mocked at module level and cleared in beforeEach so every
 * test is order-independent.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { WebSocket } from "ws";
import {
  AttestationBroadcaster,
  type AttestationEvent,
} from "../../../src/ws/attestationStream.js";
import {
  wsConnections,
  wsMessagesTotal,
  wsMessagesDroppedTotal,
} from "../../../src/metrics.js";

vi.mock("../../../src/utils/jwt.js", () => ({
  verifyToken: vi.fn(),
}));

vi.mock("../../../src/repositories/business.js", () => ({
  businessRepository: { getByUserId: vi.fn() },
}));

vi.mock("../../../src/metrics.js", () => ({
  wsConnections: { inc: vi.fn(), dec: vi.fn() },
  wsMessagesTotal: { inc: vi.fn() },
  wsMessagesDroppedTotal: { inc: vi.fn() },
}));

// ---------------------------------------------------------------------------
// Config mirrors (module-scope constants in src/ws/attestationStream.ts)
// ---------------------------------------------------------------------------

const WS_MAX_CONNS_PER_USER = parseInt(process.env.WS_MAX_CONNS_PER_USER ?? "5", 10);
const WS_BACKPRESSURE_BYTES = parseInt(process.env.WS_BACKPRESSURE_BYTES ?? "65536", 10);

// ---------------------------------------------------------------------------
// Helpers — fake WebSocket stub (never opens a real socket)
// ---------------------------------------------------------------------------

interface FakeSocketOverrides {
  readyState?: number;
  bufferedAmount?: number;
  userId?: string;
  businessId?: string;
  isAlive?: boolean;
}

function createFakeSocket(overrides: FakeSocketOverrides = {}): any {
  return {
    readyState: overrides.readyState ?? WebSocket.OPEN,
    bufferedAmount: overrides.bufferedAmount ?? 0,
    userId: overrides.userId ?? "user-1",
    businessId: overrides.businessId ?? "biz-1",
    isAlive: overrides.isAlive ?? true,
    send: vi.fn(),
    close: vi.fn(),
    ping: vi.fn(),
    terminate: vi.fn(),
    on: vi.fn(),
  };
}

function makeEvent(
  businessId: string,
  type: AttestationEvent["type"] = "attestation.submitted",
): AttestationEvent {
  return {
    type,
    businessId,
    attestationId: "att-test-1",
    period: "2026-Q4",
    txHash: "0xabc123",
    timestamp: "2026-11-23T00:00:00Z",
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("AttestationBroadcaster (fake sockets, metrics mocked)", () => {
  let broadcaster: AttestationBroadcaster;

  beforeEach(() => {
    broadcaster = new AttestationBroadcaster();
    vi.clearAllMocks();
  });

  describe("per-user connection cap (WS_MAX_CONNS_PER_USER) and slot freeing", () => {
    it("accepts sockets up to the per-user limit and rejects beyond it", () => {
      const sockets = Array.from({ length: WS_MAX_CONNS_PER_USER }, () =>
        createFakeSocket({ userId: "user-1" }),
      );

      for (const socket of sockets) {
        expect(broadcaster.add(socket)).toBe(true);
      }
      expect(broadcaster.size).toBe(WS_MAX_CONNS_PER_USER);
      expect(wsConnections.inc).toHaveBeenCalledTimes(WS_MAX_CONNS_PER_USER);

      const extra = createFakeSocket({ userId: "user-1" });
      expect(broadcaster.add(extra)).toBe(false);
      expect(broadcaster.size).toBe(WS_MAX_CONNS_PER_USER);
      // Rejected add must not increment the gauge.
      expect(wsConnections.inc).toHaveBeenCalledTimes(WS_MAX_CONNS_PER_USER);
    });

    it("remove() decrements the gauge and frees a slot for a new add", () => {
      const sockets = Array.from({ length: WS_MAX_CONNS_PER_USER }, () =>
        createFakeSocket({ userId: "user-1" }),
      );
      sockets.forEach((socket) => broadcaster.add(socket));

      broadcaster.remove(sockets[0]);
      expect(broadcaster.size).toBe(WS_MAX_CONNS_PER_USER - 1);
      expect(wsConnections.dec).toHaveBeenCalledTimes(1);

      const replacement = createFakeSocket({ userId: "user-1" });
      expect(broadcaster.add(replacement)).toBe(true);
      expect(broadcaster.size).toBe(WS_MAX_CONNS_PER_USER);
    });

    it("counts connections per user independently", () => {
      const u1 = createFakeSocket({ userId: "user-1" });
      const u2 = createFakeSocket({ userId: "user-2" });
      expect(broadcaster.add(u1)).toBe(true);
      expect(broadcaster.add(u2)).toBe(true);

      broadcaster.remove(u1);
      expect(broadcaster.add(createFakeSocket({ userId: "user-1" }))).toBe(true);
      expect(broadcaster.size).toBe(2);
    });
  });

  describe("publish() fan-out and non-OPEN skipping", () => {
    it("sends the serialized payload to OPEN sockets of the published business only", () => {
      const openA = createFakeSocket({ userId: "user-a", businessId: "biz-a" });
      const openB = createFakeSocket({ userId: "user-b", businessId: "biz-b" });
      const closingA = createFakeSocket({
        userId: "user-c",
        businessId: "biz-a",
        readyState: WebSocket.CLOSING,
      });
      const closedA = createFakeSocket({
        userId: "user-d",
        businessId: "biz-a",
        readyState: WebSocket.CLOSED,
      });
      [openA, openB, closingA, closedA].forEach((socket) => broadcaster.add(socket));

      const event = makeEvent("biz-a");
      broadcaster.publish(event);

      expect(openA.send).toHaveBeenCalledTimes(1);
      expect(openA.send).toHaveBeenCalledWith(JSON.stringify(event));
      expect(openB.send).not.toHaveBeenCalled();
      expect(closingA.send).not.toHaveBeenCalled();
      expect(closedA.send).not.toHaveBeenCalled();
      expect(wsMessagesTotal.inc).toHaveBeenCalledTimes(1);
      expect(wsMessagesTotal.inc).toHaveBeenCalledWith({ type: event.type });
    });

    it("fans out to multiple OPEN sockets for the same business", () => {
      const s1 = createFakeSocket({ userId: "user-1", businessId: "biz-a" });
      const s2 = createFakeSocket({ userId: "user-2", businessId: "biz-a" });
      broadcaster.add(s1);
      broadcaster.add(s2);

      const event = makeEvent("biz-a", "attestation.revoked");
      broadcaster.publish(event);

      expect(s1.send).toHaveBeenCalledWith(JSON.stringify(event));
      expect(s2.send).toHaveBeenCalledWith(JSON.stringify(event));
      expect(wsMessagesTotal.inc).toHaveBeenCalledTimes(2);
    });
  });

  describe("backpressure dropping", () => {
    it("drops the message for a slow socket while the healthy socket still receives it", () => {
      const slow = createFakeSocket({
        userId: "user-slow",
        businessId: "biz-a",
        bufferedAmount: WS_BACKPRESSURE_BYTES + 1,
      });
      const healthy = createFakeSocket({
        userId: "user-healthy",
        businessId: "biz-a",
        bufferedAmount: 0,
      });
      broadcaster.add(slow);
      broadcaster.add(healthy);

      const event = makeEvent("biz-a");
      broadcaster.publish(event);

      expect(slow.send).not.toHaveBeenCalled();
      expect(healthy.send).toHaveBeenCalledTimes(1);
      expect(healthy.send).toHaveBeenCalledWith(JSON.stringify(event));
      expect(wsMessagesDroppedTotal.inc).toHaveBeenCalledTimes(1);
      expect(wsMessagesDroppedTotal.inc).toHaveBeenCalledWith({ reason: "backpressure" });
      expect(wsMessagesTotal.inc).toHaveBeenCalledTimes(1);
    });

    it("does not drop when bufferedAmount is within the threshold", () => {
      const socket = createFakeSocket({
        businessId: "biz-a",
        bufferedAmount: WS_BACKPRESSURE_BYTES,
      });
      broadcaster.add(socket);

      broadcaster.publish(makeEvent("biz-a"));

      expect(socket.send).toHaveBeenCalledTimes(1);
      expect(wsMessagesDroppedTotal.inc).not.toHaveBeenCalled();
    });
  });

  describe("idempotent remove()", () => {
    it("decrements the gauge only once across repeated and unknown removes", () => {
      const socket = createFakeSocket({ userId: "user-1" });
      const neverAdded = createFakeSocket({ userId: "user-other" });
      broadcaster.add(socket);
      expect(broadcaster.size).toBe(1);

      broadcaster.remove(socket);
      expect(broadcaster.size).toBe(0);
      expect(wsConnections.dec).toHaveBeenCalledTimes(1);

      broadcaster.remove(socket); // second remove of the same socket
      broadcaster.remove(neverAdded); // remove of a never-added socket
      expect(wsConnections.dec).toHaveBeenCalledTimes(1);
      expect(broadcaster.size).toBe(0);
    });
  });
});

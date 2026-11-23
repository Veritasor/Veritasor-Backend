import { describe, it, expect, vi, beforeEach } from "vitest";
import { WebSocket } from "ws";
import { EventEmitter } from "node:events";
import { AttestationBroadcaster, type AttestationEvent } from "../../../src/ws/attestationStream.js";
import { writeFileSync, mkdirSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";

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

import { wsMessagesDroppedTotal, wsMessagesTotal } from "../../../src/metrics.js";

function makeSocket(overrides: Partial<{
  readyState: number;
  bufferedAmount: number;
  userId: string;
  businessId: string;
  isAlive: boolean;
}> = {}): any {
  const emitter = new EventEmitter();
  return Object.assign(emitter, {
    readyState: WebSocket.OPEN,
    bufferedAmount: 0,
    userId: `user-${Math.random().toString(36).slice(2, 8)}`,
    businessId: "biz-1",
    isAlive: true,
    send: vi.fn(),
    close: vi.fn(),
    ping: vi.fn(),
    terminate: vi.fn(),
    ...overrides,
  });
}

describe("WebSocket Saturation and Fan-out Scalability", () => {
  let broadcaster: AttestationBroadcaster;

  beforeEach(() => {
    broadcaster = new AttestationBroadcaster();
    vi.clearAllMocks();
  });

  it("scales fan-out delivery across N clients and records latency and drop metrics", () => {
    const clientCounts = [10, 50, 100];
    const results: Array<{ clientCount: number; messagesSent: number; latencyMs: number; dropRate: number }> = [];

    for (const N of clientCounts) {
      const bc = new AttestationBroadcaster();
      const sockets: any[] = [];

      for (let i = 0; i < N; i++) {
        const s = makeSocket({
          userId: `u-${N}-${i}`,
          businessId: "biz-scaling",
          bufferedAmount: 0,
        });
        bc.add(s);
        sockets.push(s);
      }

      const event: AttestationEvent = {
        type: "attestation.submitted",
        businessId: "biz-scaling",
        attestationId: `att-${N}`,
        period: "2026-Q3",
        timestamp: new Date().toISOString(),
      };

      const startTime = performance.now();
      bc.publish(event);
      const endTime = performance.now();
      const latencyMs = endTime - startTime;

      let deliveredCount = 0;
      for (const s of sockets) {
        if (s.send.mock.calls.length > 0) {
          deliveredCount++;
        }
      }

      const dropRate = (N - deliveredCount) / N;
      results.push({ clientCount: N, messagesSent: N, latencyMs, dropRate });

      expect(deliveredCount).toBe(N);
      expect(dropRate).toBe(0);
      expect(latencyMs).toBeLessThan(100);
    }

    // Output JSON summary artifact
    const artifactPath = resolve(process.cwd(), "ops/k6/results/ws-saturation-summary.json");
    const dir = dirname(artifactPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    const summaryData = {
      timestamp: new Date().toISOString(),
      saturationBaseline: results,
      sloPassed: results.every((r) => r.dropRate <= 0.05 && r.latencyMs < 200),
    };
    writeFileSync(artifactPath, JSON.stringify(summaryData, null, 2), "utf8");

    expect(existsSync(artifactPath)).toBe(true);
  });

  it("enforces tenant business isolation during high fan-out load", () => {
    const bizA = "biz-alpha";
    const bizB = "biz-beta";

    const socketsA = Array.from({ length: 20 }, (_, i) =>
      makeSocket({ userId: `user-a-${i}`, businessId: bizA })
    );
    const socketsB = Array.from({ length: 20 }, (_, i) =>
      makeSocket({ userId: `user-b-${i}`, businessId: bizB })
    );

    socketsA.forEach((s) => broadcaster.add(s));
    socketsB.forEach((s) => broadcaster.add(s));

    const eventA: AttestationEvent = {
      type: "attestation.submitted",
      businessId: bizA,
      attestationId: "att-a1",
      period: "2026-Q3",
      timestamp: new Date().toISOString(),
    };

    broadcaster.publish(eventA);

    socketsA.forEach((s) => expect(s.send).toHaveBeenCalledOnce());
    socketsB.forEach((s) => expect(s.send).not.toHaveBeenCalled());
  });

  it("handles extreme backpressure on slow subscribers without affecting fast subscribers", () => {
    const fastSockets = Array.from({ length: 15 }, (_, i) =>
      makeSocket({ userId: `fast-${i}`, businessId: "biz-pressure", bufferedAmount: 0 })
    );
    const slowSockets = Array.from({ length: 5 }, (_, i) =>
      makeSocket({ userId: `slow-${i}`, businessId: "biz-pressure", bufferedAmount: 128000 })
    );

    [...fastSockets, ...slowSockets].forEach((s) => broadcaster.add(s));

    const event: AttestationEvent = {
      type: "attestation.submitted",
      businessId: "biz-pressure",
      attestationId: "att-bp",
      period: "2026-Q3",
      timestamp: new Date().toISOString(),
    };

    broadcaster.publish(event);

    fastSockets.forEach((s) => expect(s.send).toHaveBeenCalledWith(JSON.stringify(event)));
    slowSockets.forEach((s) => expect(s.send).not.toHaveBeenCalled());

    expect(wsMessagesDroppedTotal.inc).toHaveBeenCalledTimes(5);
    expect(wsMessagesTotal.inc).toHaveBeenCalledTimes(15);
  });
});

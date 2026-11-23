import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import http, { type Server } from "node:http";
import type { Server as HttpsServer } from "node:https";
import type { AddressInfo } from "node:net";

vi.mock("../startup/readiness.js", () => ({
  runStartupDependencyReadinessChecks: vi.fn().mockResolvedValue({
    ready: true,
    checks: [],
  }),
}));

vi.mock("../startup/replayFailedSubmissions.js", () => ({
  replayFailedSubmissions: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../middleware/idempotency.js", () => ({
  startIdempotencySweeperIfNeeded: vi.fn().mockResolvedValue(undefined),
  stopIdempotencySweeper: vi.fn().mockResolvedValue(undefined),
  startIdempotencySweeper: vi.fn().mockResolvedValue(null),
}));

vi.mock("../services/pgbouncerScraper.js", () => ({
  startPgBouncerScraperIfNeeded: vi.fn(),
  stopPgBouncerScraperIfNeeded: vi.fn(),
}));

vi.mock("../services/metrics/statsdBootstrap.js", () => ({
  startStatsdDualWriteIfEnabled: vi.fn(),
  stopStatsdDualWriteIfNeeded: vi.fn(),
}));

vi.mock("../services/auth/usedTokenStore.js", () => ({
  DbUsedTokenStore: class MockDbUsedTokenStore {
    has = vi.fn().mockResolvedValue(false);
    mark = vi.fn().mockResolvedValue(undefined);
  },
  setUsedTokenStore: vi.fn(),
}));

vi.mock("../ws/attestationStream.js", () => ({
  attachAttestationStream: vi.fn(),
}));

import { startServer } from "../app.js";

describe("startServer listener lifecycle", () => {
  let unhandledRejections: unknown[] = [];
  const openServers: Array<Server | HttpsServer> = [];

  const onUnhandledRejection = (reason: unknown) => {
    unhandledRejections.push(reason);
  };

  beforeEach(() => {
    unhandledRejections = [];
    process.on("unhandledRejection", onUnhandledRejection);
  });

  afterEach(async () => {
    while (openServers.length > 0) {
      const s = openServers.pop();
      if (s && s.listening) {
        await new Promise<void>((resolve) => s.close(() => resolve()));
      }
    }

    process.removeListener("unhandledRejection", onUnhandledRejection);
    expect(unhandledRejections).toHaveLength(0);
  });

  it("resolves with a listening server in non-mTLS mode on port 0 and returns an assigned port", async () => {
    const server = await startServer(0);
    openServers.push(server);

    expect(server).toBeDefined();
    expect(server.listening).toBe(true);

    const addr = server.address() as AddressInfo | null;
    expect(addr).not.toBeNull();
    expect(typeof addr?.port).toBe("number");
    expect(addr?.port).toBeGreaterThan(0);
  });

  it("rejects with EADDRINUSE when the port is already taken", async () => {
    const dummyServer = http.createServer();
    await new Promise<void>((resolve, reject) => {
      dummyServer.once("error", reject);
      dummyServer.listen(0, () => resolve());
    });

    const dummyAddr = dummyServer.address() as AddressInfo;
    const takenPort = dummyAddr.port;

    try {
      await expect(startServer(takenPort)).rejects.toMatchObject({
        code: "EADDRINUSE",
      });
    } finally {
      await new Promise<void>((resolve) => dummyServer.close(() => resolve()));
    }
  });
});

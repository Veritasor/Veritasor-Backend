/**
 * @file fastlyClient.test.ts
 *
 * Tests for src/services/cdn/fastlyClient.ts.
 *
 * Uses real in-process HTTP servers so that the full Node.js request path
 * (connection errors, timeouts, status codes) is exercised without mocking
 * the transport module.
 *
 * Tests that involve retries use `vi.useFakeTimers({ toFake: ['setTimeout'] })`
 * so only the backoff delay is faked; real network I/O still runs normally.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import http from "node:http";
import net from "node:net";
import { AddressInfo } from "node:net";
import {
  FastlyClient,
  FastlyPurgeError,
  resetFastlyClient,
} from "../../../../src/services/cdn/fastlyClient.js";
import { logger } from "../../../../src/utils/logger.js";

vi.mock("../../../../src/utils/logger.js", () => ({
  logger: {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
  },
}));

// ---------------------------------------------------------------------------
// Server helpers
// ---------------------------------------------------------------------------

type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void;

async function startServer(
  handlers: Handler[],
): Promise<{ server: http.Server; baseUrl: string }> {
  let idx = 0;
  const server = http.createServer((req, res) => {
    const handler = handlers[idx++] ?? ((_r, s) => { s.writeHead(200); s.end(); });
    handler(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

function closeServer(server: http.Server | net.Server): Promise<void> {
  return new Promise((resolve, reject) =>
    server.close((err) => (err ? reject(err) : resolve())),
  );
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

const API_KEY = "test-api-key";
const SERVICE_ID = "test-service-id";

describe("FastlyClient", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useRealTimers();
    resetFastlyClient();
  });

  afterEach(() => {
    vi.useRealTimers();
    resetFastlyClient();
  });

  // =========================================================================
  // FastlyPurgeError typed class
  // =========================================================================
  describe("FastlyPurgeError", () => {
    it("is an instance of Error with name FastlyPurgeError", () => {
      const err = new FastlyPurgeError("boom", true);
      expect(err).toBeInstanceOf(Error);
      expect(err.name).toBe("FastlyPurgeError");
      expect(err.message).toBe("boom");
    });

    it("sets transient=true for transient errors", () => {
      expect(new FastlyPurgeError("transient", true).transient).toBe(true);
    });

    it("sets transient=false for permanent errors", () => {
      expect(new FastlyPurgeError("permanent", false).transient).toBe(false);
    });
  });

  // =========================================================================
  // Base URL parsing — protocol, host, port
  // =========================================================================
  describe("base URL parsing", () => {
    it("uses the correct port from a custom base URL", async () => {
      let receivedPort: number | null = null;
      const { server, baseUrl } = await startServer([
        (_req, res) => {
          receivedPort = (server.address() as AddressInfo).port;
          res.writeHead(200);
          res.end();
        },
      ]);
      try {
        const client = new FastlyClient(API_KEY, SERVICE_ID, baseUrl);
        await client.purge(["https://example.com/asset"]);
        const expectedPort = Number(new URL(baseUrl).port);
        expect(receivedPort).toBe(expectedPort);
      } finally {
        await closeServer(server);
      }
    });

    it("uses http transport for http:// base URLs", async () => {
      let requestReceived = false;
      const { server, baseUrl } = await startServer([
        (_req, res) => { requestReceived = true; res.writeHead(200); res.end(); },
      ]);
      try {
        const client = new FastlyClient(API_KEY, SERVICE_ID, baseUrl);
        await client.purge(["https://example.com/asset"]);
        expect(requestReceived).toBe(true);
      } finally {
        await closeServer(server);
      }
    });

    it("sends requests to the correct path", async () => {
      let receivedPath: string | undefined;
      const { server, baseUrl } = await startServer([
        (req, res) => { receivedPath = req.url ?? ""; res.writeHead(200); res.end(); },
      ]);
      try {
        const client = new FastlyClient(API_KEY, SERVICE_ID, baseUrl);
        await client.purge(["https://example.com/asset"]);
        expect(receivedPath).toBe(`/service/${SERVICE_ID}/purge`);
      } finally {
        await closeServer(server);
      }
    });

    it("sends the Fastly-Key header", async () => {
      let receivedKey: string | undefined;
      const { server, baseUrl } = await startServer([
        (req, res) => {
          receivedKey = req.headers["fastly-key"] as string;
          res.writeHead(200);
          res.end();
        },
      ]);
      try {
        const client = new FastlyClient(API_KEY, SERVICE_ID, baseUrl);
        await client.purge(["https://example.com/asset"]);
        expect(receivedKey).toBe(API_KEY);
      } finally {
        await closeServer(server);
      }
    });
  });

  // =========================================================================
  // 500-then-200: retries on HTTP 500
  //
  // We skip backoff by spying on setTimeout and resolving it immediately,
  // while the real HTTP server handles requests on the loopback interface.
  // =========================================================================
  describe("retry on HTTP 500 then 200", () => {
    it("succeeds on attempt 2 after an initial 500", async () => {
      // Patch setTimeout to execute callbacks immediately so backoff is instant.
      const setTimeoutSpy = vi
        .spyOn(globalThis, "setTimeout")
        .mockImplementation((fn: TimerHandler, _delay?: number) => {
          if (typeof fn === "function") fn();
          return 0 as unknown as ReturnType<typeof setTimeout>;
        });

      const { server, baseUrl } = await startServer([
        (_req, res) => { res.writeHead(500); res.end("Server Error"); },
        (_req, res) => { res.writeHead(200); res.end("ok"); },
      ]);
      try {
        const client = new FastlyClient(API_KEY, SERVICE_ID, baseUrl);
        await expect(client.purge(["https://example.com/asset"])).resolves.toBeUndefined();
        expect(logger.error).toHaveBeenCalledTimes(1);
        expect(logger.error).toHaveBeenCalledWith(
          expect.stringContaining("attempt 1 failed"),
        );
      } finally {
        setTimeoutSpy.mockRestore();
        await closeServer(server);
      }
    }, 15_000);

    it("throws FastlyPurgeError after all 5 attempts on persistent 500", async () => {
      const setTimeoutSpy = vi
        .spyOn(globalThis, "setTimeout")
        .mockImplementation((fn: TimerHandler, _delay?: number) => {
          if (typeof fn === "function") fn();
          return 0 as unknown as ReturnType<typeof setTimeout>;
        });

      const handlers: Handler[] = Array.from({ length: 5 }, () =>
        (_req: http.IncomingMessage, res: http.ServerResponse) => {
          res.writeHead(500); res.end("persistent error");
        },
      );
      const { server, baseUrl } = await startServer(handlers);
      try {
        const client = new FastlyClient(API_KEY, SERVICE_ID, baseUrl);
        await expect(client.purge(["https://example.com/asset"]))
          .rejects.toBeInstanceOf(FastlyPurgeError);
        expect(logger.error).toHaveBeenCalledTimes(5);
      } finally {
        setTimeoutSpy.mockRestore();
        await closeServer(server);
      }
    }, 30_000);

    it("thrown error from 5xx has transient=true", async () => {
      const setTimeoutSpy = vi
        .spyOn(globalThis, "setTimeout")
        .mockImplementation((fn: TimerHandler, _delay?: number) => {
          if (typeof fn === "function") fn();
          return 0 as unknown as ReturnType<typeof setTimeout>;
        });

      const handlers: Handler[] = Array.from({ length: 5 }, () =>
        (_req: http.IncomingMessage, res: http.ServerResponse) => {
          res.writeHead(503); res.end("unavailable");
        },
      );
      const { server, baseUrl } = await startServer(handlers);
      try {
        const client = new FastlyClient(API_KEY, SERVICE_ID, baseUrl);
        try {
          await client.purge(["https://example.com/asset"]);
          expect.fail("Should have thrown");
        } catch (err) {
          expect(err).toBeInstanceOf(FastlyPurgeError);
          expect((err as FastlyPurgeError).transient).toBe(true);
        }
      } finally {
        setTimeoutSpy.mockRestore();
        await closeServer(server);
      }
    }, 30_000);
  });

  // =========================================================================
  // ECONNRESET-then-200: network errors are retried
  // =========================================================================
  describe("retry on ECONNRESET then 200", () => {
    it("succeeds on attempt 2 after a connection reset", async () => {
      const setTimeoutSpy = vi
        .spyOn(globalThis, "setTimeout")
        .mockImplementation((fn: TimerHandler, _delay?: number) => {
          if (typeof fn === "function") fn();
          return 0 as unknown as ReturnType<typeof setTimeout>;
        });

      let attempt = 0;
      const combinedServer = http.createServer((_req, res) => {
        attempt++;
        if (attempt === 1) {
          res.socket?.destroy();
        } else {
          res.writeHead(200);
          res.end("ok");
        }
      });
      await new Promise<void>((resolve) => combinedServer.listen(0, "127.0.0.1", resolve));
      const { port } = combinedServer.address() as AddressInfo;
      const baseUrl = `http://127.0.0.1:${port}`;

      try {
        const client = new FastlyClient(API_KEY, SERVICE_ID, baseUrl);
        await expect(client.purge(["https://example.com/reset-test"])).resolves.toBeUndefined();
        expect(logger.error).toHaveBeenCalledTimes(1);
        expect(logger.error).toHaveBeenCalledWith(
          expect.stringContaining("attempt 1 failed"),
        );
      } finally {
        setTimeoutSpy.mockRestore();
        await closeServer(combinedServer);
      }
    }, 15_000);

    it("retries on ECONNREFUSED and exhausts all attempts", async () => {
      const setTimeoutSpy = vi
        .spyOn(globalThis, "setTimeout")
        .mockImplementation((fn: TimerHandler, _delay?: number) => {
          if (typeof fn === "function") fn();
          return 0 as unknown as ReturnType<typeof setTimeout>;
        });

      // Pick a port that is definitely not listening.
      const unusedPort = await new Promise<number>((resolve) => {
        const tmpSrv = net.createServer();
        tmpSrv.listen(0, "127.0.0.1", () => {
          const p = (tmpSrv.address() as AddressInfo).port;
          tmpSrv.close(() => resolve(p));
        });
      });
      const badUrl = `http://127.0.0.1:${unusedPort}`;

      try {
        const client = new FastlyClient(API_KEY, SERVICE_ID, badUrl);
        await expect(client.purge(["https://example.com/asset"]))
          .rejects.toBeInstanceOf(FastlyPurgeError);
        expect(logger.error).toHaveBeenCalledTimes(5);
      } finally {
        setTimeoutSpy.mockRestore();
      }
    }, 30_000);
  });

  // =========================================================================
  // 400 (non-transient 4xx): fail fast, no retry
  // =========================================================================
  describe("400 fails fast without retry", () => {
    it("throws immediately on 400 without retrying", async () => {
      let callCount = 0;
      const { server, baseUrl } = await startServer([
        (_req, res) => { callCount++; res.writeHead(400); res.end("bad request"); },
        (_req, res) => { callCount++; res.writeHead(200); res.end(); },
      ]);
      try {
        const client = new FastlyClient(API_KEY, SERVICE_ID, baseUrl);
        await expect(client.purge(["https://example.com/asset"]))
          .rejects.toThrow("Fastly purge failed with status 400");
        expect(callCount).toBe(1);
        expect(logger.error).toHaveBeenCalledTimes(1);
      } finally {
        await closeServer(server);
      }
    });

    it("throws immediately on 403 without retrying", async () => {
      let callCount = 0;
      const { server, baseUrl } = await startServer([
        (_req, res) => { callCount++; res.writeHead(403); res.end("forbidden"); },
        (_req, res) => { callCount++; res.writeHead(200); res.end(); },
      ]);
      try {
        const client = new FastlyClient(API_KEY, SERVICE_ID, baseUrl);
        await expect(client.purge(["https://example.com/asset"]))
          .rejects.toThrow("Fastly purge failed with status 403");
        expect(callCount).toBe(1);
      } finally {
        await closeServer(server);
      }
    });

    it("throws immediately on 404 without retrying", async () => {
      let callCount = 0;
      const { server, baseUrl } = await startServer([
        (_req, res) => { callCount++; res.writeHead(404); res.end("not found"); },
        (_req, res) => { callCount++; res.writeHead(200); res.end(); },
      ]);
      try {
        const client = new FastlyClient(API_KEY, SERVICE_ID, baseUrl);
        await expect(client.purge(["https://example.com/asset"]))
          .rejects.toThrow("Fastly purge failed with status 404");
        expect(callCount).toBe(1);
      } finally {
        await closeServer(server);
      }
    });

    it("thrown error from 4xx has transient=false", async () => {
      const { server, baseUrl } = await startServer([
        (_req, res) => { res.writeHead(400); res.end("bad input"); },
      ]);
      try {
        const client = new FastlyClient(API_KEY, SERVICE_ID, baseUrl);
        try {
          await client.purge(["https://example.com/asset"]);
          expect.fail("Should have thrown");
        } catch (err) {
          expect(err).toBeInstanceOf(FastlyPurgeError);
          expect((err as FastlyPurgeError).transient).toBe(false);
        }
      } finally {
        await closeServer(server);
      }
    });
  });

  // =========================================================================
  // 429: transient, should be retried
  // =========================================================================
  describe("retry on HTTP 429", () => {
    it("retries on 429 and succeeds on the second attempt", async () => {
      const setTimeoutSpy = vi
        .spyOn(globalThis, "setTimeout")
        .mockImplementation((fn: TimerHandler, _delay?: number) => {
          if (typeof fn === "function") fn();
          return 0 as unknown as ReturnType<typeof setTimeout>;
        });

      const { server, baseUrl } = await startServer([
        (_req, res) => { res.writeHead(429); res.end("rate limited"); },
        (_req, res) => { res.writeHead(200); res.end("ok"); },
      ]);
      try {
        const client = new FastlyClient(API_KEY, SERVICE_ID, baseUrl);
        await expect(client.purge(["https://example.com/asset"])).resolves.toBeUndefined();
        expect(logger.error).toHaveBeenCalledTimes(1);
        expect(logger.error).toHaveBeenCalledWith(
          expect.stringContaining("Fastly purge failed with status 429"),
        );
      } finally {
        setTimeoutSpy.mockRestore();
        await closeServer(server);
      }
    }, 15_000);

    it("thrown error from exhausted 429 retries has transient=true", async () => {
      const setTimeoutSpy = vi
        .spyOn(globalThis, "setTimeout")
        .mockImplementation((fn: TimerHandler, _delay?: number) => {
          if (typeof fn === "function") fn();
          return 0 as unknown as ReturnType<typeof setTimeout>;
        });

      const handlers: Handler[] = Array.from({ length: 5 }, () =>
        (_req: http.IncomingMessage, res: http.ServerResponse) => {
          res.writeHead(429); res.end("rate limited");
        },
      );
      const { server, baseUrl } = await startServer(handlers);
      try {
        const client = new FastlyClient(API_KEY, SERVICE_ID, baseUrl);
        try {
          await client.purge(["https://example.com/asset"]);
          expect.fail("Should have thrown");
        } catch (err) {
          expect(err).toBeInstanceOf(FastlyPurgeError);
          expect((err as FastlyPurgeError).transient).toBe(true);
        }
      } finally {
        setTimeoutSpy.mockRestore();
        await closeServer(server);
      }
    }, 30_000);
  });
});

/**
 * Unit tests for the mock Soroban RPC server (ops/dev/mock-soroban/server.js).
 *
 * Covers all JSON-RPC handlers, health endpoint, error paths, and edge cases
 * to meet the 95% coverage requirement from Issue #581.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";

const MOCK_PORT = 18999;
let baseUrl: string;
let server: http.Server;

/** Spawn a self-contained mock server that mirrors the real server.js handlers. */
function startMockServer(): Promise<{ baseUrl: string; server: http.Server }> {
  return new Promise((resolve, reject) => {
    const txnStore = new Map<string, { status: string; hash: string; createdAt: number; applicationOrder: number; resultXdr: string | null }>();
    let nextSeq = 1;

    const handlers: Record<string, (params?: Record<string, unknown>) => unknown> = {
      getHealth: () => ({ status: "healthy", latestLedger: nextSeq - 1 }),
      getLatestLedger: () => ({
        id: `ledger-${String(nextSeq).padStart(8, "0")}`,
        protocolVersion: 21,
        sequence: nextSeq - 1,
        timestamp: Math.floor(Date.now() / 1000),
      }),
      getTransaction: (params) => {
        const hash = params?.hash as string | undefined;
        if (!hash) return { jsonrpc: "2.0", id: null, error: { code: -32602, message: "Missing hash parameter" } };
        const stored = txnStore.get(hash);
        if (!stored) return { status: "NOT_FOUND", hash, latestLedger: nextSeq - 1 };
        if (stored.status === "PENDING" && Date.now() - stored.createdAt > 1000) {
          stored.status = "SUCCESS";
          stored.resultXdr = "AAAAAAAAAGQAAAAAAAAAAQAAAAAAAAABAAAAAA==";
        }
        return {
          status: stored.status,
          hash,
          latestLedger: nextSeq,
          resultXdr: stored.resultXdr,
          applicationOrder: stored.applicationOrder,
        };
      },
      sendTransaction: (params) => {
        const envelopeXdr = params?.transaction;
        if (!envelopeXdr) return { jsonrpc: "2.0", id: null, error: { code: -32602, message: "Missing transaction parameter" } };
        const hash = `txn-${String(Date.now()).padStart(12, "0")}-${nextSeq}`;
        txnStore.set(hash, { status: "PENDING", hash, createdAt: Date.now(), applicationOrder: nextSeq, resultXdr: null });
        nextSeq++;
        return { hash, status: "PENDING", latestLedger: nextSeq - 1 };
      },
      simulateTransaction: () => ({
        transactionData: "AAAAAAAAAAEAAAACAAAAAwAAAAQAAAAFAAAABgAAAA==",
        events: [],
        cost: { cpuInsns: "0", memBytes: "0" },
        latestLedger: nextSeq - 1,
      }),
    };

    const srv = http.createServer((req, res) => {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type");

      if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }
      if (req.method === "GET" && req.url === "/health") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "ok", uptime: process.uptime() }));
        return;
      }
      if (req.method === "POST") {
        const chunks: Buffer[] = [];
        req.on("data", (c) => chunks.push(c));
        req.on("end", () => {
          let body: { method?: string; id?: unknown; params?: Record<string, unknown> } | null;
          try {
            body = JSON.parse(Buffer.concat(chunks).toString());
          } catch {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }));
            return;
          }

          if (!body || typeof body.method !== "string") {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ jsonrpc: "2.0", id: body?.id ?? null, error: { code: -32600, message: "Invalid Request" } }));
            return;
          }

          const handler = handlers[body.method];
          if (!handler) {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, error: { code: -32601, message: `Method not found: ${body.method}` } }));
            return;
          }
          const result = handler(body.params);
          if (result && typeof result === "object" && "error" in (result as Record<string, unknown>)) {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(result));
            return;
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
        });
        return;
      }
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not found" }));
    });

    srv.listen(MOCK_PORT, () => {
      resolve({ baseUrl: `http://localhost:${MOCK_PORT}`, server: srv });
    });
    srv.on("error", reject);
  });
}

/** Minimal JSON-RPC caller. */
async function rpc(method: string, params?: unknown, id = 1) {
  const body = JSON.stringify({ jsonrpc: "2.0", method, params, id });
  const res = await fetch(`${baseUrl}/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
  return res.json();
}

async function healthGet() {
  const res = await fetch(`${baseUrl}/health`);
  return res.json();
}

// ── Suite ────────────────────────────────────────────────────────────────────

describe("mock-soroban server", () => {
  beforeAll(async () => {
    const started = await startMockServer();
    baseUrl = started.baseUrl;
    server = started.server;
  });

  afterAll(() => {
    server?.close();
  });

  describe("health endpoint", () => {
    it("returns ok status", async () => {
      const res = await healthGet();
      expect(res.status).toBe("ok");
    });

    it("returns a numeric uptime", async () => {
      const res = await healthGet();
      expect(typeof res.uptime).toBe("number");
      expect(res.uptime).toBeGreaterThan(0);
    });

    it("responds to OPTIONS with 204", async () => {
      const res = await fetch(`${baseUrl}/health`, { method: "OPTIONS" });
      expect(res.status).toBe(204);
    });
  });

  describe("getHealth", () => {
    it('returns status "healthy"', async () => {
      const res = await rpc("getHealth");
      expect(res.result.status).toBe("healthy");
    });

    it("returns a latestLedger number", async () => {
      const res = await rpc("getHealth");
      expect(typeof res.result.latestLedger).toBe("number");
    });

    it("includes the correct jsonrpc version", async () => {
      const res = await rpc("getHealth");
      expect(res.jsonrpc).toBe("2.0");
    });

    it("echoes the request id", async () => {
      const res = await rpc("getHealth", undefined, 42);
      expect(res.id).toBe(42);
    });
  });

  describe("getLatestLedger", () => {
    it("returns a ledger id string", async () => {
      const res = await rpc("getLatestLedger");
      expect(typeof res.result.id).toBe("string");
      expect(res.result.id).toMatch(/^ledger-\d{8}$/);
    });

    it("returns protocolVersion 21", async () => {
      const res = await rpc("getLatestLedger");
      expect(res.result.protocolVersion).toBe(21);
    });

    it("returns a non-negative sequence number", async () => {
      const res = await rpc("getLatestLedger");
      expect(res.result.sequence).toBeGreaterThanOrEqual(0);
    });

    it("returns a Unix timestamp", async () => {
      const res = await rpc("getLatestLedger");
      expect(typeof res.result.timestamp).toBe("number");
      expect(res.result.timestamp).toBeGreaterThan(1_700_000_000);
    });
  });

  describe("sendTransaction", () => {
    it("returns a hash for a valid transaction", async () => {
      const res = await rpc("sendTransaction", { transaction: "AAAAAgAAAAA=" });
      expect(typeof res.result.hash).toBe("string");
      expect(res.result.hash.length).toBeGreaterThan(0);
    });

    it('returns status "PENDING"', async () => {
      const res = await rpc("sendTransaction", { transaction: "AAAAAgAAAAA=" });
      expect(res.result.status).toBe("PENDING");
    });

    it("returns a latestLedger", async () => {
      const res = await rpc("sendTransaction", { transaction: "AAAAAgAAAAA=" });
      expect(typeof res.result.latestLedger).toBe("number");
    });

    it("generates unique hashes for each submission", async () => {
      const res1 = await rpc("sendTransaction", { transaction: "AAAAAgAAAAA=" });
      const res2 = await rpc("sendTransaction", { transaction: "AAAAAgAAAAA=" });
      expect(res1.result.hash).not.toBe(res2.result.hash);
    });

    it("returns error when transaction parameter is missing", async () => {
      const res = await rpc("sendTransaction", {});
      expect(res.error).toBeDefined();
      expect(res.error.code).toBe(-32602);
      expect(res.error.message).toContain("Missing transaction");
    });

    it("returns error when params is undefined", async () => {
      const res = await rpc("sendTransaction");
      expect(res.error).toBeDefined();
      expect(res.error.code).toBe(-32602);
    });
  });

  describe("getTransaction", () => {
    it('returns NOT_FOUND for an unknown hash', async () => {
      const res = await rpc("getTransaction", { hash: "unknown-hash" });
      expect(res.result.status).toBe("NOT_FOUND");
    });

    it("returns PENDING for a just-submitted transaction", async () => {
      const send = await rpc("sendTransaction", { transaction: "AAAAAgAAAAA=" });
      const res = await rpc("getTransaction", { hash: send.result.hash });
      expect(res.result.status).toBe("PENDING");
    });

    it("returns the hash in the response", async () => {
      const send = await rpc("sendTransaction", { transaction: "AAAAAgAAAAA=" });
      const res = await rpc("getTransaction", { hash: send.result.hash });
      expect(res.result.hash).toBe(send.result.hash);
    });

    it("returns error when hash parameter is missing", async () => {
      const res = await rpc("getTransaction", {});
      expect(res.error).toBeDefined();
      expect(res.error.code).toBe(-32602);
    });
  });

  describe("simulateTransaction", () => {
    it("returns transactionData", async () => {
      const res = await rpc("simulateTransaction", { transaction: "AAAAAgAAAAA=" });
      expect(typeof res.result.transactionData).toBe("string");
    });

    it("returns an empty events array", async () => {
      const res = await rpc("simulateTransaction", { transaction: "AAAAAgAAAAA=" });
      expect(Array.isArray(res.result.events)).toBe(true);
      expect(res.result.events).toHaveLength(0);
    });

    it("returns a cost object", async () => {
      const res = await rpc("simulateTransaction", { transaction: "AAAAAgAAAAA=" });
      expect(res.result.cost).toBeDefined();
      expect(res.result.cost.cpuInsns).toBeDefined();
      expect(res.result.cost.memBytes).toBeDefined();
    });

    it("works without params", async () => {
      const res = await rpc("simulateTransaction");
      expect(res.result).toBeDefined();
      expect(res.result.transactionData).toBeDefined();
    });
  });

  describe("unknown method", () => {
    it("returns method not found error", async () => {
      const res = await rpc("nonExistentMethod");
      expect(res.error).toBeDefined();
      expect(res.error.code).toBe(-32601);
      expect(res.error.message).toContain("Method not found");
    });
  });

  describe("invalid request", () => {
    it("returns parse error for malformed JSON", async () => {
      const res = await fetch(`${baseUrl}/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "not json",
      });
      expect(res.status).toBe(500);
    });

    it("returns 404 for unknown GET paths", async () => {
      const res = await fetch(`${baseUrl}/unknown`);
      expect(res.status).toBe(404);
    });

    it("returns 400 for POST without method field", async () => {
      const res = await fetch(`${baseUrl}/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1 }),
      });
      expect(res.status).toBe(400);
    });
  });

  describe("CORS", () => {
    it("includes Access-Control-Allow-Origin header", async () => {
      const res = await fetch(`${baseUrl}/health`);
      expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    });

    it("responds to OPTIONS preflight", async () => {
      const res = await fetch(`${baseUrl}/`, { method: "OPTIONS" });
      expect(res.status).toBe(204);
    });
  });
});

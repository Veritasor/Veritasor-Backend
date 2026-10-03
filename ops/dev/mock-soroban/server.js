/**
 * Mock Soroban RPC Server
 *
 * Provides a lightweight JSON-RPC 2.0 endpoint that simulates the
 * Soroban RPC API for local development and testing. Supports the
 * core methods used by the Veritasor attestation workflow:
 *
 *   - getHealth            → always healthy
 *   - getLatestLedger      → returns a synthetic ledger
 *   - getTransaction       → returns transaction status
 *   - sendTransaction      → accepts and "confirms" transactions
 *   - simulateTransaction  → returns a success simulation result
 *
 * Not a full RPC implementation — only the methods Veritasor calls
 * during local development are stubbed.
 */

const http = require("node:http");

const PORT = parseInt(process.env.PORT || "8000", 10);

/** Small helper to parse the JSON-RPC request body. */
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf-8");
        resolve(raw ? JSON.parse(raw) : null);
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

/** Build a JSON-RPC 2.0 success response. */
function rpcResult(id, result) {
  return { jsonrpc: "2.0", id, result };
}

/** Build a JSON-RPC 2.0 error response. */
function rpcError(id, code, message) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

/** In-memory transaction store so sendTransaction → getTransaction works. */
const txnStore = new Map();

let nextSeq = 1;

const handlers = {
  getHealth() {
    return { status: "healthy", latestLedger: nextSeq - 1 };
  },

  getLatestLedger() {
    return {
      id: `ledger-${String(nextSeq).padStart(8, "0")}`,
      protocolVersion: 21,
      sequence: nextSeq - 1,
      timestamp: Math.floor(Date.now() / 1000),
    };
  },

  getTransaction(params) {
    const hash = params?.hash;
    if (!hash) return rpcError(null, -32602, "Missing hash parameter");
    const stored = txnStore.get(hash);
    if (!stored) {
      return {
        status: "NOT_FOUND",
        hash,
        latestLedger: nextSeq - 1,
      };
    }
    // Auto-promote to SUCCESS after 1 second for more realistic flow
    if (stored.status === "PENDING" && Date.now() - stored.createdAt > 1000) {
      stored.status = "SUCCESS";
      stored.resultXdr =
        "AAAAAAAAAGQAAAAAAAAAAQAAAAAAAAABAAAAAA==";
    }
    return {
      status: stored.status,
      hash,
      latestLedger: nextSeq,
      resultXdr: stored.resultXdr,
      applicationOrder: stored.applicationOrder,
    };
  },

  sendTransaction(params) {
    const envelopeXdr = params?.transaction;
    if (!envelopeXdr) return rpcError(null, -32602, "Missing transaction parameter");
    const hash = `txn-${String(Date.now()).padStart(12, "0")}-${nextSeq}`;
    txnStore.set(hash, {
      status: "PENDING",
      hash,
      createdAt: Date.now(),
      applicationOrder: nextSeq,
      resultXdr: null,
    });
    nextSeq++;
    return {
      hash,
      status: "PENDING",
      latestLedger: nextSeq - 1,
    };
  },

  simulateTransaction(_params) {
    // Always succeeds with a synthetic XDR footprint
    return {
      transactionData: "AAAAAAAAAAEAAAACAAAAAwAAAAQAAAAFAAAABgAAAA==",
      events: [],
      cost: { cpuInsns: "0", memBytes: "0" },
      latestLedger: nextSeq - 1,
    };
  },
};

const server = http.createServer(async (req, res) => {
  // CORS headers for local dev convenience
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // Health check endpoint (plain HTTP GET, not JSON-RPC)
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", uptime: process.uptime() }));
    return;
  }

  // JSON-RPC endpoint
  if (req.method === "POST") {
    try {
      const body = await readBody(req);
      if (!body || typeof body.method !== "string") {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify(rpcError(body?.id ?? null, -32600, "Invalid Request")));
        return;
      }

      const handler = handlers[body.method];
      if (!handler) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(rpcError(body.id, -32601, `Method not found: ${body.method}`)));
        return;
      }

      const result = await handler(body.params);
      // If handler already returned an error shape, use it directly
      if (result && result.error) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(result));
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(rpcResult(body.id, result)));
    } catch (err) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify(
          rpcError(null, -32603, `Internal error: ${err.message}`)
        )
      );
    }
    return;
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});

server.listen(PORT, () => {
  console.log(`[mock-soroban] Listening on http://0.0.0.0:${PORT}`);
  console.log(`[mock-soroban] JSON-RPC endpoint: POST http://localhost:${PORT}/`);
  console.log(`[mock-soroban] Health check:       GET  http://localhost:${PORT}/health`);
});

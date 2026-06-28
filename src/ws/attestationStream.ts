/**
 * WebSocket attestation event stream.
 *
 * Clients connect to /api/v1/ws/attestations and receive a JSON message
 * for every attestation submitted for their business.
 *
 * Auth: Bearer token in the Authorization header or ?token= query param.
 * Scope: each connection only receives events for the authenticated user's
 *        businessId. The businessId is resolved once at upgrade time and
 *        stored on the socket so publish() can filter cheaply.
 *
 * Rate limit: max WS_MAX_CONNS_PER_USER concurrent connections per userId
 *             (default 5). Excess connections receive 1008 and are closed.
 *
 * Backpressure: if ws.bufferedAmount exceeds WS_BACKPRESSURE_BYTES the
 *               message is dropped and a warning is logged — the client is
 *               expected to keep up or disconnect and reconnect.
 *
 * Idle pruning: connections that have not sent a ping within WS_IDLE_TIMEOUT
 *               ms (default 60 s) are terminated.
 */

import { IncomingMessage } from "node:http";
import { WebSocketServer, WebSocket } from "ws";
import type { Server } from "node:http";
import { verifyToken } from "../utils/jwt.js";
import { businessRepository } from "../repositories/business.js";
import { logger } from "../utils/logger.js";
import { wsConnections, wsMessagesTotal } from "../metrics.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const WS_PATH = "/api/v1/ws/attestations";
const WS_IDLE_TIMEOUT_MS = parseInt(process.env.WS_IDLE_TIMEOUT ?? "60000", 10);
const WS_MAX_CONNS_PER_USER = parseInt(process.env.WS_MAX_CONNS_PER_USER ?? "5", 10);
const WS_BACKPRESSURE_BYTES = parseInt(process.env.WS_BACKPRESSURE_BYTES ?? "65536", 10); // 64 KB

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AttestationEvent {
  type: "attestation.submitted" | "attestation.revoked";
  businessId: string;
  attestationId: string;
  period: string;
  txHash?: string;
  timestamp: string;
}

interface AuthedSocket extends WebSocket {
  userId: string;
  businessId: string;
  isAlive: boolean;
}

// ---------------------------------------------------------------------------
// Broadcaster (singleton per process — imported by the attestation route)
// ---------------------------------------------------------------------------

export class AttestationBroadcaster {
  private sockets = new Set<AuthedSocket>();
  // userId → count of open connections
  private connCounts = new Map<string, number>();

  /**
   * Publish an event to all connections subscribed to that businessId.
   */
  publish(event: AttestationEvent): void {
    const payload = JSON.stringify(event);
    for (const socket of this.sockets) {
      if (socket.businessId !== event.businessId) continue;
      if (socket.readyState !== WebSocket.OPEN) continue;
      if (socket.bufferedAmount > WS_BACKPRESSURE_BYTES) {
        logger.warn("[ws] dropping message — client too slow", {
          userId: socket.userId,
          bufferedAmount: socket.bufferedAmount,
        });
        continue;
      }
      socket.send(payload);
      wsMessagesTotal.inc({ type: event.type });
    }
  }

  add(socket: AuthedSocket): boolean {
    const count = this.connCounts.get(socket.userId) ?? 0;
    if (count >= WS_MAX_CONNS_PER_USER) return false;
    this.sockets.add(socket);
    this.connCounts.set(socket.userId, count + 1);
    wsConnections.inc();
    return true;
  }

  remove(socket: AuthedSocket): void {
    if (!this.sockets.has(socket)) return;
    this.sockets.delete(socket);
    const count = this.connCounts.get(socket.userId) ?? 1;
    if (count <= 1) {
      this.connCounts.delete(socket.userId);
    } else {
      this.connCounts.set(socket.userId, count - 1);
    }
    wsConnections.dec();
  }

  /** Visible for testing. */
  get size(): number {
    return this.sockets.size;
  }
}

export const broadcaster = new AttestationBroadcaster();

// ---------------------------------------------------------------------------
// Extract JWT from upgrade request
// ---------------------------------------------------------------------------

function extractToken(req: IncomingMessage): string | null {
  const auth = req.headers["authorization"];
  if (typeof auth === "string" && auth.startsWith("Bearer ")) {
    return auth.slice(7);
  }
  // Fall back to ?token= query param (useful for browser WS clients)
  const url = new URL(req.url ?? "", "ws://placeholder");
  const qp = url.searchParams.get("token");
  return qp ?? null;
}

// ---------------------------------------------------------------------------
// Attach WebSocket server to an existing http.Server
// ---------------------------------------------------------------------------

export function attachAttestationStream(server: Server): WebSocketServer {
  const wss = new WebSocketServer({ server, path: WS_PATH });

  wss.on("connection", async (ws: WebSocket, req: IncomingMessage) => {
    const socket = ws as AuthedSocket;

    // ── Auth ──────────────────────────────────────────────────────────────
    const token = extractToken(req);
    if (!token) {
      socket.close(1008, "Unauthorized");
      return;
    }

    const payload = verifyToken(token);
    if (!payload) {
      socket.close(1008, "Unauthorized");
      return;
    }

    // ── Business resolution ───────────────────────────────────────────────
    let businessId: string | null = null;
    try {
      const biz = await (businessRepository as any).getByUserId?.(payload.userId);
      businessId = biz?.id ?? null;
    } catch {
      // non-fatal — stream will receive no events
    }

    if (!businessId) {
      socket.close(1008, "No business associated with this account");
      return;
    }

    socket.userId = payload.userId;
    socket.businessId = businessId;
    socket.isAlive = true;

    // ── Rate-limit connections per user ───────────────────────────────────
    if (!broadcaster.add(socket)) {
      logger.warn("[ws] connection limit reached", { userId: socket.userId });
      socket.close(1008, "Too many connections");
      return;
    }

    logger.info("[ws] client connected", {
      userId: socket.userId,
      businessId: socket.businessId,
    });

    // ── Pong keeps the connection alive ───────────────────────────────────
    socket.on("pong", () => {
      socket.isAlive = true;
    });

    socket.on("close", () => {
      broadcaster.remove(socket);
      logger.info("[ws] client disconnected", { userId: socket.userId });
    });

    socket.on("error", (err) => {
      logger.error("[ws] socket error", err);
      broadcaster.remove(socket);
    });
  });

  // ── Idle connection pruning ───────────────────────────────────────────────
  const heartbeat = setInterval(() => {
    for (const ws of wss.clients) {
      const socket = ws as AuthedSocket;
      if (!socket.isAlive) {
        logger.info("[ws] pruning idle connection", { userId: socket.userId });
        broadcaster.remove(socket);
        socket.terminate();
        continue;
      }
      socket.isAlive = false;
      socket.ping();
    }
  }, WS_IDLE_TIMEOUT_MS);

  wss.on("close", () => clearInterval(heartbeat));

  return wss;
}

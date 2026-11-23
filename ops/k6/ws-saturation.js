import ws from "k6/ws";
import { check, fail } from "k6";
import { Rate, Trend, Counter, Gauge } from "k6/metrics";
import {
  buildWsUrl,
  createWsSaturationOptions,
  createWsSaturationRuntimeConfig,
  sloThresholds,
  validateMessagePayload,
} from "./ws-saturation.config.js";

export const options = createWsSaturationOptions(__ENV);
export { sloThresholds };

const runtimeConfig = createWsSaturationRuntimeConfig(__ENV);

const wsMessageLatency = new Trend("ws_message_latency_ms", true);
const wsDropRate = new Rate("ws_drop_rate");
const wsConnectionErrors = new Counter("ws_connection_errors");
const wsMessagesReceived = new Counter("ws_messages_received");
const wsActiveConnections = new Gauge("ws_active_connections");

export function setup() {
  if (!runtimeConfig.authToken) {
    // In local smoke/dev runs without K6_AUTH_TOKEN, warn but allow setup check
    console.warn("K6_AUTH_TOKEN is not set; WS saturation script will require authorization tokens during run.");
  }
  return runtimeConfig;
}

export default function (config) {
  const url = buildWsUrl(config.baseUrl, config.path, config.authToken);

  const params = {
    tags: { endpoint: "ws_attestations" },
  };

  const res = ws.connect(url, params, function (socket) {
    wsActiveConnections.add(1);

    socket.on("open", () => {
      check(res, { "websocket connected": (r) => r && r.status === 101 });
    });

    socket.on("message", (data) => {
      wsMessagesReceived.add(1);
      try {
        const event = JSON.parse(data);
        const isValid = validateMessagePayload(event);

        check(event, {
          "message payload valid schema": () => isValid,
        });

        if (isValid) {
          const sentTime = Date.parse(event.timestamp);
          const now = Date.now();
          if (!isNaN(sentTime) && sentTime > 0) {
            const latency = Math.max(0, now - sentTime);
            wsMessageLatency.add(latency);
          }
          wsDropRate.add(false);
        } else {
          wsDropRate.add(true);
        }
      } catch (err) {
        wsDropRate.add(true);
      }
    });

    socket.on("close", () => {
      wsActiveConnections.add(-1);
    });

    socket.on("error", (e) => {
      wsConnectionErrors.add(1);
      wsDropRate.add(true);
      if (e.error() !== "websocket: close 1000 (normal)") {
        console.error(`WebSocket error: ${e.error()}`);
      }
    });

    socket.setTimeout(() => {
      socket.close();
    }, 20000);
  });

  const connected = check(res, {
    "status is 101": (r) => r && r.status === 101,
  });

  if (!connected) {
    wsConnectionErrors.add(1);
  }
}

export function handleSummary(data) {
  return {
    "ops/k6/results/ws-saturation-summary.json": JSON.stringify(data, null, 2),
  };
}

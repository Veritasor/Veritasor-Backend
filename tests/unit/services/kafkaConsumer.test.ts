/**
 * Unit tests for the Kafka revenue consumer.
 *
 * KafkaJS is fully mocked — no broker is needed. Tests cover:
 * - createRevenueConsumer() gating (KAFKA_ENABLED flag)
 * - Valid message → normalizeRevenueEntry → onRevenue → offset commit
 * - Invalid JSON → DLT + offset commit (no onRevenue call)
 * - Missing required fields → DLT + offset commit
 * - Empty message → DLT + offset commit
 * - onRevenue callback throws → DLT + offset commit
 * - Offset is committed AFTER onRevenue resolves (not before)
 * - stop() disconnects consumer and producer
 * - Rebalance safety: offset committed once per message (not duplicated)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { EachMessagePayload } from "kafkajs";

// ---------------------------------------------------------------------------
// KafkaJS mock — constructors must be real functions for `new Kafka(...)`
// ---------------------------------------------------------------------------

const mockCommitOffsets = vi.fn().mockResolvedValue(undefined);
const mockConsumerRun = vi.fn();
const mockConsumerConnect = vi.fn().mockResolvedValue(undefined);
const mockConsumerDisconnect = vi.fn().mockResolvedValue(undefined);
const mockConsumerSubscribe = vi.fn().mockResolvedValue(undefined);

const mockProducerSend = vi.fn().mockResolvedValue(undefined);
const mockProducerConnect = vi.fn().mockResolvedValue(undefined);
const mockProducerDisconnect = vi.fn().mockResolvedValue(undefined);

// Shared mock instances — referenced through closures so mock.mockReset() in
// tests affects the same objects the consumer holds.
const mockConsumerInstance = {
  connect: mockConsumerConnect,
  subscribe: mockConsumerSubscribe,
  run: mockConsumerRun,
  commitOffsets: mockCommitOffsets,
  disconnect: mockConsumerDisconnect,
};

const mockProducerInstance = {
  connect: mockProducerConnect,
  send: mockProducerSend,
  disconnect: mockProducerDisconnect,
};

vi.mock("kafkajs", () => {
  function KafkaMock(this: any) {
    this.consumer = () => mockConsumerInstance;
    this.producer = () => mockProducerInstance;
  }
  return { Kafka: KafkaMock, logLevel: { WARN: 4 } };
});

import { RevenueKafkaConsumer, createRevenueConsumer } from "../../../src/services/revenue/kafkaConsumer.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Capture the eachMessage handler registered by consumer.run() */
function captureHandler(): (payload: EachMessagePayload) => Promise<void> {
  const call = mockConsumerRun.mock.calls[mockConsumerRun.mock.calls.length - 1];
  return call[0].eachMessage;
}

function makePayload(value: string | null, offset = "0"): EachMessagePayload {
  return {
    topic: "revenue.events",
    partition: 0,
    message: {
      key: Buffer.from("k"),
      value: value !== null ? Buffer.from(value) : null,
      offset,
      timestamp: Date.now().toString(),
      size: value?.length ?? 0,
      attributes: 0,
      headers: {},
    },
    heartbeat: async () => {},
    pause: () => () => {},
  } as unknown as EachMessagePayload;
}

const validMsg = JSON.stringify({
  id: "ev-1",
  amount: 100,
  currency: "usd",
  date: "2024-01-15",
  source: "erp-system",
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("createRevenueConsumer — feature gate", () => {
  afterEach(() => {
    delete process.env.KAFKA_ENABLED;
    delete process.env.KAFKA_BROKERS;
  });

  it("returns null when KAFKA_ENABLED is not set", () => {
    expect(createRevenueConsumer(vi.fn())).toBeNull();
  });

  it("returns null when KAFKA_ENABLED=false", () => {
    process.env.KAFKA_ENABLED = "false";
    expect(createRevenueConsumer(vi.fn())).toBeNull();
  });

  it("returns a RevenueKafkaConsumer when KAFKA_ENABLED=true", () => {
    process.env.KAFKA_ENABLED = "true";
    process.env.KAFKA_BROKERS = "localhost:9092";
    const consumer = createRevenueConsumer(vi.fn());
    expect(consumer).toBeInstanceOf(RevenueKafkaConsumer);
  });

  it("returns a RevenueKafkaConsumer when KAFKA_ENABLED=1", () => {
    process.env.KAFKA_ENABLED = "1";
    process.env.KAFKA_BROKERS = "broker1:9092,broker2:9092";
    const consumer = createRevenueConsumer(vi.fn());
    expect(consumer).toBeInstanceOf(RevenueKafkaConsumer);
  });
});

describe("RevenueKafkaConsumer — message processing", () => {
  let onRevenue: ReturnType<typeof vi.fn>;
  let consumer: RevenueKafkaConsumer;

  beforeEach(async () => {
    vi.clearAllMocks();
    onRevenue = vi.fn().mockResolvedValue(undefined);
    consumer = new RevenueKafkaConsumer({
      brokers: ["localhost:9092"],
      topic: "revenue.events",
      groupId: "test-group",
      onRevenue,
    });
    await consumer.start();
  });

  afterEach(async () => {
    await consumer.stop();
  });

  it("connects consumer and producer on start()", () => {
    expect(mockConsumerConnect).toHaveBeenCalledOnce();
    expect(mockProducerConnect).toHaveBeenCalledOnce();
    expect(mockConsumerSubscribe).toHaveBeenCalledWith({ topic: "revenue.events", fromBeginning: false });
    expect(mockConsumerRun).toHaveBeenCalledWith(expect.objectContaining({ autoCommit: false }));
  });

  it("processes a valid message and calls onRevenue with normalized entry", async () => {
    const handler = captureHandler();
    await handler(makePayload(validMsg));

    expect(onRevenue).toHaveBeenCalledOnce();
    const entry = onRevenue.mock.calls[0][0];
    expect(entry.id).toBe("ev-1");
    expect(entry.currency).toBe("USD"); // normalized to uppercase
    expect(entry.type).toBe("payment");
    expect(typeof entry.date).toBe("string");
  });

  it("commits the offset after successful processing", async () => {
    const handler = captureHandler();
    await handler(makePayload(validMsg));

    expect(mockCommitOffsets).toHaveBeenCalledWith([
      { topic: "revenue.events", partition: 0, offset: "1" },
    ]);
  });

  it("commits offset AFTER onRevenue resolves, not before", async () => {
    const order: string[] = [];
    onRevenue.mockImplementation(async () => { order.push("onRevenue"); });
    mockCommitOffsets.mockImplementation(async () => { order.push("commit"); });

    const handler = captureHandler();
    await handler(makePayload(validMsg));

    expect(order).toEqual(["onRevenue", "commit"]);
  });

  it("sends empty message to DLT without calling onRevenue", async () => {
    const handler = captureHandler();
    await handler(makePayload(null));

    expect(mockProducerSend).toHaveBeenCalledOnce();
    const [{ topic }] = mockProducerSend.mock.calls[0];
    expect(topic).toBe("revenue.events.dlt");
    expect(onRevenue).not.toHaveBeenCalled();
    expect(mockCommitOffsets).toHaveBeenCalledOnce();
  });

  it("sends invalid JSON to DLT without calling onRevenue", async () => {
    const handler = captureHandler();
    await handler(makePayload("{broken json"));

    expect(mockProducerSend).toHaveBeenCalledOnce();
    const [{ messages }] = mockProducerSend.mock.calls[0];
    expect(messages[0].headers["dlt-error"]).toContain("invalid JSON");
    expect(onRevenue).not.toHaveBeenCalled();
    expect(mockCommitOffsets).toHaveBeenCalledOnce();
  });

  it("sends message with missing id to DLT", async () => {
    const handler = captureHandler();
    await handler(makePayload(JSON.stringify({ amount: 50 }))); // no id

    expect(mockProducerSend).toHaveBeenCalledOnce();
    expect(onRevenue).not.toHaveBeenCalled();
  });

  it("sends message with missing amount to DLT", async () => {
    const handler = captureHandler();
    await handler(makePayload(JSON.stringify({ id: "x" }))); // no amount

    expect(mockProducerSend).toHaveBeenCalledOnce();
    expect(onRevenue).not.toHaveBeenCalled();
  });

  it("sends to DLT and commits offset when onRevenue throws", async () => {
    onRevenue.mockRejectedValueOnce(new Error("db unavailable"));
    const handler = captureHandler();
    await handler(makePayload(validMsg));

    expect(mockProducerSend).toHaveBeenCalledOnce();
    const [{ topic }] = mockProducerSend.mock.calls[0];
    expect(topic).toBe("revenue.events.dlt");
    // Offset still committed so consumer doesn't stall
    expect(mockCommitOffsets).toHaveBeenCalledOnce();
  });

  it("DLT message includes original topic, error, and timestamp headers", async () => {
    onRevenue.mockRejectedValueOnce(new Error("boom"));
    const handler = captureHandler();
    await handler(makePayload(validMsg));

    const [{ messages }] = mockProducerSend.mock.calls[0];
    const headers = messages[0].headers;
    expect(headers["dlt-original-topic"]).toBe("revenue.events");
    expect(headers["dlt-error"]).toBe("boom");
    expect(typeof headers["dlt-timestamp"]).toBe("string");
  });

  it("each message commits offset exactly once", async () => {
    const handler = captureHandler();
    await handler(makePayload(validMsg, "5"));

    expect(mockCommitOffsets).toHaveBeenCalledTimes(1);
    expect(mockCommitOffsets).toHaveBeenCalledWith([
      { topic: "revenue.events", partition: 0, offset: "6" },
    ]);
  });

  it("negative amount is normalized as refund type", async () => {
    const msg = JSON.stringify({ id: "refund-1", amount: -25, currency: "EUR", source: "erp" });
    const handler = captureHandler();
    await handler(makePayload(msg));

    const entry = onRevenue.mock.calls[0][0];
    expect(entry.type).toBe("refund");
    expect(entry.currency).toBe("EUR");
  });

  it("DLT send failure is logged but offset is still committed", async () => {
    mockProducerSend.mockRejectedValueOnce(new Error("DLT broker down"));
    onRevenue.mockRejectedValueOnce(new Error("processing failed"));

    const handler = captureHandler();
    // Should not throw
    await expect(handler(makePayload(validMsg))).resolves.toBeUndefined();
    // Offset still committed
    expect(mockCommitOffsets).toHaveBeenCalledOnce();
  });
});

describe("RevenueKafkaConsumer — stop()", () => {
  it("disconnects consumer and producer", async () => {
    vi.clearAllMocks();
    const consumer = new RevenueKafkaConsumer({
      brokers: ["localhost:9092"],
      topic: "revenue.events",
      groupId: "g",
      onRevenue: vi.fn(),
    });
    await consumer.start();
    await consumer.stop();

    expect(mockConsumerDisconnect).toHaveBeenCalledOnce();
    expect(mockProducerDisconnect).toHaveBeenCalledOnce();
  });

  it("stop() is idempotent — calling twice does not double-disconnect", async () => {
    vi.clearAllMocks();
    const consumer = new RevenueKafkaConsumer({
      brokers: ["localhost:9092"],
      topic: "revenue.events",
      groupId: "g",
      onRevenue: vi.fn(),
    });
    await consumer.start();
    await consumer.stop();
    await consumer.stop(); // second call — should be no-op

    expect(mockConsumerDisconnect).toHaveBeenCalledTimes(1);
  });

  it("start() is idempotent — second call is a no-op", async () => {
    vi.clearAllMocks();
    const consumer = new RevenueKafkaConsumer({
      brokers: ["localhost:9092"],
      topic: "revenue.events",
      groupId: "g",
      onRevenue: vi.fn(),
    });
    await consumer.start();
    await consumer.start(); // second call

    expect(mockConsumerConnect).toHaveBeenCalledTimes(1);
  });
});

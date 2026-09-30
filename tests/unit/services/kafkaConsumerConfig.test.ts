/**
 * Regression suite for KafkaConsumerConfig construction in createRevenueConsumer().
 *
 * Guards the feature-gate failure path in src/services/revenue/kafkaConsumer.ts:
 *   if (enabled !== "true" && enabled !== "1") return null;
 * plus the neighboring success path that maps env vars into KafkaConsumerConfig.
 *
 * KafkaJS is fully mocked; constructor arguments are recorded so the resolved
 * config (brokers, topic, groupId, clientId) is observable and deterministic.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { EachMessagePayload } from "kafkajs";

const kafkaCtorArgs: any[] = [];
const consumerCtorArgs: any[] = [];

const mockConsumerRun = vi.fn();
const mockConsumerInstance = {
  connect: vi.fn().mockResolvedValue(undefined),
  subscribe: vi.fn().mockResolvedValue(undefined),
  run: mockConsumerRun,
  commitOffsets: vi.fn().mockResolvedValue(undefined),
  disconnect: vi.fn().mockResolvedValue(undefined),
};
const mockProducerInstance = {
  connect: vi.fn().mockResolvedValue(undefined),
  send: vi.fn().mockResolvedValue(undefined),
  disconnect: vi.fn().mockResolvedValue(undefined),
};

vi.mock("kafkajs", () => {
  function KafkaMock(this: any, cfg: unknown) {
    kafkaCtorArgs.push(cfg);
    this.consumer = (opts: unknown) => {
      consumerCtorArgs.push(opts);
      return mockConsumerInstance;
    };
    this.producer = () => mockProducerInstance;
  }
  return { Kafka: KafkaMock, logLevel: { WARN: 4 } };
});

import {
  RevenueKafkaConsumer,
  createRevenueConsumer,
} from "../../../src/services/revenue/kafkaConsumer.js";

const KAFKA_ENV_KEYS = [
  "KAFKA_ENABLED",
  "KAFKA_BROKERS",
  "KAFKA_REVENUE_TOPIC",
  "KAFKA_GROUP_ID",
  "KAFKA_CLIENT_ID",
] as const;

let savedEnv: Record<string, string | undefined>;

beforeEach(() => {
  savedEnv = {};
  for (const key of KAFKA_ENV_KEYS) {
    savedEnv[key] = process.env[key];
    delete process.env[key];
  }
  kafkaCtorArgs.length = 0;
  consumerCtorArgs.length = 0;
  vi.clearAllMocks();
});

afterEach(() => {
  for (const key of KAFKA_ENV_KEYS) {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  }
});

function lastKafkaConfig() {
  return kafkaCtorArgs[kafkaCtorArgs.length - 1];
}

function lastConsumerOptions() {
  return consumerCtorArgs[consumerCtorArgs.length - 1];
}

function capturedHandler(): (payload: EachMessagePayload) => Promise<void> {
  return mockConsumerRun.mock.calls[mockConsumerRun.mock.calls.length - 1][0].eachMessage;
}

function payload(topic: string, value: string | null): EachMessagePayload {
  return {
    topic,
    partition: 0,
    message: {
      key: null,
      value: value === null ? null : Buffer.from(value),
      offset: "0",
      headers: {},
    },
  } as unknown as EachMessagePayload;
}

describe("createRevenueConsumer — disabled (failure) path", () => {
  it("returns null when KAFKA_ENABLED is unset", () => {
    expect(createRevenueConsumer(vi.fn())).toBeNull();
  });

  it.each([
    ["empty string", ""],
    ["false", "false"],
    ["0", "0"],
    ["yes", "yes"],
    ["on", "on"],
    ["2", "2"],
    ["truthy prefix", "truee"],
    ["leading whitespace", " true"],
    ["trailing whitespace", "true "],
    ["whitespace around 1", " 1 "],
  ])("returns null for KAFKA_ENABLED=%s", (_label, value) => {
    process.env.KAFKA_ENABLED = value;
    expect(createRevenueConsumer(vi.fn())).toBeNull();
  });

  it("does not construct a Kafka client when disabled", () => {
    process.env.KAFKA_ENABLED = "false";
    process.env.KAFKA_BROKERS = "broker:9092";
    createRevenueConsumer(vi.fn());
    expect(kafkaCtorArgs).toHaveLength(0);
    expect(consumerCtorArgs).toHaveLength(0);
  });

  it("ignores all other Kafka env vars when disabled", () => {
    process.env.KAFKA_BROKERS = "a:1,b:2";
    process.env.KAFKA_REVENUE_TOPIC = "custom.topic";
    process.env.KAFKA_GROUP_ID = "custom-group";
    process.env.KAFKA_CLIENT_ID = "custom-client";
    expect(createRevenueConsumer(vi.fn())).toBeNull();
    expect(kafkaCtorArgs).toHaveLength(0);
  });

  it("does not invoke the onRevenue callback when disabled", () => {
    const onRevenue = vi.fn();
    createRevenueConsumer(onRevenue);
    expect(onRevenue).not.toHaveBeenCalled();
  });
});

describe("createRevenueConsumer — enabled path", () => {
  it.each(["true", "1", "TRUE", "True", "tRuE"])(
    "returns a RevenueKafkaConsumer for KAFKA_ENABLED=%s (case-insensitive)",
    (value) => {
      process.env.KAFKA_ENABLED = value;
      expect(createRevenueConsumer(vi.fn())).toBeInstanceOf(RevenueKafkaConsumer);
      expect(kafkaCtorArgs).toHaveLength(1);
    },
  );

  it("applies defaults when only KAFKA_ENABLED is set", () => {
    process.env.KAFKA_ENABLED = "true";
    createRevenueConsumer(vi.fn());

    expect(lastKafkaConfig()).toEqual({
      clientId: "veritasor-backend",
      brokers: ["localhost:9092"],
      logLevel: 4,
    });
    expect(lastConsumerOptions()).toEqual({
      groupId: "veritasor-revenue-consumer",
      retry: { retries: 3 },
    });
  });

  it("maps env overrides into KafkaConsumerConfig", () => {
    process.env.KAFKA_ENABLED = "1";
    process.env.KAFKA_BROKERS = "k1:9092,k2:9093";
    process.env.KAFKA_GROUP_ID = "group-x";
    process.env.KAFKA_CLIENT_ID = "client-x";
    createRevenueConsumer(vi.fn());

    expect(lastKafkaConfig()).toMatchObject({
      clientId: "client-x",
      brokers: ["k1:9092", "k2:9093"],
    });
    expect(lastConsumerOptions()).toMatchObject({ groupId: "group-x" });
  });

  it("does not connect to Kafka at construction time", () => {
    process.env.KAFKA_ENABLED = "true";
    createRevenueConsumer(vi.fn());
    expect(mockConsumerInstance.connect).not.toHaveBeenCalled();
    expect(mockProducerInstance.connect).not.toHaveBeenCalled();
  });

  it("uses KAFKA_REVENUE_TOPIC for subscription and derives the DLT topic", async () => {
    process.env.KAFKA_ENABLED = "true";
    process.env.KAFKA_REVENUE_TOPIC = "erp.revenue";
    const consumer = createRevenueConsumer(vi.fn())!;
    await consumer.start();

    expect(mockConsumerInstance.subscribe).toHaveBeenCalledWith({
      topic: "erp.revenue",
      fromBeginning: false,
    });

    await capturedHandler()(payload("erp.revenue", null));
    expect(mockProducerInstance.send.mock.calls[0][0].topic).toBe("erp.revenue.dlt");
    await consumer.stop();
  });

  it("defaults the subscription topic to revenue.events", async () => {
    process.env.KAFKA_ENABLED = "true";
    const consumer = createRevenueConsumer(vi.fn())!;
    await consumer.start();
    expect(mockConsumerInstance.subscribe).toHaveBeenCalledWith({
      topic: "revenue.events",
      fromBeginning: false,
    });
    await consumer.stop();
  });

  it("passes the onRevenue callback through to the consumer", async () => {
    process.env.KAFKA_ENABLED = "true";
    const onRevenue = vi.fn().mockResolvedValue(undefined);
    const consumer = createRevenueConsumer(onRevenue)!;
    await consumer.start();

    await capturedHandler()(
      payload("revenue.events", JSON.stringify({ id: "r-1", amount: 10, currency: "usd" })),
    );

    expect(onRevenue).toHaveBeenCalledOnce();
    expect(onRevenue.mock.calls[0][0]).toMatchObject({ id: "r-1", currency: "USD" });
    await consumer.stop();
  });
});

describe("createRevenueConsumer — KAFKA_BROKERS boundary inputs", () => {
  beforeEach(() => {
    process.env.KAFKA_ENABLED = "true";
  });

  it("trims whitespace around broker entries", () => {
    process.env.KAFKA_BROKERS = "  k1:9092 ,  k2:9092  ";
    createRevenueConsumer(vi.fn());
    expect(lastKafkaConfig().brokers).toEqual(["k1:9092", "k2:9092"]);
  });

  it("drops empty entries from repeated or trailing commas", () => {
    process.env.KAFKA_BROKERS = ",k1:9092,, ,k2:9092,";
    createRevenueConsumer(vi.fn());
    expect(lastKafkaConfig().brokers).toEqual(["k1:9092", "k2:9092"]);
  });

  it("accepts a single broker without commas", () => {
    process.env.KAFKA_BROKERS = "solo:9092";
    createRevenueConsumer(vi.fn());
    expect(lastKafkaConfig().brokers).toEqual(["solo:9092"]);
  });

  it("yields an empty broker list (no localhost fallback) when KAFKA_BROKERS is empty", () => {
    // `??` only falls back for undefined, so an explicitly empty value is
    // preserved as an empty list rather than silently defaulting to localhost.
    process.env.KAFKA_BROKERS = "";
    createRevenueConsumer(vi.fn());
    expect(lastKafkaConfig().brokers).toEqual([]);
  });

  it("yields an empty broker list when KAFKA_BROKERS is only separators/whitespace", () => {
    process.env.KAFKA_BROKERS = " , , ";
    createRevenueConsumer(vi.fn());
    expect(lastKafkaConfig().brokers).toEqual([]);
  });
});

describe("createRevenueConsumer — determinism", () => {
  it("re-reads env on every call (no cached config)", () => {
    process.env.KAFKA_ENABLED = "true";
    expect(createRevenueConsumer(vi.fn())).toBeInstanceOf(RevenueKafkaConsumer);

    process.env.KAFKA_ENABLED = "false";
    expect(createRevenueConsumer(vi.fn())).toBeNull();

    process.env.KAFKA_ENABLED = "1";
    process.env.KAFKA_BROKERS = "later:9092";
    createRevenueConsumer(vi.fn());
    expect(lastKafkaConfig().brokers).toEqual(["later:9092"]);
  });

  it("returns a distinct instance per call", () => {
    process.env.KAFKA_ENABLED = "true";
    const a = createRevenueConsumer(vi.fn());
    const b = createRevenueConsumer(vi.fn());
    expect(a).not.toBe(b);
  });
});

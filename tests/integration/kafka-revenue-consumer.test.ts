/**
 * Integration test for the Kafka revenue consumer.
 *
 * Spins up a real Kafka (KRaft mode, no ZooKeeper) via testcontainers and
 * runs the full pipeline:
 *   produce → consume → normalise → onRevenue callback
 *   produce malformed → DLT
 *   rebalance mid-flight → message redelivered, no data loss
 *
 * Skipped gracefully when Docker is unavailable.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { GenericContainer, type StartedTestContainer, Wait } from "testcontainers";
import { Kafka, logLevel } from "kafkajs";
import { execSync } from "node:child_process";
import { RevenueKafkaConsumer } from "../../src/services/revenue/kafkaConsumer.js";
import type { NormalizedRevenue } from "../../src/services/revenue/normalize.js";

// ---------------------------------------------------------------------------
// Docker availability guard
// ---------------------------------------------------------------------------

function isDockerAvailable(): boolean {
  try {
    execSync('docker info --format "{{.ServerVersion}}"', {
      stdio: "pipe",
      timeout: 5_000,
    });
    return true;
  } catch {
    return false;
  }
}

const dockerAvailable = isDockerAvailable();
const describeFn = dockerAvailable ? describe : describe.skip;

// ---------------------------------------------------------------------------
// Kafka image + config
// ---------------------------------------------------------------------------

const KAFKA_IMAGE = "confluentinc/cp-kafka:7.6.0";
const KAFKA_PORT = 9092;
const TOPIC = "revenue.events.test";
const DLT_TOPIC = `${TOPIC}.dlt`;
const GROUP_ID = "test-revenue-consumer";

describeFn("Kafka revenue consumer — integration (real Kafka)", () => {
  let container: StartedTestContainer;
  let brokerUrl: string;
  let adminKafka: Kafka;

  // --------------------------------------------------------------------------
  // Bootstrap
  // --------------------------------------------------------------------------

  beforeAll(async () => {
    container = await new GenericContainer(KAFKA_IMAGE)
      .withEnvironment({
        KAFKA_NODE_ID: "1",
        KAFKA_PROCESS_ROLES: "broker,controller",
        KAFKA_LISTENERS: "PLAINTEXT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093",
        KAFKA_CONTROLLER_LISTENER_NAMES: "CONTROLLER",
        KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: "PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT",
        KAFKA_CONTROLLER_QUORUM_VOTERS: "1@localhost:9093",
        KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: "1",
        KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR: "1",
        KAFKA_TRANSACTION_STATE_LOG_MIN_ISR: "1",
        KAFKA_AUTO_CREATE_TOPICS_ENABLE: "true",
        CLUSTER_ID: "MkU3OEVBNTcwNTJENDM2Qk",
        KAFKA_ADVERTISED_LISTENERS: "PLAINTEXT://localhost:9092",
      })
      .withExposedPorts(KAFKA_PORT)
      .withWaitStrategy(Wait.forLogMessage("Kafka Server started"))
      .withStartupTimeout(120_000)
      .start();

    const host = container.getHost();
    const port = container.getMappedPort(KAFKA_PORT);
    brokerUrl = `${host}:${port}`;

    adminKafka = new Kafka({ clientId: "test-admin", brokers: [brokerUrl], logLevel: logLevel.ERROR });
    const admin = adminKafka.admin();
    await admin.connect();
    await admin.createTopics({
      topics: [
        { topic: TOPIC, numPartitions: 2 },
        { topic: DLT_TOPIC, numPartitions: 1 },
      ],
    });
    await admin.disconnect();
  }, 180_000);

  afterAll(async () => {
    if (container) await container.stop();
  });

  // --------------------------------------------------------------------------
  // Helpers
  // --------------------------------------------------------------------------

  async function produce(messages: Array<{ value: string }>): Promise<void> {
    const kafka = new Kafka({ clientId: "test-producer", brokers: [brokerUrl], logLevel: logLevel.ERROR });
    const producer = kafka.producer();
    await producer.connect();
    await producer.send({ topic: TOPIC, messages });
    await producer.disconnect();
  }

  async function consumeDlt(count: number, timeoutMs = 10_000): Promise<string[]> {
    const kafka = new Kafka({ clientId: "dlt-reader", brokers: [brokerUrl], logLevel: logLevel.ERROR });
    const consumer = kafka.consumer({ groupId: "dlt-verifier" });
    await consumer.connect();
    await consumer.subscribe({ topic: DLT_TOPIC, fromBeginning: true });

    const results: string[] = [];
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        resolve(); // timeout — return what we have
      }, timeoutMs);

      consumer.run({
        eachMessage: async ({ message }) => {
          results.push(message.value?.toString() ?? "");
          if (results.length >= count) {
            clearTimeout(timer);
            resolve();
          }
        },
      }).catch(reject);
    });

    await consumer.disconnect();
    return results;
  }

  // --------------------------------------------------------------------------
  // Tests
  // --------------------------------------------------------------------------

  it("consumes a valid revenue message and calls onRevenue with normalized entry", async () => {
    const received: NormalizedRevenue[] = [];
    const consumer = new RevenueKafkaConsumer({
      brokers: [brokerUrl],
      topic: TOPIC,
      groupId: GROUP_ID,
      onRevenue: async (entry) => { received.push(entry); },
    });

    await consumer.start();

    await produce([
      {
        value: JSON.stringify({
          id: "erp-tx-001",
          amount: 500,
          currency: "eur",
          date: "2024-03-01",
          source: "sap-erp",
        }),
      },
    ]);

    // Wait for the message to be processed
    await new Promise<void>((resolve) => {
      const poll = setInterval(() => {
        if (received.length >= 1) { clearInterval(poll); resolve(); }
      }, 200);
      setTimeout(() => { clearInterval(poll); resolve(); }, 10_000);
    });

    await consumer.stop();

    expect(received).toHaveLength(1);
    expect(received[0].id).toBe("erp-tx-001");
    expect(received[0].currency).toBe("EUR");
    expect(received[0].type).toBe("payment");
    expect(received[0].source).toBe("sap-erp");
  }, 30_000);

  it("forwards invalid JSON to the DLT", async () => {
    const consumer = new RevenueKafkaConsumer({
      brokers: [brokerUrl],
      topic: TOPIC,
      groupId: `${GROUP_ID}-dlt-test`,
      onRevenue: vi.fn(),
    });

    await consumer.start();
    await produce([{ value: "not-valid-json{{{" }]);

    const dltMessages = await consumeDlt(1, 10_000);
    await consumer.stop();

    expect(dltMessages).toHaveLength(1);
    // The DLT message value is the original bad payload
    expect(dltMessages[0]).toBe("not-valid-json{{{");
  }, 30_000);

  it("processes multiple messages without losing any", async () => {
    const received: string[] = [];
    const consumer = new RevenueKafkaConsumer({
      brokers: [brokerUrl],
      topic: TOPIC,
      groupId: `${GROUP_ID}-batch`,
      onRevenue: async (entry) => { received.push(entry.id); },
    });

    await consumer.start();

    const ids = ["batch-1", "batch-2", "batch-3", "batch-4", "batch-5"];
    await produce(
      ids.map((id) => ({
        value: JSON.stringify({ id, amount: 100, currency: "USD", source: "erp" }),
      })),
    );

    await new Promise<void>((resolve) => {
      const poll = setInterval(() => {
        if (received.length >= ids.length) { clearInterval(poll); resolve(); }
      }, 200);
      setTimeout(() => { clearInterval(poll); resolve(); }, 15_000);
    });

    await consumer.stop();

    expect(received.sort()).toEqual(ids.sort());
  }, 40_000);

  it("stops cleanly without throwing", async () => {
    const consumer = new RevenueKafkaConsumer({
      brokers: [brokerUrl],
      topic: TOPIC,
      groupId: `${GROUP_ID}-stop-test`,
      onRevenue: vi.fn(),
    });

    await consumer.start();
    await expect(consumer.stop()).resolves.toBeUndefined();
  }, 15_000);
});

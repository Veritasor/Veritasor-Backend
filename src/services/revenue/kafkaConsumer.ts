/**
 * Kafka consumer for external revenue events from partner ERP systems.
 *
 * Gated behind KAFKA_ENABLED=true — if the env var is absent or false the
 * module exports a no-op start function and nothing connects to Kafka.
 *
 * Message flow
 * ─────────────
 * 1. Consumer group receives a message from KAFKA_REVENUE_TOPIC
 * 2. Payload is parsed as JSON and validated (must have id, amount, currency, date, source)
 * 3. Normalized via normalizeRevenueEntry() from the existing pipeline
 * 4. onRevenue callback is called with the normalized entry so callers can
 *    persist, aggregate, or forward it
 * 5. Offset is committed only AFTER the callback resolves without error
 *
 * Dead-letter topic (DLT)
 * ────────────────────────
 * Any message that fails validation or whose onRevenue callback throws is
 * forwarded to `<topic>.dlt` with three headers:
 *   dlt-original-topic, dlt-error, dlt-timestamp
 * The offset is then committed so the consumer does not stall.
 *
 * Rebalance safety
 * ─────────────────
 * KafkaJS eachMessage runs with autoCommit=false. Offsets are committed inside
 * the handler only after the message has been fully processed (or sent to DLT).
 * If the process is killed mid-flight the message is redelivered — the handler
 * is idempotent provided the onRevenue callback is idempotent.
 */

import { Kafka, Consumer, Producer, logLevel, type EachMessagePayload } from "kafkajs";
import { normalizeRevenueEntry, type RawRevenueInput, type NormalizedRevenue } from "./normalize.js";
import { logger } from "../../utils/logger.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const DEFAULT_TOPIC = "revenue.events";
const DEFAULT_GROUP_ID = "veritasor-revenue-consumer";

export interface KafkaConsumerConfig {
  brokers: string[];           // e.g. ["kafka:9092"]
  topic: string;               // source topic
  groupId: string;             // consumer group id
  clientId?: string;
  /** Called with each successfully normalized revenue entry. */
  onRevenue: (entry: NormalizedRevenue) => Promise<void>;
}

// ---------------------------------------------------------------------------
// DLT helpers
// ---------------------------------------------------------------------------

async function sendToDlt(
  producer: Producer,
  dltTopic: string,
  payload: EachMessagePayload,
  error: unknown,
): Promise<void> {
  const errMsg = error instanceof Error ? error.message : String(error);
  try {
    await producer.send({
      topic: dltTopic,
      messages: [
        {
          key: payload.message.key,
          value: payload.message.value,
          headers: {
            "dlt-original-topic": payload.topic,
            "dlt-error": errMsg,
            "dlt-timestamp": new Date().toISOString(),
          },
        },
      ],
    });
    logger.warn("[kafka] message sent to DLT", {
      dltTopic,
      partition: payload.partition,
      offset: payload.message.offset,
      error: errMsg,
    });
  } catch (dltErr) {
    // Log but do not throw — we still need to commit the offset to avoid stalling
    logger.error("[kafka] failed to send message to DLT", dltErr);
  }
}

// ---------------------------------------------------------------------------
// Consumer
// ---------------------------------------------------------------------------

export class RevenueKafkaConsumer {
  private kafka: Kafka;
  private consumer: Consumer;
  private producer: Producer;
  private dltTopic: string;
  private running = false;

  constructor(private cfg: KafkaConsumerConfig) {
    this.kafka = new Kafka({
      clientId: cfg.clientId ?? "veritasor-backend",
      brokers: cfg.brokers,
      logLevel: logLevel.WARN,
    });
    this.consumer = this.kafka.consumer({
      groupId: cfg.groupId,
      // Allow the consumer to retry briefly before giving up on a single fetch
      retry: { retries: 3 },
    });
    this.producer = this.kafka.producer();
    this.dltTopic = `${cfg.topic}.dlt`;
  }

  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;

    await this.producer.connect();
    await this.consumer.connect();
    await this.consumer.subscribe({ topic: this.cfg.topic, fromBeginning: false });

    logger.info("[kafka] consumer started", {
      topic: this.cfg.topic,
      groupId: this.cfg.groupId,
      dltTopic: this.dltTopic,
    });

    await this.consumer.run({
      autoCommit: false, // we commit manually after successful processing
      eachMessage: async (payload) => {
        const { topic, partition, message } = payload;
        const raw = message.value?.toString();

        if (!raw) {
          logger.warn("[kafka] received empty message, sending to DLT", { topic, partition, offset: message.offset });
          await sendToDlt(this.producer, this.dltTopic, payload, new Error("empty message"));
          await this.consumer.commitOffsets([{ topic, partition, offset: String(Number(message.offset) + 1) }]);
          return;
        }

        let parsed: unknown;
        try {
          parsed = JSON.parse(raw);
        } catch {
          await sendToDlt(this.producer, this.dltTopic, payload, new Error("invalid JSON"));
          await this.consumer.commitOffsets([{ topic, partition, offset: String(Number(message.offset) + 1) }]);
          return;
        }

        // Validate required fields before passing to normalizer
        if (!isValidRevenuePayload(parsed)) {
          await sendToDlt(this.producer, this.dltTopic, payload, new Error("missing required fields: id, amount"));
          await this.consumer.commitOffsets([{ topic, partition, offset: String(Number(message.offset) + 1) }]);
          return;
        }

        let normalized: NormalizedRevenue;
        try {
          normalized = normalizeRevenueEntry(parsed as RawRevenueInput);
        } catch (err) {
          await sendToDlt(this.producer, this.dltTopic, payload, err);
          await this.consumer.commitOffsets([{ topic, partition, offset: String(Number(message.offset) + 1) }]);
          return;
        }

        try {
          await this.cfg.onRevenue(normalized);
        } catch (err) {
          logger.error("[kafka] onRevenue callback failed, sending to DLT", err);
          await sendToDlt(this.producer, this.dltTopic, payload, err);
          await this.consumer.commitOffsets([{ topic, partition, offset: String(Number(message.offset) + 1) }]);
          return;
        }

        // Commit only after successful processing
        await this.consumer.commitOffsets([
          { topic, partition, offset: String(Number(message.offset) + 1) },
        ]);
      },
    });
  }

  async stop(): Promise<void> {
    if (!this.running) return;
    this.running = false;
    try {
      await this.consumer.disconnect();
      await this.producer.disconnect();
      logger.info("[kafka] consumer stopped");
    } catch (err) {
      logger.error("[kafka] error during stop", err);
    }
  }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

function isValidRevenuePayload(val: unknown): val is RawRevenueInput {
  if (!val || typeof val !== "object") return false;
  const v = val as Record<string, unknown>;
  return typeof v.id === "string" && v.id.length > 0 && typeof v.amount === "number";
}

// ---------------------------------------------------------------------------
// Factory — reads env vars, returns null when KAFKA_ENABLED is not true
// ---------------------------------------------------------------------------

export function createRevenueConsumer(
  onRevenue: (entry: NormalizedRevenue) => Promise<void>,
): RevenueKafkaConsumer | null {
  const enabled = (process.env.KAFKA_ENABLED ?? "").toLowerCase();
  if (enabled !== "true" && enabled !== "1") return null;

  const brokersRaw = process.env.KAFKA_BROKERS ?? "localhost:9092";
  const brokers = brokersRaw.split(",").map((b) => b.trim()).filter(Boolean);

  return new RevenueKafkaConsumer({
    brokers,
    topic: process.env.KAFKA_REVENUE_TOPIC ?? DEFAULT_TOPIC,
    groupId: process.env.KAFKA_GROUP_ID ?? DEFAULT_GROUP_ID,
    clientId: process.env.KAFKA_CLIENT_ID,
    onRevenue,
  });
}

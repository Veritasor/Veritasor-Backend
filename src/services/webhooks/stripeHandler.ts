import crypto from "crypto";
import { logger } from "../../utils/logger.js";
import { integrationRepository } from "../../repositories/integration.js";

const EXPECTED_SCHEME = "v1";
const TIMESTAMP_TOLERANCE_SEC = 300;

interface StripeEvent {
  id: string;
  type: string;
  data: { object: Record<string, any> };
  created: number;
  livemode: boolean;
}

function computeSignature(
  payload: string,
  secret: string,
  timestamp: string,
): string {
  return crypto
    .createHmac("sha256", secret)
    .update(`${timestamp}.${payload}`)
    .digest("hex");
}

export function verifySignature(
  rawBody: string,
  signatureHeader: string,
  secret: string,
): StripeEvent {
  const parts = signatureHeader.split(",").reduce(
    (acc, part) => {
      const [key, value] = part.split("=");
      if (key === "t") acc.timestamp = value;
      if (key === EXPECTED_SCHEME) acc.signatures.push(value);
      return acc;
    },
    { timestamp: "", signatures: [] as string[] },
  );

  if (!parts.timestamp || parts.signatures.length === 0) {
    throw new Error("Invalid signature header format");
  }

  const now = Math.floor(Date.now() / 1000);
  const ts = parseInt(parts.timestamp, 10);
  if (Math.abs(now - ts) > TIMESTAMP_TOLERANCE_SEC) {
    throw new Error("Webhook timestamp outside tolerance");
  }

  const expected = computeSignature(rawBody, secret, parts.timestamp);
  const matched = parts.signatures.some((sig) =>
    crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected)),
  );

  if (!matched) {
    throw new Error("Webhook signature verification failed");
  }

  return JSON.parse(rawBody) as StripeEvent;
}

export async function handleStripeEvent(event: StripeEvent): Promise<void> {
  switch (event.type) {
    case "payment_intent.succeeded":
    case "charge.succeeded":
      await handlePaymentSuccess(event);
      break;

    case "customer.subscription.created":
    case "customer.subscription.updated":
    case "customer.subscription.deleted":
      await handleSubscriptionChange(event);
      break;

    case "account.updated":
      await handleAccountUpdate(event);
      break;

    default:
      logger.info(`Unhandled Stripe event type: ${event.type}`);
  }
}

async function handlePaymentSuccess(event: StripeEvent): Promise<void> {
  const obj = event.data.object;
  logger.info(
    `Payment succeeded: ${obj.id}, amount: ${obj.amount}, currency: ${obj.currency}`,
  );
}

async function handleSubscriptionChange(event: StripeEvent): Promise<void> {
  const sub = event.data.object;
  logger.info(`Subscription ${event.type}: ${sub.id}, status: ${sub.status}`);
}

async function handleAccountUpdate(event: StripeEvent): Promise<void> {
  const account = event.data.object;
  logger.info(`Account updated: ${account.id}`);
}

import { Router, Request, Response } from "express";
import {
  verifySignature,
  handleStripeEvent,
} from "../services/webhooks/stripeHandler.js";
import { logger } from "../utils/logger.js";

export const stripeWebhookRouter = Router();

stripeWebhookRouter.post("/", (req: Request, res: Response) => {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) {
    logger.error("STRIPE_WEBHOOK_SECRET is not configured");
    res.status(500).json({ received: false });
    return;
  }

  const signature = req.headers["stripe-signature"] as string | undefined;
  if (!signature) {
    res.status(400).json({ error: "Missing stripe-signature header" });
    return;
  }

  const rawBody = (req as any).rawBody as string | undefined;
  if (!rawBody) {
    res.status(400).json({ error: "Missing raw body" });
    return;
  }

  let event;
  try {
    event = verifySignature(rawBody, signature, secret);
  } catch (err: any) {
    logger.warn(`Stripe webhook signature verification failed: ${err.message}`);
    res.status(400).json({ error: "Signature verification failed" });
    return;
  }

  res.status(200).json({ received: true });

  handleStripeEvent(event).catch((err) => {
    logger.error(`Error processing Stripe event ${event.id}: ${err.message}`);
  });
});

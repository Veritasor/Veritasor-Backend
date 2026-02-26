import { Router, Request, Response } from "express";
import { requireAuth } from "../middleware/requireAuth.js";
import { integrationRepository } from "../repositories/integration.js";

const router = Router();

interface IntegrationType {
  name: string;
  slug: "stripe" | "razorpay" | "shopify";
}

const AVAILABLE_INTEGRATIONS: IntegrationType[] = [
  { name: "Stripe", slug: "stripe" },
  { name: "Razorpay", slug: "razorpay" },
  { name: "Shopify", slug: "shopify" },
];

// GET /api/integrations - List available and connected integrations
router.get("/", requireAuth, (req: Request, res: Response) => {
  const userId = (req as any).userId;

  const connected = integrationRepository.findByUserId(userId);
  const connectedSlugs = new Set(connected.map((i) => i.type));

  const available = AVAILABLE_INTEGRATIONS.map((integration) => ({
    ...integration,
    isConnected: connectedSlugs.has(integration.slug),
  }));

  res.json({
    available,
    connected: connected.map((i) => ({
      id: i.id,
      type: i.type,
      connectedAt: i.connectedAt,
    })),
  });
});

export default router;

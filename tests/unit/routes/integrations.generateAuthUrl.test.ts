/**
 * Focused regression coverage for `generateAuthUrl` (issue #947).
 *
 * Evidence: `src/routes/integrations.ts:359` —
 * `throw new Error(\`Unsupported provider: ${provider}\`);` in the `default`
 * branch of `generateAuthUrl`.
 *
 * That branch is unreachable through the HTTP surface: `POST /connect` parses
 * the body with `connectIntegrationSchema`, whose `provider` is a Zod enum of
 * `stripe | razorpay | shopify`, so only those three ever reach the helper.
 * The helper had no tests at all, so the unsupported-provider contract (and the
 * per-provider URL shape, redirect encoding, and shop-domain fallback) had no
 * regression protection. This suite is unit-level and exercises the helper
 * directly; the production change is limited to exporting it.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../../src/middleware/auth.js", () => ({
  requireAuth: (_req: unknown, _res: unknown, next: () => void) => next(),
}));
vi.mock("../../../src/middleware/requireBusinessAuth.js", () => ({
  requireBusinessAuth: (_req: unknown, _res: unknown, next: () => void) => next(),
}));
vi.mock("../../../src/middleware/permissions.js", () => ({
  requirePermissions: () => (_req: unknown, _res: unknown, next: () => void) => next(),
  requirePolicy: () => (_req: unknown, _res: unknown, next: () => void) => next(),
}));
vi.mock("../../../src/repositories/integration.js", () => ({
  getById: vi.fn(),
  listByUserId: vi.fn(),
  listByBusinessId: vi.fn(),
  deleteById: vi.fn(),
}));

import { generateAuthUrl } from "../../../src/routes/integrations.js";

const ORIGINAL_SHOP_DOMAIN = process.env.SHOPIFY_SHOP_DOMAIN;

beforeEach(() => {
  delete process.env.SHOPIFY_SHOP_DOMAIN;
});

afterEach(() => {
  if (ORIGINAL_SHOP_DOMAIN === undefined) delete process.env.SHOPIFY_SHOP_DOMAIN;
  else process.env.SHOPIFY_SHOP_DOMAIN = ORIGINAL_SHOP_DOMAIN;
});

describe("generateAuthUrl — supported providers (issue #947)", () => {
  it("builds the exact Stripe OAuth URL with an encoded redirect URI", () => {
    const url = generateAuthUrl("stripe", "st_123", "https://app.test/callback");

    expect(url).toBe(
      "https://connect.stripe.com/oauth/authorize?client_id=mock_stripe_client_id" +
        "&state=st_123" +
        `&redirect_uri=${encodeURIComponent("https://app.test/callback")}` +
        "&scope=read_write",
    );
  });

  it("falls back to the local callback when Stripe gets no redirectUri", () => {
    const url = generateAuthUrl("stripe", "st_1");
    expect(url).toContain(
      `redirect_uri=${encodeURIComponent("http://localhost:3000/integrations/callback")}`,
    );
    expect(url).toContain("client_id=mock_stripe_client_id");
  });

  it("encodes reserved characters in the Stripe redirect URI", () => {
    const redirect = "https://app.test/cb?next=/a b&x=1";
    const url = generateAuthUrl("stripe", "s", redirect);

    expect(url).toContain(`redirect_uri=${encodeURIComponent(redirect)}`);
    // The raw (unencoded) value must not appear, i.e. the encoding is real.
    expect(url).not.toContain("next=/a b&x=1");
  });

  it("uses the configured SHOPIFY_SHOP_DOMAIN for Shopify", () => {
    process.env.SHOPIFY_SHOP_DOMAIN = "acme-store";
    const url = generateAuthUrl("shopify", "sh_1", "https://app.test/cb");

    expect(url).toBe(
      "https://acme-store.myshopify.com/admin/oauth/authorize" +
        "?client_id=mock_shopify_client_id" +
        "&state=sh_1" +
        `&redirect_uri=${encodeURIComponent("https://app.test/cb")}` +
        "&scope=read_products,read_orders",
    );
  });

  it("falls back to the 'example' Shopify domain when the env var is unset", () => {
    const url = generateAuthUrl("shopify", "sh_2");
    expect(url.startsWith("https://example.myshopify.com/admin/oauth/authorize?")).toBe(true);
    expect(url).toContain("scope=read_products,read_orders");
  });

  it("builds the Razorpay API-key flow URL without encoding the base URL", () => {
    const url = generateAuthUrl("razorpay", "rp_1", "https://app.test/rp");
    expect(url).toBe("https://app.test/rp?provider=razorpay&state=rp_1");
  });

  it("uses the default base for Razorpay when no redirectUri is supplied", () => {
    expect(generateAuthUrl("razorpay", "rp_2")).toBe(
      "http://localhost:3000/integrations/callback?provider=razorpay&state=rp_2",
    );
  });

  it("interpolates the state verbatim for every supported provider", () => {
    for (const provider of ["stripe", "shopify", "razorpay"]) {
      expect(generateAuthUrl(provider, "STATE-XYZ")).toContain("STATE-XYZ");
    }
  });
});

describe("generateAuthUrl — unsupported provider contract (issue #947)", () => {
  it("throws an Error naming the unsupported provider", () => {
    expect(() => generateAuthUrl("paypal", "s")).toThrow("Unsupported provider: paypal");
  });

  it("throws the exact Error type and message prefix", () => {
    const err = (() => {
      try {
        generateAuthUrl("paypal", "s");
        return undefined;
      } catch (e) {
        return e as Error;
      }
    })();

    expect(err).toBeInstanceOf(Error);
    expect(err?.message).toBe("Unsupported provider: paypal");
  });

  it("is case-sensitive: an upper-cased supported provider is rejected", () => {
    expect(() => generateAuthUrl("STRIPE", "s")).toThrow("Unsupported provider: STRIPE");
  });

  it("rejects an empty provider string", () => {
    expect(() => generateAuthUrl("", "s")).toThrow("Unsupported provider: ");
  });

  it("rejects a whitespace-padded provider rather than trimming it", () => {
    expect(() => generateAuthUrl(" stripe ", "s")).toThrow("Unsupported provider:  stripe ");
  });
});

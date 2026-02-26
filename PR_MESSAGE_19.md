# PR #19 — Implement Shopify revenue fetch service

## Summary

Adds `src/services/revenue/shopifyFetch.ts` — a Shopify revenue fetch service that retrieves orders for a given date range and returns normalized `RevenueEntry[]` objects, consistent with the existing Razorpay and Stripe fetch services.

## Changes

| File                                   | Change                              |
| -------------------------------------- | ----------------------------------- |
| `src/services/revenue/shopifyFetch.ts` | New — Shopify revenue fetch service |

## Details

- Uses Shopify REST Admin API (`/admin/api/2024-01/orders.json`) to fetch paid orders within a date range.
- Supports cursor-based pagination via `since_id` with a page size of 250 (Shopify max).
- Implements retry logic with exponential backoff for `429` rate-limit responses.
- Resolves shop + access token from environment variables (`SHOPIFY_SHOP`, `SHOPIFY_ACCESS_TOKEN`) or falls back to the in-memory token store and integration repository.
- Filters out cancelled orders; normalizes `total_price` to a numeric amount.
- Exports `fetchShopifyRevenue(integrationId, startDate, endDate)` and `fetchRevenueByUserId(userId, startDate, endDate)` — same interface pattern as `stripeFetch.ts` and `razorpayFetch.ts`.

## How to test

```bash
npm run build
```

A successful build confirms the module compiles and integrates with the existing codebase without type errors.

## Proof of successful build

<!-- Attach a screenshot of a successful `npm run build` output below -->

![Build proof](<!-- paste image URL or drag-drop screenshot here -->)

> **Tip:** Run `npm run build` in your terminal, take a screenshot of the clean output, then drag-and-drop the image into this text area when creating the PR on GitHub. GitHub will auto-upload it and replace the placeholder with a URL.

## Related

- Closes #19

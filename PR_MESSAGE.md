## feat(revenue): add Stripe revenue fetch service

### Summary

Implements a new service at `src/services/revenue/stripeFetch.ts` that fetches revenue data from the Stripe API for a given date range and returns normalized revenue entries. This is consumed by jobs and the attestation flow — no route changes.

### What changed

| File | Change |
|---|---|
| `src/services/revenue/stripeFetch.ts` | New service — `fetchRevenueForPeriod`, `fetchRevenueByUserId` |

### Details

- **`fetchRevenueForPeriod(integrationId, startDate, endDate)`** — Fetches all succeeded, non-refunded charges from Stripe's `/v1/charges` endpoint within the date range. Handles cursor-based pagination (`starting_after`) and rate-limit retries (429 with exponential backoff, up to 3 retries).
- **`fetchRevenueByUserId(userId, startDate, endDate)`** — Convenience wrapper that resolves the Stripe integration from the user's connected integrations and delegates to `fetchRevenueForPeriod`.
- Revenue entries are normalized to the same `RevenueEntry` shape used across the codebase (amount in major units, ISO date, currency code).
- Follows the same patterns established in `razorpayFetch.ts`.

### How to test

1. Set `STRIPE_SECRET_KEY` in `.env`
2. Run the build: `npm run build`
3. Import and call `fetchRevenueForPeriod` from a script or job with valid date range

### Proof of successful build

<!-- Paste screenshot of successful `npm run build` output below -->

![Build proof]()

### Related

Closes #17

# Webhook Delivery Attempt Exponential-Decay Dashboard & Metrics

## Overview
Persistently failing webhooks are difficult to prioritize and visualize when using raw counters or static thresholds because unweighted metrics blur recent outages with historical noise.

The **Exponentially Weighted Moving Average (EWMA) Decay Counter** weights failure events so that recent delivery failures carry higher score impact while historical failures naturally decay over time according to a configurable half-life ($T_{1/2}$).

## EWMA Decay Mathematics
The decayed failure score $V(t)$ at timestamp $t$ following an elapsed time $\Delta t = t - t_{\text{last}}$ is calculated as:

$$V(t) = V(t_{\text{last}}) \times 2^{-\frac{\Delta t}{T_{1/2}}} + w$$

Where:
- $T_{1/2}$ is the configurable half-life in seconds (default: `300` seconds / 5 minutes).
- $\Delta t = \max(0, \frac{\text{timestamp} - \text{lastTimestamp}}{1000})$ in seconds.
- $w$ is the failure event weight (default: `1.0`).

### Clock Skew Protection
To protect against system clock drift or backward time jumps (e.g., NTP adjustments), $\Delta t$ is strictly clamped to $\ge 0$. If the current timestamp is behind `lastTimestamp`, decay factor is held at $1.0$ and `lastTimestamp` is never moved backwards, preventing score inflation or exponential blowups.

## Prometheus Metrics & Alerts

### Gauge Metric
- `webhook_delivery_failure_ewma_score`
  - **Labels**: `subscription_id`, `business_id`, `algo`
  - **Description**: Current EWMA failure decay score per webhook subscription.

### Prometheus Alert Rules
Defined in [`ops/alerts/backend.rules.yaml`](file:///c:/Users/HELLO/OneDrive/Documents/Veritasor-Backend/ops/alerts/backend.rules.yaml):
- **`WebhookEWMAFailureScoreWarning`**: Triggers warning when `webhook_delivery_failure_ewma_score > 10` for 3 minutes.
- **`WebhookEWMAFailureScoreCritical`**: Triggers critical alert when `webhook_delivery_failure_ewma_score > 25` for 1 minute.

## Grafana Dashboard Artifact
Located at [`ops/grafana/webhook-decay-dashboard.json`](file:///c:/Users/HELLO/OneDrive/Documents/Veritasor-Backend/ops/grafana/webhook-decay-dashboard.json):
1. **Timeseries**: EWMA failure score per subscription over time.
2. **Stat Panel**: Global peak EWMA failure score.
3. **Top 10 Timeseries**: Highest-risk failing webhook subscriptions weighted by EWMA.
4. **Aggregated Business View**: Total EWMA score breakdown per tenant business ID.

## API Usage Example

```typescript
import {
  recordWebhookFailure,
  recordWebhookSuccess,
  getWebhookEWMAScore,
  setGlobalEWMADecayHalfLife,
} from "./src/services/webhooks/dispatcher.js";

// Configure decay half-life (e.g. 5 minutes)
setGlobalEWMADecayHalfLife(300);

// Record delivery failure
recordWebhookFailure(subscription, 1);

// Query score
const currentScore = getWebhookEWMAScore(subscription.id);

// Record delivery success (decays score without adding weight)
recordWebhookSuccess(subscription);
```

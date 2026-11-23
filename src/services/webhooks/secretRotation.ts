/**
 * Webhook Secret Rotation Tracker (issue #528)
 *
 * Ops need visibility into which subscriptions have adopted the newest secret.
 * This module:
 *
 *  1. Maintains the current (latest) secret version expected across all
 *     subscriptions.
 *  2. Accepts heartbeat / check-in calls from the dispatcher so it can
 *     compare each subscription's reported `secretVersion` against the
 *     current version.
 *  3. Exposes `emitRotationStatus()` that updates the
 *     `webhook_secret_rotation_status` Prometheus gauge so Grafana can
 *     render a per-subscription rollout dashboard.
 *
 * Usage
 * -----
 * The webhook dispatcher calls `reportSubscriptionVersion(sub, latestVersion)`
 * after every successful delivery attempt.  A background cron (or the same
 * dispatcher loop) calls `emitRotationStatus()` on a schedule (e.g. every
 * 60 seconds) to push metrics.
 *
 * On startup, all known subscriptions should be reported at least once so
 * the gauge is populated.
 *
 * Security
 * --------
 * The metric only exposes the *status* (current / lagging) — never the
 * actual secret or its hash.  Subscriptions that have never checked in
 * are silently omitted from the gauge, so a missing metric is
 * indistinguishable from "not yet reported".
 */

import { webhookSecretRotationStatus } from "../../metrics.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SubscriptionVersionReport {
  subscriptionId: string;
  businessId: string;
  /** The secret version this subscription is currently using. */
  currentVersion: number;
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/**
 * Highest secret version observed across *all* subscriptions.
 * Operators bump this when they deploy a new secret.
 * The tracker treats it as the "latest" version for comparison.
 */
let latestSecretVersion = 0;

/**
 * In-memory registry mapping subcriptionId → their reported version.
 * Sized by the active subscription count (typically tens to low thousands).
 */
const subscriptionVersions = new Map<string, SubscriptionVersionReport>();

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Set the latest (canonical) secret version that all subscriptions should
 * eventually adopt.  Operators call this once after deploying a new secret.
 *
 * @param version  The new latest version number (must be monotonically
 *                 increasing — no-op if lower than the current value).
 */
export function setLatestSecretVersion(version: number): void {
  if (version > latestSecretVersion) {
    latestSecretVersion = version;
  }
}

/**
 * Returns the current latest secret version.
 */
export function getLatestSecretVersion(): number {
  return latestSecretVersion;
}

/**
 * Record the secret version a particular subscription is currently using.
 *
 * @param subscriptionId  Unique identifier for the webhook subscription.
 * @param businessId      Business / tenant the subscription belongs to.
 * @param currentVersion  The secret version this subscription has adopted.
 */
export function reportSubscriptionVersion(
  subscriptionId: string,
  businessId: string,
  currentVersion: number,
): void {
  subscriptionVersions.set(subscriptionId, {
    subscriptionId,
    businessId,
    currentVersion,
  });
}

/**
 * Remove a subscription from the tracker (e.g. deactivated subscription).
 */
export function removeSubscription(subscriptionId: string): void {
  subscriptionVersions.delete(subscriptionId);
}

/**
 * Check whether a specific subscription has adopted the latest secret version.
 *
 * @returns `true` if the subscription is current, `false` if it is lagging,
 *          or `undefined` if the subscription has never reported in.
 */
export function isSubscriptionCurrent(
  subscriptionId: string,
): boolean | undefined {
  const report = subscriptionVersions.get(subscriptionId);
  if (!report) return undefined;

  if (latestSecretVersion === 0) {
    // No latest version has been published yet — treat all as current.
    return true;
  }

  return report.currentVersion >= latestSecretVersion;
}

/**
 * Returns a snapshot of all tracked subscriptions and their adoption status.
 */
export function getAdoptionSnapshot(): Array<{
  subscriptionId: string;
  businessId: string;
  currentVersion: number;
  isCurrent: boolean;
}> {
  const snapshot: Array<{
    subscriptionId: string;
    businessId: string;
    currentVersion: number;
    isCurrent: boolean;
  }> = [];

  for (const report of subscriptionVersions.values()) {
    const isCurrent =
      latestSecretVersion === 0 ||
      report.currentVersion >= latestSecretVersion;
    snapshot.push({
      subscriptionId: report.subscriptionId,
      businessId: report.businessId,
      currentVersion: report.currentVersion,
      isCurrent,
    });
  }

  return snapshot;
}

/**
 * Emit the `webhook_secret_rotation_status` Prometheus gauge for every
 * tracked subscription.  Call this periodically (e.g. every 60 seconds or
 * after each batch of dispatches) so Grafana has fresh data.
 *
 * The gauge is reset before emitting so subscriptions that have been removed
 * or expired do not carry stale labels.
 */
export function emitRotationStatus(): void {
  webhookSecretRotationStatus.reset();

  for (const report of subscriptionVersions.values()) {
    const isCurrent =
      latestSecretVersion === 0 ||
      report.currentVersion >= latestSecretVersion;

    // Set current (1) for the matching label
    webhookSecretRotationStatus.set(
      {
        subscription_id: report.subscriptionId,
        business_id: report.businessId,
        status: "current",
      },
      isCurrent ? 1 : 0,
    );

    // Set lagging (1) for the matching label
    webhookSecretRotationStatus.set(
      {
        subscription_id: report.subscriptionId,
        business_id: report.businessId,
        status: "lagging",
      },
      isCurrent ? 0 : 1,
    );
  }
}

/**
 * Clear all tracked state (useful for testing and graceful shutdown).
 */
export function reset(): void {
  latestSecretVersion = 0;
  subscriptionVersions.clear();
  webhookSecretRotationStatus.reset();
}

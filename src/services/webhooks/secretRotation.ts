/**
 * Webhook Secret Rotation Tracker (issue #528, persisted in #1279)
 *
 * Ops need visibility into which subscriptions have adopted the newest secret.
 * Adoption state is derived directly from `webhook_subscriptions.secret_version`
 * in PostgreSQL so all instances observe identical state across restarts.
 */

import { webhookSecretRotationStatus } from "../../metrics.js";
import * as webhookSubscriptionRepo from "../../repositories/webhookSubscriptionRepository.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SubscriptionVersionReport {
  subscriptionId: string;
  businessId: string;
  /** The secret version this subscription is currently using. */
  currentVersion: number;
}

export interface SecretRotationAdoptionEntry {
  subscriptionId: string;
  businessId: string;
  currentVersion: number;
  isCurrent: boolean;
}

// ---------------------------------------------------------------------------
// Timer handle (not a source of truth)
// ---------------------------------------------------------------------------

let refreshTimer: ReturnType<typeof setInterval> | null = null;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * @deprecated Secret versions are now persisted in `webhook_subscriptions.secret_version`.
 * Kept as a no-op for backwards compatibility.
 */
export function setLatestSecretVersion(_version: number): void {
  // No-op: latest version is derived from MAX(secret_version) in the database.
}

/**
 * Returns the current latest secret version from the database.
 */
export async function getLatestSecretVersion(): Promise<number> {
  return webhookSubscriptionRepo.getLatestSecretVersion();
}

/**
 * @deprecated Secret versions are now persisted in `webhook_subscriptions.secret_version`.
 * Kept as a no-op for backwards compatibility.
 */
export function reportSubscriptionVersion(
  _subscriptionId: string,
  _businessId: string,
  _currentVersion: number,
): void {
  // No-op: subscription versions are read directly from the database.
}

/**
 * @deprecated Subscription removals are reflected automatically in database queries.
 * Kept as a no-op for backwards compatibility.
 */
export function removeSubscription(_subscriptionId: string): void {
  // No-op: subscription state is read directly from the database.
}

/**
 * Check whether a specific subscription has adopted the latest secret version.
 *
 * @returns `true` if the subscription is current, `false` if it is lagging,
 *          or `undefined` if the subscription does not exist in the database.
 */
export async function isSubscriptionCurrent(
  subscriptionId: string,
): Promise<boolean | undefined> {
  if (!subscriptionId) return undefined;
  const snapshot = await getAdoptionSnapshot();
  const entry = snapshot.find((item) => item.subscriptionId === subscriptionId);
  return entry?.isCurrent;
}

/**
 * Returns a snapshot of all subscriptions and their adoption status from the database.
 */
export async function getAdoptionSnapshot(): Promise<SecretRotationAdoptionEntry[]> {
  const [latestVersion, rows] = await Promise.all([
    webhookSubscriptionRepo.getLatestSecretVersion(),
    webhookSubscriptionRepo.listSecretVersions(),
  ]);

  return rows.map((row) => ({
    subscriptionId: row.subscriptionId,
    businessId: row.businessId,
    currentVersion: row.currentVersion,
    isCurrent: latestVersion === 0 || row.currentVersion >= latestVersion,
  }));
}

/**
 * Emit the `webhook_secret_rotation_status` Prometheus gauge for every
 * subscription in the database. Idempotent across repeated calls.
 */
export async function emitRotationStatus(): Promise<void> {
  const snapshot = await getAdoptionSnapshot();
  webhookSecretRotationStatus.reset();

  for (const entry of snapshot) {
    webhookSecretRotationStatus.set(
      {
        subscription_id: entry.subscriptionId,
        business_id: entry.businessId,
        status: "current",
      },
      entry.isCurrent ? 1 : 0,
    );

    webhookSecretRotationStatus.set(
      {
        subscription_id: entry.subscriptionId,
        business_id: entry.businessId,
        status: "lagging",
      },
      entry.isCurrent ? 0 : 1,
    );
  }
}

/**
 * Start a periodic background refresh of `webhook_secret_rotation_status`.
 */
export function startRotationStatusRefresh(
  intervalMs = 60_000,
): ReturnType<typeof setInterval> {
  stopRotationStatusRefresh();
  refreshTimer = setInterval(() => {
    void emitRotationStatus();
  }, intervalMs);
  refreshTimer.unref?.();
  return refreshTimer;
}

/**
 * Stop the periodic background refresh timer if running.
 */
export function stopRotationStatusRefresh(): void {
  if (refreshTimer !== null) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
}

/**
 * Stop any refresh timer and reset the Prometheus gauge (useful for testing and shutdown).
 */
export function reset(): void {
  stopRotationStatusRefresh();
  webhookSecretRotationStatus.reset();
}

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
// State
// ---------------------------------------------------------------------------

let latestSecretVersion = 0;
const subscriptionVersions = new Map<string, SubscriptionVersionReport>();
const removedSubscriptionIds = new Set<string>();

let refreshTimer: ReturnType<typeof setInterval> | null = null;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Set the latest (canonical) secret version that all subscriptions should
 * eventually adopt. Monotonically increasing (no-op if lower than the current value).
 */
export function setLatestSecretVersion(version: number): void {
  if (version > latestSecretVersion) {
    latestSecretVersion = version;
  }
}

/**
 * Returns the current latest secret version from the database or in-memory tracking.
 */
export async function getLatestSecretVersion(): Promise<number> {
  const dbVersion = await webhookSubscriptionRepo.getLatestSecretVersion();
  return Math.max(dbVersion, latestSecretVersion);
}

/**
 * Record the secret version a particular subscription is currently using.
 */
export function reportSubscriptionVersion(
  subscriptionId: string,
  businessId: string,
  currentVersion: number,
): void {
  removedSubscriptionIds.delete(subscriptionId);
  subscriptionVersions.set(subscriptionId, {
    subscriptionId,
    businessId,
    currentVersion,
  });
}

/**
 * Remove a subscription from tracking.
 */
export function removeSubscription(subscriptionId: string): void {
  subscriptionVersions.delete(subscriptionId);
  removedSubscriptionIds.add(subscriptionId);
}

/**
 * Check whether a specific subscription has adopted the latest secret version.
 *
 * @returns `true` if the subscription is current, `false` if it is lagging,
 *          or `undefined` if the subscription does not exist in the database or reports.
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
 * Returns a snapshot of all subscriptions and their adoption status from the database and in-memory tracking.
 */
export async function getAdoptionSnapshot(): Promise<SecretRotationAdoptionEntry[]> {
  const [dbLatest, rows] = await Promise.all([
    webhookSubscriptionRepo.getLatestSecretVersion(),
    webhookSubscriptionRepo.listSecretVersions(),
  ]);

  const effectiveLatest = Math.max(dbLatest, latestSecretVersion);
  const entriesMap = new Map<string, SecretRotationAdoptionEntry>();

  for (const row of rows) {
    if (removedSubscriptionIds.has(row.subscriptionId)) {
      continue;
    }
    entriesMap.set(row.subscriptionId, {
      subscriptionId: row.subscriptionId,
      businessId: row.businessId,
      currentVersion: row.currentVersion,
      isCurrent: effectiveLatest === 0 || row.currentVersion >= effectiveLatest,
    });
  }

  for (const report of subscriptionVersions.values()) {
    if (removedSubscriptionIds.has(report.subscriptionId)) {
      continue;
    }
    entriesMap.set(report.subscriptionId, {
      subscriptionId: report.subscriptionId,
      businessId: report.businessId,
      currentVersion: report.currentVersion,
      isCurrent: effectiveLatest === 0 || report.currentVersion >= effectiveLatest,
    });
  }

  return Array.from(entriesMap.values());
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
 * Stop any refresh timer and reset state and Prometheus gauge (useful for testing and shutdown).
 */
export function reset(): void {
  stopRotationStatusRefresh();
  latestSecretVersion = 0;
  subscriptionVersions.clear();
  removedSubscriptionIds.clear();
  webhookSecretRotationStatus.reset();
}

import { queryAuditLogs } from "../repositories/auditLogRepository.js";
import { submitAttestation } from "../services/soroban/submitAttestation.js";
import { sorobanRetryBudget } from "../services/soroban/retry-budget.js";
import { submissionReplayProgress } from "../metrics.js";
import { config } from "../config/index.js";
import { logger } from "../utils/logger.js";

const SUBMIT_FAILED_ACTION = "ATTESTATION_SUBMIT_FAILED";

type ReplayEntryParams = {
  business: string;
  period: string;
  merkleRoot: string;
  timestamp: number | bigint;
  version: string;
};

/**
 * Result summary returned by replayFailedSubmissions.
 */
export interface ReplaySummary {
  scanned: number;
  attempted: number;
  succeeded: number;
  failed: number;
  skippedExpired: number;
  skippedBudget: number;
}

function parseReplayParams(metadata: unknown): ReplayEntryParams | null {
  if (!metadata || typeof metadata !== "object") return null;
  const m = metadata as Record<string, unknown>;
  if (
    typeof m.business !== "string" ||
    typeof m.period !== "string" ||
    typeof m.merkleRoot !== "string" ||
    (typeof m.timestamp !== "number" && typeof m.timestamp !== "bigint") ||
    !Number.isFinite(Number(m.timestamp)) ||
    Number(m.timestamp) < 0 ||
    typeof m.version !== "string"
  ) {
    return null;
  }
  return {
    business: m.business,
    period: m.period,
    merkleRoot: m.merkleRoot,
    timestamp: m.timestamp as number | bigint,
    version: m.version,
  };
}

function isExpired(entryTimestamp: Date, maxAgeDays: number): boolean {
  const cutoff = Date.now() - maxAgeDays * 24 * 60 * 60 * 1000;
  return entryTimestamp.getTime() < cutoff;
}

function deduplicateEntries(entries: { params: ReplayEntryParams }[]): ReplayEntryParams[] {
  const seen = new Set<string>();
  const result: ReplayEntryParams[] = [];
  for (const entry of entries) {
    const key = `${entry.params.business}:${entry.params.period}:${entry.params.merkleRoot}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(entry.params);
  }
  return result;
}

/**
 * Replays failed Soroban attestation submissions found in the audit log.
 *
 * Streams through the audit log using cursor-based pagination, filters
 * entries with action = ATTESTATION_SUBMIT_FAILED, parses submission
 * parameters from metadata, and re-submits each unique attestation.
 *
 * Respects the Soroban retry budget, skips entries older than
 * SOROBAN_REPLAY_MAX_AGE_DAYS (default 7), and deduplicates entries
 * by (business, period, merkleRoot).
 *
 * Emits submission_replay_progress gauge with phase label ("scanning",
 * "replaying", "done") and returns a summary of results.
 *
 * @param maxAgeDays - Maximum age of entries to replay. Defaults to config value.
 * @returns A promise that resolves to a ReplaySummary.
 */
export async function replayFailedSubmissions(
  maxAgeDays: number = config.soroban.replayMaxAgeDays,
): Promise<ReplaySummary> {
  const summary: ReplaySummary = {
    scanned: 0,
    attempted: 0,
    succeeded: 0,
    failed: 0,
    skippedExpired: 0,
    skippedBudget: 0,
  };

  const collectedEntries: { params: ReplayEntryParams }[] = [];

  submissionReplayProgress.set({ phase: "scanning" }, 0);

  let cursor: string | undefined;
  let hasMore = true;

  while (hasMore) {
    const page = await queryAuditLogs({
      action: SUBMIT_FAILED_ACTION,
      limit: 50,
      cursor,
    });

    for (const entry of page.data) {
      summary.scanned++;

      if (isExpired(entry.timestamp, maxAgeDays)) {
        summary.skippedExpired++;
        continue;
      }

      const params = parseReplayParams(entry.metadata?.params);
      if (!params) {
        continue;
      }

      collectedEntries.push({ params });
    }

    cursor = page.nextCursor ?? undefined;
    hasMore = page.hasMore;
  }

  submissionReplayProgress.set({ phase: "scanning" }, 0.5);

  const deduplicated = deduplicateEntries(collectedEntries);

  submissionReplayProgress.set({ phase: "replaying" }, 0);

  const sourcePublicKey = process.env.SOROBAN_SOURCE_PUBLIC_KEY ?? "";
  const sourceSecret = process.env.SOROBAN_SOURCE_SECRET ?? "";

  const total = deduplicated.length;
  for (let i = 0; i < total; i++) {
    const params = deduplicated[i];

    submissionReplayProgress.set(
      { phase: "replaying" },
      total > 0 ? (i + 1) / total : 1,
    );

    if (sourcePublicKey === "" || sourceSecret === "") {
      logger.warn({
        event: "submission_replay_skipped",
        reason: "Missing SOROBAN_SOURCE_PUBLIC_KEY or SOROBAN_SOURCE_SECRET",
      });
      summary.skippedBudget += total - i;
      break;
    }

    if (!sorobanRetryBudget.canRetry()) {
      logger.warn({
        event: "submission_replay_budget_exhausted",
        remaining: total - i,
      });
      summary.skippedBudget += total - i;
      break;
    }

    summary.attempted++;

    try {
      await submitAttestation({
        business: params.business,
        period: params.period,
        merkleRoot: params.merkleRoot,
        timestamp: params.timestamp,
        version: params.version,
        sourcePublicKey: sourcePublicKey,
        signerSecret: sourceSecret,
      });
      sorobanRetryBudget.recordRetry("replay");
      summary.succeeded++;
      logger.info({
        event: "submission_replay_succeeded",
        business: params.business,
        period: params.period,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      sorobanRetryBudget.recordRetry("replay");
      summary.failed++;
      logger.warn({
        event: "submission_replay_failed",
        business: params.business,
        period: params.period,
        error: message,
      });
    }
  }

  submissionReplayProgress.set({ phase: "done" }, 1);

  logger.info({
    event: "submission_replay_completed",
    ...summary,
  });

  return summary;
}

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// ── Mocks ────────────────────────────────────────────────────────────────────

const mocks = vi.hoisted(() => ({
  archiveOldEntries: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  fetch: vi.fn(),
}));

vi.mock('../../../src/services/webhooks/deadLetterQueue', () => ({
  DeadLetterQueue: class {
    archiveOldEntries = mocks.archiveOldEntries;
  },
}));

vi.mock('../../../src/utils/logger', () => ({
  Logger: class {
    info = mocks.info;
    warn = mocks.warn;
    error = mocks.error;
    debug = vi.fn();
  },
  logger: { info: mocks.info, warn: mocks.warn, error: mocks.error },
}));

import { runDlqArchiveJob } from '../../../src/jobs/dlq-archive-job';

// ── Helpers ──────────────────────────────────────────────────────────────────

const WEBHOOK = 'https://hooks.example.com/T000';

/** Build the shape `DeadLetterQueue#archiveOldEntries` resolves with. */
function archiveResult(archived: number, failed: number, total: number) {
  return { archived, failed, total };
}

/** `sendAlert` posts a single JSON body; unpack it for assertions. */
function alertBody(call = 0): { text: string } {
  const init = mocks.fetch.mock.calls[call]?.[1] as { body: string };
  return JSON.parse(init.body) as { text: string };
}

beforeEach(() => {
  mocks.archiveOldEntries.mockReset();
  mocks.info.mockReset();
  mocks.warn.mockReset();
  mocks.error.mockReset();
  mocks.fetch.mockReset();

  mocks.fetch.mockResolvedValue({ ok: true });
  vi.stubGlobal('fetch', mocks.fetch);
  delete process.env.SLACK_WEBHOOK_URL;
});

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.SLACK_WEBHOOK_URL;
});

// ── Happy path ───────────────────────────────────────────────────────────────

describe('runDlqArchiveJob — success path', () => {
  it('archives once and logs the counts reported by the DLQ', async () => {
    mocks.archiveOldEntries.mockResolvedValue(archiveResult(3, 0, 10));

    await expect(runDlqArchiveJob()).resolves.toBeUndefined();

    expect(mocks.archiveOldEntries).toHaveBeenCalledTimes(1);
    expect(mocks.info).toHaveBeenCalledWith(
      expect.stringContaining('3 entries archived, 0 failed'),
    );
    expect(mocks.warn).not.toHaveBeenCalled();
    expect(mocks.error).not.toHaveBeenCalled();
  });

  it('forwards no options, letting the DLQ apply its own configured defaults', async () => {
    mocks.archiveOldEntries.mockResolvedValue(archiveResult(0, 0, 0));

    await runDlqArchiveJob();

    expect(mocks.archiveOldEntries).toHaveBeenCalledWith();
  });
});

// ── Partial failure ──────────────────────────────────────────────────────────

describe('runDlqArchiveJob — partial failures', () => {
  it('warns when at least one entry failed, but stays silent under the 10% threshold', async () => {
    process.env.SLACK_WEBHOOK_URL = WEBHOOK;
    mocks.archiveOldEntries.mockResolvedValue(archiveResult(0, 1, 100)); // 1%

    await runDlqArchiveJob();

    expect(mocks.warn).toHaveBeenCalledWith(expect.stringContaining('1 entries failed'));
    expect(mocks.error).not.toHaveBeenCalled();
    expect(mocks.fetch).not.toHaveBeenCalled();
  });

  it('does not alert at exactly 10% — the threshold is strictly greater-than', async () => {
    process.env.SLACK_WEBHOOK_URL = WEBHOOK;
    mocks.archiveOldEntries.mockResolvedValue(archiveResult(0, 1, 10)); // 0.1 exactly

    await runDlqArchiveJob();

    expect(mocks.warn).toHaveBeenCalled();
    expect(mocks.error).not.toHaveBeenCalled();
    expect(mocks.fetch).not.toHaveBeenCalled();
  });

  it('treats a zero total as a 0% failure rate so the guard cannot divide by zero', async () => {
    process.env.SLACK_WEBHOOK_URL = WEBHOOK;
    mocks.archiveOldEntries.mockResolvedValue(archiveResult(0, 5, 0));

    await runDlqArchiveJob();

    expect(mocks.warn).toHaveBeenCalledWith(expect.stringContaining('5 entries failed'));
    expect(mocks.error).not.toHaveBeenCalled();
    expect(mocks.fetch).not.toHaveBeenCalled();
  });
});

// ── Alerting ─────────────────────────────────────────────────────────────────

describe('runDlqArchiveJob — high failure rate alerting', () => {
  it('logs an error and posts a Slack alert when the failure rate exceeds 10%', async () => {
    process.env.SLACK_WEBHOOK_URL = WEBHOOK;
    mocks.archiveOldEntries.mockResolvedValue(archiveResult(0, 2, 10)); // 20%

    await runDlqArchiveJob();

    expect(mocks.error).toHaveBeenCalledWith(expect.stringContaining('20.00%'));
    expect(mocks.fetch).toHaveBeenCalledTimes(1);
    expect(mocks.fetch.mock.calls[0]?.[0]).toBe(WEBHOOK);

    const init = mocks.fetch.mock.calls[0]?.[1] as {
      method: string;
      headers: Record<string, string>;
    };
    expect(init.method).toBe('POST');
    expect(init.headers['Content-Type']).toBe('application/json');

    const text = alertBody().text;
    expect(text).toContain('*DLQ Archive Failure*');
    expect(text).toContain('20.00%');
  });

  it('formats the reported rate with two decimal places', async () => {
    process.env.SLACK_WEBHOOK_URL = WEBHOOK;
    mocks.archiveOldEntries.mockResolvedValue(archiveResult(0, 1, 3)); // 33.333…%

    await runDlqArchiveJob();

    expect(alertBody().text).toContain('33.33%');
  });

  it('skips the webhook entirely when SLACK_WEBHOOK_URL is not configured', async () => {
    mocks.archiveOldEntries.mockResolvedValue(archiveResult(0, 9, 10)); // 90%

    await runDlqArchiveJob();

    expect(mocks.error).toHaveBeenCalledWith(expect.stringContaining('90.00%'));
    expect(mocks.fetch).not.toHaveBeenCalled();
  });
});

// ── Fatal path ───────────────────────────────────────────────────────────────

describe('runDlqArchiveJob — fatal path', () => {
  it('logs, alerts and rethrows when the archive call rejects', async () => {
    process.env.SLACK_WEBHOOK_URL = WEBHOOK;
    const failure = new Error('s3 unavailable');
    mocks.archiveOldEntries.mockRejectedValue(failure);

    await expect(runDlqArchiveJob()).rejects.toBe(failure);

    expect(mocks.error).toHaveBeenCalledWith('DLQ archive job failed:', failure);
    expect(mocks.fetch).toHaveBeenCalledTimes(1);
    expect(alertBody().text).toContain('*DLQ Archive Job Failed*');
    expect(alertBody().text).toContain('s3 unavailable');
  });

  it('stringifies a non-Error rejection instead of writing "undefined" into the alert', async () => {
    process.env.SLACK_WEBHOOK_URL = WEBHOOK;
    mocks.archiveOldEntries.mockRejectedValue('boom');

    await expect(runDlqArchiveJob()).rejects.toBe('boom');

    expect(alertBody().text).toContain('boom');
    expect(alertBody().text).not.toContain('undefined');
  });

  it('still resolves the job when the alert webhook itself fails', async () => {
    process.env.SLACK_WEBHOOK_URL = WEBHOOK;
    mocks.archiveOldEntries.mockResolvedValue(archiveResult(0, 2, 10));
    const webhookFailure = new Error('network down');
    mocks.fetch.mockRejectedValue(webhookFailure);

    await expect(runDlqArchiveJob()).resolves.toBeUndefined();

    expect(mocks.error).toHaveBeenCalledWith('Failed to send alert:', webhookFailure);
  });

  it('still resolves the job when the archive call succeeds and no webhook is set', async () => {
    mocks.archiveOldEntries.mockResolvedValue(archiveResult(0, 0, 0));

    await expect(runDlqArchiveJob()).resolves.toBeUndefined();
    expect(mocks.fetch).not.toHaveBeenCalled();
  });
});

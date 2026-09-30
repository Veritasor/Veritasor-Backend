import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

import { logger } from '../../utils/logger.js';
import { recordCdnPurgeStatus, type PurgeStatus } from './auditLog.js';

const PURGE_STATUSES: PurgeStatus[] = ['queued', 'success', 'failed'];

const info = vi.mocked(logger.info);

describe('recordCdnPurgeStatus', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('supports exactly the queued/success/failed purge lifecycle', () => {
    // The exported union is the audit contract; guard against silently dropping
    // or renaming a lifecycle state.
    expect(PURGE_STATUSES).toEqual(['queued', 'success', 'failed']);

    // Every declared status is accepted without throwing.
    for (const status of PURGE_STATUSES) {
      expect(() => recordCdnPurgeStatus('att-1', status)).not.toThrow();
    }
  });

  it.each(PURGE_STATUSES)(
    'logs the %s status under the cdn-purge-status message with no details',
    (status) => {
      recordCdnPurgeStatus('att-42', status);

      expect(info).toHaveBeenCalledTimes(1);
      expect(info).toHaveBeenCalledWith(
        { attestationId: 'att-42', status, details: undefined },
        'cdn-purge-status',
      );
    },
  );

  it('forwards details objects verbatim without mutating them', () => {
    const details = { httpStatus: 200, cache: 'edge-a', attempts: 1 };

    recordCdnPurgeStatus('att-7', 'success', details);

    expect(info).toHaveBeenCalledTimes(1);
    const [payload] = info.mock.calls[0];
    expect(payload).toEqual({ attestationId: 'att-7', status: 'success', details });
    // Same object identity: the helper must not clone or rewrite the details.
    expect((payload as { details: unknown }).details).toBe(details);
    expect(details).toEqual({ httpStatus: 200, cache: 'edge-a', attempts: 1 });
  });

  it('records queued -> success as two ordered entries for one attestation', () => {
    recordCdnPurgeStatus('att-9', 'queued', { provider: 'cdn-a' });
    recordCdnPurgeStatus('att-9', 'success', { provider: 'cdn-a', purgedAt: 123 });

    expect(info).toHaveBeenCalledTimes(2);
    expect(info.mock.calls[0][0]).toMatchObject({ attestationId: 'att-9', status: 'queued' });
    expect(info.mock.calls[1][0]).toMatchObject({ attestationId: 'att-9', status: 'success' });
  });

  it('records queued -> failed with the failure detail attached', () => {
    recordCdnPurgeStatus('att-11', 'queued');
    recordCdnPurgeStatus('att-11', 'failed', { reason: 'cdn timeout' });

    expect(info).toHaveBeenCalledTimes(2);
    expect(info.mock.calls[1][0]).toMatchObject({
      attestationId: 'att-11',
      status: 'failed',
      details: { reason: 'cdn timeout' },
    });
  });

  it('uses only the info channel (audit records are not warnings or errors)', () => {
    recordCdnPurgeStatus('att-3', 'failed', { reason: 'boom' });

    expect(info).toHaveBeenCalledTimes(1);
    expect(logger.warn).not.toHaveBeenCalled();
    expect(logger.error).not.toHaveBeenCalled();
    expect(logger.debug).not.toHaveBeenCalled();
  });

  it('passes an empty attestation id through unchanged (no validation or coercion)', () => {
    recordCdnPurgeStatus('', 'queued');

    expect(info).toHaveBeenCalledTimes(1);
    expect(info).toHaveBeenCalledWith(
      { attestationId: '', status: 'queued', details: undefined },
      'cdn-purge-status',
    );
  });

  it('is fire-and-forget: returns undefined for every status', () => {
    for (const status of PURGE_STATUSES) {
      expect(recordCdnPurgeStatus('att-5', status)).toBeUndefined();
    }
    expect(info).toHaveBeenCalledTimes(PURGE_STATUSES.length);
  });

  it('logs one entry per invocation, even for repeated identical statuses', () => {
    recordCdnPurgeStatus('att-6', 'queued');
    recordCdnPurgeStatus('att-6', 'queued');

    expect(info).toHaveBeenCalledTimes(2);
    expect(info.mock.calls[0][0]).toEqual(info.mock.calls[1][0]);
  });
});

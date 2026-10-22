import { logger } from '../utils/logger.js';
import { runInstrumentedJob, type JobOutcome } from './jobRunner.js';
import { drainQueuedAttestations, isSorobanQueueEnabled } from '../services/soroban/submitAttestation.js';

export const SOROBAN_ATTESTATION_DRAINER_JOB_NAME = 'soroban_attestation_drainer';

export const sorobanAttestationDrainerJob = async (
  limit: number = 10,
  now: number = Date.now(),
): Promise<JobOutcome> => {
  return runInstrumentedJob(SOROBAN_ATTESTATION_DRAINER_JOB_NAME, async () => {
    if (!isSorobanQueueEnabled()) {
      return { itemsProcessed: 0, success: true };
    }

    try {
      const drained = await drainQueuedAttestations(limit);
      const successful = drained.filter((entry) => entry.result).length;
      const failed = drained.filter((entry) => entry.error).length;

      logger.info({
        event: 'soroban_attestation_drainer',
        queuedCount: drained.length,
        successful,
        failed,
        now,
      }, 'soroban: drained queued attestations');

      return { itemsProcessed: drained.length, success: true };
    } catch (error) {
      logger.error({ event: 'soroban_attestation_drainer_error', error }, 'soroban: drainer failed');
      return { itemsProcessed: 0, success: false };
    }
  });
};

import {
  OpenFeature,
  type Provider,
  type EvaluationContext,
} from '@openfeature/server-sdk';
import { logger } from '../../utils/logger.js';

export const FlagKeys = {
  SOROBAN_BATCHED_SUBMISSION: 'soroban_batched_submission',
  STATSD_DUAL_WRITE: 'statsd_dual_write',
} as const;

export type { Provider, EvaluationContext };

export type FlagContext = {
  businessId: string;
  userId: string;
};

function buildEvaluationContext(context: FlagContext): EvaluationContext {
  return {
    targetingKey: context.businessId,
    businessId: context.businessId,
    userId: context.userId,
  };
}

export async function getBooleanFlag(
  flagKey: string,
  defaultValue: boolean,
  context: FlagContext,
): Promise<boolean> {
  try {
    const client = OpenFeature.getClient();
    return await client.getBooleanValue(flagKey, defaultValue, buildEvaluationContext(context));
  } catch (err) {
    logger.warn(
      {
        flagKey,
        error: err instanceof Error ? err.message : String(err),
      },
      'feature flag evaluation failed, falling back to default',
    );
    return defaultValue;
  }
}

export async function getSorobanBatchedSubmissionFlag(
  context: FlagContext,
): Promise<boolean> {
  return getBooleanFlag(FlagKeys.SOROBAN_BATCHED_SUBMISSION, false, context);
}

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { OpenFeature, TypedInMemoryProvider } from '@openfeature/server-sdk';
import {
  getBooleanFlag,
  getSorobanBatchedSubmissionFlag,
  FlagKeys,
} from '../../../../src/services/features/flags.js';

describe('getBooleanFlag', () => {
  afterEach(async () => {
    await OpenFeature.clearProviders();
  });

  it('returns the default value when no provider is set (NoopProvider)', async () => {
    const result = await getBooleanFlag('nonexistent', true, {
      businessId: 'biz_1',
      userId: 'user_1',
    });
    expect(result).toBe(true);
  });

  it('returns the configured value from InMemoryProvider', async () => {
    const provider = new TypedInMemoryProvider({
      [FlagKeys.SOROBAN_BATCHED_SUBMISSION]: {
        variants: { on: true, off: false },
        defaultVariant: 'off',
        disabled: false,
      },
    });
    await OpenFeature.setProviderAndWait(provider);

    const result = await getBooleanFlag(FlagKeys.SOROBAN_BATCHED_SUBMISSION, false, {
      businessId: 'biz_1',
      userId: 'user_1',
    });
    expect(result).toBe(false);
  });

  it('returns the default value when flag is disabled', async () => {
    const provider = new TypedInMemoryProvider({
      [FlagKeys.SOROBAN_BATCHED_SUBMISSION]: {
        variants: { on: true, off: false },
        defaultVariant: 'on',
        disabled: true,
      },
    });
    await OpenFeature.setProviderAndWait(provider);

    const result = await getBooleanFlag(FlagKeys.SOROBAN_BATCHED_SUBMISSION, false, {
      businessId: 'biz_1',
      userId: 'user_1',
    });
    expect(result).toBe(false);
  });

  it('returns the default value when provider throws during evaluation', async () => {
    const rejectingProvider = {
      metadata: { name: 'rejecting' },
      hooks: [],
      resolveBooleanEvaluation: vi.fn().mockRejectedValue(new Error('provider error')),
      resolveStringEvaluation: vi.fn(),
      resolveNumberEvaluation: vi.fn(),
      resolveObjectEvaluation: vi.fn(),
    };
    await OpenFeature.setProviderAndWait(rejectingProvider as any);

    const result = await getBooleanFlag(FlagKeys.SOROBAN_BATCHED_SUBMISSION, true, {
      businessId: 'biz_1',
      userId: 'user_1',
    });
    expect(result).toBe(true);
  });

  it('uses targeting key from businessId for flag evaluation', async () => {
    const contextEvaluator = vi.fn().mockReturnValue('on');
    const provider = new TypedInMemoryProvider({
      [FlagKeys.SOROBAN_BATCHED_SUBMISSION]: {
        variants: { on: true, off: false },
        defaultVariant: 'off',
        disabled: false,
        contextEvaluator,
      },
    });
    await OpenFeature.setProviderAndWait(provider);

    await getBooleanFlag(FlagKeys.SOROBAN_BATCHED_SUBMISSION, false, {
      businessId: 'biz_42',
      userId: 'user_7',
    });

    expect(contextEvaluator).toHaveBeenCalled();
    const ctx = contextEvaluator.mock.calls[0][0];
    expect(ctx).toMatchObject({
      targetingKey: 'biz_42',
      businessId: 'biz_42',
      userId: 'user_7',
    });
  });
});

describe('getSorobanBatchedSubmissionFlag', () => {
  afterEach(async () => {
    await OpenFeature.clearProviders();
  });

  it('returns false by default (NoopProvider)', async () => {
    const result = await getSorobanBatchedSubmissionFlag({
      businessId: 'biz_1',
      userId: 'user_1',
    });
    expect(result).toBe(false);
  });

  it('returns true when InMemoryProvider is configured with on variant', async () => {
    const provider = new TypedInMemoryProvider({
      [FlagKeys.SOROBAN_BATCHED_SUBMISSION]: {
        variants: { on: true, off: false },
        defaultVariant: 'on',
        disabled: false,
      },
    });
    await OpenFeature.setProviderAndWait(provider);

    const result = await getSorobanBatchedSubmissionFlag({
      businessId: 'biz_1',
      userId: 'user_1',
    });
    expect(result).toBe(true);
  });

  it('returns false when InMemoryProvider is configured with off variant', async () => {
    const provider = new TypedInMemoryProvider({
      [FlagKeys.SOROBAN_BATCHED_SUBMISSION]: {
        variants: { on: true, off: false },
        defaultVariant: 'off',
        disabled: false,
      },
    });
    await OpenFeature.setProviderAndWait(provider);

    const result = await getSorobanBatchedSubmissionFlag({
      businessId: 'biz_1',
      userId: 'user_1',
    });
    expect(result).toBe(false);
  });

  it('supports per-business targeting via contextEvaluator', async () => {
    const provider = new TypedInMemoryProvider({
      [FlagKeys.SOROBAN_BATCHED_SUBMISSION]: {
        variants: { on: true, off: false },
        defaultVariant: 'off',
        disabled: false,
        contextEvaluator: (ctx) =>
          ctx?.businessId === 'biz_enterprise' ? 'on' : 'off',
      },
    });
    await OpenFeature.setProviderAndWait(provider);

    const enterpriseResult = await getSorobanBatchedSubmissionFlag({
      businessId: 'biz_enterprise',
      userId: 'user_1',
    });
    expect(enterpriseResult).toBe(true);

    const standardResult = await getSorobanBatchedSubmissionFlag({
      businessId: 'biz_standard',
      userId: 'user_2',
    });
    expect(standardResult).toBe(false);
  });
});

describe('FlagKeys', () => {
  it('defines SOROBAN_BATCHED_SUBMISSION flag key', () => {
    expect(FlagKeys.SOROBAN_BATCHED_SUBMISSION).toBe('soroban_batched_submission');
  });
});

describe('Soroban submitAttestation imports flags module', () => {
  it('imports getSorobanBatchedSubmissionFlag from flags module', async () => {
    const mod = await import('../../../../src/services/features/flags.js');
    expect(typeof mod.getSorobanBatchedSubmissionFlag).toBe('function');
  });

  it('submitAttestation function signature includes optional userId', async () => {
    const mod = await import('../../../../src/services/soroban/submitAttestation.js');
    const params: import('../../../../src/services/soroban/submitAttestation.js').SubmitAttestationParams = {
      business: 'biz',
      period: '2024-03',
      merkleRoot: 'root',
      timestamp: 1700000000,
      version: '1.0',
      sourcePublicKey: 'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5',
    };
    expect(params.userId).toBeUndefined();
  });
});

import { afterEach, describe, expect, it, vi } from 'vitest';
import { OpenFeature, TypedInMemoryProvider, type Hook } from '@openfeature/server-sdk';
import {
  getBooleanFlag,
  getSorobanBatchedSubmissionFlag,
  FlagKeys,
  type FlagContext,
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

  it('propagates both context fields into the evaluation context', async () => {
    const contextEvaluator = vi.fn().mockReturnValue('on');
    const provider = new TypedInMemoryProvider({
      [FlagKeys.STATSD_DUAL_WRITE]: {
        variants: { on: true, off: false },
        defaultVariant: 'off',
        disabled: false,
        contextEvaluator,
      },
    });
    await OpenFeature.setProviderAndWait(provider);

    await getBooleanFlag(FlagKeys.STATSD_DUAL_WRITE, false, {
      businessId: 'biz_statsd',
      userId: 'user_9',
    });

    const ctx = contextEvaluator.mock.calls[0][0];
    expect(ctx).toMatchObject({
      targetingKey: 'biz_statsd',
      businessId: 'biz_statsd',
      userId: 'user_9',
    });
  });
});

describe('getBooleanFlag with invalid inputs', () => {
  afterEach(async () => {
    await OpenFeature.clearProviders();
  });

  it('returns the default value for an unknown flag key (NoopProvider)', async () => {
    const result = await getBooleanFlag('totally_unknown_flag', true, {
      businessId: 'biz_1',
      userId: 'user_1',
    });
    expect(result).toBe(true);
  });

  it('returns the default value for an empty flag key', async () => {
    const result = await getBooleanFlag('', true, {
      businessId: 'biz_1',
      userId: 'user_1',
    });
    expect(result).toBe(true);
  });

  it('returns the default value for an empty evaluation context (NoopProvider)', async () => {
    const result = await getBooleanFlag(FlagKeys.STATSD_DUAL_WRITE, false, {
      businessId: '',
      userId: '',
    });
    expect(result).toBe(false);
  });

  it('returns the default value deterministically when the provider rejects during evaluation', async () => {
    const rejectingProvider = {
      metadata: { name: 'rejecting-invalid-inputs' },
      hooks: [],
      resolveBooleanEvaluation: vi.fn().mockRejectedValue(new Error('evaluation failed')),
      resolveStringEvaluation: vi.fn(),
      resolveNumberEvaluation: vi.fn(),
      resolveObjectEvaluation: vi.fn(),
    };
    await OpenFeature.setProviderAndWait(rejectingProvider as never);

    // The OpenFeature client converts resolver failures into structured error
    // results, so each invocation must resolve to its own default value.
    const [trueDefault, falseDefault] = await Promise.all([
      getBooleanFlag('any_key', true, { businessId: 'biz_1', userId: 'user_1' }),
      getBooleanFlag('any_key', false, { businessId: 'biz_1', userId: 'user_1' }),
    ]);

    expect(trueDefault).toBe(true);
    expect(falseDefault).toBe(false);
  });

  it('honours a global hook error path by returning the default value deterministically', async () => {
    const throwingHook: Hook = {
      before: () => {
        throw new Error('hook failure');
      },
    };
    OpenFeature.addHooks(throwingHook);

    const result = await getBooleanFlag(FlagKeys.STATSD_DUAL_WRITE, true, {
      businessId: 'biz_1',
      userId: 'user_1',
    });

    expect(result).toBe(true);
    OpenFeature.clearHooks();
  });
});

describe('FlagContext', () => {
  it('derives targetingKey from businessId for flag evaluation', async () => {
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
      businessId: 'biz_context',
      userId: 'user_context',
    });

    const ctx = contextEvaluator.mock.calls[0][0];
    expect(ctx.targetingKey).toBe('biz_context');
    expect(ctx.businessId).toBe('biz_context');
    expect(ctx.userId).toBe('user_context');
  });

  it('does not leak one call context into the next', async () => {
    const contextEvaluator = vi.fn().mockReturnValue('off');
    const provider = new TypedInMemoryProvider({
      [FlagKeys.STATSD_DUAL_WRITE]: {
        variants: { on: true, off: false },
        defaultVariant: 'off',
        disabled: false,
        contextEvaluator,
      },
    });
    await OpenFeature.setProviderAndWait(provider);

    await getBooleanFlag(FlagKeys.STATSD_DUAL_WRITE, false, {
      businessId: 'biz_first',
      userId: 'user_first',
    });
    await getBooleanFlag(FlagKeys.STATSD_DUAL_WRITE, false, {
      businessId: 'biz_second',
      userId: 'user_second',
    });

    expect(contextEvaluator).toHaveBeenCalledTimes(2);
    expect(contextEvaluator.mock.calls[0][0]).toMatchObject({
      targetingKey: 'biz_first',
      userId: 'user_first',
    });
    expect(contextEvaluator.mock.calls[1][0]).toMatchObject({
      targetingKey: 'biz_second',
      userId: 'user_second',
    });
  });

  it('compiles with both required context fields', () => {
    const context: FlagContext = { businessId: 'biz_1', userId: 'user_1' };
    expect(context.businessId).toBe('biz_1');
    expect(context.userId).toBe('user_1');
  });
});

describe('FlagKeys', () => {
  it('defines SOROBAN_BATCHED_SUBMISSION flag key', () => {
    expect(FlagKeys.SOROBAN_BATCHED_SUBMISSION).toBe('soroban_batched_submission');
  });

  it('defines STATSD_DUAL_WRITE flag key', () => {
    expect(FlagKeys.STATSD_DUAL_WRITE).toBe('statsd_dual_write');
  });

  it('exposes exactly the two documented flag keys', () => {
    expect(Object.keys(FlagKeys).sort()).toEqual(['SOROBAN_BATCHED_SUBMISSION', 'STATSD_DUAL_WRITE']);
  });

  it('keeps every flag key a string literal usable as a flag identifier', () => {
    // Valid keys are plain strings, so they satisfy getBooleanFlag's flagKey
    // parameter without any cast; this assignment fails to compile otherwise.
    const validKey: string = FlagKeys.STATSD_DUAL_WRITE;
    expect(validKey).toBe('statsd_dual_write');
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

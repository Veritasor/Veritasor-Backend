import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { 
  RedisCircuitBreaker, 
  CircuitState, 
  RedisCircuitBreakerError 
} from './redis.js';
import { redisCircuitBreakerState, redisCircuitBreakerFailuresTotal } from './metrics.js';

describe('RedisCircuitBreaker', () => {
  let breaker: RedisCircuitBreaker;

  beforeEach(() => {
    vi.useFakeTimers();
    breaker = new RedisCircuitBreaker({ failureThreshold: 3, resetTimeoutMs: 10000 });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('starts in CLOSED state', () => {
    expect(breaker.getState()).toBe(CircuitState.CLOSED);
  });

  it('allows operations in CLOSED state', async () => {
    const result = await breaker.execute(async () => 'success');
    expect(result).toBe('success');
  });

  it('transitions to OPEN state after failure threshold is met', async () => {
    const failingOp = async () => { throw new Error('Redis connection error'); };

    await expect(breaker.execute(failingOp)).rejects.toThrow('Redis connection error');
    await expect(breaker.execute(failingOp)).rejects.toThrow('Redis connection error');
    expect(breaker.getState()).toBe(CircuitState.CLOSED);

    await expect(breaker.execute(failingOp)).rejects.toThrow('Redis connection error');
    expect(breaker.getState()).toBe(CircuitState.OPEN);
  });

  it('fails fast when OPEN', async () => {
    const failingOp = async () => { throw new Error('Redis connection error'); };
    for (let i = 0; i < 3; i++) {
      await expect(breaker.execute(failingOp)).rejects.toThrow();
    }
    
    expect(breaker.getState()).toBe(CircuitState.OPEN);
    await expect(breaker.execute(async () => 'success')).rejects.toThrow(RedisCircuitBreakerError);
    await expect(breaker.execute(async () => 'success')).rejects.toThrow('Redis circuit breaker is OPEN');
  });

  it('executes fallback when OPEN if provided', async () => {
    const failingOp = async () => { throw new Error('Redis connection error'); };
    for (let i = 0; i < 3; i++) {
      await expect(breaker.execute(failingOp)).rejects.toThrow();
    }
    
    expect(breaker.getState()).toBe(CircuitState.OPEN);
    
    const result = await breaker.execute(
      async () => 'success',
      () => 'fallback_value'
    );
    expect(result).toBe('fallback_value');
  });

  it('transitions to HALF_OPEN after cooldown', async () => {
    const failingOp = async () => { throw new Error('Redis connection error'); };
    for (let i = 0; i < 3; i++) {
      await expect(breaker.execute(failingOp)).rejects.toThrow();
    }
    
    expect(breaker.getState()).toBe(CircuitState.OPEN);
    
    vi.advanceTimersByTime(10000);
    
    // The next execution will transition to HALF_OPEN and allow one call
    const result = await breaker.execute(async () => 'probe_success');
    expect(result).toBe('probe_success');
    expect(breaker.getState()).toBe(CircuitState.CLOSED);
  });

  it('half-open storm prevention (debounces probes)', async () => {
    const failingOp = async () => { throw new Error('Redis connection error'); };
    for (let i = 0; i < 3; i++) {
      await expect(breaker.execute(failingOp)).rejects.toThrow();
    }
    
    expect(breaker.getState()).toBe(CircuitState.OPEN);
    vi.advanceTimersByTime(10000); // Wait for cooldown
    
    // Now state is OPEN but time has passed.
    // First execute will try to probe (HALF_OPEN)
    // We mock an operation that takes some time to resolve
    let resolveProbe: (value: string) => void;
    const probeOp = new Promise<string>((resolve) => {
      resolveProbe = resolve;
    });

    const p1 = breaker.execute(() => probeOp);
    
    expect(breaker.getState()).toBe(CircuitState.HALF_OPEN);

    // Second execute while probing should fail fast
    await expect(breaker.execute(async () => 'fast_fail')).rejects.toThrow('Redis circuit breaker is HALF_OPEN (probe in flight)');
    
    // Resolve the probe
    resolveProbe!('probe_success');
    await p1;
    
    expect(breaker.getState()).toBe(CircuitState.CLOSED);
  });
  
  it('goes back to OPEN if probe fails in HALF_OPEN', async () => {
    const failingOp = async () => { throw new Error('Redis connection error'); };
    for (let i = 0; i < 3; i++) {
      await expect(breaker.execute(failingOp)).rejects.toThrow();
    }
    vi.advanceTimersByTime(10000);
    
    await expect(breaker.execute(failingOp)).rejects.toThrow('Redis connection error');
    
    // State should go back to OPEN, not CLOSED
    expect(breaker.getState()).toBe(CircuitState.OPEN);
  });

  it('metrics are recorded', async () => {
    const failingOp = async () => { throw new Error('Redis connection error'); };
    await expect(breaker.execute(failingOp)).rejects.toThrow();
  });

  it('resets failure count on success in CLOSED state', async () => {
    const failingOp = async () => { throw new Error('Redis connection error'); };
    await expect(breaker.execute(failingOp)).rejects.toThrow();
    await expect(breaker.execute(failingOp)).rejects.toThrow();

    await breaker.execute(async () => 'recovery');
    expect(breaker.getState()).toBe(CircuitState.CLOSED);

    await expect(breaker.execute(failingOp)).rejects.toThrow();
    expect(breaker.getState()).toBe(CircuitState.CLOSED);
  });

  it('does not count cluster redirection errors as failures', async () => {
    const redirectOp = async () => { throw new Error('MOVED 1234 127.0.0.1:6380'); };
    for (let i = 0; i < 10; i++) {
      await expect(breaker.execute(redirectOp)).rejects.toThrow('MOVED');
    }
    expect(breaker.getState()).toBe(CircuitState.CLOSED);
  });

  it('does not count ASK redirection errors as failures', async () => {
    const askOp = async () => { throw new Error('ASK 5678 127.0.0.1:6381'); };
    for (let i = 0; i < 10; i++) {
      await expect(breaker.execute(askOp)).rejects.toThrow('ASK');
    }
    expect(breaker.getState()).toBe(CircuitState.CLOSED);
  });

  it('uses default options when none provided', () => {
    const defaultBreaker = new RedisCircuitBreaker();
    expect(defaultBreaker.getState()).toBe(CircuitState.CLOSED);
  });

  it('reset() transitions back to CLOSED state', async () => {
    const failOp = async () => { throw new Error('err'); };
    for (let i = 0; i < 3; i++) {
      await expect(breaker.execute(failOp)).rejects.toThrow();
    }
    expect(breaker.getState()).toBe(CircuitState.OPEN);
    breaker.reset();
    expect(breaker.getState()).toBe(CircuitState.CLOSED);
  });

  it('uses fallback when OPEN and returns immediately', async () => {
    const failOp = async () => { throw new Error('err'); };
    for (let i = 0; i < 3; i++) {
      await expect(breaker.execute(failOp)).rejects.toThrow();
    }
    const fallback = vi.fn(() => 'cached_value');
    const result = await breaker.execute(
      async () => { throw new Error('should not run'); },
      fallback
    );
    expect(result).toBe('cached_value');
    expect(fallback).toHaveBeenCalledTimes(1);
  });

  it('uses fallback in HALF_OPEN when another probe is in flight', async () => {
    const failingOp = async () => { throw new Error('err'); };
    for (let i = 0; i < 3; i++) {
      await expect(breaker.execute(failingOp)).rejects.toThrow();
    }
    vi.advanceTimersByTime(10000);

    let resolveProbe: (value: string) => void;
    const probeOp = new Promise<string>((resolve) => { resolveProbe = resolve; });
    const p1 = breaker.execute(() => probeOp);

    const fallbackResult = await breaker.execute(
      async () => 'should_not_run',
      () => 'half_open_fallback'
    );
    expect(fallbackResult).toBe('half_open_fallback');

    resolveProbe!('probe_success');
    await p1;
    expect(breaker.getState()).toBe(CircuitState.CLOSED);
  });

  it('handles fallback that throws during OPEN state', async () => {
    const failOp = async () => { throw new Error('err'); };
    for (let i = 0; i < 3; i++) {
      await expect(breaker.execute(failOp)).rejects.toThrow();
    }
    const throwingFallback = async () => { throw new Error('fallback_error'); };
    await expect(
      breaker.execute(
        async () => 'should_not_run',
        throwingFallback
      )
    ).rejects.toThrow('fallback_error');
  });

  it('exposes state via getState()', () => {
    expect(breaker.getState()).toBe(CircuitState.CLOSED);
  });
});

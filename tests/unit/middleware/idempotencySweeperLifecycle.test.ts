import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as idempotencyModule from '../../src/middleware/idempotency.js';
import {
  startIdempotencySweeperIfNeeded,
  stopIdempotencySweeper,
} from '../../src/middleware/idempotency.js';
import { stopIdempotencySweeper as stopFromApp } from '../../src/app.js';

describe('idempotency sweeper lifecycle (startIdempotencySweeperIfNeeded / stopIdempotencySweeper)', () => {
  const originalEnv = process.env.NODE_ENV;

  beforeEach(async () => {
    // Ensure clean state before each test
    await stopIdempotencySweeper();
    vi.clearAllMocks();
  });

  afterEach(async () => {
    process.env.NODE_ENV = originalEnv;
    await stopIdempotencySweeper();
  });

  it('skips starting the sweeper when NODE_ENV === "test"', async () => {
    process.env.NODE_ENV = 'test';
    const spy = vi.spyOn(idempotencyModule, 'startIdempotencySweeper');

    const handle = await startIdempotencySweeperIfNeeded();

    expect(handle).toBeNull();
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('calling startIdempotencySweeperIfNeeded() twice creates exactly one sweeper', async () => {
    process.env.NODE_ENV = 'production';
    const spy = vi.spyOn(idempotencyModule, 'startIdempotencySweeper');

    const handle1 = await startIdempotencySweeperIfNeeded();
    const handle2 = await startIdempotencySweeperIfNeeded();

    expect(spy).toHaveBeenCalledTimes(1);
    expect(handle1).not.toBeNull();
    expect(handle2).toBe(handle1);

    spy.mockRestore();
  });

  it('stopIdempotencySweeper() stops the active sweeper and is idempotent', async () => {
    process.env.NODE_ENV = 'production';

    const handle = await startIdempotencySweeperIfNeeded();
    expect(handle).not.toBeNull();

    const stopSpy = vi.spyOn(handle!, 'stop');

    // First stop call
    await stopIdempotencySweeper();
    expect(stopSpy).toHaveBeenCalledTimes(1);

    // Second stop call (should be a no-op, not throw or call stop again)
    await expect(stopIdempotencySweeper()).resolves.toBeUndefined();
    expect(stopSpy).toHaveBeenCalledTimes(1);
  });

  it('stopIdempotencySweeper is correctly re-exported by src/app.js', async () => {
    process.env.NODE_ENV = 'production';

    await startIdempotencySweeperIfNeeded();
    // Call the re-exported function from app.js
    await expect(stopFromApp()).resolves.toBeUndefined();
    // Idempotent second call
    await expect(stopFromApp()).resolves.toBeUndefined();
  });
});

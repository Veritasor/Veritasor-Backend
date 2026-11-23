import { rpc } from "@stellar/stellar-sdk";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { config } from "../../../config/index.js";
import {
  CircuitBreaker,
  CircuitBreakerState,
  createSorobanRpcServer,
  executeSorobanRequest,
  getSorobanCircuitBreaker,
  SorobanCircuitBreakerError,
} from "../client.js";
import { sorobanRetryBudget } from "../retry-budget.js";

const testPolicy = {
  timeoutMs: 100,
  maxRetries: 0,
  retryBaseDelayMs: 1,
  retryMaxDelayMs: 1,
  circuitBreakerThreshold: 2,
  circuitBreakerResetMs: 1_000,
};

describe("Soroban RPC circuit breaker", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    sorobanRetryBudget.reset();
  });

  afterEach(() => {
    sorobanRetryBudget.reset();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("shares failure state across server instances for the same RPC URL", async () => {
    const getAccount = vi
      .spyOn(rpc.Server.prototype, "getAccount")
      .mockRejectedValue(new Error("fetch failed"));
    const rpcUrl = "https://soroban-shared-breaker.test";
    const first = createSorobanRpcServer(rpcUrl, testPolicy);
    const second = createSorobanRpcServer(rpcUrl, testPolicy);

    await expect(first.getAccount("account")).rejects.toThrow("fetch failed");
    await expect(second.getAccount("account")).rejects.toThrow("fetch failed");
    await expect(first.getAccount("account")).rejects.toBeInstanceOf(
      SorobanCircuitBreakerError,
    );

    expect(getAccount).toHaveBeenCalledTimes(2);
  });

  it("keeps breakers independent for different RPC URLs", async () => {
    const getAccount = vi
      .spyOn(rpc.Server.prototype, "getAccount")
      .mockRejectedValue(new Error("fetch failed"));
    const first = createSorobanRpcServer(
      "https://soroban-primary-breaker.test",
      { ...testPolicy, circuitBreakerThreshold: 1 },
    );
    const second = createSorobanRpcServer(
      "https://soroban-backup-breaker.test",
      { ...testPolicy, circuitBreakerThreshold: 1 },
    );

    await expect(first.getAccount("account")).rejects.toThrow("fetch failed");
    await expect(second.getAccount("account")).rejects.toThrow("fetch failed");
    await expect(first.getAccount("account")).rejects.toBeInstanceOf(
      SorobanCircuitBreakerError,
    );
    await expect(second.getAccount("account")).rejects.toBeInstanceOf(
      SorobanCircuitBreakerError,
    );

    expect(getAccount).toHaveBeenCalledTimes(2);
  });

  it("closes after a successful HALF_OPEN probe", async () => {
    const circuitBreaker = getSorobanCircuitBreaker(
      "https://soroban-half-open-breaker.test",
      { ...testPolicy, circuitBreakerThreshold: 1 },
    );
    circuitBreaker.recordFailure();
    vi.advanceTimersByTime(testPolicy.circuitBreakerResetMs);

    await expect(
      executeSorobanRequest({
        operationName: "getAccount",
        execute: async () => "probe succeeded",
        policy: testPolicy,
        circuitBreaker,
      }),
    ).resolves.toBe("probe succeeded");

    expect(circuitBreaker.getState()).toBe(CircuitBreakerState.CLOSED);
  });

  it("records a failure when the retry budget is exhausted", async () => {
    for (let retry = 0; retry < config.soroban.retryBudgetMaxRetries; retry += 1) {
      sorobanRetryBudget.recordRetry("test");
    }
    const circuitBreaker = new CircuitBreaker(1, testPolicy.circuitBreakerResetMs);

    await expect(
      executeSorobanRequest({
        operationName: "getAccount",
        execute: async () => {
          throw new Error("fetch failed");
        },
        policy: { ...testPolicy, maxRetries: 1 },
        circuitBreaker,
      }),
    ).rejects.toThrow("retry budget exhausted");

    expect(circuitBreaker.getState()).toBe(CircuitBreakerState.OPEN);
  });
});

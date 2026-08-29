/**
 * @file client.test.ts
 * @description Comprehensive unit tests for Soroban RPC client with exponential backoff retries
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  executeSorobanRequest,
  getSorobanRetryPolicy,
  isRetryableSorobanError,
  CircuitBreakerState,
  CircuitBreaker,
  SorobanRpcTimeoutError,
  SorobanCircuitBreakerError,
} from "../../../../src/services/soroban/client.js";
import {
  SorobanRetryBudgetExceededError,
  sorobanRetryBudget,
} from "../../../../src/services/soroban/retry-budget.js";
import { metricsRegistry } from "../../../../src/metrics.js";

beforeEach(async () => {
  await metricsRegistry.resetMetrics();
  sorobanRetryBudget.reset();
  vi.useRealTimers();
  vi.clearAllMocks();
});

describe("executeSorobanRequest — exponential backoff retries", () => {
  describe("basic success", () => {
    it("executes successfully on first attempt without retries", async () => {
      const execute = vi.fn().mockResolvedValue({ status: "ok" });

      const result = await executeSorobanRequest({
        operationName: "getAccount",
        execute,
      });

      expect(result).toEqual({ status: "ok" });
      expect(execute).toHaveBeenCalledTimes(1);
    });

    it("returns result from first successful attempt", async () => {
      const expectedResult = { id: "123", balance: "1000" };
      const execute = vi.fn().mockResolvedValue(expectedResult);

      const result = await executeSorobanRequest({
        operationName: "prepareTransaction",
        execute,
      });

      expect(result).toEqual(expectedResult);
    });
  });

  describe("exponential backoff on retryable errors", () => {
    it("retries on transient network error", async () => {
      const execute = vi
        .fn()
        .mockRejectedValueOnce(new Error("ECONNREFUSED"))
        .mockResolvedValue({ status: "ok" });

      const delays: number[] = [];
      const mockSleep = vi.fn((delayMs: number) => {
        delays.push(delayMs);
        return Promise.resolve();
      });

      const result = await executeSorobanRequest({
        operationName: "getAccount",
        execute,
        policy: {
          maxRetries: 3,
          retryBaseDelayMs: 100,
          retryMaxDelayMs: 5000,
          timeoutMs: 5000,
          retryJitterRatio: 0.2,
          circuitBreakerThreshold: 5,
          circuitBreakerResetMs: 30_000,
        },
        sleep: mockSleep,
        random: () => 0.5,
      });

      expect(result).toEqual({ status: "ok" });
      expect(execute).toHaveBeenCalledTimes(2);
      expect(delays).toHaveLength(1);
      // fullJitter(0, 100, 5000, 0.5) = floor(0.5 * 100) = 50
      expect(delays[0]).toBe(50);
    });

    it("retries multiple times with increasing delays", async () => {
      const execute = vi
        .fn()
        .mockRejectedValueOnce(new Error("ETIMEDOUT"))
        .mockRejectedValueOnce(new Error("ECONNRESET"))
        .mockResolvedValue({ status: "ok" });

      const delays: number[] = [];
      const mockSleep = vi.fn((delayMs: number) => {
        delays.push(delayMs);
        return Promise.resolve();
      });

      await executeSorobanRequest({
        operationName: "sendTransaction",
        execute,
        policy: {
          maxRetries: 5,
          retryBaseDelayMs: 100,
          retryMaxDelayMs: 2000,
          timeoutMs: 5000,
          retryJitterRatio: 0.2,
          circuitBreakerThreshold: 5,
          circuitBreakerResetMs: 30_000,
        },
        sleep: mockSleep,
        random: () => 0.8,
      });

      expect(execute).toHaveBeenCalledTimes(3);
      expect(delays).toHaveLength(2);
      // First retry: fullJitter(0, 100, 2000, 0.8) = floor(0.8 * 100) = 80
      expect(delays[0]).toBe(80);
      // Second retry: fullJitter(1, 100, 2000, 0.8) = floor(0.8 * 200) = 160
      expect(delays[1]).toBe(160);
      expect(delays[1]).toBeGreaterThan(delays[0]);
    });

    it("caps retry delays at retryMaxDelayMs", async () => {
      const execute = vi
        .fn()
        .mockRejectedValueOnce(new Error("network timeout"))
        .mockResolvedValue({ status: "ok" });

      const delays: number[] = [];
      const mockSleep = vi.fn((delayMs: number) => {
        delays.push(delayMs);
        return Promise.resolve();
      });

      await executeSorobanRequest({
        operationName: "test",
        execute,
        policy: {
          maxRetries: 10,
          retryBaseDelayMs: 100,
          retryMaxDelayMs: 500,
          timeoutMs: 5000,
          retryJitterRatio: 0.2,
          circuitBreakerThreshold: 5,
          circuitBreakerResetMs: 30_000,
        },
        sleep: mockSleep,
        random: () => 0.9999,
      });

      expect(delays).toHaveLength(1);
      expect(delays[0]).toBeLessThanOrEqual(500);
    });

    it("fails fast after maxRetries exhausted", async () => {
      const execute = vi
        .fn()
        .mockRejectedValue(new Error("ECONNREFUSED persistent"));

      const mockSleep = vi.fn().mockResolvedValue(undefined);

      await expect(
        executeSorobanRequest({
          operationName: "getAccount",
          execute,
          policy: {
            maxRetries: 2,
            retryBaseDelayMs: 10,
            retryMaxDelayMs: 100,
            timeoutMs: 5000,
            retryJitterRatio: 0.2,
            circuitBreakerThreshold: 5,
            circuitBreakerResetMs: 30_000,
          },
          sleep: mockSleep,
        }),
      ).rejects.toThrow("ECONNREFUSED persistent");

      // 1 initial + 2 retries = 3 total attempts
      expect(execute).toHaveBeenCalledTimes(3);
      expect(mockSleep).toHaveBeenCalledTimes(2);
    });
  });

  describe("non-retryable errors", () => {
    it("fails immediately on validation error", async () => {
      const execute = vi
        .fn()
        .mockRejectedValue(new Error("Invalid contract ID"));

      const mockSleep = vi.fn();

      await expect(
        executeSorobanRequest({
          operationName: "prepareTransaction",
          execute,
          policy: {
            maxRetries: 5,
            retryBaseDelayMs: 100,
            retryMaxDelayMs: 1000,
            timeoutMs: 5000,
            retryJitterRatio: 0.2,
            circuitBreakerThreshold: 5,
            circuitBreakerResetMs: 30_000,
          },
          sleep: mockSleep,
        }),
      ).rejects.toThrow("Invalid contract ID");

      expect(execute).toHaveBeenCalledTimes(1);
      expect(mockSleep).not.toHaveBeenCalled();
    });

    it("fails immediately on unauthorized error", async () => {
      const execute = vi
        .fn()
        .mockRejectedValue(new Error("Unauthorized: invalid signature"));

      const mockSleep = vi.fn();

      await expect(
        executeSorobanRequest({
          operationName: "sendTransaction",
          execute,
          policy: {
            maxRetries: 5,
            retryBaseDelayMs: 100,
            retryMaxDelayMs: 1000,
            timeoutMs: 5000,
            retryJitterRatio: 0.2,
            circuitBreakerThreshold: 5,
            circuitBreakerResetMs: 30_000,
          },
          sleep: mockSleep,
        }),
      ).rejects.toThrow("Unauthorized");

      expect(execute).toHaveBeenCalledTimes(1);
      expect(mockSleep).not.toHaveBeenCalled();
    });
  });

  describe("retryable error classification", () => {
    it("classifies SorobanRpcTimeoutError as retryable", () => {
      const error = new SorobanRpcTimeoutError(
        "Operation timed out",
        5000,
        "getAccount",
      );
      expect(isRetryableSorobanError(error)).toBe(true);
    });

    it("classifies AbortError as retryable", () => {
      const error = new Error("The operation was aborted");
      (error as NodeJS.ErrnoException).name = "AbortError";
      expect(isRetryableSorobanError(error)).toBe(true);
    });

    it("classifies network errno codes as retryable", () => {
      const codes = [
        "ECONNRESET",
        "ECONNREFUSED",
        "EHOSTUNREACH",
        "ETIMEDOUT",
        "ENOTFOUND",
      ];
      codes.forEach((code) => {
        const error = new Error("Network error");
        (error as NodeJS.ErrnoException).code = code;
        expect(isRetryableSorobanError(error)).toBe(true);
      });
    });

    it("classifies timeout in message as retryable", () => {
      expect(isRetryableSorobanError(new Error("Request timeout"))).toBe(true);
      expect(isRetryableSorobanError(new Error("timed out waiting"))).toBe(
        true,
      );
      expect(isRetryableSorobanError(new Error("connection timeout"))).toBe(
        true,
      );
    });

    it("classifies rate limit (429) as retryable", () => {
      expect(isRetryableSorobanError(new Error("429 too many requests"))).toBe(
        true,
      );
      expect(isRetryableSorobanError(new Error("rate limit exceeded"))).toBe(
        true,
      );
    });

    it("classifies 503/504 server errors as retryable", () => {
      expect(isRetryableSorobanError(new Error("503 Service Unavailable"))).toBe(
        true,
      );
      expect(isRetryableSorobanError(new Error("504 Gateway Timeout"))).toBe(
        true,
      );
    });

    it("classifies DNS errors as retryable", () => {
      expect(isRetryableSorobanError(new Error("DNS resolution failed"))).toBe(
        true,
      );
      expect(isRetryableSorobanError(new Error("ENOTFOUND"))).toBe(true);
      const err = new Error("name resolution error");
      (err as NodeJS.ErrnoException).code = "EAI_AGAIN";
      expect(isRetryableSorobanError(err)).toBe(true);
    });

    it("classifies undici errors as retryable", () => {
      expect(isRetryableSorobanError(new Error("undici connection error"))).toBe(
        true,
      );
      const err = new Error("network failed");
      (err as NodeJS.ErrnoException).code = "UND_ERR_SOCKET";
      expect(isRetryableSorobanError(err)).toBe(true);
    });

    it("classifies non-Error objects as non-retryable", () => {
      expect(isRetryableSorobanError("string error")).toBe(false);
      expect(isRetryableSorobanError(null)).toBe(false);
      expect(isRetryableSorobanError(undefined)).toBe(false);
      expect(isRetryableSorobanError({})).toBe(false);
    });

    it("classifies contract errors as non-retryable", () => {
      expect(isRetryableSorobanError(new Error("ContractError: validation"))).toBe(
        false,
      );
    });
  });

  describe("retry budget integration", () => {
    it("respects retry budget when exceeded", async () => {
      sorobanRetryBudget.reset();
      for (let i = 0; i < 20; i++) {
        sorobanRetryBudget.recordRetry("test");
      }

      const execute = vi
        .fn()
        .mockRejectedValue(new Error("ECONNREFUSED"));

      await expect(
        executeSorobanRequest({
          operationName: "getAccount",
          execute,
          policy: {
            maxRetries: 5,
            retryBaseDelayMs: 1,
            retryMaxDelayMs: 10,
            timeoutMs: 100,
            retryJitterRatio: 0.2,
            circuitBreakerThreshold: 5,
            circuitBreakerResetMs: 30_000,
          },
          sleep: async () => undefined,
        }),
      ).rejects.toThrow(SorobanRetryBudgetExceededError);

      expect(execute).toHaveBeenCalledTimes(1);
    });

    it("increments retry budget on each retry", async () => {
      sorobanRetryBudget.reset();

      const execute = vi
        .fn()
        .mockRejectedValueOnce(new Error("timeout"))
        .mockResolvedValue({ ok: true });

      await executeSorobanRequest({
        operationName: "sendTransaction",
        execute,
        policy: {
          maxRetries: 3,
          retryBaseDelayMs: 1,
          retryMaxDelayMs: 10,
          timeoutMs: 100,
          retryJitterRatio: 0.2,
          circuitBreakerThreshold: 5,
          circuitBreakerResetMs: 30_000,
        },
        sleep: async () => undefined,
      });

      expect(sorobanRetryBudget.getRetryCount()).toBe(1);
    });
  });

  describe("circuit breaker", () => {
    it("prevents requests when circuit is open", async () => {
      const circuitBreaker = new CircuitBreaker(2, 30_000);

      // Record 2 failures to open the circuit
      circuitBreaker.recordFailure();
      circuitBreaker.recordFailure();
      expect(circuitBreaker.getState()).toBe(CircuitBreakerState.OPEN);

      const execute = vi.fn();

      await expect(
        executeSorobanRequest({
          operationName: "test",
          execute,
          circuitBreaker,
        }),
      ).rejects.toThrow(SorobanCircuitBreakerError);

      expect(execute).not.toHaveBeenCalled();
    });

    it("allows requests when circuit is closed", async () => {
      const circuitBreaker = new CircuitBreaker(5, 30_000);
      expect(circuitBreaker.getState()).toBe(CircuitBreakerState.CLOSED);

      const execute = vi.fn().mockResolvedValue({ status: "ok" });

      const result = await executeSorobanRequest({
        operationName: "test",
        execute,
        circuitBreaker,
      });

      expect(result).toEqual({ status: "ok" });
      expect(execute).toHaveBeenCalled();
    });

    it("closes circuit after successful operation from half-open state", async () => {
      vi.useFakeTimers();
      const circuitBreaker = new CircuitBreaker(1, 1000);

      // Open the circuit
      circuitBreaker.recordFailure();
      expect(circuitBreaker.getState()).toBe(CircuitBreakerState.OPEN);

      // Advance time to allow half-open transition
      vi.advanceTimersByTime(1100);

      const execute = vi.fn().mockResolvedValue({ status: "ok" });

      const result = await executeSorobanRequest({
        operationName: "test",
        execute,
        circuitBreaker,
      });

      expect(result).toEqual({ status: "ok" });
      // Circuit should be closed after successful attempt from half-open
      expect(circuitBreaker.getState()).toBe(CircuitBreakerState.CLOSED);
    });
  });

  describe("timeout enforcement", () => {
    it("times out after configured timeout ms", async () => {
      vi.useFakeTimers();

      const execute = vi.fn(() => {
        return new Promise(() => {
          // Never resolves
        });
      });

      const promise = executeSorobanRequest({
        operationName: "longOp",
        execute,
        policy: {
          maxRetries: 0,
          retryBaseDelayMs: 100,
          retryMaxDelayMs: 1000,
          timeoutMs: 5000,
          retryJitterRatio: 0.2,
          circuitBreakerThreshold: 5,
          circuitBreakerResetMs: 30_000,
        },
      });

      vi.advanceTimersByTime(5100);

      await expect(promise).rejects.toThrow(SorobanRpcTimeoutError);
      expect(execute).toHaveBeenCalled();
    });

    it("retries after timeout if error is retryable", async () => {
      vi.useFakeTimers();

      let callCount = 0;
      const execute = vi.fn(() => {
        callCount++;
        if (callCount === 1) {
          // First call times out
          return new Promise(() => {});
        }
        // Second call succeeds
        return Promise.resolve({ status: "ok" });
      });

      const delays: number[] = [];
      const mockSleep = vi.fn((delayMs: number) => {
        delays.push(delayMs);
        vi.advanceTimersByTime(delayMs);
        return Promise.resolve();
      });

      const promise = executeSorobanRequest({
        operationName: "test",
        execute,
        policy: {
          maxRetries: 2,
          retryBaseDelayMs: 100,
          retryMaxDelayMs: 1000,
          timeoutMs: 100,
          retryJitterRatio: 0.2,
          circuitBreakerThreshold: 5,
          circuitBreakerResetMs: 30_000,
        },
        sleep: mockSleep,
        random: () => 0.5,
      });

      vi.advanceTimersByTime(200);

      const result = await promise;
      expect(result).toEqual({ status: "ok" });
      expect(execute).toHaveBeenCalledTimes(2);
      expect(mockSleep).toHaveBeenCalled();
    });
  });

  describe("observability hooks", () => {
    it("calls onRequestStart before attempt", async () => {
      const onRequestStart = vi.fn();
      const execute = vi.fn().mockResolvedValue({ status: "ok" });

      await executeSorobanRequest({
        operationName: "test",
        execute,
        observabilityHooks: { onRequestStart },
      });

      expect(onRequestStart).toHaveBeenCalledWith("test", 1);
    });

    it("calls onRequestSuccess after successful attempt", async () => {
      const onRequestSuccess = vi.fn();
      const execute = vi.fn().mockResolvedValue({ status: "ok" });

      await executeSorobanRequest({
        operationName: "getAccount",
        execute,
        observabilityHooks: { onRequestSuccess },
      });

      expect(onRequestSuccess).toHaveBeenCalledWith(
        "getAccount",
        1,
        expect.any(Number),
      );
    });

    it("calls onRequestFailure after failed attempt", async () => {
      const onRequestFailure = vi.fn();
      const execute = vi.fn().mockRejectedValue(new Error("test error"));

      await expect(
        executeSorobanRequest({
          operationName: "test",
          execute,
          policy: { maxRetries: 0 } as any,
          observabilityHooks: { onRequestFailure },
        }),
      ).rejects.toThrow("test error");

      expect(onRequestFailure).toHaveBeenCalledWith(
        "test",
        1,
        expect.any(Number),
        expect.any(Error),
      );
    });

    it("calls onRetry when retrying after error", async () => {
      const onRetry = vi.fn();
      const execute = vi
        .fn()
        .mockRejectedValueOnce(new Error("timeout"))
        .mockResolvedValue({ status: "ok" });

      await executeSorobanRequest({
        operationName: "test",
        execute,
        policy: {
          maxRetries: 2,
          retryBaseDelayMs: 100,
          retryMaxDelayMs: 1000,
          timeoutMs: 5000,
          retryJitterRatio: 0.2,
          circuitBreakerThreshold: 5,
          circuitBreakerResetMs: 30_000,
        },
        sleep: async () => undefined,
        random: () => 0.5,
        observabilityHooks: { onRetry },
      });

      expect(onRetry).toHaveBeenCalledWith(
        "test",
        1,
        expect.any(Number),
        expect.any(Error),
      );
    });

    it("calls onCircuitBreakerStateChange on state transition", async () => {
      const onCircuitBreakerStateChange = vi.fn();
      const circuitBreaker = new CircuitBreaker(
        1,
        30_000,
        onCircuitBreakerStateChange,
      );

      // Trigger state change
      circuitBreaker.recordFailure();

      expect(onCircuitBreakerStateChange).toHaveBeenCalledWith(
        CircuitBreakerState.CLOSED,
        CircuitBreakerState.OPEN,
      );
    });
  });

  describe("shouldRetryResult callback", () => {
    it("retries when shouldRetryResult returns true", async () => {
      const execute = vi
        .fn()
        .mockResolvedValueOnce({ status: "TRY_AGAIN_LATER" })
        .mockResolvedValue({ status: "SUCCESS" });

      const mockSleep = vi.fn().mockResolvedValue(undefined);

      const result = await executeSorobanRequest({
        operationName: "sendTransaction",
        execute,
        shouldRetryResult: (result: any) =>
          result.status === "TRY_AGAIN_LATER",
        policy: {
          maxRetries: 3,
          retryBaseDelayMs: 10,
          retryMaxDelayMs: 100,
          timeoutMs: 5000,
          retryJitterRatio: 0.2,
          circuitBreakerThreshold: 5,
          circuitBreakerResetMs: 30_000,
        },
        sleep: mockSleep,
      });

      expect(result).toEqual({ status: "SUCCESS" });
      expect(execute).toHaveBeenCalledTimes(2);
      expect(mockSleep).toHaveBeenCalled();
    });

    it("stops retrying when shouldRetryResult returns false", async () => {
      const execute = vi
        .fn()
        .mockResolvedValue({ status: "TRY_AGAIN_LATER" });

      const mockSleep = vi.fn();

      const result = await executeSorobanRequest({
        operationName: "test",
        execute,
        shouldRetryResult: () => false,
        policy: {
          maxRetries: 5,
          retryBaseDelayMs: 10,
          retryMaxDelayMs: 100,
          timeoutMs: 5000,
          retryJitterRatio: 0.2,
          circuitBreakerThreshold: 5,
          circuitBreakerResetMs: 30_000,
        },
        sleep: mockSleep,
      });

      expect(result).toEqual({ status: "TRY_AGAIN_LATER" });
      expect(execute).toHaveBeenCalledTimes(1);
      expect(mockSleep).not.toHaveBeenCalled();
    });
  });

  describe("policy configuration", () => {
    it("uses default policy when no overrides provided", async () => {
      const execute = vi.fn().mockResolvedValue({ ok: true });

      await executeSorobanRequest({
        operationName: "test",
        execute,
      });

      expect(execute).toHaveBeenCalled();
    });

    it("applies policy overrides", async () => {
      const execute = vi
        .fn()
        .mockRejectedValueOnce(new Error("timeout"))
        .mockResolvedValue({ ok: true });

      const mockSleep = vi.fn().mockResolvedValue(undefined);

      await executeSorobanRequest({
        operationName: "test",
        execute,
        policy: {
          maxRetries: 1,
          retryBaseDelayMs: 50,
          retryMaxDelayMs: 500,
        },
        sleep: mockSleep,
        random: () => 0.5,
      });

      expect(mockSleep).toHaveBeenCalledWith(
        expect.any(Number),
      );
      const calledDelay = (mockSleep.mock.calls[0] as any)[0];
      expect(calledDelay).toBeLessThanOrEqual(500);
      expect(calledDelay).toBeGreaterThanOrEqual(0);
    });

    it("validates retry policy bounds", () => {
      expect(() => getSorobanRetryPolicy({ maxRetries: -1 })).toThrow();
      expect(() =>
        getSorobanRetryPolicy({ retryBaseDelayMs: 0 }),
      ).toThrow();
      expect(() =>
        getSorobanRetryPolicy({ retryMaxDelayMs: 0 }),
      ).toThrow();
    });

    it("throws when baseDelayMs > maxDelayMs", () => {
      expect(() =>
        getSorobanRetryPolicy({
          retryBaseDelayMs: 5000,
          retryMaxDelayMs: 1000,
        }),
      ).toThrow(/must be less than or equal to/);
    });
  });

  describe("injectable sleep function", () => {
    it("uses injected sleep function for delays", async () => {
      const execute = vi
        .fn()
        .mockRejectedValueOnce(new Error("timeout"))
        .mockResolvedValue({ ok: true });

      const mockSleep = vi.fn().mockResolvedValue(undefined);

      await executeSorobanRequest({
        operationName: "test",
        execute,
        policy: { maxRetries: 1 },
        sleep: mockSleep,
      });

      expect(mockSleep).toHaveBeenCalledWith(expect.any(Number));
    });

    it("uses default sleep when not provided", async () => {
      vi.useFakeTimers();

      const execute = vi
        .fn()
        .mockRejectedValueOnce(new Error("timeout"))
        .mockResolvedValue({ ok: true });

      const promise = executeSorobanRequest({
        operationName: "test",
        execute,
        policy: {
          maxRetries: 1,
          retryBaseDelayMs: 100,
          retryMaxDelayMs: 1000,
          timeoutMs: 5000,
          retryJitterRatio: 0.2,
          circuitBreakerThreshold: 5,
          circuitBreakerResetMs: 30_000,
        },
        random: () => 0.5,
      });

      // Advance past the timeout
      vi.advanceTimersByTime(200);

      const result = await promise;
      expect(result).toEqual({ ok: true });
    });
  });

  describe("injectable random function", () => {
    it("uses injected random for deterministic delays", async () => {
      const execute = vi
        .fn()
        .mockRejectedValueOnce(new Error("timeout"))
        .mockResolvedValue({ ok: true });

      const delays: number[] = [];
      const mockSleep = vi.fn((delayMs: number) => {
        delays.push(delayMs);
        return Promise.resolve();
      });

      const mockRandom = vi.fn(() => 0.25);

      await executeSorobanRequest({
        operationName: "test",
        execute,
        policy: {
          maxRetries: 2,
          retryBaseDelayMs: 200,
          retryMaxDelayMs: 2000,
          timeoutMs: 5000,
          retryJitterRatio: 0.2,
          circuitBreakerThreshold: 5,
          circuitBreakerResetMs: 30_000,
        },
        sleep: mockSleep,
        random: mockRandom,
      });

      expect(mockRandom).toHaveBeenCalled();
      expect(delays).toHaveLength(1);
      // fullJitter(0, 200, 2000, 0.25) = floor(0.25 * 200) = 50
      expect(delays[0]).toBe(50);
    });

    it("uses Math.random by default", async () => {
      const execute = vi.fn().mockResolvedValue({ ok: true });

      await executeSorobanRequest({
        operationName: "test",
        execute,
      });

      expect(execute).toHaveBeenCalled();
    });
  });

  describe("edge cases", () => {
    it("handles maxRetries=0 (no retries)", async () => {
      const execute = vi
        .fn()
        .mockRejectedValue(new Error("ECONNREFUSED"));

      await expect(
        executeSorobanRequest({
          operationName: "test",
          execute,
          policy: {
            maxRetries: 0,
            retryBaseDelayMs: 100,
            retryMaxDelayMs: 1000,
            timeoutMs: 5000,
            retryJitterRatio: 0.2,
            circuitBreakerThreshold: 5,
            circuitBreakerResetMs: 30_000,
          },
        }),
      ).rejects.toThrow("ECONNREFUSED");

      expect(execute).toHaveBeenCalledTimes(1);
    });

    it("handles very small delays", async () => {
      const execute = vi
        .fn()
        .mockRejectedValueOnce(new Error("timeout"))
        .mockResolvedValue({ ok: true });

      const mockSleep = vi.fn().mockResolvedValue(undefined);

      await executeSorobanRequest({
        operationName: "test",
        execute,
        policy: {
          maxRetries: 1,
          retryBaseDelayMs: 1,
          retryMaxDelayMs: 10,
          timeoutMs: 5000,
          retryJitterRatio: 0.2,
          circuitBreakerThreshold: 5,
          circuitBreakerResetMs: 30_000,
        },
        sleep: mockSleep,
        random: () => 0.1,
      });

      expect(mockSleep).toHaveBeenCalledWith(expect.any(Number));
    });

    it("handles very large delays", async () => {
      const execute = vi
        .fn()
        .mockRejectedValueOnce(new Error("timeout"))
        .mockResolvedValue({ ok: true });

      const mockSleep = vi.fn().mockResolvedValue(undefined);

      await executeSorobanRequest({
        operationName: "test",
        execute,
        policy: {
          maxRetries: 1,
          retryBaseDelayMs: 10000,
          retryMaxDelayMs: 60000,
          timeoutMs: 120_000,
          retryJitterRatio: 0.2,
          circuitBreakerThreshold: 5,
          circuitBreakerResetMs: 30_000,
        },
        sleep: mockSleep,
        random: () => 0.9,
      });

      expect(mockSleep).toHaveBeenCalledWith(expect.any(Number));
      const calledDelay = (mockSleep.mock.calls[0] as any)[0];
      expect(calledDelay).toBeLessThanOrEqual(60000);
    });
  });
});

describe("CircuitBreaker", () => {
  it("initializes in CLOSED state", () => {
    const breaker = new CircuitBreaker(3, 5000);
    expect(breaker.getState()).toBe(CircuitBreakerState.CLOSED);
    expect(breaker.canProceed()).toBe(true);
  });

  it("opens after threshold failures", () => {
    const breaker = new CircuitBreaker(2, 5000);

    expect(breaker.canProceed()).toBe(true);
    breaker.recordFailure();
    expect(breaker.canProceed()).toBe(true);
    breaker.recordFailure();
    expect(breaker.canProceed()).toBe(false);
    expect(breaker.getState()).toBe(CircuitBreakerState.OPEN);
  });

  it("resets failure count on success", () => {
    const breaker = new CircuitBreaker(2, 5000);

    breaker.recordFailure();
    breaker.recordSuccess();
    expect(breaker.getState()).toBe(CircuitBreakerState.CLOSED);
  });

  it("transitions to HALF_OPEN after reset timeout", () => {
    vi.useFakeTimers();
    const breaker = new CircuitBreaker(1, 5000);

    breaker.recordFailure();
    expect(breaker.getState()).toBe(CircuitBreakerState.OPEN);

    vi.advanceTimersByTime(5100);
    expect(breaker.canProceed()).toBe(true);
    expect(breaker.getState()).toBe(CircuitBreakerState.HALF_OPEN);
  });

  it("closes after successful operation from HALF_OPEN", () => {
    vi.useFakeTimers();
    const breaker = new CircuitBreaker(1, 5000);

    breaker.recordFailure();
    vi.advanceTimersByTime(5100);
    expect(breaker.getState()).toBe(CircuitBreakerState.HALF_OPEN);

    breaker.recordSuccess();
    expect(breaker.getState()).toBe(CircuitBreakerState.CLOSED);
  });

  it("reopens on failure from HALF_OPEN", () => {
    vi.useFakeTimers();
    const breaker = new CircuitBreaker(1, 5000);

    breaker.recordFailure();
    vi.advanceTimersByTime(5100);
    expect(breaker.getState()).toBe(CircuitBreakerState.HALF_OPEN);

    breaker.recordFailure();
    expect(breaker.getState()).toBe(CircuitBreakerState.OPEN);
  });

  it("calls onStateChange callback", () => {
    const onStateChange = vi.fn();
    const breaker = new CircuitBreaker(1, 5000, onStateChange);

    breaker.recordFailure();
    expect(onStateChange).toHaveBeenCalledWith(
      CircuitBreakerState.CLOSED,
      CircuitBreakerState.OPEN,
    );

    vi.useFakeTimers();
    vi.advanceTimersByTime(5100);
    breaker.canProceed();
    expect(onStateChange).toHaveBeenCalledWith(
      CircuitBreakerState.OPEN,
      CircuitBreakerState.HALF_OPEN,
    );
  });
});

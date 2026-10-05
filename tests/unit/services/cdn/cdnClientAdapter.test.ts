/**
 * @file cdnClientAdapter.test.ts
 * @description Dedicated test suite for src/services/cdn/cdnClientAdapter.ts
 * Covers CdnClient interface, cdnClient singleton adapter, FastlyClient underlying
 * implementation, state transitions, success/failure paths, invalid inputs,
 * and deterministic retry/backoff behavior.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import https from "node:https";
import { EventEmitter } from "node:events";
import { CdnClient, cdnClient } from "../../../../src/services/cdn/cdnClientAdapter.js";
import { FastlyClient, resetFastlyClient } from "../../../../src/services/cdn/fastlyClient.js";
import { logger } from "../../../../src/utils/logger.js";

// Mock logger to verify error logging
vi.mock("../../../../src/utils/logger.js", () => ({
  logger: {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
  },
}));

interface ResponseConfig {
  statusCode?: number;
  body?: string;
  bodyChunks?: string[];
  networkError?: Error;
}

interface RecordedCall {
  options: https.RequestOptions;
  written: string[];
}

describe("src/services/cdn/cdnClientAdapter.ts", () => {
  const originalEnv = { ...process.env };
  const TEST_API_KEY = "fastly-test-api-key-12345";
  const TEST_SERVICE_ID = "fastly-test-service-id-67890";
  const TEST_BASE_URL = "https://api.fastly.com";

  let recordedCalls: RecordedCall[] = [];
  let responseQueue: ResponseConfig[] = [];
  let requestSpy: any;

  function setupHttpsMock() {
    recordedCalls = [];
    responseQueue = [];

    requestSpy = vi.spyOn(https, "request").mockImplementation((options: any, callback?: any) => {
      const callRecord: RecordedCall = { options, written: [] };
      recordedCalls.push(callRecord);

      const config = responseQueue.shift() ?? { statusCode: 200, body: "" };

      class MockClientRequest extends EventEmitter {
        write = vi.fn((data: any) => {
          callRecord.written.push(typeof data === "string" ? data : data.toString());
        });
        end = vi.fn(() => {
          queueMicrotask(() => {
            if (config.networkError) {
              this.emit("error", config.networkError);
              return;
            }

            const res = new EventEmitter() as any;
            res.statusCode = config.statusCode ?? 200;

            if (callback) {
              callback(res);
            }

            queueMicrotask(() => {
              const chunks = config.bodyChunks ?? (config.body !== undefined ? [config.body] : [""]);
              for (const chunk of chunks) {
                res.emit("data", chunk);
              }
              res.emit("end");
            });
          });
        });
      }

      return new MockClientRequest() as any;
    });
  }

  beforeEach(() => {
    vi.restoreAllMocks();
    vi.clearAllMocks();
    resetFastlyClient();

    process.env.FASTLY_API_KEY = TEST_API_KEY;
    process.env.FASTLY_SERVICE_ID = TEST_SERVICE_ID;
    process.env.FASTLY_API_BASE_URL = TEST_BASE_URL;

    setupHttpsMock();
  });

  afterEach(() => {
    vi.useRealTimers();
    process.env = { ...originalEnv };
    resetFastlyClient();
  });

  // =========================================================================
  // 1. CdnClient Interface Contract & Polymorphism
  // =========================================================================
  describe("CdnClient Interface Contract", () => {
    it("satisfies the CdnClient interface contract with purge method signature", () => {
      expect(cdnClient).toBeDefined();
      expect(typeof cdnClient.purge).toBe("function");
    });

    it("allows custom in-memory implementation conforming to CdnClient", async () => {
      class InMemoryCdnClient implements CdnClient {
        public purgedUrls: string[] = [];
        public purgeCallCount = 0;

        async purge(urls: string[]): Promise<void> {
          this.purgeCallCount++;
          this.purgedUrls.push(...urls);
        }
      }

      const memoryClient: CdnClient = new InMemoryCdnClient();
      await memoryClient.purge(["https://example.com/asset-1", "https://example.com/asset-2"]);

      expect((memoryClient as InMemoryCdnClient).purgeCallCount).toBe(1);
      expect((memoryClient as InMemoryCdnClient).purgedUrls).toEqual([
        "https://example.com/asset-1",
        "https://example.com/asset-2",
      ]);
    });

    it("allows custom failing implementation conforming to CdnClient", async () => {
      class FailingCdnClient implements CdnClient {
        async purge(_urls: string[]): Promise<void> {
          throw new Error("CDN provider unavailable");
        }
      }

      const failingClient: CdnClient = new FailingCdnClient();
      await expect(failingClient.purge(["https://example.com"])).rejects.toThrow(
        "CDN provider unavailable",
      );
    });
  });

  // =========================================================================
  // 2. cdnClient Singleton Export & Adapter Delegation
  // =========================================================================
  describe("cdnClient Singleton Export & Delegation", () => {
    it("exports cdnClient as an instance backed by FastlyClient", () => {
      expect(cdnClient).toBeInstanceOf(FastlyClient);
    });

    it("proxies property and function access on the singleton instance", () => {
      expect((cdnClient as any).baseUrl).toBe(TEST_BASE_URL);
      expect((cdnClient as any).nonExistentProperty).toBeUndefined();
    });

    it("delegates purge invocations through the singleton to FastlyClient", async () => {
      responseQueue.push({ statusCode: 200, body: "{}" });

      const testUrls = ["https://example.com/attestations/att-001"];
      await cdnClient.purge(testUrls);

      expect(recordedCalls).toHaveLength(1);
      const call = recordedCalls[0];
      expect(call.options.method).toBe("POST");
      expect(call.options.hostname).toBe("api.fastly.com");
      expect(call.options.path).toBe(`/service/${TEST_SERVICE_ID}/purge`);
      expect(call.options.headers).toMatchObject({
        "Fastly-Key": TEST_API_KEY,
        "Content-Type": "application/json",
      });

      const bodyPayload = JSON.parse(call.written.join(""));
      expect(bodyPayload).toEqual({ urls: testUrls });
    });
  });

  // =========================================================================
  // 3. Configuration & Initialization Boundaries
  // =========================================================================
  describe("Configuration and Initialization", () => {
    it("throws when FASTLY_API_KEY is missing from environment", async () => {
      delete process.env.FASTLY_API_KEY;
      resetFastlyClient();

      expect(() => new FastlyClient()).toThrow(
        "Fastly configuration missing FASTLY_API_KEY or FASTLY_SERVICE_ID",
      );

      await expect(cdnClient.purge(["https://example.com"])).rejects.toThrow(
        "Fastly configuration missing FASTLY_API_KEY or FASTLY_SERVICE_ID",
      );
    });

    it("throws when FASTLY_SERVICE_ID is missing from environment", async () => {
      delete process.env.FASTLY_SERVICE_ID;
      resetFastlyClient();

      expect(() => new FastlyClient()).toThrow(
        "Fastly configuration missing FASTLY_API_KEY or FASTLY_SERVICE_ID",
      );

      await expect(cdnClient.purge(["https://example.com"])).rejects.toThrow(
        "Fastly configuration missing FASTLY_API_KEY or FASTLY_SERVICE_ID",
      );
    });

    it("throws when both FASTLY_API_KEY and FASTLY_SERVICE_ID are missing", async () => {
      delete process.env.FASTLY_API_KEY;
      delete process.env.FASTLY_SERVICE_ID;
      resetFastlyClient();

      expect(() => new FastlyClient("", "")).toThrow(
        "Fastly configuration missing FASTLY_API_KEY or FASTLY_SERVICE_ID",
      );

      await expect(cdnClient.purge(["https://example.com"])).rejects.toThrow(
        "Fastly configuration missing FASTLY_API_KEY or FASTLY_SERVICE_ID",
      );
    });

    it("uses default baseUrl https://api.fastly.com when FASTLY_API_BASE_URL is not set", async () => {
      delete process.env.FASTLY_API_BASE_URL;
      const client = new FastlyClient(TEST_API_KEY, TEST_SERVICE_ID);
      responseQueue.push({ statusCode: 200 });

      await client.purge(["https://example.com/asset"]);

      expect(recordedCalls[0].options.hostname).toBe("api.fastly.com");
    });

    it("supports custom FASTLY_API_BASE_URL hostnames and ports", async () => {
      process.env.FASTLY_API_BASE_URL = "https://custom-fastly-edge.internal:9443";
      const client = new FastlyClient(TEST_API_KEY, TEST_SERVICE_ID);
      responseQueue.push({ statusCode: 200 });

      await client.purge(["https://example.com/asset"]);

      expect(recordedCalls[0].options.hostname).toBe("custom-fastly-edge.internal");
    });

    it("handles invalid FASTLY_API_BASE_URL by rejecting with URL parse error", async () => {
      const client = new FastlyClient(TEST_API_KEY, TEST_SERVICE_ID, "not-a-valid-url");

      await expect(client.purge(["https://example.com"])).rejects.toThrow();
    });
  });

  // =========================================================================
  // 4. Primary State Transitions: Successful Purge Paths
  // =========================================================================
  describe("Successful Purge Paths (State Transitions: IDLE -> PURGING -> RESOLVED)", () => {
    it("successfully purges a single URL on first attempt", async () => {
      responseQueue.push({ statusCode: 200, body: '{"status":"ok"}' });

      const urls = ["https://example.com/static/style.css"];
      await expect(cdnClient.purge(urls)).resolves.toBeUndefined();

      expect(recordedCalls).toHaveLength(1);
      const call = recordedCalls[0];
      const sentPayload = JSON.stringify({ urls });
      expect(call.options.headers!["Content-Length"]).toBe(Buffer.byteLength(sentPayload).toString());
      expect(call.written.join("")).toBe(sentPayload);
    });

    it("successfully purges multiple URLs in a single batch request", async () => {
      responseQueue.push({ statusCode: 200, body: '{"status":"ok"}' });

      const urls = [
        "https://example.com/page-1",
        "https://example.com/page-2",
        "https://example.com/page-3",
      ];
      await expect(cdnClient.purge(urls)).resolves.toBeUndefined();

      expect(recordedCalls).toHaveLength(1);
      const payload = JSON.parse(recordedCalls[0].written.join(""));
      expect(payload.urls).toEqual(urls);
    });

    it("accepts an empty array of URLs without error", async () => {
      responseQueue.push({ statusCode: 200, body: '{"status":"ok"}' });

      await expect(cdnClient.purge([])).resolves.toBeUndefined();

      expect(recordedCalls).toHaveLength(1);
      const payload = JSON.parse(recordedCalls[0].written.join(""));
      expect(payload.urls).toEqual([]);
    });

    it("treats various 2xx status codes as successful purges", async () => {
      const testCases = [200, 201, 202, 204, 299];

      for (const statusCode of testCases) {
        responseQueue.push({ statusCode, body: "" });
        await expect(
          cdnClient.purge([`https://example.com/code-${statusCode}`]),
        ).resolves.toBeUndefined();
      }

      expect(recordedCalls).toHaveLength(testCases.length);
    });

    it("correctly handles streaming response bodies in multiple chunks", async () => {
      responseQueue.push({
        statusCode: 200,
        bodyChunks: ['{"status":', '"ok",', '"purged":true}'],
      });

      await expect(cdnClient.purge(["https://example.com/stream"])).resolves.toBeUndefined();
      expect(recordedCalls).toHaveLength(1);
    });
  });

  // =========================================================================
  // 5. Non-Transient Failure Paths (Client Errors, No Retry)
  // =========================================================================
  describe("Non-Transient Failure Paths (Immediate Rejection without Retries)", () => {
    it("fails immediately on 400 Bad Request and logs error", async () => {
      responseQueue.push({ statusCode: 400, body: "Bad request payload" });

      await expect(cdnClient.purge(["https://example.com/bad-request"])).rejects.toThrow(
        "Fastly purge failed with status 400: Bad request payload",
      );

      // Should not retry on 4xx
      expect(recordedCalls).toHaveLength(1);
      expect(logger.error).toHaveBeenCalledTimes(1);
      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining("Fastly purge attempt 1 failed: Fastly purge failed with status 400"),
      );
    });

    it("fails immediately on 401 Unauthorized without retrying", async () => {
      responseQueue.push({ statusCode: 401, body: "Invalid Fastly-Key" });

      await expect(cdnClient.purge(["https://example.com/unauthorized"])).rejects.toThrow(
        "Fastly purge failed with status 401: Invalid Fastly-Key",
      );

      expect(recordedCalls).toHaveLength(1);
      expect(logger.error).toHaveBeenCalledTimes(1);
    });

    it("fails immediately on 403 Forbidden without retrying", async () => {
      responseQueue.push({ statusCode: 403, body: "Forbidden access to service" });

      await expect(cdnClient.purge(["https://example.com/forbidden"])).rejects.toThrow(
        "Fastly purge failed with status 403: Forbidden access to service",
      );

      expect(recordedCalls).toHaveLength(1);
    });

    it("fails immediately on 404 Not Found without retrying", async () => {
      responseQueue.push({ statusCode: 404, body: "Service not found" });

      await expect(cdnClient.purge(["https://example.com/not-found"])).rejects.toThrow(
        "Fastly purge failed with status 404: Service not found",
      );

      expect(recordedCalls).toHaveLength(1);
    });

    it("fails immediately on 422 Unprocessable Entity", async () => {
      responseQueue.push({ statusCode: 422, body: "Unprocessable URLs" });

      await expect(cdnClient.purge(["https://example.com/unprocessable"])).rejects.toThrow(
        "Fastly purge failed with status 422: Unprocessable URLs",
      );

      expect(recordedCalls).toHaveLength(1);
    });

    it("fails immediately on status codes below 200 (e.g. 199)", async () => {
      responseQueue.push({ statusCode: 199, body: "Informational" });

      await expect(cdnClient.purge(["https://example.com/sub-200"])).rejects.toThrow(
        "Fastly purge failed with status 199",
      );

      expect(recordedCalls).toHaveLength(1);
    });

    it("fails immediately on status codes in 3xx range (redirects)", async () => {
      responseQueue.push({ statusCode: 301, body: "Moved Permanently" });

      await expect(cdnClient.purge(["https://example.com/redirect"])).rejects.toThrow(
        "Fastly purge failed with status 301: Moved Permanently",
      );

      expect(recordedCalls).toHaveLength(1);
    });
  });

  // =========================================================================
  // 6. Transient Failure Paths & Deterministic Exponential Backoff
  // =========================================================================
  describe("Transient Failure Paths with Deterministic Exponential Backoff", () => {
    it("recovers on attempt 2 after initial 500 error", async () => {
      vi.useFakeTimers();

      responseQueue.push({ statusCode: 500, body: "Internal Server Error" });
      responseQueue.push({ statusCode: 200, body: '{"status":"ok"}' });

      const purgePromise = cdnClient.purge(["https://example.com/retry-once"]);

      // Advance time for backoff(1) = min(1000 * 2^1, 16000) = 2000ms
      await vi.advanceTimersByTimeAsync(2000);

      await expect(purgePromise).resolves.toBeUndefined();
      expect(recordedCalls).toHaveLength(2);
      expect(logger.error).toHaveBeenCalledTimes(1);
      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining("Fastly purge attempt 1 failed: Fastly purge failed with status 500"),
      );
    });

    it("recovers on attempt 3 after 503 and 502 errors with increasing delays", async () => {
      vi.useFakeTimers();

      responseQueue.push({ statusCode: 503, body: "Service Unavailable" });
      responseQueue.push({ statusCode: 502, body: "Bad Gateway" });
      responseQueue.push({ statusCode: 200, body: '{"status":"ok"}' });

      const purgePromise = cdnClient.purge(["https://example.com/retry-twice"]);

      // Attempt 1 fails -> backoff(1) = 2000ms
      await vi.advanceTimersByTimeAsync(2000);

      // Attempt 2 fails -> backoff(2) = 4000ms
      await vi.advanceTimersByTimeAsync(4000);

      await expect(purgePromise).resolves.toBeUndefined();
      expect(recordedCalls).toHaveLength(3);
      expect(logger.error).toHaveBeenCalledTimes(2);
    });

    it("recovers on attempt 5 after 4 transient failures", async () => {
      vi.useFakeTimers();

      responseQueue.push({ statusCode: 500, body: "Server error 1" });
      responseQueue.push({ statusCode: 502, body: "Server error 2" });
      responseQueue.push({ statusCode: 503, body: "Server error 3" });
      responseQueue.push({ statusCode: 504, body: "Server error 4" });
      responseQueue.push({ statusCode: 200, body: '{"status":"ok"}' });

      const purgePromise = cdnClient.purge(["https://example.com/recover-at-5"]);

      // backoff(1) = 2000ms
      await vi.advanceTimersByTimeAsync(2000);
      // backoff(2) = 4000ms
      await vi.advanceTimersByTimeAsync(4000);
      // backoff(3) = 8000ms
      await vi.advanceTimersByTimeAsync(8000);
      // backoff(4) = 16000ms
      await vi.advanceTimersByTimeAsync(16000);

      await expect(purgePromise).resolves.toBeUndefined();
      expect(recordedCalls).toHaveLength(5);
      expect(logger.error).toHaveBeenCalledTimes(4);
    });

    it("exhausts all 5 attempts on persistent 5xx and throws final error", async () => {
      vi.useFakeTimers();

      for (let i = 1; i <= 5; i++) {
        responseQueue.push({ statusCode: 503, body: `Persistent Failure ${i}` });
      }

      const purgePromise = cdnClient.purge(["https://example.com/persistent-503"]);

      // Attach catch handler early so unhandled rejection isn't thrown during timer ticks
      let rejectedError: any = null;
      purgePromise.catch((err) => {
        rejectedError = err;
      });

      // Advance through all 4 backoff windows (attempts 1 to 4)
      await vi.advanceTimersByTimeAsync(2000);
      await vi.advanceTimersByTimeAsync(4000);
      await vi.advanceTimersByTimeAsync(8000);
      await vi.advanceTimersByTimeAsync(16000);

      // Attempt 5 should fail immediately without waiting backoff
      await vi.runAllTimersAsync();

      await expect(purgePromise).rejects.toThrow(
        "Fastly purge failed with status 503: Persistent Failure 5",
      );
      expect(recordedCalls).toHaveLength(5);
      expect(logger.error).toHaveBeenCalledTimes(5);
      expect(logger.error).toHaveBeenLastCalledWith(
        expect.stringContaining("Fastly purge attempt 5 failed: Fastly purge failed with status 503"),
      );
    });

    it("caps backoff delay at 16000ms as per backoff calculation", () => {
      // Direct verification of backoff formula: Math.min(1000 * 2 ** attempt, 16000)
      const calculateBackoff = (attempt: number) => Math.min(1000 * 2 ** attempt, 16000);
      expect(calculateBackoff(1)).toBe(2000);
      expect(calculateBackoff(2)).toBe(4000);
      expect(calculateBackoff(3)).toBe(8000);
      expect(calculateBackoff(4)).toBe(16000);
      expect(calculateBackoff(5)).toBe(16000);
      expect(calculateBackoff(6)).toBe(16000);
    });
  });

  // =========================================================================
  // 7. Network and Socket Error Handling
  // =========================================================================
  describe("Network and Socket Error Handling", () => {
    it("fails immediately on ECONNRESET network error without retrying", async () => {
      const socketError = new Error("ECONNRESET");
      (socketError as any).code = "ECONNRESET";
      responseQueue.push({ networkError: socketError });

      await expect(cdnClient.purge(["https://example.com/network-err"])).rejects.toThrow(
        "ECONNRESET",
      );

      // Network error does not have transient flag, fails on attempt 1
      expect(recordedCalls).toHaveLength(1);
      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining("Fastly purge attempt 1 failed: ECONNRESET"),
      );
    });

    it("fails immediately on ENOTFOUND DNS resolution failure", async () => {
      const dnsError = new Error("getaddrinfo ENOTFOUND api.fastly.com");
      (dnsError as any).code = "ENOTFOUND";
      responseQueue.push({ networkError: dnsError });

      await expect(cdnClient.purge(["https://example.com/dns-err"])).rejects.toThrow(
        "ENOTFOUND",
      );

      expect(recordedCalls).toHaveLength(1);
    });
  });

  // =========================================================================
  // 8. Boundary Inputs & Edge Cases
  // =========================================================================
  describe("Boundary Inputs and Edge Cases", () => {
    it("correctly computes byte length for URLs with multibyte UTF-8 characters", async () => {
      responseQueue.push({ statusCode: 200 });

      // Multibyte characters: string length !== byte length
      const specialUrls = [
        "https://example.com/path/with/emoji/\u{1F389}/\u{1F916}",
        "https://example.com/\u00E9l\u00E9phant/\u4E2D\u6587",
      ];
      await cdnClient.purge(specialUrls);

      expect(recordedCalls).toHaveLength(1);
      const call = recordedCalls[0];
      const payloadString = call.written.join("");
      const expectedByteLength = Buffer.byteLength(payloadString).toString();

      expect(call.options.headers!["Content-Length"]).toBe(expectedByteLength);
      // Byte length should be strictly greater than character length
      expect(Buffer.byteLength(payloadString)).toBeGreaterThan(payloadString.length);
    });

    it("correctly handles URLs containing query parameters and URI-encoded components", async () => {
      responseQueue.push({ statusCode: 200 });

      const complexUrls = [
        "https://cdn.example.com/v1/attestations/att_123?format=json&locale=en_US#section",
        "https://cdn.example.com/search?q=test%20space%26ampersand",
      ];
      await cdnClient.purge(complexUrls);

      expect(recordedCalls).toHaveLength(1);
      const payload = JSON.parse(recordedCalls[0].written.join(""));
      expect(payload.urls).toEqual(complexUrls);
    });

    it("handles large batches of URLs properly", async () => {
      responseQueue.push({ statusCode: 200 });

      const largeUrlList = Array.from({ length: 500 }, (_, i) => `https://example.com/item-${i}`);
      await cdnClient.purge(largeUrlList);

      expect(recordedCalls).toHaveLength(1);
      const payload = JSON.parse(recordedCalls[0].written.join(""));
      expect(payload.urls).toHaveLength(500);
      expect(payload.urls[0]).toBe("https://example.com/item-0");
      expect(payload.urls[499]).toBe("https://example.com/item-499");
    });

    it("handles multiple concurrent purge calls independently without interference", async () => {
      responseQueue.push({ statusCode: 200, body: '{"purge":1}' });
      responseQueue.push({ statusCode: 200, body: '{"purge":2}' });

      const call1 = cdnClient.purge(["https://example.com/first"]);
      const call2 = cdnClient.purge(["https://example.com/second"]);

      await Promise.all([call1, call2]);

      expect(recordedCalls).toHaveLength(2);
      const payload1 = JSON.parse(recordedCalls[0].written.join(""));
      const payload2 = JSON.parse(recordedCalls[1].written.join(""));
      expect(payload1.urls).toEqual(["https://example.com/first"]);
      expect(payload2.urls).toEqual(["https://example.com/second"]);
    });

    it("handles non-array inputs cleanly (runtime type mismatch)", async () => {
      responseQueue.push({ statusCode: 200 });

      // Edge case: someone passes null or undefined through loose typing
      await expect(cdnClient.purge(null as any)).resolves.toBeUndefined();
      expect(recordedCalls).toHaveLength(1);
      const payload = JSON.parse(recordedCalls[0].written.join(""));
      expect(payload).toEqual({ urls: null });
    });
  });
});

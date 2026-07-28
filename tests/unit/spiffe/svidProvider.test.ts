import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  createSvidProvider,
  responseToTlsMaterial,
  SpiffeMaterialError,
  type SvidProvider,
} from "../../../src/spiffe/svidProvider.js";
import type { WorkloadApiClient, WorkloadX509Response } from "../../../src/spiffe/types.js";

const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), "../../fixtures/spiffe");
const TEST_CERT = readFileSync(join(fixtureDir, "spiffe-test-cert.pem"));
const TEST_KEY = readFileSync(join(fixtureDir, "spiffe-test-key.pem"));
const TRUST_DOMAIN = "example.org";
const SPIFFE_ID = `spiffe://${TRUST_DOMAIN}/backend`;

function buildResponse(spiffeId = SPIFFE_ID): WorkloadX509Response {
  return {
    svids: [
      {
        x509Svid: TEST_CERT,
        privateKey: TEST_KEY,
        spiffeId,
      },
    ],
    bundles: new Map([
      [
        TRUST_DOMAIN,
        {
          authorities: [TEST_CERT],
        },
      ],
    ]),
  };
}

describe("responseToTlsMaterial", () => {
  it("maps Workload API output into TLS material", () => {
    const material = responseToTlsMaterial(buildResponse(), TRUST_DOMAIN);
    expect(material.spiffeId).toBe(SPIFFE_ID);
    expect(material.cert.toString()).toContain("BEGIN CERTIFICATE");
    expect(material.key.toString()).toContain("BEGIN PRIVATE KEY");
    expect(material.ca.toString()).toContain("BEGIN CERTIFICATE");
    expect(material.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it("throws when no SVID matches the configured trust domain", () => {
    expect(() =>
      responseToTlsMaterial(buildResponse("spiffe://other.org/service"), TRUST_DOMAIN),
    ).toThrow(SpiffeMaterialError);
  });

  it("throws when the trust bundle is missing for the configured domain", () => {
    expect(() =>
      responseToTlsMaterial(
        {
          svids: buildResponse().svids,
          bundles: new Map(),
        },
        TRUST_DOMAIN,
      ),
    ).toThrow(SpiffeMaterialError);
  });
});

describe("SvidProvider", () => {
  let mockClient: WorkloadApiClient;
  let stopWatch: ReturnType<typeof vi.fn>;
  let provider: SvidProvider;
  const timers: Array<{ cb: () => void; delay: number }> = [];

  beforeEach(() => {
    vi.useFakeTimers();
    stopWatch = vi.fn();
    let watchCalls = 0;
    mockClient = {
      fetchX509Svid: vi.fn().mockResolvedValue(buildResponse()),
      watchX509Svid: vi.fn().mockImplementation((onUpdate) => {
        watchCalls += 1;
        if (watchCalls === 1) {
          onUpdate(buildResponse());
        }
        return stopWatch;
      }),
    };

    provider = createSvidProvider({
      trustDomain: TRUST_DOMAIN,
      client: mockClient,
      refreshRatio: 0.5,
      reconnectBaseMs: 100,
      reconnectMaxMs: 400,
      now: () => new Date("2026-07-28T09:00:00.000Z"),
      setTimeoutFn: ((cb: () => void, delay: number) => {
        timers.push({ cb, delay });
        return timers.length as unknown as ReturnType<typeof setTimeout>;
      }) as typeof setTimeout,
      clearTimeoutFn: vi.fn(),
    });
  });

  afterEach(() => {
    provider.stop();
    vi.useRealTimers();
    timers.length = 0;
  });

  it("loads initial SVID material and starts the watch stream", async () => {
    await provider.start();
    const material = provider.getTlsMaterial();
    expect(material.spiffeId).toBe(SPIFFE_ID);
    expect(mockClient.fetchX509Svid).toHaveBeenCalledOnce();
    expect(mockClient.watchX509Svid).toHaveBeenCalledOnce();
  });

  it("invokes onRotate when a subsequent SVID arrives", async () => {
    const onRotate = vi.fn();
    const delayedWatchClient: WorkloadApiClient = {
      fetchX509Svid: vi.fn().mockResolvedValue(buildResponse()),
      watchX509Svid: vi.fn().mockReturnValue(() => undefined),
    };

    provider = createSvidProvider({
      trustDomain: TRUST_DOMAIN,
      client: delayedWatchClient,
      now: () => new Date("2026-07-28T09:00:00.000Z"),
      onRotate,
    });

    await provider.start();
    const watchCallback = vi.mocked(delayedWatchClient.watchX509Svid).mock.calls[0]?.[0];
    watchCallback?.(buildResponse(`${SPIFFE_ID}/rotated`));

    expect(onRotate).toHaveBeenCalledOnce();
    expect(provider.getTlsMaterial().spiffeId).toBe(`${SPIFFE_ID}/rotated`);
  });

  it("reconnects after a Workload API stream failure", async () => {
    await provider.start();
    const timerCountAfterStart = timers.length;

    const watchError = vi.mocked(mockClient.watchX509Svid).mock.calls[0]?.[1];
    watchError?.(new Error("socket hang up"));

    expect(timers.length).toBe(timerCountAfterStart + 1);
    vi.mocked(mockClient.fetchX509Svid).mockResolvedValue(buildResponse(`${SPIFFE_ID}/restarted`));

    const reconnectTimer = timers[timerCountAfterStart];
    await reconnectTimer?.cb();
    expect(mockClient.fetchX509Svid).toHaveBeenCalledTimes(2);
    expect(provider.getTlsMaterial().spiffeId).toBe(`${SPIFFE_ID}/restarted`);
    expect(mockClient.watchX509Svid).toHaveBeenCalledTimes(2);
  });

  it("schedules TTL-based refresh fetches", async () => {
    await provider.start();
    expect(timers.length).toBeGreaterThan(0);

    vi.mocked(mockClient.fetchX509Svid).mockResolvedValue(buildResponse(`${SPIFFE_ID}/refreshed`));
    await timers.at(-1)?.cb();

    expect(provider.getTlsMaterial().spiffeId).toBe(`${SPIFFE_ID}/refreshed`);
  });

  it("reports seconds until SVID expiry", async () => {
    await provider.start();
    expect(provider.getSecondsUntilExpiry()).toBeGreaterThan(0);
  });

  it("retries reconnect when fetch fails after a stream error", async () => {
    await provider.start();
    const timerCountAfterStart = timers.length;

    vi.mocked(mockClient.fetchX509Svid)
      .mockRejectedValueOnce(new Error("agent unavailable"))
      .mockResolvedValueOnce(buildResponse(`${SPIFFE_ID}/restarted`));

    const watchError = vi.mocked(mockClient.watchX509Svid).mock.calls[0]?.[1];
    watchError?.(new Error("socket hang up"));

    await timers[timerCountAfterStart]?.cb();
    expect(mockClient.fetchX509Svid).toHaveBeenCalledTimes(2);

    const retryTimerCount = timers.length;
    await timers[retryTimerCount - 1]?.cb();
    expect(provider.getTlsMaterial().spiffeId).toBe(`${SPIFFE_ID}/restarted`);
  });

  it("retries when a TTL refresh fetch fails", async () => {
    await provider.start();
    const refreshTimer = timers.at(-1);
    vi.mocked(mockClient.fetchX509Svid).mockRejectedValueOnce(new Error("refresh failed"));

    await refreshTimer?.cb();
    expect(timers.length).toBeGreaterThan(1);
  });

  it("does not reconnect after stop is called", async () => {
    await provider.start();
    provider.stop();

    const watchError = vi.mocked(mockClient.watchX509Svid).mock.calls[0]?.[1];
    watchError?.(new Error("socket hang up"));

    expect(timers.length).toBeGreaterThan(0);
    const fetchCallsBefore = vi.mocked(mockClient.fetchX509Svid).mock.calls.length;
    await timers.at(-1)?.cb();
    expect(mockClient.fetchX509Svid).toHaveBeenCalledTimes(fetchCallsBefore);
  });

  it("returns undefined seconds-to-expiry before the provider starts", () => {
    expect(provider.getSecondsUntilExpiry()).toBeUndefined();
  });

  it("throws when material is requested before start", () => {
    expect(() => provider.getTlsMaterial()).toThrow(SpiffeMaterialError);
  });

  it("applies streamed updates after a Workload API reconnect", async () => {
    await provider.start();
    const timerCountAfterStart = timers.length;

    vi.mocked(mockClient.fetchX509Svid).mockResolvedValue(buildResponse(`${SPIFFE_ID}/restarted`));
    const watchError = vi.mocked(mockClient.watchX509Svid).mock.calls[0]?.[1];
    watchError?.(new Error("socket hang up"));

    await timers[timerCountAfterStart]?.cb();

    const reconnectedWatch = vi.mocked(mockClient.watchX509Svid).mock.calls[1]?.[0];
    reconnectedWatch?.(buildResponse(`${SPIFFE_ID}/streamed`));

    expect(provider.getTlsMaterial().spiffeId).toBe(`${SPIFFE_ID}/streamed`);
  });

  it("schedules reconnect timers that support unref", async () => {
    const unref = vi.fn();
    provider = createSvidProvider({
      trustDomain: TRUST_DOMAIN,
      client: mockClient,
      setTimeoutFn: ((cb: () => void, delay: number) => {
        timers.push({ cb, delay });
        return { unref } as unknown as ReturnType<typeof setTimeout>;
      }) as typeof setTimeout,
      clearTimeoutFn: vi.fn(),
    });

    await provider.start();
    const watchError = vi.mocked(mockClient.watchX509Svid).mock.calls[0]?.[1];
    watchError?.(new Error("socket hang up"));

    expect(unref).toHaveBeenCalled();
  });
});

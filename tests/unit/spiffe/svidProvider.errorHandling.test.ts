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
import type {
  WorkloadApiClient,
  WorkloadX509Response,
} from "../../../src/spiffe/types.js";

const fixtureDir = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../fixtures/spiffe",
);
const TEST_CERT = readFileSync(join(fixtureDir, "spiffe-test-cert.pem"));
const TEST_KEY = readFileSync(join(fixtureDir, "spiffe-test-key.pem"));
const TRUST_DOMAIN = "example.org";
const SPIFFE_ID = `spiffe://${TRUST_DOMAIN}/backend`;

const MISSING_SVID_MESSAGE = `Workload API returned no SVID for trust domain ${TRUST_DOMAIN}`;
const MISSING_BUNDLE_MESSAGE = `Workload API returned no trust bundle for domain ${TRUST_DOMAIN}`;

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

function expectSpiffeMaterialError(fn: () => unknown, message: string): void {
  let caught: unknown;
  try {
    fn();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(SpiffeMaterialError);
  const error = caught as SpiffeMaterialError;
  expect(error.name).toBe("SpiffeMaterialError");
  expect(error.message).toBe(message);
}

describe("SpiffeMaterialError public contract", () => {
  it("reports the exact error when SVID material is requested before start", () => {
    const provider = createSvidProvider({
      trustDomain: TRUST_DOMAIN,
      client: {
        fetchX509Svid: vi.fn(),
        watchX509Svid: vi.fn(),
      },
    });

    expectSpiffeMaterialError(
      () => provider.getTlsMaterial(),
      "SVID material is not loaded yet",
    );
  });

  it("reports the exact error when no SVID matches the trust domain", () => {
    expectSpiffeMaterialError(
      () =>
        responseToTlsMaterial(
          buildResponse("spiffe://other.org/service"),
          TRUST_DOMAIN,
        ),
      MISSING_SVID_MESSAGE,
    );
  });

  it("reports the exact error when the trust bundle is missing", () => {
    expectSpiffeMaterialError(
      () =>
        responseToTlsMaterial(
          {
            svids: buildResponse().svids,
            bundles: new Map(),
          },
          TRUST_DOMAIN,
        ),
      MISSING_BUNDLE_MESSAGE,
    );
  });

  it("reports the exact error when the trust bundle has no authorities", () => {
    expectSpiffeMaterialError(
      () =>
        responseToTlsMaterial(
          {
            svids: buildResponse().svids,
            bundles: new Map([[TRUST_DOMAIN, { authorities: [] }]]),
          },
          TRUST_DOMAIN,
        ),
      MISSING_BUNDLE_MESSAGE,
    );
  });

  it("is a distinct Error subclass named SpiffeMaterialError", () => {
    const error = new SpiffeMaterialError("boom");
    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(SpiffeMaterialError);
    expect(error.name).toBe("SpiffeMaterialError");
    expect(error.message).toBe("boom");
  });
});

describe("SvidProvider.getSecondsUntilExpiry boundaries", () => {
  let provider: SvidProvider;
  let clock: Date;
  const timers: Array<{ cb: () => void; delay: number }> = [];
  let stopWatch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.useFakeTimers();
    clock = new Date("2026-07-28T09:00:00.000Z");
    stopWatch = vi.fn();
    const client: WorkloadApiClient = {
      fetchX509Svid: vi.fn().mockResolvedValue(buildResponse()),
      watchX509Svid: vi.fn().mockReturnValue(stopWatch),
    };
    provider = createSvidProvider({
      trustDomain: TRUST_DOMAIN,
      client,
      refreshRatio: 0.5,
      now: () => new Date(clock.getTime()),
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

  it("pins the empty-result regression: undefined before start", () => {
    expect(provider.getSecondsUntilExpiry()).toBeUndefined();
  });

  it("returns a positive integer once material is loaded", async () => {
    await provider.start();
    const seconds = provider.getSecondsUntilExpiry();
    expect(Number.isInteger(seconds)).toBe(true);
    expect(seconds).toBeGreaterThan(0);
  });

  it("uses the injected now() and returns the exact fixture delta", async () => {
    await provider.start();
    // Fixture certificate validTo is 2027-07-28T09:04:31.000Z; the injected
    // clock is fixed at 2026-07-28T09:00:00.000Z -> exactly 31,536,271s.
    expect(provider.getSecondsUntilExpiry()).toBe(31_536_271);
  });

  it("re-evaluates the injected now() on every call", async () => {
    await provider.start();
    const expiresAt = provider.getTlsMaterial().expiresAt;

    clock = new Date(expiresAt.getTime() - 5_000);
    expect(provider.getSecondsUntilExpiry()).toBe(5);

    clock = new Date(expiresAt.getTime() - 1_000);
    expect(provider.getSecondsUntilExpiry()).toBe(1);
  });

  it("returns 0 (never negative) when the certificate is already expired", async () => {
    await provider.start();
    clock = new Date("2027-08-01T00:00:00.000Z");
    expect(provider.getSecondsUntilExpiry()).toBe(0);
  });

  it("floors fractional seconds", async () => {
    await provider.start();
    const expiresAt = provider.getTlsMaterial().expiresAt;

    clock = new Date(expiresAt.getTime() - 2_500);
    expect(provider.getSecondsUntilExpiry()).toBe(2);

    clock = new Date(expiresAt.getTime() - 999);
    expect(provider.getSecondsUntilExpiry()).toBe(0);
  });
});

describe("SvidProvider failure isolation", () => {
  it("propagates a streamed-update conversion failure and keeps prior material", async () => {
    const timers: Array<{ cb: () => void; delay: number }> = [];
    const client: WorkloadApiClient = {
      fetchX509Svid: vi.fn().mockResolvedValue(buildResponse()),
      watchX509Svid: vi.fn().mockReturnValue(() => undefined),
    };
    const provider = createSvidProvider({
      trustDomain: TRUST_DOMAIN,
      client,
      now: () => new Date("2026-07-28T09:00:00.000Z"),
      setTimeoutFn: ((cb: () => void, delay: number) => {
        timers.push({ cb, delay });
        return timers.length as unknown as ReturnType<typeof setTimeout>;
      }) as typeof setTimeout,
      clearTimeoutFn: vi.fn(),
    });

    await provider.start();
    const loaded = provider.getTlsMaterial();
    const onUpdate = vi.mocked(client.watchX509Svid).mock.calls[0]?.[0];

    // applyMaterial does not swallow: the conversion error propagates to the
    // caller rather than being silently discarded.
    expectSpiffeMaterialError(
      () => onUpdate?.(buildResponse("spiffe://other.org/service")),
      MISSING_SVID_MESSAGE,
    );

    // The previously loaded material is untouched (assignment happens only
    // after a successful conversion).
    expect(provider.getTlsMaterial()).toBe(loaded);
    expect(provider.getTlsMaterial().spiffeId).toBe(SPIFFE_ID);

    provider.stop();
  });
});

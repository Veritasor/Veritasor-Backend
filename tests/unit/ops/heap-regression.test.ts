import { mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it, beforeEach, afterEach } from "vitest";

import {
  measureMemory,
  measureSoak,
  allocatePressure,
  compareToBaseline,
  loadBaseline,
  writeBaseline,
  formatBytes,
} from "../../../ops/heap-regression/soak.js";
import { parseConfig } from "../../../ops/heap-regression/config.js";
import type { ProcessMemory, BaselineData, SoakConfig } from "../../../ops/heap-regression/types.js";

const TEST_CONFIG: SoakConfig = {
  allocationSizeMb: 1,
  allocationSteps: 2,
  gcBetweenSteps: false,
  regressionThresholdBytes: 10 * 1024 * 1024,
};

function fakeMemory(heapUsed: number): ProcessMemory {
  return { rss: heapUsed + 5_000_000, heapTotal: heapUsed + 2_000_000, heapUsed, external: 100_000 };
}

describe("parseConfig", () => {
  it("parses default values when env is empty", () => {
    const cfg = parseConfig({});
    expect(cfg.allocationSizeMb).toBe(50);
    expect(cfg.allocationSteps).toBe(5);
    expect(cfg.gcBetweenSteps).toBe(true);
    expect(cfg.regressionThresholdBytes).toBe(10 * 1024 * 1024);
    expect(cfg.updateBaseline).toBe(false);
  });

  it("reads custom env values", () => {
    const cfg = parseConfig({
      ALLOCATION_SIZE_MB: "20",
      ALLOCATION_STEPS: "3",
      GC_BETWEEN_STEPS: "false",
      REGRESSION_THRESHOLD_MB: "5",
      HEAP_REGRESSION_UPDATE_BASELINE: "true",
    });
    expect(cfg.allocationSizeMb).toBe(20);
    expect(cfg.allocationSteps).toBe(3);
    expect(cfg.gcBetweenSteps).toBe(false);
    expect(cfg.regressionThresholdBytes).toBe(5 * 1024 * 1024);
    expect(cfg.updateBaseline).toBe(true);
  });

  it("clamps allocation size to 500 max", () => {
    const cfg = parseConfig({ ALLOCATION_SIZE_MB: "9999" });
    expect(cfg.allocationSizeMb).toBe(500);
  });

  it("falls back to default for invalid numeric values", () => {
    const cfg = parseConfig({
      ALLOCATION_SIZE_MB: "not-a-number",
      ALLOCATION_STEPS: "-1",
      REGRESSION_THRESHOLD_MB: "0",
    });
    expect(cfg.allocationSizeMb).toBe(50);
    expect(cfg.allocationSteps).toBe(5);
    expect(cfg.regressionThresholdBytes).toBe(10 * 1024 * 1024);
  });

  it("clamps steps to 50 max", () => {
    const cfg = parseConfig({ ALLOCATION_STEPS: "100" });
    expect(cfg.allocationSteps).toBe(50);
  });
});

describe("measureMemory", () => {
  it("returns numeric fields for all memory metrics", () => {
    const mem = measureMemory();
    expect(mem.rss).toBeGreaterThan(0);
    expect(mem.heapTotal).toBeGreaterThan(0);
    expect(mem.heapUsed).toBeGreaterThan(0);
    expect(mem.external).toBeGreaterThanOrEqual(0);
  });
});

describe("measureSoak", () => {
  it("includes the step label and valid heap stats", () => {
    const m = measureSoak("test-label");
    expect(m.stepLabel).toBe("test-label");
    expect(m.timestamp).toBeGreaterThan(0);
    expect(m.memory.heapUsed).toBeGreaterThan(0);
    expect(m.heapStats.total_heap_size).toBeGreaterThan(0);
  });
});

describe("allocatePressure", () => {
  it("allocates memory and returns step measurements", () => {
    const result = allocatePressure(TEST_CONFIG);
    expect(result.steps.length).toBe(2);
    expect(result.peak.heapUsed).toBeGreaterThan(0);
    for (const s of result.steps) {
      expect(s.memory.heapUsed).toBeGreaterThan(0);
      expect(s.step).toBeGreaterThanOrEqual(0);
    }
  });

  it("invokes onStep callback for each step", () => {
    const steps: number[] = [];
    allocatePressure(TEST_CONFIG, (step, _mem) => {
      steps.push(step);
    });
    expect(steps).toEqual([0, 1]);
  });

  it("allocates memory with gc between steps", () => {
    const cfg: SoakConfig = { ...TEST_CONFIG, gcBetweenSteps: true };
    const result = allocatePressure(cfg);
    expect(result.steps.length).toBe(2);
    expect(result.peak.heapUsed).toBeGreaterThan(0);
  });

  it("handles single step gracefully", () => {
    const cfg: SoakConfig = { ...TEST_CONFIG, allocationSteps: 1 };
    const result = allocatePressure(cfg);
    expect(result.steps.length).toBe(1);
  });
});

describe("compareToBaseline", () => {
  const baseline: BaselineData = {
    preSoak: fakeMemory(30_000_000),
    pressurePeak: fakeMemory(120_000_000),
    postRelease: fakeMemory(35_000_000),
    pressurePhase: [],
    config: TEST_CONFIG,
    meta: { createdAt: "2026-01-01T00:00:00.000Z", nodeVersion: "v22.0.0", platform: "linux" },
  };

  it("passes when heap is within threshold", () => {
    const post = fakeMemory(36_000_000);
    const result = compareToBaseline(post, baseline, 10 * 1024 * 1024);
    expect(result.passed).toBe(true);
    expect(result.delta).toBe(1_000_000);
  });

  it("passes when heap is exactly at threshold", () => {
    const post = fakeMemory(45_000_000);
    const result = compareToBaseline(post, baseline, 10 * 1024 * 1024);
    expect(result.passed).toBe(true);
    expect(result.delta).toBe(10_000_000);
  });

  it("fails when heap exceeds threshold", () => {
    const post = fakeMemory(50_000_000);
    const result = compareToBaseline(post, baseline, 10 * 1024 * 1024);
    expect(result.passed).toBe(false);
    expect(result.delta).toBe(15_000_000);
  });

  it("passes when heap is lower than baseline (improvement)", () => {
    const post = fakeMemory(30_000_000);
    const result = compareToBaseline(post, baseline, 10 * 1024 * 1024);
    expect(result.passed).toBe(true);
    expect(result.delta).toBe(-5_000_000);
  });

  it("includes a descriptive message", () => {
    const post = fakeMemory(35_000_000);
    const result = compareToBaseline(post, baseline, 10 * 1024 * 1024);
    expect(result.message).toContain("delta");
    expect(result.message).toContain("threshold");
  });
});

describe("loadBaseline", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "heap-test-"));
  });

  it("returns null for missing file", () => {
    expect(loadBaseline(join(tmpDir, "nope.json"))).toBeNull();
  });

  it("returns null for invalid JSON", () => {
    const p = join(tmpDir, "bad.json");
    writeFileSync(p, "not-json");
    expect(loadBaseline(p)).toBeNull();
  });

  it("returns null for incomplete data", () => {
    const p = join(tmpDir, "incomplete.json");
    writeFileSync(p, JSON.stringify({ foo: 1 }));
    expect(loadBaseline(p)).toBeNull();
  });

  it("loads a valid baseline", () => {
    const p = join(tmpDir, "good.json");
    const data: BaselineData = {
      preSoak: fakeMemory(30_000_000),
      pressurePeak: fakeMemory(120_000_000),
      postRelease: fakeMemory(35_000_000),
      pressurePhase: [],
      config: TEST_CONFIG,
      meta: { createdAt: "2026-01-01T00:00:00.000Z", nodeVersion: "v22.0.0", platform: "linux" },
    };
    writeFileSync(p, JSON.stringify(data));
    const loaded = loadBaseline(p);
    expect(loaded).not.toBeNull();
    expect(loaded!.postRelease.heapUsed).toBe(35_000_000);
  });
});

describe("writeBaseline", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "heap-test-"));
  });

  it("writes a valid baseline JSON file", () => {
    const p = join(tmpDir, "baseline.json");
    writeBaseline(fakeMemory(30_000_000), fakeMemory(120_000_000), fakeMemory(35_000_000), [], TEST_CONFIG, p);
    expect(existsSync(p)).toBe(true);
    const raw = JSON.parse(readFileSync(p, "utf8"));
    expect(raw.postRelease.heapUsed).toBe(35_000_000);
    expect(raw.meta.nodeVersion).toBe(process.version);
    expect(raw.meta.platform).toBe(process.platform);
  });

  it("creates intermediate directories", () => {
    const p = join(tmpDir, "nested", "deep", "baseline.json");
    writeBaseline(fakeMemory(30_000_000), fakeMemory(120_000_000), fakeMemory(35_000_000), [], TEST_CONFIG, p);
    expect(existsSync(p)).toBe(true);
  });
});

describe("formatBytes", () => {
  it("formats bytes", () => {
    expect(formatBytes(500)).toBe("500 B");
  });

  it("formats kilobytes", () => {
    expect(formatBytes(2048)).toBe("2.0 KB");
  });

  it("formats megabytes", () => {
    expect(formatBytes(5_242_880)).toBe("5.00 MB");
  });
});

describe("baseline file at expected path", () => {
  it("exists and is valid JSON with postRelease", () => {
    const baselinePath = resolve(process.cwd(), "ops/heap-regression/baseline.json");
    expect(existsSync(baselinePath)).toBe(true);
    const raw = readFileSync(baselinePath, "utf8");
    const data = JSON.parse(raw);
    expect(data).toHaveProperty("postRelease");
    expect(data).toHaveProperty("preSoak");
    expect(data).toHaveProperty("pressurePeak");
    expect(data).toHaveProperty("config");
    expect(data).toHaveProperty("meta");
  });
});

describe("integration — config + compare roundtrip", () => {
  it("parses env, creates config, comparison works with zero threshold", () => {
    const cfg = parseConfig({ REGRESSION_THRESHOLD_MB: "0" });
    const baseline: BaselineData = {
      preSoak: fakeMemory(30_000_000),
      pressurePeak: fakeMemory(120_000_000),
      postRelease: fakeMemory(35_000_000),
      pressurePhase: [],
      config: { ...cfg, regressionThresholdBytes: 1 },
      meta: { createdAt: "2026-01-01T00:00:00.000Z", nodeVersion: "v22.0.0", platform: "linux" },
    };
    const post = fakeMemory(35_001_000);
    const result = compareToBaseline(post, baseline, 1);
    expect(result.passed).toBe(false);
    expect(result.delta).toBe(1000);
  });
});

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { getHeapStatistics, writeHeapSnapshot } from "node:v8";

import { parseConfig } from "./config.js";
import type { SoakMeasurement, ProcessMemory, BaselineData, SoakConfig } from "./types.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const BASELINE_PATH = resolve(__dirname, "baseline.json");

function getGc(): () => void {
  if (typeof globalThis.gc === "function") return globalThis.gc;
  return () => {};
}

export function measureMemory(): ProcessMemory {
  const mem = process.memoryUsage();
  return {
    rss: mem.rss,
    heapTotal: mem.heapTotal,
    heapUsed: mem.heapUsed,
    external: mem.external,
  };
}

export function measureSoak(stepLabel: string): SoakMeasurement {
  return {
    timestamp: Date.now(),
    memory: measureMemory(),
    heapStats: getHeapStatistics(),
    stepLabel,
  };
}

export interface AllocResult {
  steps: Array<{ step: number; memory: ProcessMemory }>;
  peak: ProcessMemory;
}

export function allocatePressure(
  config: SoakConfig,
  onStep?: (step: number, mem: ProcessMemory) => void,
): AllocResult {
  const gc = getGc();
  const bytesPerStep = config.allocationSizeMb * 1024 * 1024;
  const holders: Array<Array<Record<string, number>>> = [];
  const steps: Array<{ step: number; memory: ProcessMemory }> = [];

  try {
    for (let i = 0; i < config.allocationSteps; i++) {
      const batch: Array<Record<string, number>> = [];
      const targetObjects = Math.max(1, Math.floor(bytesPerStep / 256));
      for (let j = 0; j < targetObjects; j++) {
        const obj: Record<string, number> = {};
        for (let k = 0; k < 16; k++) {
          obj[`f${i}_${j}_${k}`] = Math.random();
        }
        batch.push(obj);
      }
      holders.push(batch);

      if (config.gcBetweenSteps) gc();

      const mem = measureMemory();
      steps.push({ step: i, memory: mem });
      if (onStep) onStep(i, mem);
    }

    const peak = steps.reduce((max, s) => (s.memory.heapUsed > max.heapUsed ? s.memory : max), steps[0]?.memory ?? measureMemory());

    return { steps, peak };
  } finally {
    holders.length = 0;
  }
}

export function compareToBaseline(
  postRelease: ProcessMemory,
  baseline: BaselineData,
  thresholdBytes: number,
): { passed: boolean; delta: number; message: string } {
  const delta = postRelease.heapUsed - baseline.postRelease.heapUsed;
  const absDelta = Math.abs(delta);
  const passed = absDelta <= thresholdBytes;

  let message: string;
  if (passed) {
    message = `heap delta within threshold: ${formatBytes(absDelta)} <= ${formatBytes(thresholdBytes)}`;
  } else {
    message = `heap regression detected: ${formatBytes(absDelta)} exceeds threshold ${formatBytes(thresholdBytes)}`;
  }

  return { passed, delta, message };
}

export function loadBaseline(path: string = BASELINE_PATH): BaselineData | null {
  try {
    const raw = readFileSync(path, "utf8");
    const data = JSON.parse(raw) as BaselineData;
    if (!data.postRelease || typeof data.postRelease.heapUsed !== "number") return null;
    return data;
  } catch {
    return null;
  }
}

export function writeBaseline(
  preSoak: ProcessMemory,
  pressurePeak: ProcessMemory,
  postRelease: ProcessMemory,
  pressurePhase: AllocResult["steps"],
  config: SoakConfig,
  path: string = BASELINE_PATH,
): void {
  const baseline: BaselineData = {
    preSoak,
    pressurePeak,
    postRelease,
    pressurePhase,
    config: { ...config },
    meta: {
      createdAt: new Date().toISOString(),
      nodeVersion: process.version,
      platform: process.platform,
    },
  };
  const dir = dirname(path);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(path, JSON.stringify(baseline, null, 2) + "\n");
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

async function main(): Promise<number> {
  const config = parseConfig();
  const gc = getGc();

  console.log(`heap-regression soak — ${config.allocationSteps} steps × ${config.allocationSizeMb} MB`);

  gc();
  const preSoak = measureMemory();
  console.log(`pre-soak:  heapUsed=${formatBytes(preSoak.heapUsed)}`);

  const pressureResult = allocatePressure(config, (step, mem) => {
    console.log(`  step ${step + 1}/${config.allocationSteps}: heapUsed=${formatBytes(mem.heapUsed)}`);
  });

  const pressurePeak = pressureResult.peak;
  console.log(`pressure peak: heapUsed=${formatBytes(pressurePeak.heapUsed)}`);

  gc();
  const postRelease = measureMemory();
  console.log(`post-release: heapUsed=${formatBytes(postRelease.heapUsed)}`);

  if (config.updateBaseline) {
    writeBaseline(preSoak, pressurePeak, postRelease, pressureResult.steps, {
      allocationSizeMb: config.allocationSizeMb,
      allocationSteps: config.allocationSteps,
      gcBetweenSteps: config.gcBetweenSteps,
      regressionThresholdBytes: config.regressionThresholdBytes,
    });
    console.log(`baseline written to ${BASELINE_PATH}`);
    return 0;
  }

  const baseline = loadBaseline();
  if (!baseline) {
    writeBaseline(preSoak, pressurePeak, postRelease, pressureResult.steps, {
      allocationSizeMb: config.allocationSizeMb,
      allocationSteps: config.allocationSteps,
      gcBetweenSteps: config.gcBetweenSteps,
      regressionThresholdBytes: config.regressionThresholdBytes,
    });
    console.log(`no baseline found — bootstrapped at ${BASELINE_PATH}`);
    return 0;
  }

  const result = compareToBaseline(postRelease, baseline, config.regressionThresholdBytes);
  console.log(result.message);

  if (!result.passed) {
    const snapshotPath = writeHeapSnapshot();
    console.log(`heap snapshot written to ${snapshotPath}`);
    return 1;
  }

  return 0;
}

if (process.argv[1] && (process.argv[1] === __filename || process.argv[1].endsWith("/soak.ts"))) {
  main()
    .then((code) => {
      process.exit(code);
    })
    .catch((err) => {
      console.error("soak failed:", err);
      process.exit(2);
    });
}

export { main };

import type { HeapInfo } from "node:v8";

export interface ProcessMemory {
  rss: number;
  heapTotal: number;
  heapUsed: number;
  external: number;
}

export interface SoakMeasurement {
  timestamp: number;
  memory: ProcessMemory;
  heapStats: HeapInfo;
  stepLabel: string;
}

export interface BaselineData {
  preSoak: SoakMeasurement["memory"];
  pressurePeak: SoakMeasurement["memory"];
  postRelease: SoakMeasurement["memory"];
  pressurePhase: Array<{ step: number; memory: SoakMeasurement["memory"] }>;
  config: SoakConfig;
  meta: {
    createdAt: string;
    nodeVersion: string;
    platform: string;
  };
}

export interface SoakConfig {
  allocationSizeMb: number;
  allocationSteps: number;
  gcBetweenSteps: boolean;
  regressionThresholdBytes: number;
}

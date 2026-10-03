import { z } from "zod";

const envSchema = z.object({
  ALLOCATION_SIZE_MB: z
    .string()
    .default("50")
    .transform((v) => {
      const n = Number(v);
      if (!Number.isFinite(n) || n <= 0) return 50;
      return Math.min(n, 500);
    }),
  ALLOCATION_STEPS: z
    .string()
    .default("5")
    .transform((v) => {
      const n = Number.parseInt(v, 10);
      if (!Number.isFinite(n) || n <= 0) return 5;
      return Math.min(n, 50);
    }),
  GC_BETWEEN_STEPS: z
    .string()
    .default("true")
    .transform((v) => v === "true" || v === "1"),
  REGRESSION_THRESHOLD_MB: z
    .string()
    .default("10")
    .transform((v) => {
      const n = Number(v);
      if (!Number.isFinite(n) || n <= 0) return 10;
      return Math.min(n, 500);
    }),
  HEAP_REGRESSION_UPDATE_BASELINE: z
    .string()
    .default("false")
    .transform((v) => v === "true" || v === "1"),
});

export type ParsedConfig = ReturnType<typeof parseConfig>;

export function parseConfig(env: Record<string, string | undefined> = process.env) {
  const parsed = envSchema.parse(env);
  return {
    allocationSizeMb: parsed.ALLOCATION_SIZE_MB,
    allocationSteps: parsed.ALLOCATION_STEPS,
    gcBetweenSteps: parsed.GC_BETWEEN_STEPS,
    regressionThresholdBytes: parsed.REGRESSION_THRESHOLD_MB * 1024 * 1024,
    updateBaseline: parsed.HEAP_REGRESSION_UPDATE_BASELINE,
  };
}

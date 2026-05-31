/**
 * Contract test: generated OpenAPI spec vs. committed snapshot.
 *
 * Regenerates the OpenAPI 3.1 specification in-memory from the Express router
 * stack and diffs it against the on-disk snapshot at `docs/openapi.json`.
 * Fails CI if the two diverge, ensuring any route / schema changes are
 * accompanied by a regenerated snapshot.
 *
 * Quick-fix when this test fails:
 *
 *   npx tsx scripts/generate-openapi.ts
 *   git add docs/openapi.json
 *   git commit -m "chore: regenerate OpenAPI snapshot"
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { app } from "../../src/app.js";
import { generateRouteMap } from "../../src/utils/routeMap.js";
import { generateOpenApiSpec } from "../../src/utils/openapi.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const SNAPSHOT_PATH = resolve(__dirname, "../../docs/openapi.json");

/** Load the committed snapshot from disk. */
function loadSnapshot(): unknown {
  const raw = readFileSync(SNAPSHOT_PATH, "utf-8");
  return JSON.parse(raw);
}

/**
 * Recursively collect all path-like keys from two objects so we can surface
 * a human-readable list of differences rather than a wall of JSON.
 */
function findDifferences(
  a: unknown,
  b: unknown,
  path = "$",
): string[] {
  const diffs: string[] = [];

  if (typeof a !== typeof b) {
    diffs.push(`${path}: type mismatch (${typeof a} vs ${typeof b})`);
    return diffs;
  }

  if (a === null && b === null) return diffs;
  if (a === null || b === null) {
    diffs.push(`${path}: one side is null`);
    return diffs;
  }

  if (Array.isArray(a) && Array.isArray(b)) {
    const maxLen = Math.max(a.length, b.length);
    for (let i = 0; i < maxLen; i++) {
      if (i >= a.length) {
        diffs.push(`${path}[${i}]: missing in generated`);
      } else if (i >= b.length) {
        diffs.push(`${path}[${i}]: missing in snapshot`);
      } else {
        diffs.push(...findDifferences(a[i], b[i], `${path}[${i}]`));
      }
    }
    return diffs;
  }

  if (typeof a === "object" && typeof b === "object") {
    const aKeys = Object.keys(a as Record<string, unknown>).sort();
    const bKeys = Object.keys(b as Record<string, unknown>).sort();

    const onlyA = aKeys.filter((k) => !(k in (b as Record<string, unknown>)));
    const onlyB = bKeys.filter((k) => !(k in (a as Record<string, unknown>)));

    for (const key of onlyA) diffs.push(`${path}.${key}: present in generated, missing in snapshot`);
    for (const key of onlyB) diffs.push(`${path}.${key}: present in snapshot, missing in generated`);

    for (const key of aKeys) {
      if (key in (b as Record<string, unknown>)) {
        diffs.push(
          ...findDifferences(
            (a as Record<string, unknown>)[key],
            (b as Record<string, unknown>)[key],
            `${path}.${key}`,
          ),
        );
      }
    }
    return diffs;
  }

  if (a !== b) {
    const aStr = typeof a === "string" ? `"${a}"` : String(a);
    const bStr = typeof b === "string" ? `"${b}"` : String(b);
    diffs.push(`${path}: ${aStr} !== ${bStr}`);
  }

  return diffs;
}

// ─── Contract test ─────────────────────────────────────────────────────────────

describe("OpenAPI spec snapshot contract", () => {
  it("generated spec matches the committed snapshot", () => {
    // Regenerate in-memory
    const routes = generateRouteMap(app);
    const generated = generateOpenApiSpec(routes);

    // Load committed snapshot
    const snapshot = loadSnapshot();

    // Deep compare
    const diffs = findDifferences(generated, snapshot);

    if (diffs.length > 0) {
      const summary = [
        "",
        "❌ The generated OpenAPI spec differs from the committed snapshot.",
        "",
        "To fix this, regenerate the snapshot:",
        "",
        "    npx tsx scripts/generate-openapi.ts",
        "",
        "Differences found:",
        ...diffs.map((d) => `  • ${d}`),
        "",
      ].join("\n");

      // Also let Vitest produce its own structured diff for detailed inspection
      expect(generated, summary).toEqual(snapshot);
    }
  });

  it("generated spec is valid JSON and has the expected envelope", () => {
    const routes = generateRouteMap(app);
    const spec = generateOpenApiSpec(routes);

    expect(spec).toHaveProperty("openapi", "3.1.0");
    expect(spec).toHaveProperty("info.title", "Veritasor Backend API");
    expect(spec).toHaveProperty("info.version", "1.0.0");
    expect(spec).toHaveProperty("paths");
    expect(spec).toHaveProperty("tags");
    expect(Array.isArray((spec as { tags: unknown }).tags)).toBe(true);
    expect(Object.keys((spec as { paths: Record<string, unknown> }).paths).length).toBeGreaterThan(0);
  });

  it("routes produce the same number of path entries each run (determinism)", () => {
    const routesA = generateRouteMap(app);
    const routesB = generateRouteMap(app);
    expect(routesA).toEqual(routesB);
  });
});

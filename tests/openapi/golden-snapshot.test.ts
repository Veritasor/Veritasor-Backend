/**
 * Golden snapshot tests for OpenAPI spec generator output.
 *
 * These tests lock down the structural output of `generateOpenApiSpec()` by
 * comparing normalized output against a committed golden snapshot file.
 * Any structural change (new paths, modified schemas, reordered keys) will
 * cause a test failure, requiring explicit review and snapshot regeneration.
 *
 * To update the snapshot after intentional changes:
 *   npm run snapshot:update
 *
 * @module tests/openapi/golden-snapshot.test
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateOpenApiSpec } from '../../src/utils/openapi.js';
import { normalizeSpec } from '../../src/utils/normalizeSpec.js';
import {
  ALL_ROUTES,
  AUTH_ROUTES,
  HEALTH_ROUTES,
  ANALYTICS_ROUTES,
  ATTESTATIONS_ROUTES,
  BUSINESSES_ROUTES,
  WEBHOOK_ROUTES,
} from './fixtures/routes.js';
import type { RouteInfo } from '../../src/utils/routeMap.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const SNAPSHOT_PATH = resolve(__dirname, 'golden.snap.json');

/** Load and parse the golden snapshot from disk. */
function loadGoldenSnapshot(): unknown {
  if (!existsSync(SNAPSHOT_PATH)) {
    throw new Error(
      `Golden snapshot not found at ${SNAPSHOT_PATH}.\n` +
        'Run `npm run snapshot:update` to generate it.',
    );
  }
  return JSON.parse(readFileSync(SNAPSHOT_PATH, 'utf-8'));
}

/**
 * Generate a normalized spec from the canonical fixture routes.
 * This is the "generated" side of the snapshot comparison.
 */
function generateNormalizedSpec(): unknown {
  const spec = generateOpenApiSpec(ALL_ROUTES);
  return normalizeSpec(spec);
}

/**
 * Collect all JSON paths where two values differ, for human-readable diffs.
 */
function collectDiffs(
  a: unknown,
  b: unknown,
  path = '$',
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
        diffs.push(...collectDiffs(a[i], b[i], `${path}[${i}]`));
      }
    }
    return diffs;
  }

  if (typeof a === 'object' && typeof b === 'object') {
    const aKeys = Object.keys(a as Record<string, unknown>).sort();
    const bKeys = Object.keys(b as Record<string, unknown>).sort();

    for (const key of aKeys.filter((k) => !(k in (b as Record<string, unknown>)))) {
      diffs.push(`${path}.${key}: present in generated, missing in snapshot`);
    }
    for (const key of bKeys.filter((k) => !(k in (a as Record<string, unknown>)))) {
      diffs.push(`${path}.${key}: present in snapshot, missing in generated`);
    }

    for (const key of aKeys) {
      if (key in (b as Record<string, unknown>)) {
        diffs.push(
          ...collectDiffs(
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
    diffs.push(`${path}: ${JSON.stringify(a)} !== ${JSON.stringify(b)}`);
  }

  return diffs;
}

/**
 * Fisher-Yates shuffle for array randomization (deterministic test input).
 */
function shuffle<T>(arr: T[]): T[] {
  const result = [...arr];
  for (let i = result.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('OpenAPI golden snapshot', () => {
  let generated: unknown;
  let snapshot: unknown;

  beforeAll(() => {
    generated = generateNormalizedSpec();
    snapshot = loadGoldenSnapshot();
  });

  // ─── Full structural match ──────────────────────────────────────────────

  describe('full structural match', () => {
    it('normalized spec matches the golden snapshot', () => {
      const diffs = collectDiffs(generated, snapshot);

      if (diffs.length > 0) {
        const message = [
          '',
          '❌ The generated OpenAPI spec differs from the golden snapshot.',
          '',
          'To update the snapshot after intentional changes:',
          '',
          '    npm run snapshot:update',
          '',
          `Differences found (${diffs.length}):`,
          ...diffs.slice(0, 30).map((d) => `  • ${d}`),
          diffs.length > 30 ? `  … and ${diffs.length - 30} more` : '',
          '',
        ].join('\n');

        expect(generated, message).toEqual(snapshot);
      }
    });

    it('serialized JSON is byte-identical between runs', () => {
      const jsonA = JSON.stringify(generated, null, 2);
      const jsonB = JSON.stringify(generateNormalizedSpec(), null, 2);
      expect(jsonA).toBe(jsonB);
    });
  });

  // ─── Ordering stability ─────────────────────────────────────────────────

  describe('ordering stability', () => {
    it('path keys are sorted alphabetically in the snapshot', () => {
      const spec = generated as Record<string, unknown>;
      const paths = spec.paths as Record<string, unknown>;
      const keys = Object.keys(paths);
      expect(keys).toEqual([...keys].sort());
    });

    it('tag names are sorted alphabetically in the snapshot', () => {
      const spec = generated as Record<string, unknown>;
      const tags = spec.tags as { name: string }[];
      const names = tags.map((t) => t.name);
      expect(names).toEqual([...names].sort());
    });

    it('shuffled route input produces identical normalized output', () => {
      // Run multiple shuffles to increase confidence
      for (let i = 0; i < 5; i++) {
        const shuffled = shuffle(ALL_ROUTES);
        const spec = generateOpenApiSpec(shuffled);
        const normalized = normalizeSpec(spec);
        const json = JSON.stringify(normalized, null, 2);
        const goldenJson = JSON.stringify(generated, null, 2);
        expect(json, `shuffle iteration ${i + 1}`).toBe(goldenJson);
      }
    });

    it('response status codes are sorted numerically', () => {
      const spec = generated as Record<string, Record<string, Record<string, unknown>>>;
      for (const [pathKey, pathItem] of Object.entries(spec.paths)) {
        for (const [method, operation] of Object.entries(pathItem)) {
          const op = operation as Record<string, unknown>;
          if (op.responses && typeof op.responses === 'object') {
            const codes = Object.keys(op.responses as Record<string, unknown>);
            const sorted = [...codes].sort((a, b) => parseInt(a, 10) - parseInt(b, 10));
            expect(codes, `${method.toUpperCase()} ${pathKey} response codes`).toEqual(sorted);
          }
        }
      }
    });
  });

  // ─── Structural counts ──────────────────────────────────────────────────

  describe('structural counts', () => {
    it('paths count matches the snapshot', () => {
      const genPaths = Object.keys((generated as Record<string, unknown>).paths as Record<string, unknown>);
      const snapPaths = Object.keys((snapshot as Record<string, unknown>).paths as Record<string, unknown>);
      expect(genPaths.length).toBe(snapPaths.length);
    });

    it('tag count matches the snapshot', () => {
      const genTags = ((generated as Record<string, unknown>).tags as unknown[]);
      const snapTags = ((snapshot as Record<string, unknown>).tags as unknown[]);
      expect(genTags.length).toBe(snapTags.length);
    });

    it('component schema count matches the snapshot', () => {
      const genSchemas = Object.keys(
        ((generated as Record<string, unknown>).components as Record<string, unknown>).schemas as Record<string, unknown>,
      );
      const snapSchemas = Object.keys(
        ((snapshot as Record<string, unknown>).components as Record<string, unknown>).schemas as Record<string, unknown>,
      );
      expect(genSchemas.length).toBe(snapSchemas.length);
    });

    it('path key sets are identical', () => {
      const genPaths = Object.keys((generated as Record<string, unknown>).paths as Record<string, unknown>).sort();
      const snapPaths = Object.keys((snapshot as Record<string, unknown>).paths as Record<string, unknown>).sort();
      expect(genPaths).toEqual(snapPaths);
    });
  });

  // ─── Envelope immutability ──────────────────────────────────────────────

  describe('envelope immutability', () => {
    it('openapi version matches snapshot', () => {
      const gen = generated as Record<string, unknown>;
      const snap = snapshot as Record<string, unknown>;
      expect(gen.openapi).toBe(snap.openapi);
      expect(gen.openapi).toBe('3.1.0');
    });

    it('info.title matches snapshot', () => {
      const gen = (generated as Record<string, unknown>).info as Record<string, unknown>;
      const snap = (snapshot as Record<string, unknown>).info as Record<string, unknown>;
      expect(gen.title).toBe(snap.title);
    });

    it('servers array matches snapshot', () => {
      const gen = (generated as Record<string, unknown>).servers;
      const snap = (snapshot as Record<string, unknown>).servers;
      expect(gen).toEqual(snap);
    });

    it('security schemes match snapshot', () => {
      const genSchemes = (
        (generated as Record<string, unknown>).components as Record<string, unknown>
      ).securitySchemes;
      const snapSchemes = (
        (snapshot as Record<string, unknown>).components as Record<string, unknown>
      ).securitySchemes;
      expect(genSchemes).toEqual(snapSchemes);
    });
  });

  // ─── Example value stability ────────────────────────────────────────────

  describe('example value stability', () => {
    it('example fields in the snapshot remain stable', () => {
      // Collect all example values from both generated and snapshot
      const genExamples = collectExampleValues(generated);
      const snapExamples = collectExampleValues(snapshot);
      expect(genExamples).toEqual(snapExamples);
    });
  });

  // ─── Empty route baseline ──────────────────────────────────────────────

  describe('empty route baseline', () => {
    it('empty input produces a minimal valid envelope', () => {
      const emptySpec = normalizeSpec(generateOpenApiSpec([]));
      const spec = emptySpec as Record<string, unknown>;

      expect(spec.openapi).toBe('3.1.0');
      expect(spec.info).toBeDefined();
      expect(spec.paths).toEqual({});
      expect(spec.tags).toEqual([]);
      expect(spec.components).toBeDefined();
    });

    it('empty spec has no paths or tags', () => {
      const emptySpec = normalizeSpec(generateOpenApiSpec([])) as Record<string, unknown>;
      expect(Object.keys(emptySpec.paths as Record<string, unknown>)).toHaveLength(0);
      expect((emptySpec.tags as unknown[])).toHaveLength(0);
    });

    it('empty spec still defines component schemas', () => {
      const emptySpec = normalizeSpec(generateOpenApiSpec([])) as Record<string, unknown>;
      const components = emptySpec.components as Record<string, unknown>;
      const schemas = components.schemas as Record<string, unknown>;
      expect(Object.keys(schemas).length).toBeGreaterThan(0);
    });
  });

  // ─── Subset structural checks ──────────────────────────────────────────

  describe('subset route generation', () => {
    it('auth-only routes produce only auth tag', () => {
      const spec = normalizeSpec(generateOpenApiSpec(AUTH_ROUTES)) as Record<string, unknown>;
      const tags = (spec.tags as { name: string }[]).map((t) => t.name);
      expect(tags).toEqual(['auth']);
    });

    it('health-only routes produce only health tag', () => {
      const spec = normalizeSpec(generateOpenApiSpec(HEALTH_ROUTES)) as Record<string, unknown>;
      const tags = (spec.tags as { name: string }[]).map((t) => t.name);
      expect(tags).toEqual(['health']);
    });

    it('each route group produces the expected number of paths', () => {
      const groups: { name: string; routes: RouteInfo[]; expectedPaths: number }[] = [
        { name: 'auth', routes: AUTH_ROUTES, expectedPaths: 7 },
        { name: 'health', routes: HEALTH_ROUTES, expectedPaths: 1 },
        { name: 'analytics', routes: ANALYTICS_ROUTES, expectedPaths: 2 },
        { name: 'attestations', routes: ATTESTATIONS_ROUTES, expectedPaths: 3 }, // :id and :id/revoke share {id} prefix
        { name: 'businesses', routes: BUSINESSES_ROUTES, expectedPaths: 3 }, // me and :id share
        { name: 'webhooks', routes: WEBHOOK_ROUTES, expectedPaths: 1 },
      ];

      for (const group of groups) {
        const spec = generateOpenApiSpec(group.routes);
        const pathCount = Object.keys(spec.paths).length;
        expect(pathCount, `${group.name} path count`).toBe(group.expectedPaths);
      }
    });
  });

  // ─── Drift detection ────────────────────────────────────────────────────

  describe('drift detection', () => {
    it('adding a new route causes a diff', () => {
      const extraRoute: RouteInfo = { method: 'DELETE', path: '/api/users/:id' };
      const modifiedSpec = normalizeSpec(
        generateOpenApiSpec([...ALL_ROUTES, extraRoute]),
      );
      const diffs = collectDiffs(modifiedSpec, snapshot);
      expect(diffs.length, 'adding a route should produce diffs').toBeGreaterThan(0);
    });

    it('removing a route causes a diff', () => {
      const reducedRoutes = ALL_ROUTES.slice(1); // Remove first route
      const modifiedSpec = normalizeSpec(generateOpenApiSpec(reducedRoutes));
      const diffs = collectDiffs(modifiedSpec, snapshot);
      expect(diffs.length, 'removing a route should produce diffs').toBeGreaterThan(0);
    });

    it('changing version causes a diff', () => {
      const modifiedSpec = normalizeSpec(generateOpenApiSpec(ALL_ROUTES, '2.0.0'));
      const diffs = collectDiffs(modifiedSpec, snapshot);
      expect(diffs.length, 'changing version should produce diffs').toBeGreaterThan(0);
    });
  });
});

// ─── Utility: collect example values ──────────────────────────────────────────

/**
 * Recursively extract all `example` field values from a nested object,
 * returning them as a sorted array of [path, value] tuples.
 */
function collectExampleValues(
  obj: unknown,
  path = '$',
): [string, unknown][] {
  const examples: [string, unknown][] = [];

  if (obj === null || obj === undefined || typeof obj !== 'object') {
    return examples;
  }

  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      examples.push(...collectExampleValues(obj[i], `${path}[${i}]`));
    }
    return examples;
  }

  const record = obj as Record<string, unknown>;
  for (const key of Object.keys(record).sort()) {
    if (key === 'example') {
      examples.push([`${path}.example`, record[key]]);
    }
    examples.push(...collectExampleValues(record[key], `${path}.${key}`));
  }

  return examples.sort((a, b) => a[0].localeCompare(b[0]));
}

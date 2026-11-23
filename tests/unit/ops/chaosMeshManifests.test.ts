import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

const CHAOS_MESH_DIR = join(process.cwd(), 'ops', 'chaos-mesh');

const MANIFESTS = [
  'network-partition-postgres.yaml',
  'network-partition-redis.yaml',
  'network-partition-postgres-partial.yaml',
] as const;

const NONPROD_LABEL_KEY = 'chaos-mesh.org/environment';
const NONPROD_LABEL_VALUE = 'nonprod';

// Chaos Mesh self-heals once `duration` elapses; cap how long any manifest
// in this directory is allowed to keep a partition active, so a mistake
// here can't leave a long-lived partition in place.
const MAX_DURATION_SECONDS = 300;

function loadManifest(fileName: string): Record<string, unknown> {
  const raw = readFileSync(join(CHAOS_MESH_DIR, fileName), 'utf8');
  return parse(raw) as Record<string, unknown>;
}

function parseDurationSeconds(duration: unknown): number {
  expect(typeof duration).toBe('string');
  const match = /^(\d+)([sm])$/.exec(duration as string);
  expect(match, `duration "${duration}" must match /^(\\d+)([sm])$/`).not.toBeNull();
  const [, amount, unit] = match!;
  return unit === 'm' ? Number(amount) * 60 : Number(amount);
}

describe('Chaos Mesh network-partition manifests', () => {
  it.each(MANIFESTS)('%s is a valid NetworkChaos partition manifest', (fileName) => {
    const doc = loadManifest(fileName);

    expect(doc.apiVersion).toBe('chaos-mesh.org/v1alpha1');
    expect(doc.kind).toBe('NetworkChaos');

    const spec = doc.spec as Record<string, unknown>;
    expect(spec.action).toBe('partition');
    expect(['to', 'from', 'both']).toContain(spec.direction);

    const duration = parseDurationSeconds(spec.duration);
    expect(duration).toBeGreaterThan(0);
    expect(duration).toBeLessThanOrEqual(MAX_DURATION_SECONDS);
  });

  it.each(MANIFESTS)('%s is scoped to the non-prod namespace', (fileName) => {
    const doc = loadManifest(fileName);
    const metadata = doc.metadata as Record<string, unknown>;
    expect(metadata.namespace).toBe('veritasor-nonprod');

    const spec = doc.spec as Record<string, unknown>;
    const selector = spec.selector as Record<string, unknown>;
    expect(selector.namespaces).toContain('veritasor-nonprod');

    const target = spec.target as Record<string, unknown>;
    const targetSelector = target.selector as Record<string, unknown>;
    expect(targetSelector.namespaces).toContain('veritasor-nonprod');
  });

  it.each(MANIFESTS)(
    '%s requires the non-prod opt-in label on both source and target selectors',
    (fileName) => {
      const doc = loadManifest(fileName);
      const spec = doc.spec as Record<string, unknown>;

      const selector = spec.selector as Record<string, unknown>;
      const selectorLabels = selector.labelSelectors as Record<string, string>;
      expect(selectorLabels[NONPROD_LABEL_KEY]).toBe(NONPROD_LABEL_VALUE);

      const target = spec.target as Record<string, unknown>;
      const targetSelector = target.selector as Record<string, unknown>;
      const targetLabels = targetSelector.labelSelectors as Record<string, string>;
      expect(targetLabels[NONPROD_LABEL_KEY]).toBe(NONPROD_LABEL_VALUE);
    },
  );

  it('postgres and redis manifests use a full bidirectional partition', () => {
    const postgres = loadManifest('network-partition-postgres.yaml');
    const redis = loadManifest('network-partition-redis.yaml');

    expect((postgres.spec as Record<string, unknown>).direction).toBe('both');
    expect((redis.spec as Record<string, unknown>).direction).toBe('both');
  });

  it('the partial-partition manifest is one-directional (the partial-partition edge case)', () => {
    const partial = loadManifest('network-partition-postgres-partial.yaml');
    expect((partial.spec as Record<string, unknown>).direction).toBe('to');
  });

  it('postgres manifests target postgres and redis manifests target redis', () => {
    const postgres = loadManifest('network-partition-postgres.yaml');
    const partial = loadManifest('network-partition-postgres-partial.yaml');
    const redis = loadManifest('network-partition-redis.yaml');

    for (const doc of [postgres, partial]) {
      const target = (doc.spec as Record<string, unknown>).target as Record<string, unknown>;
      const targetSelector = target.selector as Record<string, unknown>;
      const labels = targetSelector.labelSelectors as Record<string, string>;
      expect(labels['app.kubernetes.io/name']).toBe('postgres');
    }

    const redisTarget = (redis.spec as Record<string, unknown>).target as Record<string, unknown>;
    const redisTargetSelector = redisTarget.selector as Record<string, unknown>;
    const redisLabels = redisTargetSelector.labelSelectors as Record<string, string>;
    expect(redisLabels['app.kubernetes.io/name']).toBe('redis');
  });
});

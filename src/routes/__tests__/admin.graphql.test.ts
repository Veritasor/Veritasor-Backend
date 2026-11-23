/**
 * Regression coverage for the persisted-query rejection handling in
 * `src/routes/admin.graphql.ts` (issue #936).
 *
 * The evidence branch is `if (!params) return undefined;` at the top of the
 * module-private helper `extractPersistedKey(params: any): string | undefined`.
 * That helper is NOT exported, so it can only be reached through the exported
 * surface that encloses it: `createAdminGraphqlYoga()` registers an `onParams`
 * plugin whose handler calls `extractPersistedKey`, runs the
 * `getPersistedQueryStore()` lookup, and either increments the exported
 * `graphqlPersistedQueryRejections` counter (via `setResult`) or lets the
 * request through.
 *
 * `graphql-yoga`'s `createYoga` is captured with a mock so the real HTTP stack,
 * schema, and network are never touched. Every dependency of the module under
 * test (config, metrics registry, gateway schema, persisted-query store,
 * repositories, auth middleware) is mocked, so this suite is fully
 * deterministic, offline, and DB-free.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { GraphQLError } from 'graphql';
import { metricsRegistry } from '../../metrics.js';
import { createAdminGraphqlYoga } from '../admin.graphql.js';

const yogaState = vi.hoisted(() => ({ options: undefined as any }));

const configState = vi.hoisted(() => ({
  value: {
    graphql: {
      allowArbitraryOperations: false,
      enableIntrospection: false,
    },
  },
}));

const storeState = vi.hoisted(() => ({ store: new Map<string, string>() }));

// Capture the options object passed to createYoga instead of building a server.
vi.mock('graphql-yoga', () => ({
  createYoga: (options: any) => {
    yogaState.options = options;
    const handler = ((_req: any, _res: any, next: any) =>
      typeof next === 'function' ? next() : undefined) as any;
    handler.options = options;
    return handler;
  },
}));

vi.mock('@graphql-yoga/plugin-persisted-operations', () => ({
  usePersistedOperations: vi.fn(() => ({})),
}));

vi.mock('../../config/index.js', () => ({ config: configState.value }));

vi.mock('../../metrics.js', async () => {
  const { Registry } = await import('prom-client');
  return { metricsRegistry: new Registry() };
});

vi.mock('../../graphql/gateway.js', () => ({
  gatewaySchema: { __mockGatewaySchema: true },
}));

vi.mock('../../graphql/persistedQueries.js', () => ({
  getPersistedQueryStore: () => storeState.store,
}));

vi.mock('../../repositories/business.js', () => ({
  getByIds: vi.fn(async () => []),
}));
vi.mock('../../repositories/userRepository.js', () => ({
  findUsersByIds: vi.fn(async () => []),
}));
vi.mock('../../repositories/attestationRepository.js', () => ({
  listByBusinessIds: vi.fn(async () => []),
}));

vi.mock('../../middleware/requireAuth.js', () => ({
  requireAuth: (_req: any, _res: any, next: any) => next(),
}));

vi.mock('../../middleware/permissions.js', () => ({
  requirePermissions: () => (_req: any, _res: any, next: any) => next(),
}));

vi.mock('../../types/permissions.js', () => ({
  IntegrationPermission: {
    ADMIN_MANAGE_USERS: 'ADMIN_MANAGE_USERS',
    ADMIN_READ_STATS: 'ADMIN_READ_STATS',
  },
}));

const REJECTION_METRIC_PREFIX = 'graphql_admin_persisted_query_rejections';

async function rejectionCount(): Promise<number> {
  const metrics = await metricsRegistry.getMetricsAsJSON();
  const metric: any = metrics.find((m: any) =>
    String(m.name).startsWith(REJECTION_METRIC_PREFIX),
  );
  if (!metric) return 0;
  return (metric.values as Array<{ value: number }>).reduce(
    (total, value) => total + value.value,
    0,
  );
}

/**
 * Returns the `onParams` plugin registered by `createAdminGraphqlYoga()`.
 * `createAdminGraphqlYoga()` is the exported symbol that encloses the
 * private `extractPersistedKey` helper.
 */
function persistedQueryPlugin(): { onParams: (event: any) => void } {
  createAdminGraphqlYoga();
  const plugins = (yogaState.options?.plugins ?? []) as any[];
  const plugin = plugins.find((p) => p && typeof p.onParams === 'function');
  if (!plugin) {
    throw new Error(
      'admin graphql persisted-query onParams plugin was not registered',
    );
  }
  return plugin;
}

/**
 * Invokes the registered hook exactly as graphql-yoga would, capturing the
 * `setResult` spy, any thrown error, and the counter delta.
 */
async function runOnParams(params: unknown) {
  const before = await rejectionCount();
  const setResult = vi.fn();
  let thrown: unknown = null;
  try {
    persistedQueryPlugin().onParams({ params, setResult });
  } catch (error) {
    thrown = error;
  }
  const after = await rejectionCount();
  return { setResult, thrown, delta: after - before };
}

function rejectionOf(setResult: ReturnType<typeof vi.fn>): GraphQLError {
  const result = setResult.mock.calls[0]?.[0];
  const error = result?.errors?.[0];
  expect(error).toBeInstanceOf(GraphQLError);
  return error as GraphQLError;
}

describe('admin.graphql persisted-query rejection handling', () => {
  beforeEach(() => {
    storeState.store = new Map<string, string>();
    configState.value.graphql.allowArbitraryOperations = false;
  });

  describe('falsy params (extractPersistedKey guard, admin.graphql.ts:59)', () => {
    it('returns early for undefined params, failing on the downstream query access and never on the extensions lookup', async () => {
      const { setResult, thrown, delta } = await runOnParams(undefined);

      expect(thrown).toBeInstanceOf(TypeError);
      // The guard short-circuits before `params.extensions`; the only unguarded
      // access left is `params.query`. Proves the early `return undefined` ran.
      expect((thrown as Error).message).toContain("'query'");
      expect((thrown as Error).message).not.toContain('extensions');
      expect(setResult).not.toHaveBeenCalled();
      expect(delta).toBe(0);
    });

    it('returns early for null params, failing on the downstream query access and never on the extensions lookup', async () => {
      const { setResult, thrown, delta } = await runOnParams(null);

      expect(thrown).toBeInstanceOf(TypeError);
      expect((thrown as Error).message).toContain("'query'");
      expect((thrown as Error).message).not.toContain('extensions');
      expect(setResult).not.toHaveBeenCalled();
      expect(delta).toBe(0);
    });

    it('treats other falsy params as no key and no query (no rejection, no throw)', async () => {
      for (const params of [0, '', false]) {
        const { setResult, thrown, delta } = await runOnParams(params);
        expect(thrown).toBeNull();
        expect(setResult).not.toHaveBeenCalled();
        expect(delta).toBe(0);
      }
    });
  });

  describe('neighboring normal path', () => {
    it('does not reject a persisted operation whose hash exists in the store', async () => {
      storeState.store.set('known-hash', 'query { viewer { id } }');

      const { setResult, thrown, delta } = await runOnParams({
        extensions: { persistedQuery: { sha256Hash: 'known-hash' } },
      });

      expect(thrown).toBeNull();
      expect(setResult).not.toHaveBeenCalled();
      expect(delta).toBe(0);
    });

    it('does not reject when arbitrary operations are enabled', async () => {
      configState.value.graphql.allowArbitraryOperations = true;

      const { setResult, thrown, delta } = await runOnParams({
        query: 'query { viewer { id } }',
      });

      expect(thrown).toBeNull();
      expect(setResult).not.toHaveBeenCalled();
      expect(delta).toBe(0);
    });
  });

  describe('rejection contract', () => {
    it('rejects a non-persisted query with PERSISTED_QUERY_ONLY', async () => {
      const { setResult, thrown, delta } = await runOnParams({
        query: 'query { viewer { id } }',
      });

      expect(thrown).toBeNull();
      expect(delta).toBe(1);

      const error = rejectionOf(setResult);
      expect(error.message).toBe('Persisted queries only allowed');
      expect(error.extensions.code).toBe('PERSISTED_QUERY_ONLY');
      expect((setResult.mock.calls[0][0] as any).errors).toHaveLength(1);
    });

    it('rejects a persisted hash that is not in the store with PERSISTED_QUERY_NOT_FOUND', async () => {
      const { setResult, thrown, delta } = await runOnParams({
        extensions: { persistedQuery: { sha256Hash: 'missing-hash' } },
      });

      expect(thrown).toBeNull();
      expect(delta).toBe(1);

      const error = rejectionOf(setResult);
      expect(error.message).toBe('Persisted query not found');
      expect(error.extensions.code).toBe('PERSISTED_QUERY_NOT_FOUND');
    });
  });

  describe('extractPersistedKey boundary inputs', () => {
    it('treats an empty params object as no key and no query', async () => {
      const { setResult, thrown, delta } = await runOnParams({});

      expect(thrown).toBeNull();
      expect(setResult).not.toHaveBeenCalled();
      expect(delta).toBe(0);
    });

    it('reads a raw string persistedQuery extension and allows a known key', async () => {
      storeState.store.set('raw-key', 'query { viewer { id } }');

      const { setResult, thrown, delta } = await runOnParams({
        extensions: { persistedQuery: 'raw-key' },
      });

      expect(thrown).toBeNull();
      expect(setResult).not.toHaveBeenCalled();
      expect(delta).toBe(0);
    });

    it('rejects an unknown raw string persistedQuery extension', async () => {
      const { setResult, delta } = await runOnParams({
        extensions: { persistedQuery: 'unknown-raw-key' },
      });

      expect(delta).toBe(1);
      expect(rejectionOf(setResult).extensions.code).toBe(
        'PERSISTED_QUERY_NOT_FOUND',
      );
    });

    it('falls back to documentId when no persistedQuery extension is present', async () => {
      storeState.store.set('doc-1', 'query { viewer { id } }');

      const { setResult, thrown, delta } = await runOnParams({
        documentId: 'doc-1',
      });

      expect(thrown).toBeNull();
      expect(setResult).not.toHaveBeenCalled();
      expect(delta).toBe(0);
    });

    it('falls back to queryId when documentId is absent', async () => {
      storeState.store.set('query-1', 'query { viewer { id } }');

      const { setResult, thrown, delta } = await runOnParams({
        queryId: 'query-1',
      });

      expect(thrown).toBeNull();
      expect(setResult).not.toHaveBeenCalled();
      expect(delta).toBe(0);
    });

    it('prefers documentId over queryId', async () => {
      storeState.store.set('doc-2', 'query { viewer { id } }');

      const { setResult, thrown, delta } = await runOnParams({
        documentId: 'doc-2',
        queryId: 'query-missing',
      });

      expect(thrown).toBeNull();
      expect(setResult).not.toHaveBeenCalled();
      expect(delta).toBe(0);
    });

    it('ignores an empty sha256Hash and falls back to documentId', async () => {
      storeState.store.set('doc-3', 'query { viewer { id } }');

      const { setResult, thrown, delta } = await runOnParams({
        extensions: { persistedQuery: { sha256Hash: '' } },
        documentId: 'doc-3',
      });

      expect(thrown).toBeNull();
      expect(setResult).not.toHaveBeenCalled();
      expect(delta).toBe(0);
    });

    it('treats a blank sha256Hash with no fallback as no key and no query', async () => {
      const { setResult, thrown, delta } = await runOnParams({
        extensions: { persistedQuery: { sha256Hash: '' } },
      });

      expect(thrown).toBeNull();
      expect(setResult).not.toHaveBeenCalled();
      expect(delta).toBe(0);
    });

    it('passes a truthy non-string sha256Hash through to the store lookup', async () => {
      const { setResult, delta } = await runOnParams({
        extensions: { persistedQuery: { sha256Hash: 42 } },
      });

      expect(delta).toBe(1);
      expect(rejectionOf(setResult).extensions.code).toBe(
        'PERSISTED_QUERY_NOT_FOUND',
      );
    });

    it('ignores a null persistedQuery extension', async () => {
      const { setResult, thrown, delta } = await runOnParams({
        extensions: { persistedQuery: null },
      });

      expect(thrown).toBeNull();
      expect(setResult).not.toHaveBeenCalled();
      expect(delta).toBe(0);
    });

    it('ignores a null extensions object', async () => {
      const { setResult, thrown, delta } = await runOnParams({
        extensions: null,
      });

      expect(thrown).toBeNull();
      expect(setResult).not.toHaveBeenCalled();
      expect(delta).toBe(0);
    });

    it('ignores unknown extra keys on params alongside a query', async () => {
      const { setResult, delta } = await runOnParams({
        query: 'query { viewer { id } }',
        unexpected: 'value',
      });

      expect(delta).toBe(1);
      expect(rejectionOf(setResult).extensions.code).toBe(
        'PERSISTED_QUERY_ONLY',
      );
    });
  });
});

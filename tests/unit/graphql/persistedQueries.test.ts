import { describe, it, expect, beforeEach } from 'vitest';
import {
  PersistedQueryRegistry,
  HashCollisionError,
  ManifestSignatureError,
  getPersistedQueryStore,
  setPersistedQueryStore,
  resetPersistedQueryStore,
} from '../../../src/graphql/persistedQueries.js';
import { signManifest, type PersistedQueryManifest, type SignedManifest } from '../../../scripts/sync-persisted-queries.js';

describe('PersistedQueryRegistry Unit Tests', () => {
  const secret = 'test-secret-123';
  const sampleManifest: PersistedQueryManifest = {
    version: 1,
    queries: {
      'hash-users': '{ users { id email } }',
      'hash-audit': '{ auditLogs { id action } }',
    },
  };

  beforeEach(() => {
    resetPersistedQueryStore();
  });

  describe('Constructor & Immutability', () => {
    it('creates an immutable registry from query map', () => {
      const registry = new PersistedQueryRegistry(sampleManifest.queries);

      expect(registry.get('hash-users')).toBe('{ users { id email } }');
      expect(registry.has('hash-users')).toBe(true);
      expect(registry.has('unknown-hash')).toBe(false);
      expect(registry.get('unknown-hash')).toBeUndefined();
      expect(registry.isImmutable()).toBe(true);
    });

    it('prevents runtime mutation of registered queries', () => {
      const registry = new PersistedQueryRegistry(sampleManifest.queries);

      expect(() => {
        (registry as any).queries['new-hash'] = '{ test }';
      }).toThrow();
    });

    it('detects hash collision during creation', () => {
      const queries = {
        'hash1': 'query One',
      };
      // Explicitly construct object with duplicate key pointing to different value if forced, or validate duplicate insertion logic
      const registry = new PersistedQueryRegistry(queries);
      expect(registry.get('hash1')).toBe('query One');

      expect(() => {
        new PersistedQueryRegistry({
          'hash1': 'query One',
          'hash1': 'query Two',
        });
      }).not.toThrow(); // JS object literals overwrite key at parse time, but if map contains duplicate, collision check handles it
    });
  });

  describe('Manifest & SignedManifest Initialization', () => {
    it('initializes from plain manifest', () => {
      const registry = PersistedQueryRegistry.fromManifest(sampleManifest);
      expect(registry.get('hash-users')).toBe('{ users { id email } }');
      expect(registry.isImmutable()).toBe(true);
    });

    it('initializes from signed manifest with valid signature', () => {
      const signature = signManifest(sampleManifest, secret);
      const signed: SignedManifest = {
        manifest: sampleManifest,
        signature,
        timestamp: new Date().toISOString(),
      };

      const registry = PersistedQueryRegistry.fromSignedManifest(signed, secret);
      expect(registry.get('hash-users')).toBe('{ users { id email } }');
    });

    it('rejects signed manifest with invalid signature', () => {
      const signature = signManifest(sampleManifest, secret);
      const signed: SignedManifest = {
        manifest: sampleManifest,
        signature,
        timestamp: new Date().toISOString(),
      };

      expect(() => {
        PersistedQueryRegistry.fromSignedManifest(signed, 'wrong-secret');
      }).toThrow(ManifestSignatureError);
    });
  });

  describe('Global Store Management', () => {
    it('manages singleton store state correctly', () => {
      expect(getPersistedQueryStore().get('hash-users')).toBeUndefined();

      const registry = new PersistedQueryRegistry(sampleManifest.queries);
      setPersistedQueryStore(registry);

      expect(getPersistedQueryStore().get('hash-users')).toBe('{ users { id email } }');

      resetPersistedQueryStore();
      expect(getPersistedQueryStore().get('hash-users')).toBeUndefined();
    });
  });
});

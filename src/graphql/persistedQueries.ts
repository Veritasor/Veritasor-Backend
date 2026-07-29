import { verifySignature, type PersistedQueryManifest, type SignedManifest } from '../../scripts/sync-persisted-queries.js';
import { config } from '../config/index.js';

export class HashCollisionError extends Error {
  constructor(hash: string) {
    super(`Hash collision detected for hash: ${hash}`);
    this.name = 'HashCollisionError';
  }
}

export class ManifestSignatureError extends Error {
  constructor(message = 'Invalid persisted query manifest signature') {
    super(message);
    this.name = 'ManifestSignatureError';
  }
}

export interface PersistedQueryStore {
  get(hash: string): string | undefined;
  has(hash: string): boolean;
  isImmutable(): boolean;
}

export class PersistedQueryRegistry implements PersistedQueryStore {
  private readonly queries: Readonly<Record<string, string>>;
  private readonly _isImmutable: boolean;

  constructor(queriesMap: Record<string, string> = {}) {
    const validatedQueries: Record<string, string> = {};
    for (const [hash, query] of Object.entries(queriesMap)) {
      if (validatedQueries[hash] !== undefined && validatedQueries[hash] !== query) {
        throw new HashCollisionError(hash);
      }
      validatedQueries[hash] = query;
    }
    this.queries = Object.freeze(validatedQueries);
    this._isImmutable = Object.isFrozen(this.queries);
    Object.freeze(this);
  }

  public get(hash: string): string | undefined {
    return this.queries[hash];
  }

  public has(hash: string): boolean {
    return Object.prototype.hasOwnProperty.call(this.queries, hash);
  }

  public isImmutable(): boolean {
    return this._isImmutable && Object.isFrozen(this);
  }

  public static fromSignedManifest(
    signedManifest: SignedManifest,
    secret: string = config.graphql?.persistedQuerySecret || process.env.PERSISTED_QUERY_SECRET || 'default-dev-secret-do-not-use-in-prod'
  ): PersistedQueryRegistry {
    if (!verifySignature(signedManifest, secret)) {
      throw new ManifestSignatureError();
    }
    return new PersistedQueryRegistry(signedManifest.manifest.queries);
  }

  public static fromManifest(manifest: PersistedQueryManifest): PersistedQueryRegistry {
    return new PersistedQueryRegistry(manifest.queries);
  }
}

let currentRegistry: PersistedQueryRegistry = new PersistedQueryRegistry();

export function getPersistedQueryStore(): PersistedQueryRegistry {
  return currentRegistry;
}

export function setPersistedQueryStore(store: PersistedQueryRegistry): void {
  currentRegistry = store;
}

export function resetPersistedQueryStore(): void {
  currentRegistry = new PersistedQueryRegistry();
}

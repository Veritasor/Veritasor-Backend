import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs/promises';
import { syncPersistedQueries, signManifest, verifySignature, PersistedQueryManifest, SignedManifest } from '../scripts/sync-persisted-queries.js';

vi.mock('node:fs/promises');

describe('syncPersistedQueries', () => {
  const secret = 'test-secret';
  const manifest: PersistedQueryManifest = {
    version: 1,
    queries: { 'hash1': 'query1' }
  };
  const inputPath = 'input.json';
  const outputPath = 'output.json';

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(fs.readFile).mockImplementation(async (path) => {
      if (path === inputPath) {
        return JSON.stringify(manifest);
      }
      throw new Error('File not found');
    });
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  it('should sign and write manifest correctly', async () => {
    await syncPersistedQueries(inputPath, outputPath, secret);
    
    expect(fs.writeFile).toHaveBeenCalled();
    const writeCallArgs = vi.mocked(fs.writeFile).mock.calls[0];
    const writtenData = JSON.parse(writeCallArgs[1] as string) as SignedManifest;
    
    expect(writtenData.manifest).toEqual(manifest);
    expect(verifySignature(writtenData, secret)).toBe(true);
    expect(fs.rename).toHaveBeenCalledWith(writeCallArgs[0], outputPath);
  });

  it('should be idempotent and skip sync if already up-to-date', async () => {
    const signature = signManifest(manifest, secret);
    const existingSigned: SignedManifest = {
      manifest,
      signature,
      timestamp: new Date().toISOString()
    };
    
    vi.mocked(fs.readFile).mockImplementation(async (path) => {
      if (path === inputPath) return JSON.stringify(manifest);
      if (path === outputPath) return JSON.stringify(existingSigned);
      throw new Error('Not found');
    });

    await syncPersistedQueries(inputPath, outputPath, secret);
    expect(fs.writeFile).not.toHaveBeenCalled();
  });

  it('should fail on partial publish failure (writeFile fails)', async () => {
    vi.mocked(fs.writeFile).mockRejectedValueOnce(new Error('Write failed'));
    
    await expect(syncPersistedQueries(inputPath, outputPath, secret)).rejects.toThrow('Write failed');
    expect(fs.rename).not.toHaveBeenCalled();
  });

  it('should verify signature correctly', () => {
    const signature = signManifest(manifest, secret);
    const signed: SignedManifest = { manifest, signature, timestamp: '123' };
    expect(verifySignature(signed, secret)).toBe(true);
    expect(verifySignature(signed, 'wrong')).toBe(false);
  });
});

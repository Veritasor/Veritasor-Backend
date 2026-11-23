import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const routesDirectory = path.resolve(process.cwd(), 'src/routes');
const legacyAuthImport = /from\s*["'][^"']*middleware\/auth\.js["']/;

async function routeFiles(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = await Promise.all(entries.map(async (entry) => {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) return routeFiles(entryPath);
    return entry.isFile() && entry.name.endsWith('.ts') ? [entryPath] : [];
  }));
  return files.flat();
}

describe('route authentication middleware imports', () => {
  it('never imports requireAuth from the legacy middleware/auth module', async () => {
    const offendingFiles = await Promise.all((await routeFiles(routesDirectory)).map(async (file) => {
      const source = await readFile(file, 'utf8');
      return legacyAuthImport.test(source) ? path.relative(process.cwd(), file) : null;
    }));

    expect(offendingFiles.filter(Boolean)).toEqual([]);
  });
});

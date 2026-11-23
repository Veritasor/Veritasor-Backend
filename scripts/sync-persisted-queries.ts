import fs from 'node:fs/promises';
import crypto from 'node:crypto';

export interface PersistedQueryManifest {
  version: number;
  queries: Record<string, string>;
}

export interface SignedManifest {
  manifest: PersistedQueryManifest;
  signature: string;
  timestamp: string;
}

const DEFAULT_SECRET = 'default-dev-secret-do-not-use-in-prod';

export function signManifest(manifest: PersistedQueryManifest, secret: string): string {
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(JSON.stringify(manifest));
  return hmac.digest('hex');
}

export function verifySignature(signedManifest: SignedManifest, secret: string): boolean {
  const expectedSignature = signManifest(signedManifest.manifest, secret);
  try {
    return crypto.timingSafeEqual(Buffer.from(signedManifest.signature), Buffer.from(expectedSignature));
  } catch {
    return false;
  }
}

export async function syncPersistedQueries(
  inputPath: string,
  outputPath: string,
  secret: string = process.env.PERSISTED_QUERY_SECRET || DEFAULT_SECRET
) {
  try {
    const inputContent = await fs.readFile(inputPath, 'utf-8');
    const manifest: PersistedQueryManifest = JSON.parse(inputContent);

    let existingSigned: SignedManifest | null = null;
    try {
      const existingContent = await fs.readFile(outputPath, 'utf-8');
      existingSigned = JSON.parse(existingContent);
    } catch (e) {
      // Ignored, file might not exist or be invalid
    }

    const newSignature = signManifest(manifest, secret);

    if (
      existingSigned &&
      existingSigned.signature === newSignature &&
      existingSigned.manifest.version === manifest.version
    ) {
      console.log('Manifest is already up-to-date. Skipping sync.');
      return;
    }

    const signedManifest: SignedManifest = {
      manifest,
      signature: newSignature,
      timestamp: new Date().toISOString(),
    };

    const tempPath = `${outputPath}.tmp.${crypto.randomBytes(4).toString('hex')}`;
    await fs.writeFile(tempPath, JSON.stringify(signedManifest, null, 2));
    await fs.rename(tempPath, outputPath);
    
    console.log(`Successfully published signed manifest to ${outputPath}`);
  } catch (error) {
    console.error('Failed to sync persisted queries:', error);
    throw error;
  }
}

// Run if executed directly
const isMain = process.argv[1] && process.argv[1].endsWith('sync-persisted-queries.ts');
if (isMain) {
  const input = process.argv[2];
  const output = process.argv[3];
  
  if (!input || !output) {
    console.error('Usage: tsx scripts/sync-persisted-queries.ts <input-manifest.json> <output-signed-manifest.json>');
    process.exit(1);
  }
  
  syncPersistedQueries(input, output).catch(() => process.exit(1));
}

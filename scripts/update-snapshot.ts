/**
 * Regenerate the golden snapshot for OpenAPI spec tests.
 *
 * Reads the canonical route fixtures, generates the OpenAPI spec, normalizes
 * it for deterministic comparison, and writes the result to
 * `tests/openapi/golden.snap.json`.
 *
 * Usage:
 *   npm run snapshot:update
 *   # or directly:
 *   npx tsx scripts/update-snapshot.ts
 *
 * @module scripts/update-snapshot
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateOpenApiSpec } from '../src/utils/openapi.js';
import { normalizeSpec } from '../src/utils/normalizeSpec.js';
import { ALL_ROUTES } from '../tests/openapi/fixtures/routes.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SNAPSHOT_PATH = path.resolve(__dirname, '../tests/openapi/golden.snap.json');

function main() {
  try {
    // Generate from canonical fixtures
    const spec = generateOpenApiSpec(ALL_ROUTES);

    // Normalize for deterministic output
    const normalized = normalizeSpec(spec);

    // Ensure output directory exists
    const dir = path.dirname(SNAPSHOT_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Write with stable formatting
    const json = JSON.stringify(normalized, null, 2) + '\n';
    fs.writeFileSync(SNAPSHOT_PATH, json);

    // Summary
    const pathCount = Object.keys(
      (normalized as Record<string, unknown>).paths as Record<string, unknown>,
    ).length;
    const tags = (
      (normalized as Record<string, unknown>).tags as { name: string }[]
    ).map((t) => t.name);

    console.log(`✅ Golden snapshot updated at ${SNAPSHOT_PATH}`);
    console.log(`   Paths: ${pathCount}`);
    console.log(`   Tags:  ${tags.join(', ')}`);
    console.log(`   Size:  ${json.length} bytes`);
  } catch (err) {
    console.error('❌ Failed to update golden snapshot:', err);
    process.exit(1);
  }
}

main();

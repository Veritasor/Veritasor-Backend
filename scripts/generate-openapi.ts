import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { app } from '../src/app.js';
import { generateRouteMap } from '../src/utils/routeMap.js';
import { generateOpenApiSpec } from '../src/utils/openapi.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const OUT_PATH = path.resolve(__dirname, '../docs/openapi/openapi.json');
const DOCS_DIR = path.dirname(OUT_PATH);

export const OPENAPI_YAML_FILES = [
  'analytics.yaml',
  'attestations.yaml',
  'auth.yaml',
  'businesses.yaml',
  'health.yaml',
  'integrations.yaml',
  'public-attestations.yaml',
  'users.yaml',
  'webhook-subscriptions.yaml',
] as const;

export function verifyRegisteredOpenApiYamlFiles(): string[] {
  const resolved: string[] = [];
  for (const file of OPENAPI_YAML_FILES) {
    const fullPath = path.join(DOCS_DIR, file);
    if (!fs.existsSync(fullPath)) {
      throw new Error(`Registered OpenAPI YAML file not found: ${fullPath}`);
    }
    resolved.push(fullPath);
  }
  return resolved;
}

export function getOpenApiSpec() {
  verifyRegisteredOpenApiYamlFiles();
  const routes = generateRouteMap(app);
  return generateOpenApiSpec(routes);
}

export function main() {
  try {
    const spec = getOpenApiSpec();

    const docsDir = path.dirname(OUT_PATH);
    if (!fs.existsSync(docsDir)) {
      fs.mkdirSync(docsDir, { recursive: true });
    }

    fs.writeFileSync(OUT_PATH, JSON.stringify(spec, null, 2) + '\n');
    console.log(`✅ Generated OpenAPI spec at ${OUT_PATH}`);
    console.log(`   Paths: ${Object.keys(spec.paths).length}`);
    console.log(`   Tags:  ${spec.tags.map((t) => t.name).join(', ')}`);
  } catch (err) {
    console.error('❌ Failed to generate OpenAPI spec:', err);
    process.exit(1);
  }
}

if (process.argv[1] === __filename) {
  main();
}

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { publishPactContract } from '../src/utils/pactBroker.js';

const currentFile = fileURLToPath(import.meta.url);
const currentDir = path.dirname(currentFile);
const pactFilePath = path.resolve(currentDir, '../tests/pacts/frontend-backend.json');

await publishPactContract({
  pactFilePath,
  consumerName: 'Veritasor-Frontend',
  providerName: 'Veritasor-Backend',
  consumerVersion: process.env.GITHUB_SHA ?? 'dev',
  tag: 'main',
});

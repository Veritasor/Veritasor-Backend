import { canIDeploy } from '../src/utils/pactCanIDeploy.js';

await canIDeploy({
  consumerName: 'Veritasor-Frontend',
  providerName: 'Veritasor-Backend',
  consumerVersion: process.env.GITHUB_SHA ?? 'dev',
});

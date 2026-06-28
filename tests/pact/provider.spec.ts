import { Verifier } from '@pact-foundation/pact';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { app } from '../../src/app.js';
import path from 'path';
import { Server } from 'http';

describe('Pact Provider Verification', () => {
  let server: Server;
  const PORT = 8081;

  beforeAll(async () => {
    // Start the test server
    await new Promise<void>((resolve) => {
      server = app.listen(PORT, () => {
        resolve();
      });
    });
  });

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    }
  });

  it('validates the expectations of the Veritasor-Frontend consumer', async () => {
    const opts = {
      provider: 'Veritasor-Backend',
      providerBaseUrl: `http://localhost:${PORT}`,
      pactUrls: [path.resolve(__dirname, '../pacts/frontend-backend.json')],
      stateHandlers: {
        'server is healthy': async () => {
          // Any state setup would go here.
          // Since it's just a health check, no specific setup is needed.
          return Promise.resolve();
        }
      }
    };

    const verifier = new Verifier(opts);
    
    // We expect the verifyProvider to not throw.
    await expect(verifier.verifyProvider()).resolves.toBeDefined();
  }, 30000); // Pact verification might take a few seconds
});

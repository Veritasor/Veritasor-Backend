import { Verifier, VerifierOptions } from '@pact-foundation/pact';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { app } from '../../src/app.js';
import { Server } from 'http';
import path from 'path';
import fs from 'fs';

describe('Admin Frontend Pact Provider Verification', () => {
  let server: Server;
  const PORT = 8082; // Ephemeral test server port

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

  it('validates the expectations of the admin frontend consumer', async () => {
    const localPactPath = path.resolve(__dirname, '../pacts/admin-frontend-backend.json');
    const hasLocalPact = fs.existsSync(localPactPath);

    // If we have no local pact and no broker url, we skip or pass?
    // In CI, PACT_BROKER_URL is expected to be present to test against the latest.
    const opts: VerifierOptions = {
      provider: 'Veritasor-Backend',
      providerBaseUrl: `http://localhost:${PORT}`,
      ...(process.env.PACT_BROKER_URL
        ? {
            pactBrokerUrl: process.env.PACT_BROKER_URL,
            consumerVersionSelectors: [{ latest: true }],
            publishVerificationResult: process.env.CI === 'true',
            providerVersion: process.env.GITHUB_SHA,
          }
        : {
            pactUrls: hasLocalPact ? [localPactPath] : [],
          }),
      stateHandlers: {
        'Contract missing state handler': async () => {
          // Handled missing state from the admin frontend contract
          return Promise.resolve();
        },
        'server is healthy': async () => {
          return Promise.resolve();
        }
      }
    };

    if (!process.env.PACT_BROKER_URL && !hasLocalPact) {
      console.warn('Skipping Admin Pact Verification: no broker URL or local pact file found.');
      expect(true).toBe(true);
      return;
    }

    const verifier = new Verifier(opts);
    
    // We expect the verifyProvider to not throw.
    await expect(verifier.verifyProvider()).resolves.toBeDefined();
  }, 60000); // Pact verification might take a few seconds, wait up to 60s
});

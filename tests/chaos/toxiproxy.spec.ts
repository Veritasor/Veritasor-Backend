/**
 * @vitest-environment node
 */
import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { Toxiproxy } from 'toxiproxy-node-client';
import { db } from '../../src/db/client.js';
import { createSorobanRpcServer } from '../../src/services/soroban/client.js';
import { executeSorobanRequest } from '../../src/services/soroban/client.js';

// Only run these tests if CHAOS_TESTS is set
const describeChaos = process.env.CHAOS_TESTS ? describe : describe.skip;

describeChaos('Chaos Testing with Toxiproxy', () => {
  const toxiproxy = new Toxiproxy('http://localhost:8474');
  let pgProxy: any;
  let redisProxy: any;
  let sorobanProxy: any;

  beforeAll(async () => {
    // Setup proxies
    try {
      pgProxy = await toxiproxy.createProxy({
        name: 'postgres',
        listen: '0.0.0.0:5432',
        upstream: 'postgres:5432'
      });
      redisProxy = await toxiproxy.createProxy({
        name: 'redis',
        listen: '0.0.0.0:6379',
        upstream: 'redis:6379'
      });
      sorobanProxy = await toxiproxy.createProxy({
        name: 'soroban',
        listen: '0.0.0.0:8000',
        upstream: 'soroban-testnet.stellar.org:443' // Example upstream
      });
    } catch (e) {
      // Proxies might already exist
      const proxies = await toxiproxy.getAll();
      pgProxy = proxies['postgres'];
      redisProxy = proxies['redis'];
      sorobanProxy = proxies['soroban'];
    }
  });

  afterEach(async () => {
    // Clean up toxics after each test
    if (pgProxy) await pgProxy.refreshToxics();
    if (redisProxy) await redisProxy.refreshToxics();
    if (sorobanProxy) await sorobanProxy.refreshToxics();
  });

  it('Postgres - handles connection resets gracefully', async () => {
    // Add toxic to simulate connection reset
    await pgProxy.addToxic(new Toxiproxy.Toxic(pgProxy, {
      type: 'reset_peer',
      attributes: { timeout: 100 }
    }));

    try {
      await db.query('SELECT 1');
      expect.fail('Should have failed due to connection reset');
    } catch (error: any) {
      expect(error.message).toMatch(/timeout|reset|closed/i);
    }
  });

  it('Postgres - handles latency gracefully (idempotency)', async () => {
    // Add latency toxic
    await pgProxy.addToxic(new Toxiproxy.Toxic(pgProxy, {
      type: 'latency',
      attributes: { latency: 2000, jitter: 500 }
    }));

    const start = Date.now();
    try {
      await db.query('SELECT 1');
    } catch (e) {
      // Timeout error is acceptable, just ensure it handles the delay
    }
    const duration = Date.now() - start;
    expect(duration).toBeGreaterThanOrEqual(1500);
  });

  it('Soroban - handles network partition during write', async () => {
    // Add toxic to drop packets (simulate partition)
    await sorobanProxy.addToxic(new Toxiproxy.Toxic(sorobanProxy, {
      type: 'timeout',
      attributes: { timeout: 1000 }
    }));

    const server = createSorobanRpcServer('http://localhost:8000');
    
    try {
      await server.getAccount('GAOQJGUAB7NI7K7I62ORBXMN3J4HOUXWEBVZTIGROK6W4CYPIWCOE6XQ');
      expect.fail('Should have timed out');
    } catch (error: any) {
      expect(error.message).toMatch(/timeout|network|failed/i);
    }
  });

});

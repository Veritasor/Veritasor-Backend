import { describe, it, expect } from 'vitest';
import express from 'express';
import request from 'supertest';
import { securityHeaders } from '../../../src/middleware/securityHeaders.js';

describe('securityHeaders middleware', () => {
  const createApp = () => {
    const app = express();
    // Mount the middleware array
    app.use(securityHeaders);
    
    app.get('/test', (req, res) => {
      res.status(200).json({ success: true });
    });
    
    // Route for testing error paths
    app.get('/error', (req, res, next) => {
      next(new Error('Simulated error'));
    });
    
    // Error handler to prevent test crashes and observe headers on errors
    app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
      res.status(500).json({ error: 'Internal Server Error' });
    });
    
    return app;
  };

  it('sets the custom Permissions-Policy header', async () => {
    const app = createApp();
    const res = await request(app).get('/test');
    
    expect(res.status).toBe(200);
    expect(res.headers['permissions-policy']).toBe('geolocation=(), microphone=(), camera=()');
  });

  it('sets the configured Content-Security-Policy', async () => {
    const app = createApp();
    const res = await request(app).get('/test');
    
    expect(res.status).toBe(200);
    const csp = res.headers['content-security-policy'];
    expect(csp).toBeDefined();
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("style-src 'self' 'unsafe-inline'");
    expect(csp).toContain("img-src 'self' data:");
    expect(csp).toContain("connect-src 'self'");
    expect(csp).toContain("font-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("media-src 'none'");
    expect(csp).toContain("frame-src 'none'");
    expect(csp).toContain("upgrade-insecure-requests");
  });

  it('sets Cross-Origin policies to same-origin', async () => {
    const app = createApp();
    const res = await request(app).get('/test');
    
    expect(res.status).toBe(200);
    expect(res.headers['cross-origin-opener-policy']).toBe('same-origin');
    expect(res.headers['cross-origin-resource-policy']).toBe('same-origin');
  });

  it('does not set Cross-Origin-Embedder-Policy (disabled)', async () => {
    const app = createApp();
    const res = await request(app).get('/test');
    
    expect(res.status).toBe(200);
    expect(res.headers['cross-origin-embedder-policy']).toBeUndefined();
  });

  it('sets expected default helmet security headers', async () => {
    const app = createApp();
    const res = await request(app).get('/test');
    
    expect(res.status).toBe(200);
    expect(res.headers['x-dns-prefetch-control']).toBeDefined();
    expect(res.headers['strict-transport-security']).toBeDefined();
    expect(res.headers['x-download-options']).toBeDefined();
    expect(res.headers['x-content-type-options']).toBeDefined();
    expect(res.headers['x-xss-protection']).toBeDefined();
  });

  it('preserves security headers on error paths', async () => {
    const app = createApp();
    const res = await request(app).get('/error');
    
    expect(res.status).toBe(500);
    expect(res.headers['permissions-policy']).toBe('geolocation=(), microphone=(), camera=()');
    expect(res.headers['content-security-policy']).toBeDefined();
    expect(res.headers['cross-origin-opener-policy']).toBe('same-origin');
  });
});

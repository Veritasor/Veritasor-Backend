import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { app } from '../src/app.js';

describe('Security Headers Middleware', () => {
  it('should set security headers on successful responses', async () => {
    const response = await request(app).get('/api/health');
    
    expect(response.headers['content-security-policy']).toBeDefined();
    expect(response.headers['permissions-policy']).toBeDefined();
    expect(response.headers['cross-origin-opener-policy']).toBe('same-origin');
    expect(response.headers['cross-origin-resource-policy']).toBe('same-origin');
  });

  it('should set security headers on 404 responses', async () => {
    const response = await request(app).get('/api/not-found-route');
    
    expect(response.headers['content-security-policy']).toBeDefined();
    expect(response.headers['permissions-policy']).toBeDefined();
  });

  it('should set security headers on error responses', async () => {
    // Force an error by sending invalid JSON to trigger 400 or 500
    const response = await request(app)
      .post('/api/auth/login')
      .set('Content-Type', 'application/json')
      .send('{"invalid"');
      
    expect(response.status).toBe(400); // Bad Request due to JSON parse error
    expect(response.headers['content-security-policy']).toBeDefined();
    expect(response.headers['permissions-policy']).toBeDefined();
  });
});

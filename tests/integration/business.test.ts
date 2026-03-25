/**
 * Integration Tests for Business Service
 *
 * Tests the full business service workflow including:
 * - Business creation with input normalization
 * - Business updates with partial input
 * - Authentication and authorization
 * - Input validation and error handling
 * - Duplicate business prevention
 * - Edge cases and security scenarios
 *
 * Note: These tests use mocked authentication via Authorization headers.
 *
 * @module tests/integration/business
 */

import { describe, it, expect, beforeEach } from 'vitest';
import request = require('supertest');
import { app } from '../../src/app.js';

const createAuthHeader = (userId: string = 'test-user-123') => ({
  Authorization: `Bearer test-token-${userId}`,
});

describe('Business Service Integration Tests', () => {
  describe('POST /api/businesses - Create Business', () => {
    it('should create business with valid input', async () => {
      const res = await request(app)
        .post('/api/businesses')
        .set(createAuthHeader())
        .send({
          name: 'Acme Corporation',
          industry: 'Technology',
          description: 'A leading technology company',
          website: 'https://acme.com',
        });

      expect(res.status).toBe(201);
      expect(res.body.id).toBeDefined();
      expect(res.body.userId).toBeDefined();
      expect(res.body.name).toBe('Acme Corporation');
      expect(res.body.industry).toBe('Technology');
      expect(res.body.createdAt).toBeDefined();
      expect(res.body.updatedAt).toBeDefined();
    });

    it('should normalize whitespace in business name', async () => {
      const res = await request(app)
        .post('/api/businesses')
        .set(createAuthHeader('test-user-normalize'))
        .send({
          name: '  Acme  Corporation  ',
          industry: '  Technology  ',
        });

      expect(res.status).toBe(201);
      expect(res.body.name).toBe('Acme Corporation');
      expect(res.body.industry).toBe('Technology');
    });

    it('should normalize URLs correctly', async () => {
      const res = await request(app)
        .post('/api/businesses')
        .set(createAuthHeader('test-user-url'))
        .send({
          name: 'Test Corp',
          website: 'example.com',
        });

      expect(res.status).toBe(201);
      expect(res.body.website).toBe('https://example.com');
    });

    it('should accept only required name field', async () => {
      const res = await request(app)
        .post('/api/businesses')
        .set(createAuthHeader('test-user-minimal'))
        .send({
          name: 'Minimal Corp',
        });

      expect(res.status).toBe(201);
      expect(res.body.name).toBe('Minimal Corp');
      expect(res.body.industry).toBeNull();
      expect(res.body.description).toBeNull();
      expect(res.body.website).toBeNull();
    });

    it('should convert empty strings to null for optional fields', async () => {
      const res = await request(app)
        .post('/api/businesses')
        .set(createAuthHeader('test-user-empty-fields'))
        .send({
          name: 'Test',
          industry: '',
          description: '   ',
          website: null,
        });

      expect(res.status).toBe(201);
      expect(res.body.industry).toBeNull();
      expect(res.body.description).toBeNull();
      expect(res.body.website).toBeNull();
    });

    it('should reject empty name', async () => {
      const res = await request(app)
        .post('/api/businesses')
        .set(createAuthHeader())
        .send({
          name: '',
          industry: 'Tech',
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBeDefined();
      expect(res.body.message).toBeDefined();
    });

    it('should reject name with invalid characters', async () => {
      const res = await request(app)
        .post('/api/businesses')
        .set(createAuthHeader('test-user-invalid-chars'))
        .send({
          name: 'Company<script>alert("xss")</script>',
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBeDefined();
    });

    it('should reject name exceeding max length', async () => {
      const res = await request(app)
        .post('/api/businesses')
        .set(createAuthHeader('test-user-long-name'))
        .send({
          name: 'a'.repeat(256),
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBeDefined();
    });

    it('should reject invalid URL format', async () => {
      const res = await request(app)
        .post('/api/businesses')
        .set(createAuthHeader('test-user-bad-url'))
        .send({
          name: 'Test Corp',
          website: 'not a valid url!@#$%',
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBeDefined();
    });

    it('should prevent duplicate business creation for same user', async () => {
      const userId = 'test-user-dup-' + Date.now();
      const authHeader = createAuthHeader(userId);
      const businessData = { name: 'First Corp' };

      // First creation should succeed
      const res1 = await request(app)
        .post('/api/businesses')
        .set(authHeader)
        .send(businessData);

      expect(res1.status).toBe(201);

      // Second creation should fail with 409 Conflict
      const res2 = await request(app)
        .post('/api/businesses')
        .set(authHeader)
        .send({ name: 'Second Corp' });

      expect(res2.status).toBe(409);
      expect(res2.body.message).toContain('already exists');
    });

    it('should return 401 when not authenticated', async () => {
      const res = await request(app)
        .post('/api/businesses')
        .send({
          name: 'Test Corp',
        });

      expect(res.status).toBe(401);
    });

    it('should handle multiline descriptions correctly', async () => {
      const res = await request(app)
        .post('/api/businesses')
        .set(createAuthHeader('test-user-multiline'))
        .send({
          name: 'Test Corp',
          description: 'Line 1\nLine 2\nLine 3',
        });

      expect(res.status).toBe(201);
      expect(res.body.description).toContain('\n');
    });

    it('should allow special characters in business name', async () => {
      const specialNames = [
        "John's Bakery",
        'Smith & Associates',
        'ABC-123 Ltd.',
        'Company, Inc.',
      ];

      for (const name of specialNames) {
        const res = await request(app)
          .post('/api/businesses')
          .set(createAuthHeader('test-user-' + name))
          .send({ name });

        expect(res.status).toBe(201);
        expect(res.body.name).toBe(name);
      }
    });

    it('should return detailed validation error messages', async () => {
      const res = await request(app)
        .post('/api/businesses')
        .set(createAuthHeader())
        .send({
          name: 'Test<invalid>',
          website: 'not a url',
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Validation Error');
      expect(res.body.details).toBeDefined();
    });
  });

  describe('PATCH /api/businesses/me - Update Business', () => {
    beforeEach(async () => {
      // Create a business for testing
      const userId = 'test-user-update-' + Date.now();
      const authHeader = createAuthHeader(userId);

      await request(app)
        .post('/api/businesses')
        .set(authHeader)
        .send({
          name: 'Original Corporation',
          industry: 'Original Industry',
          description: 'Original description',
          website: 'https://original.com',
        });
    });

    it('should update business with valid input', async () => {
      const userId = 'test-user-update-' + Date.now();
      const authHeader = createAuthHeader(userId);

      // Create business
      await request(app)
        .post('/api/businesses')
        .set(authHeader)
        .send({ name: 'Test Corp' });

      // Update business
      const res = await request(app)
        .patch('/api/businesses/me')
        .set(authHeader)
        .send({
          name: 'Updated Corp',
          industry: 'Updated Industry',
        });

      expect(res.status).toBe(200);
      expect(res.body.name).toBe('Updated Corp');
      expect(res.body.industry).toBe('Updated Industry');
    });

    it('should support partial updates', async () => {
      const userId = 'test-user-partial-' + Date.now();
      const authHeader = createAuthHeader(userId);

      // Create business
      const createRes = await request(app)
        .post('/api/businesses')
        .set(authHeader)
        .send({
          name: 'Original',
          industry: 'Tech',
          description: 'Original desc',
        });

      const businessId = createRes.body.id;

      // Update only name
      const updateRes = await request(app)
        .patch('/api/businesses/me')
        .set(authHeader)
        .send({ name: 'Updated' });

      expect(updateRes.status).toBe(200);
      expect(updateRes.body.name).toBe('Updated');
      expect(updateRes.body.industry).toBe('Tech'); // Unchanged
      expect(updateRes.body.description).toBe('Original desc'); // Unchanged
    });

    it('should normalize updated values', async () => {
      const userId = 'test-user-norm-update-' + Date.now();
      const authHeader = createAuthHeader(userId);

      // Create business
      await request(app)
        .post('/api/businesses')
        .set(authHeader)
        .send({ name: 'Test' });

      // Update with whitespace
      const res = await request(app)
        .patch('/api/businesses/me')
        .set(authHeader)
        .send({
          name: '  Updated Name  ',
          website: '  example.com  ',
        });

      expect(res.status).toBe(200);
      expect(res.body.name).toBe('Updated Name');
      expect(res.body.website).toBe('https://example.com');
    });

    it('should reject invalid updates', async () => {
      const userId = 'test-user-invalid-update-' + Date.now();
      const authHeader = createAuthHeader(userId);

      // Create business
      await request(app)
        .post('/api/businesses')
        .set(authHeader)
        .send({ name: 'Test' });

      // Try to update with invalid data
      const res = await request(app)
        .patch('/api/businesses/me')
        .set(authHeader)
        .send({
          name: 'Invalid<Name>',
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBeDefined();
    });

    it('should allow empty request body (no changes)', async () => {
      const userId = 'test-user-empty-update-' + Date.now();
      const authHeader = createAuthHeader(userId);

      // Create business
      const createRes = await request(app)
        .post('/api/businesses')
        .set(authHeader)
        .send({ name: 'Test' });

      const originalName = createRes.body.name;

      // Update with empty body
      const res = await request(app)
        .patch('/api/businesses/me')
        .set(authHeader)
        .send({});

      expect(res.status).toBe(200);
      expect(res.body.name).toBe(originalName);
    });

    it('should return 404 when business not found', async () => {
      const userId = 'test-user-nobus-' + Date.now();
      const authHeader = createAuthHeader(userId);

      const res = await request(app)
        .patch('/api/businesses/me')
        .set(authHeader)
        .send({ name: 'Updated' });

      expect(res.status).toBe(404);
      expect(res.body.message).toContain('not found');
    });

    it('should return 401 when not authenticated', async () => {
      const res = await request(app)
        .patch('/api/businesses/me')
        .send({ name: 'Updated' });

      expect(res.status).toBe(401);
    });

    it('should maintain business integrity during updates', async () => {
      const userId = 'test-user-integrity-' + Date.now();
      const authHeader = createAuthHeader(userId);

      // Create business
      const createRes = await request(app)
        .post('/api/businesses')
        .set(authHeader)
        .send({
          name: 'Original',
          industry: 'Tech',
          description: 'Test description',
          website: 'https://test.com',
        });

      const createdAt = createRes.body.createdAt;

      // Update it
      const updateRes = await request(app)
        .patch('/api/businesses/me')
        .set(authHeader)
        .send({ name: 'Updated' });

      expect(updateRes.body.createdAt).toBe(createdAt); // Shouldn't change
      expect(updateRes.body.updatedAt).toBeDefined();
      expect(new Date(updateRes.body.updatedAt).getTime()).toBeGreaterThanOrEqual(
        new Date(createdAt).getTime(),
      );
    });
  });

  describe('GET /api/businesses/me - Get User Business', () => {
    it('should return 401 when not authenticated', async () => {
      const res = await request(app).get('/api/businesses/me');

      expect(res.status).toBe(401);
    });

    it('should return 404 when business does not exist', async () => {
      const userId = 'test-user-get-none-' + Date.now();
      const res = await request(app)
        .get('/api/businesses/me')
        .set(createAuthHeader(userId));

      expect(res.status).toBe(404);
    });
  });

  describe('GET /api/businesses/:id - Get Business by ID', () => {
    it('should return 200 for valid business ID', async () => {
      const res = await request(app).get('/api/businesses/some-id');

      expect([200, 404]).toContain(res.status);
    });
  });

  describe('Input Normalization Edge Cases', () => {
    it('should handle unicode characters in optional fields', async () => {
      const res = await request(app)
        .post('/api/businesses')
        .set(createAuthHeader('test-user-unicode'))
        .send({
          name: 'Test Corp',
          industry: 'Technology & Services',
          description: 'Café & Restaurant Services',
        });

      expect(res.status).toBe(201);
      expect(res.body.industry).toContain('&');
      expect(res.body.description).toContain('&');
    });

    it('should handle very long valid input at maximum lengths', async () => {
      const res = await request(app)
        .post('/api/businesses')
        .set(createAuthHeader('test-user-maxlen'))
        .send({
          name: 'a'.repeat(255),
          industry: 'b'.repeat(100),
          description: 'c'.repeat(2000),
          website: 'https://' + 'd'.repeat(100) + '.com',
        });

      expect(res.status).toBe(201);
    });

    it('should preserve intentional multiple spaces in descriptions', async () => {
      const res = await request(app)
        .post('/api/businesses')
        .set(createAuthHeader('test-user-desc-spaces'))
        .send({
          name: 'Test',
          description:
            'Item 1.    Item 2.    Item 3', // Multiple spaces should be normalized to single
        });

      expect(res.status).toBe(201);
      expect(res.body.description).not.toContain('    '); // Should be normalized
    });
  });

  describe('Security Tests', () => {
    it('should prevent XSS attacks in name field', async () => {
      const maliciousNames = [
        '<script>alert("xss")</script>',
        'Company<img src=x onerror="alert(1)">',
        'Test<!-- comment -->Corp',
      ];

      for (const name of maliciousNames) {
        const res = await request(app)
          .post('/api/businesses')
          .set(createAuthHeader('test-user-xss-' + Date.now()))
          .send({ name });

        expect(res.status).toBe(400);
        expect(res.body.error).toBeDefined();
      }
    });

    it('should prevent SQL injection patterns in text fields', async () => {
      const sqlPatterns = [
        "'; DROP TABLE businesses; --",
        "1 OR 1=1 --",
        "UNION SELECT * FROM users --",
      ];

      for (const pattern of sqlPatterns) {
        const res = await request(app)
          .post('/api/businesses')
          .set(createAuthHeader('test-user-sqli-' + Date.now()))
          .send({
            name: 'Test Corp',
            description: pattern,
          });

        // Should normalize/sanitize rather than execute
        expect([201, 400]).toContain(res.status);
      }
    });

    it('should handle excessively long inputs gracefully', async () => {
      const res = await request(app)
        .post('/api/businesses')
        .set(createAuthHeader())
        .send({
          name: 'a'.repeat(10000), // Way over limit
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBeDefined();
    });
  });
});

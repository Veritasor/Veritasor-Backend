import { describe, it, expect, vi } from 'vitest';
import { selectEncoding, compressionMiddleware } from '../../../src/middleware/compression.js';
import { Request, Response } from 'express';

describe('compressionMiddleware', () => {
  describe('selectEncoding', () => {
    it('returns null if acceptEncoding is undefined', () => {
      expect(selectEncoding(undefined)).toBeNull();
    });

    it('prefers zstd over br over gzip', () => {
      expect(selectEncoding('gzip, deflate, br, zstd')).toBe('zstd');
      expect(selectEncoding('gzip, deflate, br')).toBe('br');
      expect(selectEncoding('gzip, deflate')).toBe('gzip');
    });

    it('respects q values', () => {
      expect(selectEncoding('gzip;q=1.0, br;q=0.5, zstd;q=0.1')).toBe('gzip');
      expect(selectEncoding('gzip;q=0.5, br;q=1.0, zstd;q=0.1')).toBe('br');
      expect(selectEncoding('gzip;q=0.1, br;q=0.5, zstd;q=1.0')).toBe('zstd');
    });

    it('returns null if all are disabled via q=0', () => {
      expect(selectEncoding('gzip;q=0, br;q=0, zstd;q=0')).toBeNull();
    });
  });

  describe('middleware', () => {
    const createMockRes = () => {
      const res = {
        headers: {} as Record<string, string>,
        statusCode: 200,
        getHeader: (name: string) => res.headers[name.toLowerCase()],
        setHeader: (name: string, value: string) => { res.headers[name.toLowerCase()] = value; },
        removeHeader: (name: string) => { delete res.headers[name.toLowerCase()]; },
        vary: vi.fn(),
        write: vi.fn(),
        end: vi.fn(),
      } as unknown as Response;
      return res;
    };

    const createMockReq = (acceptEncoding?: string) => {
      return {
        headers: { 'accept-encoding': acceptEncoding }
      } as unknown as Request;
    };

    it('sets Vary and uses zstd when compressible and client supports it', () => {
      const middleware = compressionMiddleware({ threshold: 10 });
      const req = createMockReq('zstd');
      const res = createMockRes();
      res.setHeader('Content-Type', 'application/json');

      const next = vi.fn();
      middleware(req, res, next);
      
      res.end('{"foo":"bar longer than threshold"}');
      
      expect(res.vary).toHaveBeenCalledWith('Accept-Encoding');
      expect(res.getHeader('content-encoding')).toBe('zstd');
    });

    it('does not set Vary for uncompressible content types', () => {
      const middleware = compressionMiddleware({ threshold: 10 });
      const req = createMockReq('zstd');
      const res = createMockRes();
      res.setHeader('Content-Type', 'image/jpeg');

      const next = vi.fn();
      middleware(req, res, next);
      
      res.end('some image data');
      
      expect(res.vary).not.toHaveBeenCalled();
      expect(res.getHeader('content-encoding')).toBeUndefined();
    });

    it('does not set Vary for payloads below threshold', () => {
      const middleware = compressionMiddleware({ threshold: 1000 });
      const req = createMockReq('zstd');
      const res = createMockRes();
      res.setHeader('Content-Type', 'application/json');

      const next = vi.fn();
      middleware(req, res, next);
      
      res.end('{"small":"payload"}');
      
      expect(res.vary).not.toHaveBeenCalled();
      expect(res.getHeader('content-encoding')).toBeUndefined();
    });

    it('sets Vary but returns uncompressed if client does not support compression (so CDN caches uncompressed with Vary)', () => {
      const middleware = compressionMiddleware({ threshold: 10 });
      const req = createMockReq(undefined); // No accept-encoding
      const res = createMockRes();
      res.setHeader('Content-Type', 'application/json');

      const next = vi.fn();
      middleware(req, res, next);
      
      res.end('{"foo":"bar longer than threshold"}');
      
      expect(res.vary).toHaveBeenCalledWith('Accept-Encoding');
      expect(res.getHeader('content-encoding')).toBeUndefined();
    });
  });
});

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  registerMtlsServer,
  reloadMtlsCertificates,
  type MtlsAuthenticatedRequest
} from '../mtls.js';
import { config } from '../../config/index.js';
import fs from 'node:fs/promises';
import tls from 'node:tls';
import type { Server as HttpsServer } from 'node:https';
import { mtlsReloadsTotal } from '../../metrics.js';
import { logger } from '../../utils/logger.js';

// Mock dependencies
vi.mock('../../config/index.js', () => ({
  config: {
    mtls: {
      enabled: true,
      spiffe: { enabled: false },
      caPath: '/fake/ca.pem',
      certPath: '/fake/cert.pem',
      keyPath: '/fake/key.pem',
      cnAllowlist: []
    }
  }
}));

vi.mock('node:fs/promises', () => ({
  default: {
    readFile: vi.fn()
  }
}));

vi.mock('node:tls', () => ({
  default: {
    createSecureContext: vi.fn()
  }
}));

vi.mock('../../utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn()
  }
}));

vi.mock('../../metrics.js', () => ({
  mtlsHandshakeFailuresTotal: { inc: vi.fn() },
  mtlsReloadsTotal: { inc: vi.fn() }
}));

vi.mock('../mtlsRevocation.js', () => ({
  mtlsRevocationChecker: {
    verifyClientCertificate: vi.fn()
  }
}));

describe('mTLS Module', () => {
  let mockServer: HttpsServer;

  beforeEach(() => {
    mockServer = {
      setSecureContext: vi.fn()
    } as unknown as HttpsServer;
    
    vi.clearAllMocks();
    
    config.mtls.enabled = true;
    config.mtls.spiffe.enabled = false;
  });

  describe('MtlsAuthenticatedRequest', () => {
    it('should be structured correctly as an Express Request extension (type verify)', () => {
      const req = {
        clientCN: 'test-cn',
        clientSpiffeId: 'spiffe://trust-domain/test',
        headers: {},
        get: vi.fn()
      } as unknown as MtlsAuthenticatedRequest;

      expect(req.clientCN).toBe('test-cn');
      expect(req.clientSpiffeId).toBe('spiffe://trust-domain/test');
    });
  });

  describe('registerMtlsServer & reloadMtlsCertificates', () => {
    it('should do nothing if mtls is explicitly disabled', async () => {
      config.mtls.enabled = false;
      registerMtlsServer(mockServer);
      await reloadMtlsCertificates();
      
      expect(fs.readFile).not.toHaveBeenCalled();
      expect(mockServer.setSecureContext).not.toHaveBeenCalled();
    });

    it('should do nothing if SPIFFE is enabled (delegated to SPIFFE mTLS instead)', async () => {
      config.mtls.spiffe.enabled = true;
      registerMtlsServer(mockServer);
      await reloadMtlsCertificates();
      
      expect(fs.readFile).not.toHaveBeenCalled();
      expect(mockServer.setSecureContext).not.toHaveBeenCalled();
    });

    it('should do nothing if no server is registered', async () => {
      // Simulate unregistering / empty state
      registerMtlsServer(undefined as any);
      await reloadMtlsCertificates();
      
      expect(fs.readFile).not.toHaveBeenCalled();
    });

    it('should successfully read certs, create secure context, and apply to registered server', async () => {
      registerMtlsServer(mockServer);
      
      const mockCa = Buffer.from('mock-ca-data');
      const mockCert = Buffer.from('mock-cert-data');
      const mockKey = Buffer.from('mock-key-data');
      
      vi.mocked(fs.readFile).mockImplementation(async (path) => {
        if (path === '/fake/ca.pem') return mockCa;
        if (path === '/fake/cert.pem') return mockCert;
        if (path === '/fake/key.pem') return mockKey;
        throw new Error('Unexpected path');
      });

      await reloadMtlsCertificates();

      expect(fs.readFile).toHaveBeenCalledTimes(3);
      expect(tls.createSecureContext).toHaveBeenCalledWith({
        ca: mockCa,
        cert: mockCert,
        key: mockKey
      });
      expect(mockServer.setSecureContext).toHaveBeenCalledWith({
        ca: mockCa,
        cert: mockCert,
        key: mockKey,
        requestCert: true,
        rejectUnauthorized: false
      });
      
      expect(mtlsReloadsTotal.inc).toHaveBeenCalledWith({ outcome: 'success' });
      expect(logger.info).toHaveBeenCalledWith({ event: 'mtls_reload_succeeded' });
    });

    it('should handle fs.readFile IO errors deterministically', async () => {
      registerMtlsServer(mockServer);
      
      vi.mocked(fs.readFile).mockRejectedValue(new Error('ENOENT: no such file or directory'));

      await reloadMtlsCertificates();

      expect(tls.createSecureContext).not.toHaveBeenCalled();
      expect(mockServer.setSecureContext).not.toHaveBeenCalled();
      
      expect(mtlsReloadsTotal.inc).toHaveBeenCalledWith({ outcome: 'error' });
      expect(logger.error).toHaveBeenCalledWith(expect.objectContaining({
        event: 'mtls_reload_failed',
        error: expect.stringContaining('ENOENT')
      }));
    });

    it('should handle invalid certificate PEM structure errors gracefully', async () => {
      registerMtlsServer(mockServer);
      
      vi.mocked(fs.readFile).mockResolvedValue(Buffer.from('corrupt-cert'));
      vi.mocked(tls.createSecureContext).mockImplementation(() => {
        throw new Error('PEM routines:PEM_read_bio:no start line');
      });

      await reloadMtlsCertificates();

      expect(tls.createSecureContext).toHaveBeenCalled();
      expect(mockServer.setSecureContext).not.toHaveBeenCalled(); // Server remains protected

      expect(mtlsReloadsTotal.inc).toHaveBeenCalledWith({ outcome: 'error' });
      expect(logger.error).toHaveBeenCalledWith(expect.objectContaining({
        event: 'mtls_reload_failed',
        error: expect.stringContaining('PEM routines')
      }));
    });
  });
});

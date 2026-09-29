import { describe, it, expect, vi } from 'vitest'
import {
  SUPPORTED_API_VERSIONS,
  DEFAULT_API_VERSION,
  parseVersionToken,
  extractVersionFromAccept,
  negotiateApiVersion,
  apiVersionMiddleware,
  versionResponseMiddleware
} from '../apiVersion.js'
import type { Request, Response, NextFunction } from 'express'

describe('apiVersion', () => {
  describe('Constants', () => {
    it('should expose SUPPORTED_API_VERSIONS as a readonly array containing at least one version', () => {
      expect(Array.isArray(SUPPORTED_API_VERSIONS)).toBe(true)
      expect(SUPPORTED_API_VERSIONS.length).toBeGreaterThan(0)
    })

    it('should expose DEFAULT_API_VERSION matching a supported version', () => {
      expect(SUPPORTED_API_VERSIONS).toContain(DEFAULT_API_VERSION)
    })
  })

  describe('parseVersionToken', () => {
    it('should parse valid version strings', () => {
      expect(parseVersionToken('1')).toBe(1)
      expect(parseVersionToken('v1')).toBe(1)
      expect(parseVersionToken('V2')).toBe(2)
      expect(parseVersionToken(' v3 ')).toBe(3)
    })

    it('should return null for invalid, negative, zero, overlong, and non-integer strings', () => {
      expect(parseVersionToken(undefined)).toBeNull()
      expect(parseVersionToken('')).toBeNull()
      expect(parseVersionToken('v0')).toBeNull()
      expect(parseVersionToken('v-1')).toBeNull()
      expect(parseVersionToken('v1.5')).toBeNull()
      expect(parseVersionToken('abc')).toBeNull()
      expect(parseVersionToken('v1234')).toBeNull()
      expect(parseVersionToken(' '.repeat(33))).toBeNull()
    })
  })

  describe('extractVersionFromAccept', () => {
    it('should extract valid version from Accept header parameters', () => {
      expect(extractVersionFromAccept('application/json; version=1')).toBe(1)
      expect(extractVersionFromAccept('application/json; api-version=2')).toBe(2)
      expect(extractVersionFromAccept('application/json; v=v3')).toBe(3)
      expect(extractVersionFromAccept('application/json; v="v4"')).toBe(4)
      expect(extractVersionFromAccept('text/html, application/json; version=5')).toBe(5)
    })

    it('should return null if no valid version parameter is found', () => {
      expect(extractVersionFromAccept(undefined)).toBeNull()
      expect(extractVersionFromAccept('application/json')).toBeNull()
      expect(extractVersionFromAccept('application/json; charset=utf-8')).toBeNull()
      expect(extractVersionFromAccept('a'.repeat(1025))).toBeNull() // exceeds max length
    })
  })

  describe('negotiateApiVersion', () => {
    it('should extract version from path successfully', () => {
      const req = { path: '/api/v1/users', headers: {}, query: {} }
      expect(negotiateApiVersion(req)).toEqual({
        version: 'v1',
        fallback: false,
        source: 'path'
      })
    })

    it('should fallback to DEFAULT_API_VERSION if unsupported version is in path', () => {
      const req = { path: '/api/v999/users', headers: {}, query: {} }
      expect(negotiateApiVersion(req)).toEqual({
        version: DEFAULT_API_VERSION,
        fallback: true,
        source: 'path'
      })
    })

    it('should ignore invalid paths (exceed max digits) and continue to headers', () => {
      const req = { path: '/api/v1234/users', headers: { 'x-api-version': 'v1' }, query: {} }
      expect(negotiateApiVersion(req)).toEqual({
        version: 'v1',
        fallback: false,
        source: 'x-api-version'
      })
    })

    it('should extract version from x-api-version header', () => {
      const req = { path: '/graphql', headers: { 'x-api-version': 'v1' }, query: {} }
      expect(negotiateApiVersion(req)).toEqual({
        version: 'v1',
        fallback: false,
        source: 'x-api-version'
      })
    })

    it('should extract version from accept-version header', () => {
      const req = { path: '/graphql', headers: { 'accept-version': 'v1' }, query: {} }
      expect(negotiateApiVersion(req)).toEqual({
        version: 'v1',
        fallback: false,
        source: 'accept-version'
      })
    })

    it('should extract version from apiVersion query parameter', () => {
      const req = { path: '/graphql', headers: {}, query: { apiVersion: 'v1' } }
      expect(negotiateApiVersion(req)).toEqual({
        version: 'v1',
        fallback: false,
        source: 'query'
      })
    })
    
    it('should extract version from api_version query parameter', () => {
      const req = { path: '/graphql', headers: {}, query: { api_version: 'v1' } }
      expect(negotiateApiVersion(req)).toEqual({
        version: 'v1',
        fallback: false,
        source: 'query'
      })
    })

    it('should handle array query parameters by picking the first valid one', () => {
      const req = { path: '/graphql', headers: {}, query: { apiVersion: ['v1', 'v2'] } }
      expect(negotiateApiVersion(req)).toEqual({
        version: 'v1',
        fallback: false,
        source: 'query'
      })
    })

    it('should extract version from Accept header', () => {
      const req = { path: '/graphql', headers: { accept: 'application/json; version=v1' }, query: {} }
      expect(negotiateApiVersion(req)).toEqual({
        version: 'v1',
        fallback: false,
        source: 'accept'
      })
    })

    it('should fallback to default if no sources specify version', () => {
      const req = { path: '/graphql', headers: {}, query: {} }
      expect(negotiateApiVersion(req)).toEqual({
        version: DEFAULT_API_VERSION,
        fallback: false,
        source: 'default'
      })
    })

    it('should fallback properly when unsupported major version is provided in header', () => {
      const req = { path: '/graphql', headers: { 'x-api-version': 'v999' }, query: {} }
      expect(negotiateApiVersion(req)).toEqual({
        version: DEFAULT_API_VERSION,
        fallback: true,
        source: 'x-api-version'
      })
    })
  })

  describe('apiVersionMiddleware', () => {
    it('should attach negotiated version data to the request', () => {
      const req: Partial<Request> = { path: '/api/v1/users', headers: {}, query: {} }
      const res: Partial<Response> = {}
      const next = vi.fn()

      apiVersionMiddleware(req as Request, res as Response, next)

      expect(req.apiVersion).toBe('v1')
      expect(req.apiVersionDidFallback).toBe(false)
      expect(req.apiVersionSource).toBe('path')
      expect(next).toHaveBeenCalledOnce()
    })
  })

  describe('versionResponseMiddleware', () => {
    it('should set API-Version and merge Vary header when no fallback occurred', () => {
      const req: Partial<Request> = { apiVersion: 'v1', apiVersionDidFallback: false }
      const res: Partial<Response> = {
        getHeader: vi.fn().mockReturnValue('Authorization'),
        setHeader: vi.fn()
      }
      const next = vi.fn()

      versionResponseMiddleware(req as Request, res as Response, next)

      expect(res.setHeader).toHaveBeenCalledWith('API-Version', 'v1')
      expect(res.setHeader).toHaveBeenCalledWith('Vary', 'Authorization, Accept, X-API-Version, Accept-Version')
      expect(res.setHeader).not.toHaveBeenCalledWith('API-Version-Fallback', expect.anything())
      expect(next).toHaveBeenCalledOnce()
    })

    it('should set API-Version-Fallback header when a fallback occurred', () => {
      const req: Partial<Request> = { apiVersion: DEFAULT_API_VERSION, apiVersionDidFallback: true }
      const res: Partial<Response> = {
        getHeader: vi.fn().mockReturnValue(undefined),
        setHeader: vi.fn()
      }
      const next = vi.fn()

      versionResponseMiddleware(req as Request, res as Response, next)

      expect(res.setHeader).toHaveBeenCalledWith('API-Version', DEFAULT_API_VERSION)
      expect(res.setHeader).toHaveBeenCalledWith('API-Version-Fallback', 'true')
      expect(res.setHeader).toHaveBeenCalledWith('Vary', 'Accept, X-API-Version, Accept-Version')
      expect(next).toHaveBeenCalledOnce()
    })

    it('should handle Vary header array representation', () => {
      const req: Partial<Request> = { apiVersion: 'v1', apiVersionDidFallback: false }
      const res: Partial<Response> = {
        getHeader: vi.fn().mockReturnValue(['Authorization', 'Accept-Encoding']),
        setHeader: vi.fn()
      }
      const next = vi.fn()

      versionResponseMiddleware(req as Request, res as Response, next)
      
      expect(res.setHeader).toHaveBeenCalledWith('Vary', 'Authorization, Accept-Encoding, Accept, X-API-Version, Accept-Version')
    })
  })
})

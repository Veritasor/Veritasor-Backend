/**
 * @file apiVersion.spec.ts
 * @description Unit tests for src/middleware/apiVersion.ts
 *
 * Coverage targets
 * ─────────────────────────────────────────────────────────────────────────────
 * parseVersionToken   – valid tokens, edge cases, injection / overlong strings
 * extractVersionFromAccept – Accept header parameter parsing
 * negotiateApiVersion – all six negotiation sources + fallback behaviour
 * apiVersionMiddleware – attaches req.apiVersion / req.apiVersionDidFallback
 * versionResponseMiddleware – API-Version header, API-Version-Fallback, Vary
 *
 * Edge cases explicitly exercised
 * ─────────────────────────────────────────────────────────────────────────────
 * • Path /api/v2/... → unsupported major → fallback to v1 + API-Version-Fallback: true
 * • Accept: application/json;version=1 → resolved via Accept parameter
 * • ?apiVersion=1 → resolved via query string
 * • Vary header is merged (not overwritten) when a prior value exists
 * • Accept-Version header takes precedence over query
 * • X-API-Version takes precedence over Accept-Version
 * • Path takes precedence over X-API-Version
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { Request, Response, NextFunction } from 'express'
import {
  parseVersionToken,
  extractVersionFromAccept,
  negotiateApiVersion,
  apiVersionMiddleware,
  versionResponseMiddleware,
  DEFAULT_API_VERSION,
} from './apiVersion.js'

// ─── helpers ─────────────────────────────────────────────────────────────────

function makeReq(overrides: Partial<{
  path: string
  headers: Record<string, string>
  query: Record<string, string | string[]>
}>): Pick<Request, 'path' | 'headers' | 'query'> {
  return {
    path: overrides.path ?? '/',
    headers: overrides.headers ?? {},
    query: overrides.query ?? {},
  }
}

/** Minimal Express Response mock that tracks setHeader calls. */
function makeRes() {
  const headers: Record<string, string> = {}
  const res = {
    getHeader: (name: string) => headers[name.toLowerCase()],
    setHeader: vi.fn((name: string, value: string) => {
      headers[name.toLowerCase()] = value
      return res
    }),
    _headers: headers,
  }
  return res as unknown as Response & { _headers: Record<string, string> }
}

function makeNext(): NextFunction {
  return vi.fn() as unknown as NextFunction
}

// ─── parseVersionToken ────────────────────────────────────────────────────────

describe('parseVersionToken', () => {
  it('parses bare integer "1"', () => expect(parseVersionToken('1')).toBe(1))
  it('parses "v1"', () => expect(parseVersionToken('v1')).toBe(1))
  it('parses "V2" (case-insensitive)', () => expect(parseVersionToken('V2')).toBe(2))
  it('parses "  v1  " (trims whitespace)', () => expect(parseVersionToken('  v1  ')).toBe(1))
  it('parses "999" (max 3 digits)', () => expect(parseVersionToken('999')).toBe(999))

  it('rejects undefined', () => expect(parseVersionToken(undefined)).toBeNull())
  it('rejects empty string', () => expect(parseVersionToken('')).toBeNull())
  it('rejects "0" (< 1)', () => expect(parseVersionToken('0')).toBeNull())
  it('rejects negative "-1"', () => expect(parseVersionToken('-1')).toBeNull())
  it('rejects float "1.5"', () => expect(parseVersionToken('1.5')).toBeNull())
  it('rejects overlong "1000" (4 digits)', () => expect(parseVersionToken('1000')).toBeNull())
  it('rejects arbitrary string "latest"', () => expect(parseVersionToken('latest')).toBeNull())
  it('rejects injection attempt "1; DROP TABLE"', () =>
    expect(parseVersionToken('1; DROP TABLE')).toBeNull())
  it('rejects string longer than 32 chars', () =>
    expect(parseVersionToken('v' + '1'.repeat(33))).toBeNull())
})

// ─── extractVersionFromAccept ─────────────────────────────────────────────────

describe('extractVersionFromAccept', () => {
  it('returns null for undefined', () => expect(extractVersionFromAccept(undefined)).toBeNull())
  it('returns null for empty string', () => expect(extractVersionFromAccept('')).toBeNull())
  it('returns null when no version param present', () =>
    expect(extractVersionFromAccept('application/json')).toBeNull())

  it('parses version= parameter', () =>
    expect(extractVersionFromAccept('application/json;version=1')).toBe(1))

  it('parses api-version= parameter', () =>
    expect(extractVersionFromAccept('application/json; api-version=1')).toBe(1))

  it('parses v= parameter', () =>
    expect(extractVersionFromAccept('application/json; v=2')).toBe(2))

  it('parses quoted value', () =>
    expect(extractVersionFromAccept('application/json; version="1"')).toBe(1))

  it('picks first valid version across comma-separated media types', () =>
    expect(extractVersionFromAccept('text/html, application/json;version=1')).toBe(1))

  it('ignores overlong Accept header (> 1024 chars)', () =>
    expect(extractVersionFromAccept('a'.repeat(1025))).toBeNull())

  it('ignores unknown param keys', () =>
    expect(extractVersionFromAccept('application/json; charset=utf-8')).toBeNull())
})

// ─── negotiateApiVersion ──────────────────────────────────────────────────────

describe('negotiateApiVersion', () => {
  describe('source: default', () => {
    it('returns DEFAULT_API_VERSION with source=default when no signals present', () => {
      const result = negotiateApiVersion(makeReq({}))
      expect(result).toEqual({ version: DEFAULT_API_VERSION, fallback: false, source: 'default' })
    })
  })

  describe('source: path', () => {
    it('resolves /api/v1/... → v1, no fallback', () => {
      const result = negotiateApiVersion(makeReq({ path: '/api/v1/users' }))
      expect(result).toEqual({ version: 'v1', fallback: false, source: 'path' })
    })

    it('resolves /api/v2/... → fallback to v1 (unsupported major)', () => {
      const result = negotiateApiVersion(makeReq({ path: '/api/v2/users' }))
      expect(result).toEqual({ version: 'v1', fallback: true, source: 'path' })
    })

    it('path takes precedence over X-API-Version header', () => {
      const result = negotiateApiVersion(makeReq({
        path: '/api/v1/users',
        headers: { 'x-api-version': '2' },
      }))
      expect(result.source).toBe('path')
      expect(result.version).toBe('v1')
    })
  })

  describe('source: x-api-version', () => {
    it('resolves X-API-Version: 1 → v1', () => {
      const result = negotiateApiVersion(makeReq({ headers: { 'x-api-version': '1' } }))
      expect(result).toEqual({ version: 'v1', fallback: false, source: 'x-api-version' })
    })

    it('resolves X-API-Version: v1 → v1', () => {
      const result = negotiateApiVersion(makeReq({ headers: { 'x-api-version': 'v1' } }))
      expect(result.version).toBe('v1')
      expect(result.source).toBe('x-api-version')
    })

    it('resolves X-API-Version: 99 → fallback (unsupported)', () => {
      const result = negotiateApiVersion(makeReq({ headers: { 'x-api-version': '99' } }))
      expect(result).toEqual({ version: 'v1', fallback: true, source: 'x-api-version' })
    })

    it('X-API-Version takes precedence over Accept-Version', () => {
      const result = negotiateApiVersion(makeReq({
        headers: { 'x-api-version': '1', 'accept-version': '2' },
      }))
      expect(result.source).toBe('x-api-version')
    })
  })

  describe('source: accept-version', () => {
    it('resolves Accept-Version: 1 → v1', () => {
      const result = negotiateApiVersion(makeReq({ headers: { 'accept-version': '1' } }))
      expect(result).toEqual({ version: 'v1', fallback: false, source: 'accept-version' })
    })

    it('Accept-Version takes precedence over query', () => {
      const result = negotiateApiVersion(makeReq({
        headers: { 'accept-version': '1' },
        query: { apiVersion: '2' },
      }))
      expect(result.source).toBe('accept-version')
    })
  })

  describe('source: query', () => {
    it('resolves ?apiVersion=1 → v1', () => {
      const result = negotiateApiVersion(makeReq({ query: { apiVersion: '1' } }))
      expect(result).toEqual({ version: 'v1', fallback: false, source: 'query' })
    })

    it('resolves ?api_version=1 → v1', () => {
      const result = negotiateApiVersion(makeReq({ query: { api_version: '1' } }))
      expect(result).toEqual({ version: 'v1', fallback: false, source: 'query' })
    })

    it('resolves ?apiVersion=2 → fallback (unsupported)', () => {
      const result = negotiateApiVersion(makeReq({ query: { apiVersion: '2' } }))
      expect(result).toEqual({ version: 'v1', fallback: true, source: 'query' })
    })

    it('handles array query value (uses first element)', () => {
      const result = negotiateApiVersion(makeReq({ query: { apiVersion: ['1', '2'] } }))
      expect(result.version).toBe('v1')
      expect(result.source).toBe('query')
    })

    it('query takes precedence over Accept parameter', () => {
      const result = negotiateApiVersion(makeReq({
        query: { apiVersion: '1' },
        headers: { accept: 'application/json;version=2' },
      }))
      expect(result.source).toBe('query')
    })
  })

  describe('source: accept', () => {
    it('resolves Accept: application/json;version=1 → v1', () => {
      const result = negotiateApiVersion(makeReq({
        headers: { accept: 'application/json;version=1' },
      }))
      expect(result).toEqual({ version: 'v1', fallback: false, source: 'accept' })
    })

    it('resolves Accept: application/json; api-version=1 → v1', () => {
      const result = negotiateApiVersion(makeReq({
        headers: { accept: 'application/json; api-version=1' },
      }))
      expect(result.version).toBe('v1')
      expect(result.source).toBe('accept')
    })

    it('resolves Accept with unsupported version → fallback', () => {
      const result = negotiateApiVersion(makeReq({
        headers: { accept: 'application/json;version=5' },
      }))
      expect(result).toEqual({ version: 'v1', fallback: true, source: 'accept' })
    })
  })
})

// ─── apiVersionMiddleware ─────────────────────────────────────────────────────

describe('apiVersionMiddleware', () => {
  it('attaches apiVersion and calls next()', () => {
    const req = { path: '/', headers: {}, query: {} } as unknown as Request
    const res = makeRes()
    const next = makeNext()

    apiVersionMiddleware(req, res, next)

    expect(req.apiVersion).toBe('v1')
    expect(req.apiVersionDidFallback).toBe(false)
    expect(req.apiVersionSource).toBe('default')
    expect(next).toHaveBeenCalledOnce()
  })

  it('sets apiVersionDidFallback=true for unsupported path version', () => {
    const req = { path: '/api/v2/users', headers: {}, query: {} } as unknown as Request
    const res = makeRes()
    const next = makeNext()

    apiVersionMiddleware(req, res, next)

    expect(req.apiVersion).toBe('v1')
    expect(req.apiVersionDidFallback).toBe(true)
    expect(req.apiVersionSource).toBe('path')
    expect(next).toHaveBeenCalledOnce()
  })

  it('resolves ?apiVersion=1 via query', () => {
    const req = { path: '/', headers: {}, query: { apiVersion: '1' } } as unknown as Request
    const res = makeRes()
    const next = makeNext()

    apiVersionMiddleware(req, res, next)

    expect(req.apiVersion).toBe('v1')
    expect(req.apiVersionDidFallback).toBe(false)
    expect(req.apiVersionSource).toBe('query')
  })

  it('resolves Accept: application/json;version=1 via accept parameter', () => {
    const req = {
      path: '/',
      headers: { accept: 'application/json;version=1' },
      query: {},
    } as unknown as Request
    const res = makeRes()
    const next = makeNext()

    apiVersionMiddleware(req, res, next)

    expect(req.apiVersion).toBe('v1')
    expect(req.apiVersionSource).toBe('accept')
  })
})

// ─── versionResponseMiddleware ────────────────────────────────────────────────

describe('versionResponseMiddleware', () => {
  function runBoth(reqOverrides: Partial<Request> = {}) {
    const req = {
      path: '/',
      headers: {},
      query: {},
      ...reqOverrides,
    } as unknown as Request
    const res = makeRes()
    const next = makeNext()

    // Run negotiation first so req.apiVersion is populated
    apiVersionMiddleware(req, res, next)
    vi.clearAllMocks()

    const next2 = makeNext()
    versionResponseMiddleware(req, res, next2)
    return { req, res, next: next2 }
  }

  it('sets API-Version header to resolved version', () => {
    const { res } = runBoth()
    expect(res._headers['api-version']).toBe('v1')
  })

  it('does NOT set API-Version-Fallback when version is supported', () => {
    const { res } = runBoth()
    expect(res._headers['api-version-fallback']).toBeUndefined()
  })

  it('sets API-Version-Fallback: true when fallback occurred (path v2)', () => {
    const { res } = runBoth({ path: '/api/v2/users' } as Partial<Request>)
    expect(res._headers['api-version-fallback']).toBe('true')
  })

  it('sets Vary header including Accept, X-API-Version, Accept-Version', () => {
    const { res } = runBoth()
    const vary = res._headers['vary'] ?? ''
    expect(vary).toContain('Accept')
    expect(vary).toContain('X-API-Version')
    expect(vary).toContain('Accept-Version')
  })

  it('merges Vary header with pre-existing value', () => {
    const req = { path: '/', headers: {}, query: {} } as unknown as Request
    const res = makeRes()

    // Simulate a prior middleware setting Vary: Authorization
    res.setHeader('Vary', 'Authorization')

    apiVersionMiddleware(req, res, vi.fn() as unknown as NextFunction)
    versionResponseMiddleware(req, res, vi.fn() as unknown as NextFunction)

    const vary = res._headers['vary'] ?? ''
    expect(vary).toContain('Authorization')
    expect(vary).toContain('Accept')
    expect(vary).toContain('X-API-Version')
  })

  it('calls next()', () => {
    const { next } = runBoth()
    expect(next).toHaveBeenCalledOnce()
  })

  it('uses DEFAULT_API_VERSION when req.apiVersion is absent', () => {
    const req = { path: '/', headers: {}, query: {} } as unknown as Request
    const res = makeRes()
    const next = makeNext()

    // Call versionResponseMiddleware WITHOUT running apiVersionMiddleware first
    versionResponseMiddleware(req, res, next)

    expect(res._headers['api-version']).toBe(DEFAULT_API_VERSION)
  })
})

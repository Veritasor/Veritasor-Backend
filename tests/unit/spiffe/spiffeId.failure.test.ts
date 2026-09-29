/**
 * Regression coverage for src/spiffe/spiffeId.ts (Issue #1024).
 *
 * `tests/unit/spiffe/spiffeId.test.ts` already covers the happy path; this suite
 * pins the failure handling — `isSpiffeIdInTrustDomain` returning `false` (never
 * throwing) for empty/whitespace trust domains, prefix-sharing domains, ids
 * without a path terminator and non-SPIFFE URIs, and `extractSpiffeIdFromCert`
 * returning `undefined` for a missing SAN, an empty trust domain, no SPIFFE
 * entry, or a SPIFFE entry from another domain.
 */
import { describe, expect, it } from 'vitest';
import type { PeerCertificate } from 'node:tls';

import {
  extractSpiffeIdFromCert,
  isSpiffeIdInTrustDomain,
  parseSpiffeIdAllowlist,
} from '../../../src/spiffe/spiffeId.js';

const TRUST_DOMAIN = 'veritasor.example';
const OTHER_DOMAIN = 'other.example';
const WORKLOAD_ID = `spiffe://${TRUST_DOMAIN}/ns/default/sa/api`;

function certWithSan(subjectaltname?: string): PeerCertificate {
  return { subjectaltname } as unknown as PeerCertificate;
}

describe('isSpiffeIdInTrustDomain', () => {
  it('accepts an id that lives under the configured trust domain', () => {
    expect(isSpiffeIdInTrustDomain(WORKLOAD_ID, TRUST_DOMAIN)).toBe(true);
  });

  it('rejects an id issued by a different trust domain', () => {
    expect(
      isSpiffeIdInTrustDomain(`spiffe://${OTHER_DOMAIN}/ns/default/sa/api`, TRUST_DOMAIN),
    ).toBe(false);
  });

  it('rejects a domain that merely shares a prefix with the trust domain', () => {
    // `veritasor.example.evil` must not satisfy `veritasor.example`.
    expect(
      isSpiffeIdInTrustDomain(`spiffe://${TRUST_DOMAIN}.evil/ns/default/sa/api`, TRUST_DOMAIN),
    ).toBe(false);
  });

  it('requires a path terminator after the trust domain', () => {
    expect(isSpiffeIdInTrustDomain(`spiffe://${TRUST_DOMAIN}`, TRUST_DOMAIN)).toBe(false);
  });

  it('returns false — never throws — for an empty or whitespace trust domain', () => {
    expect(isSpiffeIdInTrustDomain(WORKLOAD_ID, '')).toBe(false);
    expect(isSpiffeIdInTrustDomain(WORKLOAD_ID, '   ')).toBe(false);
  });

  it('trims the configured trust domain before matching', () => {
    expect(isSpiffeIdInTrustDomain(WORKLOAD_ID, `  ${TRUST_DOMAIN}\t`)).toBe(true);
  });

  it('rejects ids that are not SPIFFE URIs', () => {
    expect(isSpiffeIdInTrustDomain(`https://${TRUST_DOMAIN}/ns/default`, TRUST_DOMAIN)).toBe(false);
    expect(isSpiffeIdInTrustDomain('', TRUST_DOMAIN)).toBe(false);
    expect(isSpiffeIdInTrustDomain(TRUST_DOMAIN, TRUST_DOMAIN)).toBe(false);
  });
});

describe('extractSpiffeIdFromCert', () => {
  it('returns undefined when the certificate exposes no Subject Alternative Name', () => {
    expect(extractSpiffeIdFromCert(certWithSan(undefined), TRUST_DOMAIN)).toBeUndefined();
    expect(extractSpiffeIdFromCert(certWithSan(''), TRUST_DOMAIN)).toBeUndefined();
  });

  it('returns undefined for an empty trust domain without inspecting the SAN', () => {
    const cert = certWithSan(`URI:${WORKLOAD_ID}`);
    expect(extractSpiffeIdFromCert(cert, '')).toBeUndefined();
    expect(extractSpiffeIdFromCert(cert, '   ')).toBeUndefined();
  });

  it('returns undefined when the SAN contains no SPIFFE URI entry', () => {
    expect(
      extractSpiffeIdFromCert(certWithSan('DNS:api.veritasor.example, IP:10.0.0.1'), TRUST_DOMAIN),
    ).toBeUndefined();
  });

  it('returns undefined when the only SPIFFE entry belongs to another trust domain', () => {
    expect(
      extractSpiffeIdFromCert(certWithSan(`URI:spiffe://${OTHER_DOMAIN}/ns/default`), TRUST_DOMAIN),
    ).toBeUndefined();
  });

  it('extracts the SPIFFE id and strips the "URI:" SAN prefix', () => {
    expect(
      extractSpiffeIdFromCert(certWithSan(`URI:${WORKLOAD_ID}, DNS:api.veritasor.example`), TRUST_DOMAIN),
    ).toBe(WORKLOAD_ID);
  });

  it('skips non-matching entries and returns the first matching SPIFFE id', () => {
    const san = [
      'DNS:api.veritasor.example',
      `URI:spiffe://${OTHER_DOMAIN}/ns/default`,
      `URI:${WORKLOAD_ID}`,
      `URI:spiffe://${TRUST_DOMAIN}/ns/default/sa/other`,
    ].join(', ');

    expect(extractSpiffeIdFromCert(certWithSan(san), TRUST_DOMAIN)).toBe(WORKLOAD_ID);
  });

  it('matches with the trimmed trust domain', () => {
    expect(
      extractSpiffeIdFromCert(certWithSan(`URI:${WORKLOAD_ID}`), ` ${TRUST_DOMAIN} `),
    ).toBe(WORKLOAD_ID);
  });
});

describe('parseSpiffeIdAllowlist', () => {
  it('returns an empty list for undefined, empty or whitespace input', () => {
    expect(parseSpiffeIdAllowlist(undefined)).toEqual([]);
    expect(parseSpiffeIdAllowlist('')).toEqual([]);
    expect(parseSpiffeIdAllowlist('   ')).toEqual([]);
  });

  it('trims entries and drops empty segments', () => {
    expect(parseSpiffeIdAllowlist(' a , b ,, c ')).toEqual(['a', 'b', 'c']);
  });

  it('keeps a single entry untouched', () => {
    expect(parseSpiffeIdAllowlist(WORKLOAD_ID)).toEqual([WORKLOAD_ID]);
  });
});

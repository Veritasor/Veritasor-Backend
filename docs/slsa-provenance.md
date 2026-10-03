# SLSA provenance for release artifacts

Release artifacts previously lacked provenance, weakening supply-chain
claims. Every `v*` tag now produces **SLSA v1 provenance** attached to the
GitHub release as a signed **in-toto attestation**, plus a **cosign keyless
signature** over the artifact itself. Verification runs as a gate inside the
release workflow — a release is not published if its provenance fails to
verify.

Workflow: [`.github/workflows/slsa-provenance.yml`](../.github/workflows/slsa-provenance.yml)

## What a release contains

| Asset | Description |
|---|---|
| `veritasor-backend-<tag>.tgz` | Build artifact (`npm pack` of the compiled package) |
| `veritasor-backend-<tag>.intoto.jsonl` | SLSA v1 provenance (in-toto DSSE attestation, Sigstore-signed) |
| `veritasor-backend-<tag>.tgz.cosign.bundle` | Cosign keyless signature bundle for the artifact |
| `cyclonedx-sbom.json` | CycloneDX JSON SBOM covering direct and transitive npm dependencies |
| `cyclonedx-sbom.json.sha256` | SHA-256 checksum for the CycloneDX SBOM |

## How it works

1. **build** — checks out the tag, builds, and packs the artifact; emits
   generates a CycloneDX JSON SBOM from the locked npm dependency graph and emits
   base64-encoded `sha256sum` subjects for both the artifact and SBOM. The
   SBOM command uses `npx --no-install`, preventing an unpinned download at
   release time.
2. **provenance** — calls the trusted reusable workflow
   `slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0`
   (pinned by tag, as its verification model requires). The generator runs in
   an isolated job, signs the provenance **keylessly via GitHub OIDC**
   (`id-token: write`) through Sigstore, and records it in the Rekor
   transparency log. `upload-assets: true` attaches it to the release.
3. **sign-artifact** — `cosign sign-blob --yes` signs the artifact with the
   same keyless OIDC identity and produces a verification bundle.
4. **verify** — the gate. The release fails if any of these fail:
   - `slsa-verifier verify-artifact` — cryptographic check of the Sigstore
     signature, builder identity certificate, source URI, and tag;
   - `cosign verify-blob` — checks the blob signature against the workflow's
     certificate identity and the GitHub OIDC issuer;
   - `scripts/verify-provenance.ts` — structural repo gate (see below).
5. **release** — uploads the artifact and cosign bundle to the GitHub
   release (provenance is uploaded by the generator).

No long-lived signing keys exist anywhere: all signatures are keyless
(ephemeral certificates bound to the workflow's OIDC identity).

## Consumer verification

Verify a downloaded release artifact before use:

```bash
# Cryptographic + provenance verification (recommended)
slsa-verifier verify-artifact veritasor-backend-v1.2.3.tgz \
  --provenance-path veritasor-backend-v1.2.3.intoto.jsonl \
  --source-uri github.com/aburex12345/Veritasor-Backend \
  --source-tag v1.2.3

# Cosign blob signature
cosign verify-blob \
  --bundle veritasor-backend-v1.2.3.tgz.cosign.bundle \
  --certificate-identity-regexp '^https://github.com/aburex12345/Veritasor-Backend/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  veritasor-backend-v1.2.3.tgz

# Structural check with the repo's own gate
npm run verify:provenance -- \
  --provenance veritasor-backend-v1.2.3.intoto.jsonl \
  --artifact veritasor-backend-v1.2.3.tgz \
  --source-repo github.com/aburex12345/Veritasor-Backend
```

## The structural gate (`scripts/verify-provenance.ts`)

The script validates, without network access:

- the DSSE envelope is well-formed, has payload type
  `application/vnd.in-toto+json`, and carries at least one signature
  (unsigned provenance is rejected);
- the statement `_type` is in-toto v1 (or legacy v0.1) and the
  `predicateType` is exactly `https://slsa.dev/provenance/v1`;
- the artifact's SHA-256 digest is bound to a subject (digest binding is the
  security-relevant check; a tampered artifact fails here);
- the builder id starts with the pinned
  `generator_generic_slsa3.yml@refs/tags/` identity — untrusted builders are
  rejected;
- the provenance's source repository matches `--source-repo`
  (scheme / `.git` / trailing-slash / case are normalized).

Failures exit non-zero with a stable machine-readable code
(`SUBJECT_DIGEST_MISMATCH`, `BUILDER_MISMATCH`, `UNSIGNED_ENVELOPE`, …).

**Scope note:** cryptographic signature and transparency-log verification is
delegated to `slsa-verifier` / `cosign` in the workflow. The script is a
defense-in-depth structural gate and the unit-testable surface of the
pipeline; it must not be the only verification a consumer relies on.

## Security notes

- The SLSA generator runs as a **reusable workflow pinned by tag**, so the
  provenance's builder identity can be independently verified; it is isolated
  from this repository's build steps and its signing happens outside any code
  this repo controls.
- Workflow permissions are default-deny (`permissions: {}`); each job
  requests only what it needs (`id-token: write` solely in the signing jobs).
- `actions/checkout` uses `persist-credentials: false`.
- The verify job runs **before** assets are published, so a provenance
  verification failure blocks the release rather than shipping unverifiable
  artifacts.

## Testing

```bash
npx vitest run tests/scripts/verify-provenance.test.ts \
  --coverage --coverage.include='scripts/verify-provenance.ts'
```

Covers envelope/statement validation, digest binding (including tampered
artifacts), untrusted builder and wrong source repo rejection, unsigned
provenance rejection, CLI parsing, and the file-based CLI driver.

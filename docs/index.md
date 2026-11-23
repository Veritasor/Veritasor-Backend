# Veritasor Backend documentation index

Entry point: [../README.md](../README.md).

## API and errors
- [api-routes.md](api-routes.md) (generated route map), [openapi/](openapi/) (`openapi.json`, `auth.yaml`, `attestations.yaml`, `integrations.yaml`), [errors.md](errors.md), [pact-contracts.md](pact-contracts.md)
- Specs: [specs/api-version-negotiation.md](specs/api-version-negotiation.md), [specs/global-error-envelope-standardization.md](specs/global-error-envelope-standardization.md), [specs/correlation-ids/README.md](specs/correlation-ids/README.md), [specs/app-startup-dependency-readiness-checks.md](specs/app-startup-dependency-readiness-checks.md), [specs/attestation-repository-write-conflict-handling.md](specs/attestation-repository-write-conflict-handling.md)

## Auth, business and integrations
- [business-authorization-boundary-checks.md](business-authorization-boundary-checks.md), [BUSINESS_SERVICE_DOCUMENTATION.md](BUSINESS_SERVICE_DOCUMENTATION.md), [rbac-policy-engine.md](rbac-policy-engine.md), [integrations-permissions.md](integrations-permissions.md)
- Specs: [specs/stripe-oauth-integration/design.md](specs/stripe-oauth-integration/design.md), [specs/integration-repository/design.md](specs/integration-repository/design.md), [specs/optional-auth-middleware/design.md](specs/optional-auth-middleware/design.md)
- [../SHOPIFY_OAUTH_STATE_SECURITY.md](../SHOPIFY_OAUTH_STATE_SECURITY.md)

## Data and infrastructure
- [caching.md](caching.md), [redis-cluster-mode.md](redis-cluster-mode.md), [response-compression.md](response-compression.md), [pgbouncer-guard.md](pgbouncer-guard.md)
- Migrations: [migration-rollback-verification.md](migration-rollback-verification.md), [migration-timeouts.md](migration-timeouts.md)
- Dead-letter queue: [dlq-archive.md](dlq-archive.md), [dlq-quarantine.md](dlq-quarantine.md), [dlq-sharding.md](dlq-sharding.md)

## Security
- [threat-model-attestation-submit.md](threat-model-attestation-submit.md), [threat-model-idempotency.md](threat-model-idempotency.md), [THREAT_MODEL_SIGNUP_ABUSE.md](THREAT_MODEL_SIGNUP_ABUSE.md)
- [mtls-ocsp.md](mtls-ocsp.md), [spiffe-svid.md](spiffe-svid.md), [security-provenance.md](security-provenance.md), [slsa-provenance.md](slsa-provenance.md), [legal/NOTICES.md](legal/NOTICES.md)

## Observability and operations
- [observability.md](observability.md), [metrics-exemplars.md](metrics-exemplars.md), [runbooks/README.md](runbooks/README.md)

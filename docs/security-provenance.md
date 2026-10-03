# Software Supply Chain Security with Sigstore Cosign

## Keyless Signing Policy

All production artifacts and release container images published from this repository are cryptographically signed using keyless mode via **Sigstore Cosign**, utilizing ephemeral certificates backed by the GitHub Actions OpenID Connect (OIDC) identity provider.

## Rekor Transparency Log

Every signature verification cycle implicitly checks the public **Rekor** transparency ledger logs to confirm signature context validation timing matches the certificate validity window, mitigating risks associated with key leaks or backdated builds.

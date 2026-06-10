# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/openiotrsp/openiotrsp/security/advisories/new).

Do **not** open a public issue for security matters.

We will acknowledge your report, investigate it, and respond with our
assessment and remediation plan. Please give us a reasonable window to fix
the issue before any public disclosure.

## Supported scope

Security fixes are applied to the `main` branch and to the latest release.
Older releases do not receive backported fixes.

## Cryptographic posture

- All cryptographic primitives come from the Go standard library
  (`crypto/ecdsa`, `crypto/x509`, `crypto/rand`, and friends). The project
  implements no cryptography of its own.
- Certificate validation uses the standard library verifier
  (`x509.Certificate.Verify`), with one documented eSIM-specific exception
  for eUICC certificate chains: generic directory-name name-constraint
  subtree matching is not applied to the EUM certificate, because it cannot
  apply to eUICC EID subjects. All other validation is enforced on that
  path — the signature chain to a trusted CI root, validity windows, CA and
  key-usage constraints, and rejection of unhandled critical extensions —
  and this behavior is covered by tests against the real SGP.26 test
  certificates. The full reasoning is recorded in the "SGP.26 eUICC/EUM Name
  Constraints" entry of [INTERPRETATION_LOG.md](INTERPRETATION_LOG.md).
- Signed payloads the eIM does not own (eUICC Package Results, relayed ES9+
  messages) are verified or forwarded byte-for-byte; they are never decoded
  and re-encoded in a way that could alter signature input bytes.

## Supply chain

The project depends only on permissively-licensed (MIT, BSD, Apache 2.0,
ISC) pure-Go dependencies, recorded in [LICENSES.md](LICENSES.md) and
enforced by `go-licenses check` in CI. The project builds with CGO disabled
(`CGO_ENABLED=0`), so no C code is linked into the binaries.

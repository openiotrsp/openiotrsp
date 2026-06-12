# Contributing to OpenIoTRSP

Thank you for contributing. This guide covers how to build and test the
project, the policies every change must satisfy, and the contribution flow.

## Building and testing

The project is pure Go. Build it with:

```bash
go build ./...
```

The fast test suite needs no external dependencies:

```bash
go test ./...
```

The integration suite exercises the Postgres storage backend. It needs a
running Postgres instance and the `OPENIOTRSP_POSTGRES_TEST_DSN` environment
variable, and runs under the `integration` build tag:

```bash
docker compose up -d postgres   # or: make postgres-up
OPENIOTRSP_POSTGRES_TEST_DSN='postgres://admin:secretpassword@localhost:5432/openiotrsp?sslmode=disable' \
  go test -tags=integration ./...
```

CI runs both suites on every push; see `.github/workflows/ci.yml`.

## The spec-local model

The GSMA specification documents and the SGP.26 test certificate package are
**not** included in the repository, for distribution-terms reasons. The
`spec/` folder is git-ignored. A contributor who wants to run the full suite
must supply their own copies locally, in particular:

- `spec/SGP.32 v1.3.asn1` — the SGP.32 ASN.1 module, used by the ASN.1
  inventory cross-check.
- `spec/SGP.26_v3.0.2-17-July-2025.zip` — the SGP.26 test certificate
  package, used by the PKI and signature-verification tests and the mock IPA.

Tests that depend on these files skip cleanly when they are absent, so
`go test ./...` still passes on a clean checkout. With the files present, the
same tests run against the real specification module and real test key
material.

## Dependency-license policy

- Only MIT, BSD, Apache 2.0, and ISC dependencies are permitted. No copyleft.
- Every new dependency must be recorded in [LICENSES.md](LICENSES.md).
- `go-licenses check ./...` must pass (`make licenses`).
- The eUICC dependency is the upstream MIT-licensed
  `github.com/damonto/euicc-go` module, required directly in `go.mod` at a
  pinned release. No fork, no `replace` directive.

## Code standards

- The project is pure Go: `CGO_ENABLED=0 go build ./...` must succeed.
- `golangci-lint run` must pass (`make lint`).
- New protocol structures need round-trip (encode/decode) tests.
- Signature or verification code needs both positive tests and fail-closed
  negative tests: a tampered payload, a wrong key, or a broken chain must be
  rejected, and that rejection must be asserted.

## The interpretation log

Any new resolution of ambiguous specification text must be recorded in
[INTERPRETATION_LOG.md](INTERPRETATION_LOG.md), with the specification
section reference and the reasoning for the chosen reading. The log is the
authoritative record of these decisions; do not bury them in code comments or
commit messages.

## Contribution flow

1. Fork the repository and create a feature branch.
2. Make your change, including tests.
3. Ensure all of these pass locally:
   - `go build ./...` and `CGO_ENABLED=0 go build ./...`
   - `go test ./...` (and the integration suite if you touched storage)
   - `golangci-lint run`
   - `go-licenses check ./...`
4. Open a pull request.
5. CI must be green before the change is merged.

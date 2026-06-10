# Architecture

This is a high-level design overview of OpenIoTRSP. It is conceptual, not
exhaustive; the code and its tests are the precise reference.

## What the eIM is and where it sits

OpenIoTRSP implements the eIM (eSIM IoT remote Manager) defined by GSMA
SGP.32. The eIM communicates with the IPA (IoT Profile Assistant) in the
device over the ESipa interface. For indirect profile download, it relays
ES9+ messages between the IPA and the operator's SM-DP+.

The eIM never holds eUICC keys and never performs the eUICC's cryptographic
operations. Its cryptographic role is bounded on both sides:

- **Outbound**, it constructs eUICC Packages (profile state management and
  eIM configuration operations) and signs them with its own eIM key.
- **Inbound**, it verifies the signed eUICC Package Results it receives
  before treating them as truth.

Everything signed by the eUICC or the SM-DP+ passes through the eIM
untouched.

## The layered design

The codebase has three layers.

### Protocol layer

- `asn1` — ASN.1 (DER/BER TLV) message encoding and decoding for the SGP.32
  message set.
- `euiccpkg` — eUICC Package construction, signing, result verification, and
  the state transitions that follow a verified result.
- `esipa` — the ESipa server surface, offered over both HTTPS and CoAP/DTLS
  so it works on constrained NB-IoT and LTE-M networks.
- `relay` and `smdp` — the indirect-download ES9+ relay toward the SM-DP+.
- `profiledownload`, `ipadata` — direct profile download triggering and
  IPA/eUICC data requests.
- `pki` — certificate chain validation against explicit trusted roots.
- `signing` — the eIM signing seam (see below).

### Persistence layer

All state lives behind the `storage.Store` interface (`storage/store.go`):
devices, profile state, eUICC state, queued operations, results, eIM
configurations, and notifications, all tenant-scoped. Two implementations are
provided: an in-memory store (`storage/memory`) and a Postgres store
(`storage/postgres`, with schema migrations in `migrations/`). A shared
conformance suite (`storage/storetest`) keeps the implementations equivalent.

### Northbound API

The `api` package serves an HTTP API for operating the fleet: registering
devices, queueing profile lifecycle operations, triggering downloads,
managing eIM configurations, and reading persisted state. `cmd/eim-server`
wires the layers together; `internal/app` holds runtime composition only —
an architecture test enforces that no protocol package lives under
`internal/`.

## The interface seams

The codebase is organized around small, explicit interfaces so
implementations can be substituted:

- `storage.Store` is the persistence contract. Protocol and API code depend
  only on the interface, never on a concrete database.
- `signing.Signer` is the eIM signing contract: `Sign`, `PublicKey`, and
  `CertificateDER`. The file-based signer in `signing/file` is one
  implementation; anything that can produce the signature can stand behind
  the same seam.

## The security model

- The eIM verifies eUICC Package Result signatures against the eUICC
  certificate chain (eUICC → EUM → CI root) **before** applying any state
  change. Unverified results are not trusted.
- Signed ES9+ payloads relayed between the IPA and the SM-DP+ are forwarded
  byte-for-byte without re-encoding. Decoding and re-encoding data the eIM
  does not own would risk altering signature input bytes; the eIM adapts only
  the unsigned outer transport envelope.
- All cryptographic primitives come from the Go standard library
  (`crypto/ecdsa`, `crypto/x509`, and friends). The project implements no
  cryptography of its own.
- Certificate validation uses the standard library verifier, with one
  documented eSIM-specific exception for eUICC certificate chains, where
  generic directory-name name-constraint subtree matching is not applied
  because it cannot apply to eUICC EID subjects. See the "SGP.26 eUICC/EUM
  Name Constraints" entry in
  [INTERPRETATION_LOG.md](INTERPRETATION_LOG.md) for the full reasoning.

## Specification interpretation decisions

[INTERPRETATION_LOG.md](INTERPRETATION_LOG.md) is the authoritative record of
every deliberate reading of ambiguous specification text, including the
section reference and rationale for each. When this document and the log
appear to disagree, the log wins.

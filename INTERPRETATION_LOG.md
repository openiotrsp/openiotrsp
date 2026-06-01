# Interpretation Log

This file records deliberate readings of ambiguous specification text.

Each entry must include:

- Spec section
- Ambiguity
- Chosen reading
- Rationale
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it

## SGP.26 BrainpoolP256r1 Support Deferred

- Spec section: SGP.26 test certificate curve sets.
- Ambiguity: SGP.26 test PKI may include both prime256v1/P-256 and
  BrainpoolP256r1 variants, while Go's standard X.509 verifier supports P-256
  but not BrainpoolP256r1.
- Chosen reading: v1 validates only the mandatory P-256 SGP.26 test
  certificate chain through Go's standard `crypto/x509` verifier. Brainpool
  support is deliberately deferred as an optional curve.
- Rationale: Keeping v1 on `x509.Certificate.Verify()` avoids custom security
  parsing and reproducing certificate path validation. If a real counterparty
  requires Brainpool later, support must be confined to one narrow code path
  rather than replacing the standard validator.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No.

## SGP.26 eUICC/EUM Name Constraints

- Spec section: SGP.26 v3.0.2 Variant O test certificates; SGP.32
  certificate fields carrying `CERT.EUICC.ECDSA` and `CERT.EUM.ECDSA`.
- Ambiguity: The real P-256 EUM test certificate carries a critical
  directory-name `nameConstraints` extension that Go's generic
  `x509.Certificate.Verify()` cannot apply to the eUICC EID subject, causing
  the real eUICC chain to fail generic RFC 5280 validation even though the EUM
  and eUICC signatures chain to the trusted CI.
- Chosen reading: Keep generic `x509.Certificate.Verify()` for ordinary
  eIM/server certificate chains. Validate eUICC/EUM/CI chains through a
  separate eSIM-specific path that uses Go's X.509 parser and ECDSA signature
  checks, but does not apply generic directory-name name-constraint subtree
  matching to the EUM certificate.
- Rationale: This confines the exception to the eUICC certificate role exposed
  by the real SGP.26 test PKI, without weakening strict validation for eIM or
  server certificates.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No.

## eUICC Package Profile State Persistence

- Spec section: SGP.32 `EuiccPackageResultDataSigned` and SGP.22
  `ProfileState`.
- Ambiguity: The wire result reports operation success or failure, but the
  open-source store's `profile_state` payload is an internal persistence
  boundary and is not specified by SGP.32.
- Chosen reading: Store the eIM's profile-state view as compact JSON containing
  `profiles[]` entries keyed by canonical lowercase hex ICCID, with profile
  states `enabled` or `disabled`. A successful delete removes the profile entry.
- Rationale: This keeps the wire encoding strictly in the ASN.1 package while
  making the persisted state deterministic and easy to assert in conformance
  tests.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: The SGP.33-1
  document is not present in this checkout, so no.

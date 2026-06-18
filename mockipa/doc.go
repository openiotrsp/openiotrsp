package mockipa

// Package mockipa implements a demo IoT Profile Assistant that polls an eIM over
// ESipa and drives the software eUICC for local interoperability testing.
//
// From the eIM's perspective, mockipa now presents verified SGP.32 ESipa traffic
// using the committed SGP.26 Variant O NIST test PKI (testdata/sgp26_variant_o).
//
// Supported from the eIM side:
//   - HTTPS and CoAP/DTLS ESipa polling (set OPENIOTRSP_EIM_ESIPA_URL to
//     http://… or coaps://host:5683/esipa)
//   - Verified EuiccPackageResult signatures (DER ECDSA)
//   - Direct profile download (live ES9+ via SM-DP+ JSON binding)
//   - Indirect profile download when the eIM configures IndirectProfileDownload
//     (ES9+ relayed through the eIM over ESipa BER relay arms)
//   - IPA eUICC data reads with fixture-backed EUICCInfo and certificates
//   - Persistent profile inventory and notification sequence state
//
// Remaining limitations (eIM-visible or operational):
//
//   - BPP provisioning: the software eUICC captures Bound Profile Packages but
//     does not decrypt or install them on secure-element silicon. OpenIoTRSP
//     profile state is observational, not radio attach.
//   - ES10b bootstrap and fallback execution: AddInitialEim, ExecuteFallback,
//     ReturnFromFallback, memory reset, and similar device-side ES10b functions
//     are stubbed or unsupported; the eIM may receive success stubs for some
//     PSMO/ECO operations without real silicon execution.
//   - External eIMs must trust the SGP.26 Variant O test CI root
//     (testdata/sgp26_variant_o/CERT_CI_SIG_NIST.der) before they can verify
//     signed EuiccPackageResult messages from this mock IPA.
//   - IPA eUICC data and profile inventory reflect persisted mock state, not a
//     post-install silicon readback.
//   - Profile download trigger results are accepted without a separate eUICC
//     signature over the installation result (same as production eIM behavior).
//   - Notifications are signed with DER ECDSA for realism, but the eIM does not
//     yet verify notification signatures.
//   - Blockwise TransferEimPackage for very large eUICC packages is not
//     implemented on the mock IPA poll loop.
//   - CoAP/DTLS uses demo PSK credentials; certificate-based DTLS is not wired.
//   - ContactDefaultSMDP and ContactSMDS profile-download triggers are not
//     implemented (activation-code triggers only).

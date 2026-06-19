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
- Ambiguity: The wire result reports operation success or failure, but the eIM's
  queryable orchestration state is an internal persistence boundary and is not
  specified by SGP.32.
- Chosen reading: Store the eIM's profile-state view as relational rows keyed by
  tenant, EID, and canonical lowercase hex ICCID, with discrete columns for
  enabled state and SM-DP+ address. A successful delete removes the profile row.
- Rationale: This keeps the wire encoding strictly in the ASN.1 package while
  giving the orchestration layer indexed profile state for fleet-wide queries.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: Partly. SGP.33-1
  sections 4.2.31 through 4.2.33 and Annex D settle the successful enable,
  disable, and delete state transitions. The exact relational persistence shape
  remains an OpenIoTRSP implementation detail.

## SGP.33-1 eUICC Package Known-Answer DER

- Spec section: SGP.33-1 sections 4.2.31 through 4.2.33, Annex C methods, and
  Annex D ESep responses.
- Ambiguity: SGP.33-1 defines symbolic ASN.1 fixtures such as
  `MTD_EUICC_PACKAGE_REQUEST_ENABLE`, `ENABLE_RES_OK_1`, and dynamic signature
  placeholders, but does not publish literal DER hex strings for those complete
  eUICC Package request/result values.
- Chosen reading: Keep known-answer tests hardcoded as DER hex, using fixed
  substitute values for the SGP.33-1 symbols and fixed signature octets. Do not
  derive the expected bytes by round-tripping the value under test.
- Rationale: This still pins the encoder output byte-for-byte while making clear
  which parts are fixed local substitutions for SGP.33-1 symbolic parameters.
  The OpenSSL differential parse test adds independent evidence that the
  produced DER is structurally well-formed and has the asserted ordered
  tag-length-value tree, including application-class tags. OpenSSL is a generic
  ASN.1 parser and does not know SGP.32, so this check does not independently
  prove that the asserted tree is the correct SGP.32 semantic structure.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No. It settles the
  ASN.1 structure and result behavior, not complete byte vectors.

## SGP.32 Initial eIM Association Bootstrap

- Spec section: SGP.32 `AddInitialEimRequest` and `AddInitialEimResponse`.
- Ambiguity: The eIM must participate in initial trust establishment, but
  `AddInitialEim` is an ES10b IPA-to-eUICC function and is unsigned because it
  is only valid when the eUICC has no Associated eIM.
- Chosen reading: OpenIoTRSP emits provisioning-ready `EimConfigurationData`
  and records the association token/state returned by vendor or IPA
  provisioning. It does not orchestrate ES10b `AddInitialEim` over the eIM
  ESipa surface. Although SGP.32 marks `eimFqdn` optional, OpenIoTRSP requires
  it for initial provisioning so a provisioned eUICC has a reachable eIM or
  intermediate-server address.
- Rationale: Once any eIM is associated, SGP.32 ECOs are signed eUICC Packages
  and the signature input includes the association token. Keeping bootstrap as a
  recorded vendor/IPA result avoids creating an unsigned eIM command path that
  the eIM interface does not own. When the last Associated eIM is deleted, the
  local eIM state reports the eUICC as bootstrappable again.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No. It confirms
  interoperability behavior around eIM configuration operations, but the ES10b
  bootstrap orchestration remains outside the eIM's ESipa surface.

## SGP.32 Fallback Attribute Boundary

- Spec section: SGP.32 `setFallbackAttribute` and `unsetFallbackAttribute`;
  ES10b `ExecuteFallbackMechanism` and `ReturnFromFallback`.
- Ambiguity: The eIM owns signed PSMO commands that mark which profile is the
  fallback profile, while the actual fallback switch is an IPA-to-eUICC ES10b
  procedure.
- Chosen reading: OpenIoTRSP exposes and persists eIM fallback attribute
  management only. It does not expose eIM commands for executing or returning
  from fallback; those events are observed through results, profile inventory,
  and notifications.
- Rationale: This keeps the eIM surface aligned with the signed SGP.32 PSMO
  CHOICE and avoids inventing an eIM command for an ES10b function performed by
  the device IPA.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No. It confirms the
  operation boundary, but fallback execution remains outside the eIM's direct
  ESipa command surface.

## SGP.32 Indirect ES9+ Relay Payloads

- Spec section: SGP.32 `EsipaMessageFromIpaToEim` relay arms
  `initiateAuthenticationRequestEsipa`, `authenticateClientRequestEsipa`,
  `getBoundProfilePackageRequestEsipa`, `handleNotificationEsipa`, and
  `cancelSessionRequestEsipa`.
- Ambiguity: The eIM must route indirect profile-download messages to the
  SM-DP+, but the relayed ES9+ exchange is signed between the eUICC and SM-DP+.
- Chosen reading: The eIM routes by the ESipa tag and extracts the minimum
  routing metadata needed to choose the SM-DP+ address. On the SM-DP+ leg,
  ES9+' uses the SGP.22 ES9+ binding with the eIM in the LPA role; for ASN.1
  this means the BF39/BF3B/BF3A/BF41/BF3D function object is carried inside the
  `RemoteProfileProvisioningRequest`/`Response` `[2]` (`A2`) wrapper on
  `/gsma/rsp2/asn1`. The relayed signed eUICC payloads, including
  `ProfileInstallationResult` and compact variants, remain raw TLV bytes unless
  a future consumer needs structured decoded fields.
- Rationale: Decoding and re-encoding the signed ES9+ objects would add eIM
  trust in data it does not own and risks changing signature input bytes. The
  eIM may adapt the unsigned outer interface binding, but must preserve the
  signed eUICC-originated TLVs.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No. It confirms the
  interface behavior, but byte-preserving relay handling is an implementation
  boundary.

## SGP.32 EimConfigurationData X.509 CHOICE Encoding

- Spec section: SGP.32 `EimConfigurationData` fields `eimPublicKeyData [5]` and
  `trustedPublicKeyDataTls [6]`, each a CHOICE of SubjectPublicKeyInfo
  (`eimPublicKey` / `trustedEimPkTls`, context tag `[0]`) or Certificate
  (`eimCertificate` / `trustedCertificateTls`, context tag `[1]`).
- Ambiguity: Whether the outer context `[5]`/`[6]` field embeds the X.509 object
  directly as a universal SEQUENCE (`30...`) or wraps it in the inner CHOICE
  arm tag (`A0`/`A1`).
- Chosen reading: The inner CHOICE arm tag is mandatory on the wire. Encode and
  decode `A5 { A1 { 30... } }` for certificates and `A5 { A0 { 30... } }` for
  SubjectPublicKeyInfo; the same pattern applies to `[6]`.
- Rationale: SGP.32 defines explicit CHOICE arms with distinct context tags.
  Vendor interop hex diffs and a second eIM rejection on Add eIM ECO confirm bare
  `30...` under `A5` is non-conformant.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No.

## SGP.32 IpaEuiccDataRequest.tagList vs EID Tag 5A

- Spec section: SGP.32 `IpaEuiccDataRequest.tagList` (`[APPLICATION 28]`,
  wire tag `5C`); `IpaEuiccData` field tags (`BF20`, `BF22`, `BF2D`, `A5`, `A6`,
  `A8`, etc.); EID as `[APPLICATION 26]` / tag `5A` on other structures.
- Ambiguity: Whether EID tag `5A` may appear in the `tagList` OCTET STRING.
- Chosen reading: `tagList` contains only tags of data objects returned inside
  `IpaEuiccData`. EID (`5A`) is not a valid `tagList` entry; the IPA already
  knows the target EID from ESipa context. `incorrectTagList (1)` covers invalid
  lists.
- Rationale: Vendor IPA returned `ipaEuiccDataResponseError` /
  `incorrectTagList` when OpenIoTRSP sent `5A` as the first tagList byte.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No.

## SGP.32 ProvideEimPackageResultResponse on IpaEuiccDataResponse.error

- Spec section: SGP.32 `ProvideEimPackageResultResponse` CHOICE
  (`eimAcknowledgements` / `emptyResponse` / `provideEimPackageResultError`);
  `EimAcknowledgements` as `SEQUENCE OF SequenceNumber`; `IpaEuiccDataResponse`
  CHOICE (`ipaEuiccData` / `ipaEuiccDataResponseError`).
- Ambiguity: Whether the eIM should return `eimAcknowledgements` containing the
  queued BF52 operation's internal sequence when the IPA reports
  `ipaEuiccDataResponseError`.
- Chosen reading: `EimAcknowledgements` sequence numbers identify pending
  notifications delivered in `notificationsList` (and analogous notification
  payloads bundled with eUICC package results). They are not eIM queue operation
  IDs. On `ipaEuiccDataResponseError`, or on successful `ipaEuiccData` with no
  `notificationsList`, return `emptyResponse`. Acknowledge only notification
  sequence numbers when `notificationsList` is present.
- Rationale: The spec provides `emptyResponse` for the no-acknowledgement case.
  "clear notification #1" and fail with NothingToDelete.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No.

## SGP.32 IpaEuiccDataRequest.tagList vs BF2D ProfileInfoListResponse

- Spec section: SGP.32 `IpaEuiccDataRequest.tagList` (v1.2 §5.x / p.35); `IpaEuiccData`
  `notificationsList [0]` (tag `A0`); `ProfileInfoListResponse` (tag `BF2D`).
- Ambiguity: Whether `BF2D` may appear in `tagList` to request profile inventory via
  BF52 fetch.
- Chosen reading: `tagList` entries are tags of objects returned inside
  `IpaEuiccData`. Notifications are requested with `A0` (`notificationsList`).
  `BF2D` is a response CHOICE for PSMO `listProfileInfo`, not a valid `tagList`
  entry. Profile inventory is obtained via signed eUICC Package PSMO, not
  `IpaEuiccDataRequest.tagList`.
- Rationale: Vendor IPA returned `incorrectTagList` when OpenIoTRSP v0.2.2 sent
  `BF2D` in the default tag list (after v0.2.1 had already removed invalid `5A`).
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No.

## SGP.32 EuiccPackageErrorUnsigned CHOICE tag A2

- Spec section: SGP.32 `EuiccPackageResult` CHOICE arm
  `euiccPackageErrorUnsigned [2]`; `EuiccPackageErrorUnsigned` SEQUENCE.
- Ambiguity: Whether the unsigned error payload under `BF51` is the bare SEQUENCE
  or the context-specific constructed tag `A2` wrapping the SEQUENCE fields.
- Chosen reading: Accept both universal `SEQUENCE` and `A2` (`[2] constructed`) on
  decode. Vendor IPA sends `BF51 { A2 { ... } }` inside `ePRAndNotifications`.
- Rationale: Strict `expectTag(SEQUENCE)` rejected vendor provideResult with HTTP
  400 and left operations stuck pending.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No.

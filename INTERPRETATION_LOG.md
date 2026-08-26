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

## SGP.32 Profile List via Signed EuiccPackage listProfileInfo

- Spec section: SGP.32 PSMO `listProfileInfo` (`ProfileInfoListRequest`, tag
  `BF2D`); ESipa `getEimPackage` delivery of `euiccPackageRequest` (`BF51`) vs
  `ipaEuiccDataRequest` (`BF52`); SGP.32 v1.3 section 5.9.14
  `ProfileInfoListRequest.tagList` defaults.
- Ambiguity: Whether fleet profile inventory should be fetched with
  `IpaEuiccDataRequest.tagList` (BF52) or a signed eUICC Package PSMO
  `listProfileInfo` operation (BF51).
- Chosen reading: Profile list belongs exclusively on the signed euicc-package
  path. OpenIoTRSP maps `POST /v1/devices/{eid}/profiles/list` to PSMO
  `listProfileInfo` inside `EuiccPackageRequest`. `IpaEuiccDataRequest`
  (`DefaultTagList` in `ipadata/request.go`) is for device data such as certs,
  `eUICCInfo`, and notifications—not profile inventory. When both BF52 and BF51
  operations are pending, `getEimPackage` prefers the earliest pending
  euicc-package so profile-list work is not blocked behind a stuck ipa-euicc-data
  op. `ProfileInfoListRequest.tagList` uses SGP.32 section 5.9.14 defaults
  (`DefaultProfileInfoListTagList` in `euiccpkg/constructors.go`); production IPA
  on a real card served profile list only after the eIM delivered BF51
  listProfileInfo, not BF52.
- Rationale: Production debugging showed ipa-euicc-data ops queued ahead of
  profile-list euicc-packages blocked delivery; the IPA rejected BF52 on the
  profile-list workflow. The prior minimal four-tag list (`5A 9F70 9F26`)
  omitted spec-default fields and production IPA tags.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No.

## SGP.32 EuiccPackageResult.seqNumber vs eIM operations.sequence_number

- Spec section: SGP.32 `EuiccPackageResultDataSigned.seqNumber`; eIM local
  operation queue `operations.sequence_number` / `EimAcknowledgements`.
- Ambiguity: Whether `seqNumber` in a signed EPR is the same counter as the eIM
  operation sequence used for `GetOperationBySequence`.
- Chosen reading: They are different counters. Match signed EPR completion to
  pending `euicc-package` operations by `(eid, eimTransactionId)` (with eimId /
  counter as additional correlation). Use eUICC `seqNumber` only in
  `EimAcknowledgements` for IPA/card-side notification and package-result
  deletion. Do not treat `seqNumber` as `operations.sequence_number`.
- Rationale: Production silicon reports card notification/package-result
  sequences (e.g. 13/14) while eIM operation sequences advance independently
  (e.g. 18/19). Matching by `seqNumber` attached results to the wrong pending
  op or returned `ErrNotFound`.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No.


- Spec section: SGP.32 `EuiccPackageResult` CHOICE under `BF51` with AUTOMATIC
  TAGS arms `euiccPackageResultSigned [0]`, `euiccPackageErrorSigned [1]`,
  `euiccPackageErrorUnsigned [2]`.
- Ambiguity: Whether the selected arm under `BF51` is a bare UNIVERSAL 16
  SEQUENCE (or vendor bare INTEGER for unsigned error) or the context-specific
  constructed CHOICE tag `A0`/`A1`/`A2` whose children are the SEQUENCE fields.
- Chosen reading: Accept both forms on decode. Unwrap `A0`/`A1`/`A2` to a
  synthetic SEQUENCE over the arm's children before signed/unsigned SEQUENCE
  parsers run. Encode path continues to emit bare SEQUENCE children under
  `BF51` for fixtures/mocks.
- Child shapes: `[0]` and `[1]` are SEQUENCE `{ data, signature (5F37) }`;
  `[2]` is the unsigned SEQUENCE (no signature). Production silicon sends
  signed OK results as `BF51 { A0 { data SEQUENCE, 5F37 } }`.
- Rationale: Strict `expectTag(SEQUENCE)` rejected production IPA provideResult
  and handleNotification payloads with HTTP 400
  (`got [0], want [UNIVERSAL 16]`) and left operations stuck pending.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No.

## SGP.22 ProfileInfoListResponse CHOICE under BF2D

- Spec section: SGP.22 / SGP.32 `ProfileInfoListResponse ::= [45] CHOICE {
  profileInfoListOk SEQUENCE OF ProfileInfo, profileInfoListError
  ProfileInfoListError }` with AUTOMATIC TAGS (tag `BF2D`).
- Ambiguity: Whether success under `BF2D` is a bare UNIVERSAL 16 SEQUENCE of
  `ProfileInfo` (mockIPA / fixtures) or CONTEXT CONSTRUCTED `[0]` whose children
  are the `ProfileInfo` values directly (IMPLICIT AUTOMATIC TAGS). Whether the
  error arm is a bare INTEGER or CONTEXT `[1]`.
- Chosen reading: Accept both success forms on decode. Unwrap `[0]` to a
  synthetic SEQUENCE over its children before the existing `ProfileInfo` loop.
  Accept bare INTEGER, CONTEXT PRIMITIVE `[1]`, and CONTEXT CONSTRUCTED `[1]`
  wrapping a single INTEGER for the error arm. Encode path continues to emit
  `BF2D → SEQUENCE → ProfileInfo*` / bare INTEGER for fixtures/mocks.
- Rationale: Production IPAd nested `listProfileInfo` results inside signed EPR
  as `BF2D { A0 { E3… } }`. Strict `expectTag(SEQUENCE)` failed apply of
  provide/handleNotification with `got [0], want [UNIVERSAL 16]` after the
  BF51 CHOICE unwrap (same class of bug). Dual-accept decode avoids requiring
  enterprise eIM TLV rewriting.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No.

## SGP.32 IpaEuiccDataResponse CHOICE under BF52

- Spec section: SGP.32 `IpaEuiccDataResponse ::= [82] CHOICE {
  ipaEuiccData IpaEuiccData, ipaEuiccDataResponseError
  IpaEuiccDataResponseError }` with AUTOMATIC TAGS (tag `BF52`).
- Ambiguity: Whether success under `BF52` places `IpaEuiccData` fields directly
  under `BF52` (mockIPA / fixtures) or wraps them in CONTEXT CONSTRUCTED `[0]`
  (IMPLICIT AUTOMATIC TAGS). Whether error is a bare INTEGER under `BF52` or
  CONTEXT CONSTRUCTED `[1]`.
- Chosen reading: Accept both forms on decode. Unwrap success `[0]` to a
  synthetic `BF52` over the arm's children before `IpaEuiccData` field decode.
  Unwrap error `[1]` similarly before `IpaEuiccDataResponseError` decode. A sole
  CONTEXT `[0]` whose children are only PendingNotification TLVs (no nested
  notificationsList `A0` and no other `IpaEuiccData` fields) remains bare
  `notificationsList`, not a CHOICE arm. Encode path continues to emit bare
  data objects / bare error fields for fixtures/mocks.
- Rationale: Production IPAd `provideEimPackageResult` payloads arrive as
  `BF52 { A0 { A0…, BF20…, A5…, A6… } }`. Without unwrap, the sole `[0]` is
  misread as `notificationsList` and decode fails on `BF20`
  (`unknown PendingNotification tag [32]`). Same AUTOMATIC TAGS CHOICE class as
  BF51 / BF2D.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No.

## SGP.32 IpaEuiccData Certificate under A5/A6

- Spec section: SGP.32 `IpaEuiccData` fields `eumCertificate [5] Certificate`
  and `euiccCertificate [6] Certificate` (PKIX `Certificate` SEQUENCE) with
  AUTOMATIC TAGS / IMPLICIT context tagging.
- Ambiguity: Whether A5/A6 carry one UNIVERSAL 16 `Certificate` SEQUENCE child
  (fixtures/mocks that nest a full Certificate DER) or the three Certificate
  fields as siblings under the context tag (TBS SEQUENCE, AlgorithmIdentifier
  SEQUENCE, BIT STRING signature) after IMPLICIT replacement of the outer
  SEQUENCE tag.
- Chosen reading: Accept both on decode via `CertificateDERFromTagged`. One
  SEQUENCE child is returned as-is; three sibling fields are re-wrapped as
  `SEQUENCE {…}` before `x509.ParseCertificate` / EID extraction.
- Rationale: Production silicon emits the IMPLICIT three-sibling shape under
  A6. Taking only `Children[0].MarshalBinary()` yields TBS alone and fails with
  `x509: malformed tbs certificate`, blocking EID recovery when GSMA JSON omits
  `eidValue`.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No.

## GSMA JSON provide without eidValue for BF52 IpaEuiccDataResponse

- Spec section: SGP.32 `ProvideEimPackageResult` (`eidValue` OPTIONAL) and
  `IpaEuiccData` (no EID field; eUICC certificate at tag A6).
- Ambiguity: How the eIM associates a GSMA JSON `provideEimPackageResult` that
  carries only `eimPackageResult` (bare BF52) and omits `eidValue`.
- Chosen reading: Before wrapping/handling, recover EID from the payload:
  prefer Application 26 EID inside `ipaEuiccData` when present, else the eUICC
  certificate subject `serialNumber` (32-digit hex). Walk data objects after
  BF52 CHOICE unwrap without requiring every `IpaEuiccData` field to decode.
  Fall back to matching `eimTransactionId` against pending operations. Document
  that IPAs must send `eidValue` when neither embedded EID nor eUICC certificate
  is present.
- Rationale: Default BF52 `tagList` requests A5/A6 certificates and excludes
  EID (`5A`); production provides often omit JSON `eidValue`. Without recovery
  the result cannot be keyed to a device Store row. CHOICE / A6 Certificate
  shape bugs must be fixed in OpenIoTRSP decode, not papered over in the host
  eIM.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No.

## eUICC Package Result signature encoding (euiccSignEPR / euiccSignEPE)

- Spec section: SGP.32 `EuiccPackageResultSigned.euiccSignEPR` and
  `EuiccPackageErrorSigned.euiccSignEPE` (both `[APPLICATION 55]` OCTET STRING,
  tag `5F37`); related SGP.22 eUICC ECDSA signature conventions.
- Ambiguity: The ASN.1 module types the signature as an opaque OCTET STRING and
  does not state whether the bytes are ASN.1 DER ECDSA (`SEQUENCE` of INTEGER
  `r`, `s`) or BSI TR-03111 fixed-width `r||s` (64 octets on P-256).
- Chosen reading: Verify SHA-256(raw signed data) against either encoding: try
  ASN.1 DER first (`ecdsa.VerifyASN1`), then TR-03111
  (`pki.VerifyECDSATR03111`) when DER fails. Reject only if both fail.
- Rationale: Lab and production eUICC Package Results commonly emit TR-03111
  `r||s` under `5F37`. Accepting only DER rejects valid silicon results while
  ASN.1 DER remains useful for software fixtures and interoperability tests.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No.

## eUICC Package Result signature input (associationToken)

- Spec section: SGP.32 §2.11.1.2 — `euiccSignEPR` / `euiccSignEPE` SHALL apply
  on the concatenated data objects `euiccPackageResultDataSigned` (or
  `euiccPackageErrorDataSigned`) and `associationToken`. If no association
  token is configured for the eIM, the token data object SHALL be used with
  value zero (`84 01 00`). Same concatenation rule as `eimSignature` over
  `euiccPackageSigned` (§2.11.1.1).
- Ambiguity: Whether AUTOMATIC TAGS BF51 CHOICE `[0]` changes which TLV bytes
  are hashed (outer `A0`, full `BF51`, SEQUENCE value only, or children
  concat).
- Chosen reading: Hash the wire encoding of the signed data object SEQUENCE
  (first child under bare SEQUENCE or under CHOICE `[0]`/`[1]`), concatenated
  with `associationToken` `[4] INTEGER`. Do not include `BF51`, `A0`/`A1`, or
  `5F37`. Nil / missing configured token means zero. Use CERT.EUICC
  (`PK.EUICC.ECDSA`) for verify.
- Rationale: Production silicon TR-03111 `euiccSignEPR` over BF51/`A0` fails
  ECDSA verify when only `euiccPackageResultDataSigned` is hashed, and succeeds
  when `|| 84 01 00` (or the configured token TLV) is appended. Confirmed with
  a lab IPA handleNotification / provideEimPackageResult capture (BF51 CHOICE
  `[0]` + CERT.EUICC from BF52 A6) and covered by
  `TestEuiccSignEPRRequiresAssociationTokenBinding`.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No (prose in SGP.32
  is explicit).

## SGP.32 ESipa X-Admin-Protocol Default Version

- Spec section: SGP.32 v1.3 section 6.1 ("X-Admin-Protocol" header field SHALL
  be set to highest version of SGP.32 [This document] supported by the sender),
  amended from SGP.32 v1.2 section 6.1 ("SHALL be set to v2.1.0 in both HTTP
  request and HTTP response. NOTE: this value provides interoperability with
  previous versions of SGP.22") by CR13009R01; SGP.22 v2.7 section 6.2, from
  which the `gsma/rsp/v<x.y.z>` syntax is inherited.
- Ambiguity: v1.3 keeps the `gsma/rsp/v<x.y.z>` syntax, whose version namespace
  has always been SGP.22, while redefining the value as an SGP.32 version. It
  does not say whether an eIM should therefore advertise `gsma/rsp/v1.3.0`, nor
  what to send when the requester offers no version at all.
- Chosen reading: Echo the requester's value whenever it names a `gsma/rsp/`
  protocol, and fall back to `gsma/rsp/v2.1.0` otherwise, on both the ASN.1 and
  the JSON binding. Do not emit an SGP.32 version number in a `gsma/rsp/`
  header.
- Rationale: Echoing means a conformant v1.3 IPA is answered with exactly the
  version it negotiated, so the v1.3 rule is satisfied wherever it is
  observable. The fallback only applies to requesters that sent nothing, and
  `v2.1.0` is the one value SGP.32 ever named explicitly and the value deployed
  IPAs put on the wire. The previous default, `gsma/rsp/v2.4.0`, matched no
  specification text and risked rejection by a strict IPAe.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No.

## SGP.32 ESipa HTTP Connection Reuse

- Spec section: SGP.32 v1.3 sections 6.1 and 6.1.1; SGP.22 v2.7 section 6.2,
  which SGP.32 section 6.1 adopts by reference.
- Ambiguity: Neither specification states whether an ESipa response may keep
  the HTTP connection open. Both list the mandatory header fields and allow
  additional ones without constraining `Connection`.
- Chosen reading: Do not set `Connection: close`. Leave connection lifetime to
  the HTTP server and to the client's own `Connection` request header.
- Rationale: A normal exchange is getEimPackage, provideEimPackageResult, then
  getEimPackage again. Forcing close costs a full TLS handshake per message,
  which is a real power and latency penalty on a constrained NB-IoT device, and
  IPAs request `keep-alive`. Nothing in the mandated message flow depends on a
  fresh connection.
- Whether `spec/SGP.33-1-IoT-eUICC-v1.2.docx` settled it: No.

# Roadmap

This roadmap describes planned and deferred work. items are ordered by priority within each section.

## Structured ASN.1 coverage

The implementation covers the eIM's owned operations end to end, while a
number of less-common ASN.1 structures are retained as raw TLV or are not yet
structurally decoded. The authoritative status of every structure is tracked
in two places that this roadmap mirrors: the inventory in
`asn1/inventory_test.go` and [INTERPRETATION_LOG.md](INTERPRETATION_LOG.md).

The inventory currently classifies all 129 local type definitions of the
SGP.32 v1.3 ASN.1 module:

| Status | Count | Meaning |
| --- | --- | --- |
| structured | 36 | Fully decoded and round-trip tested |
| integer-alias | 17 | Plain INTEGER enumerations, fully handled |
| partial | 7 | Key fields decoded; remaining detail kept as raw TLV |
| raw-tlv | 21 | Tag-validated and byte-preserved, not structurally decoded |
| not-implemented | 48 | Outside the current eIM scope (mostly ES10b/IPA-side or compact variants) |

Planned work is to decode the partial and raw-TLV structures as consumer
needs require, prioritized by what the API and downstream consumers actually
read. Specifically called out:

- **Detailed profile-download result decoding** beyond final success and
  failure: `ProfileDownloadTriggerResult` and `ProfileInstallationResult` are
  partial today — the final success/failure result is decoded while the
  detailed SGP.22 success/error payloads remain raw TLV. Extracting the
  failure reason has operational value for fleet management.
- **Structured decoding of the notification model**: `PendingNotification`
  is decoded only enough for EID, sequence, kind, and payload persistence;
  `RetrieveNotificationsListRequest`/`Response` and the compact variants
  (`CompactProfileInstallationResult`, `CompactProfileInstallationResultData`,
  `CompactSuccessResult`, `CompactOtherSignedNotification`) are not yet
  implemented.
- **Structured decoding of the remaining ESipa result and error branches**
  currently retained as raw TLV: the top-level envelopes
  (`EsipaMessageFromIpaToEim`, `EsipaMessageFromEimToIpa`), the
  indirect-download relay arms (`InitiateAuthenticationRequestEsipa`/
  `ResponseEsipa`/`OkEsipa`, `AuthenticateClientRequestEsipa`/`ResponseEsipa`/
  `OkDPEsipa`/`OkDSEsipa`, `GetBoundProfilePackageRequestEsipa`/
  `ResponseEsipa`/`OkEsipa`, `HandleNotificationEsipa`,
  `CancelSessionRequestEsipa`/`ResponseEsipa`/`CancelSessionOk`), the relayed
  ES9+ payloads (`AuthenticateServerResponse`, `AuthenticateResponseOk`,
  `PrepareDownloadResponse`, `CancelSessionResponse`), and the
  `EuiccResultData` CHOICE wrapper.
- **Fuller decoding of the eUICC data structures** beyond the fields
  currently consumed: `IpaEuiccData` and `ProfileInfo` are partial (eUICC
  info, IPA capabilities, and profile state are decoded; certificates and
  unknown objects are raw TLV), and `EUICCInfo2` with its `IoTSpecificInfo`
  and `IpaMode` substructures is deferred.

Retaining these as raw TLV is a deliberate scoping decision, not a defect:
the relayed and signed payloads are forwarded and verified correctly without
full structured decoding, and the inventory is kept truthful. An entry is
promoted to structured only when it is fully decoded and round-trip tested.

## Scope boundaries (not planned as eIM features)

Operations that belong to the IPA-to-eUICC interface are intentionally
outside the eIM's surface: ES10b functions such as initial-eIM bootstrap
execution (`AddInitialEim`), fallback execution
(`ExecuteFallbackMechanism`, `ReturnFromFallback`), memory reset
(`EuiccMemoryReset`), immediate enable, and similar. The eIM produces the
configuration and observes the results; it does not implement these
device-side operations. This is a deliberate boundary, recorded here so it
is not mistaken for missing work. See the bootstrap and fallback entries in
[INTERPRETATION_LOG.md](INTERPRETATION_LOG.md).

## Optional curve support

`brainpoolP256r1` is deliberately not implemented; only the mandatory NIST
P-256 curve is supported. Brainpool would be added only if a counterparty
requires it. The reasoning is recorded in
[INTERPRETATION_LOG.md](INTERPRETATION_LOG.md).

## Continuous verification

Extend CI coverage so the integration, migration, and signature-verification
suites re-prove on every push, building on the existing Postgres integration
job.

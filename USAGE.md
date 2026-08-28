# OpenIoTRSP Usage

## Local Demo

Run the default demo from the repository root:

```bash
docker compose up
```

The stack starts Postgres, `eim-server`, and `mockipa`. The eIM registers the demo EID, queues a direct profile download trigger for `1$smdpp.test.rsp.sysmocom.de$TS48V1-B-UNIQUE`, and serves the SGP.32 ASN.1 binding on `http://localhost:8080/gsma/rsp2/asn1`, the GSMA HTTP JSON binding on `/gsma/rsp2/esipa/{getEimPackage,provideEimPackageResult,handleNotification}`, and the same BER-TLV messages on the legacy `/esipa` path. The mock IPA polls ESipa, handles the trigger, and uploads a profile download result. Override the demo profile with `OPENIOTRSP_DEMO_SMDP_ADDRESS` and `OPENIOTRSP_DEMO_MATCHING_ID`.

### ESipa bindings and HTTP headers

`esipa.Handler.HTTPHandler()` mounts all three HTTP surfaces, so one handler serves an IPAe and an IPAd:

| Path | Binding | Response `Content-Type` |
| --- | --- | --- |
| `/gsma/rsp2/asn1` (`esipa.GSMAPathASN1`) | SGP.32 §6.1.1 ASN.1 | `application/x-gsma-rsp-asn1` |
| `/gsma/rsp2/esipa/{getEimPackage,provideEimPackageResult,handleNotification}` | SGP.32 §6.1.2 JSON | `application/json;charset=UTF-8` |
| `/esipa` (`esipa.DefaultPath`) | same ASN.1 messages, legacy path | `application/x-gsma-rsp-asn1` |

Every response carries `X-Admin-Protocol`. The requester's value is echoed when it names a `gsma/rsp/` protocol, otherwise `esipa.DefaultAdminProtocol` (`gsma/rsp/v2.1.0`) is sent. Responses do not force `Connection: close`, so a constrained device can reuse one TLS session across a `getEimPackage` / `provideEimPackageResult` / `getEimPackage` exchange.

The request `Content-Type` is not inspected; the binding is chosen by path. Probe a running eIM with a `getEimPackageRequest` for an EID that has nothing queued:

```bash
printf '\xbf\x4f\x12\x5a\x10\x89\x04\x40\x45\x93\x00\x00\x00\x00\x00\x00\x21\x53\x89\x32\x10' > getpkg.ber
curl -s -D - -o resp.ber -X POST --data-binary @getpkg.ber \
  -H 'Content-Type: application/x-gsma-rsp-asn1' \
  -H 'X-Admin-Protocol: gsma/rsp/v2.1.0' \
  -H 'User-Agent: gsma-rsp-ipae' \
  http://127.0.0.1:8080/gsma/rsp2/asn1
```

The response headers must include `X-Admin-Protocol: gsma/rsp/v2.1.0` and `Content-Type: application/x-gsma-rsp-asn1`, and `resp.ber` must be one `EsipaMessageFromEimToIpa`: `bf4f 03 02 01 01`, a `getEimPackageResponse` of `eimPackageError(1)`.

A `handleNotificationEsipa` request answers `204` with an empty body and no `Content-Type`, per SGP.32 §6.1.1.

`HandleNotificationEsipa` also has a `provideEimPackageResult` arm, and IPAe implementations use it: a profile download trigger result commonly arrives as `BF3D(BF50(BF54))` while eUICC Package Results arrive as a bare `BF50`. Both are recorded against the same operation, and the notification form keeps the `204` response. A host that resolves the routing EID itself — a multi-tenant eIM must, before it can pick the tenant — reaches the payload with `esipa.ProvideResultFromMessage`, which unwraps either shape, and passes the result to `esipa.ResolveProvideResultEID` without reimplementing the envelope rule:

```go
if eidValue, result, ok := esipa.ProvideResultFromMessage(message.Raw); ok {
	eid, errCode, err := esipa.ResolveProvideResultEID(ctx, store, tenantID, eidValue, result)
	// eid selects the tenant-scoped device; forward the original bytes unchanged.
}
```

An IPAe may omit `eidValue` at every depth, in which case `eimTransactionId` is the only routing key and `ResolveProvideResultEID` recovers the EID from the pending operation that carries it.

### BF52 vs profile inventory

`ipadata.DefaultTagList` (BF52 `IpaEuiccDataRequest`) requests eUICCInfo, notifications, EUM/eUICC certificates, and IPA capabilities. Profile inventory on production IPA/silicon is delivered as a signed `euiccPackageRequest` with `listProfileInfo` PSMO (BF51), not BF52. Hosts must not treat BF52 as a substitute for `listProfileInfo`. Presented EUM/eUICC certificates in `storage.EUICCState` remain observational unless the host validates them against an explicit CI root store before using them as EPR trust material.

### GSMA JSON `provideEimPackageResult` without `eidValue`

SGP.32 allows omitting `eidValue` on `ProvideEimPackageResult` (BF50). When GSMA JSON posts only `eimPackageResult` (for example a bare BF52 `ipaEuiccDataResponse`), OpenIoTRSP recovers the device EID before wrapping/handling:

1. Application 26 (`5A`) EID inside `ipaEuiccData`, when present
2. eUICC certificate (`A6`) subject `serialNumber` (32-digit hex EID encoding)
3. `eimTransactionId`, matched against the outstanding operations for the tenant

Decode accepts AUTOMATIC TAGS CHOICE `[0]` under BF52 (same class as BF51 / BF2D) and both A6 Certificate shapes: one nested SEQUENCE, or IMPLICIT TBS / AlgorithmIdentifier / signature siblings. EID recovery walks those data objects after CHOICE unwrap and does not require every `IpaEuiccData` field to decode successfully.

The same recovery runs in `provideTLVFromGSMA` / `ServeGSMAJSON` (and the ASN.1 provide path), so a consumer does not need its own `eimTransactionId`-to-EID adapter in front of the handler. Step 3 covers a bare BF51 `euiccPackageResult` that carries neither an embedded EID nor an eUICC certificate, which is what Kigen's IPA sends. It resolves only while the correlated operation is still outstanding: an IPA that omits `eidValue` on a redelivery after the operation completed cannot be associated to a device, so IPAs should still send `eidValue` whenever they have it.

### Profile download triggers

`profiledownload.NewActivationCodeTrigger` validates the activation code against the SGP.22 §4.1 structure — format version `1` and a non-empty SM-DP+ address — and strips a QR `LPA:` prefix, because the `activationCode` field carries the activation code itself. Every caller is covered, including `POST /v1/profile-downloads`, which answers `400` instead of signing a trigger the eUICC will reject after delivery.

A trigger result reports `profileDownloadError` with a `profileDownloadErrorReason`. SGP.32 v1.3 names only `ecallActive(104)` and `undefinedError(127)`; `asn1.ProfileDownloadErrorReason.String` renders any other value cards emit as the bare integer rather than inventing a name.

A successful download records the operation result and the install notification, and nothing else. No profile row is derived from the trigger: an activation code carries a matching ID, which is only sometimes an ICCID, and SGP.22 §3.1.3 installs a downloaded profile in the Disabled state. The profile inventory is populated from the eUICC's own `ProfileInfoListResponse` — `POST /v1/devices/{eid}/profiles/list`, or the `profileInfoList` object of an `IpaEuiccDataResponse` — which carries the real ICCID, `profileState`, and fallback attribute. Until one of those runs, `GET /v1/devices/{eid}/status` lists no profile for a freshly downloaded one. Consistently with that, the ICCID path segment of the profile routes must be 10 hex-encoded bytes (SGP.22 `Iccid`), so a matching ID cannot be mistaken for a profile and signed into a PSMO.

### eUICC Package Result signatures (`euiccSignEPR` / `euiccSignEPE`)

Strict verify accepts both ASN.1 DER ECDSA and BSI TR-03111 fixed-width `r||s` (64 octets on P-256) under tag `5F37`. DER is tried first; TR-03111 is the common encoding from production eUICC silicon.

Per SGP.32, the signed input is the wire `euiccPackageResultDataSigned` (or error) SEQUENCE concatenated with `associationToken` (`[4] INTEGER`). When no token is configured for the Associated eIM, the token value is zero (`84 01 00`). AUTOMATIC TAGS BF51 CHOICE `[0]`/`[1]` do not change the covered bytes: still the inner data SEQUENCE, not `BF51`/`A0`/`5F37`.

### Unrecognised `EuiccResultData` alternatives

`asn1.EuiccResultData` keeps whatever alternative tag it is given. A result the eIM cannot name never fails the enclosing `EuiccPackageResult`: by the time a result is sent the eUICC has executed the operation and advanced its counter, and refusing to decode only prevents the eIM from learning what happened and from routing a message whose `eimTransactionId` may be its sole key. `euiccpkg.ParseOperationResult` and `VerifyPackageResult` map one deviation seen in the field — the base type identifier `02 01 02` where a single-operation package expects, say, `disableResult` `84 01 02` — onto the operation the request names. Anything still unmatched returns `euiccpkg.ErrResultNotFound`, which the ESipa handler records as a failed operation with the raw result payload, rather than answering `400` and leaving the IPAe to retry a completed operation.

The adoption log line is:

```text
trigger->download->enable complete
```

Check persisted state with:

```bash
curl http://localhost:8080/status
```

Restart the stack without deleting volumes:

```bash
docker compose down
docker compose up
```

The previously enabled profile state is stored in the Postgres volume and should still appear in `/status`. This cold-start and restart path must be run on a machine with Docker daemon access before considering the demo adoption path proven.

## Live Versus Offline

By default, `mockipa` uses live mode and runs the direct ES9+ flow against the public sysmocom test SM-DP+ host. The mock IPA loads the local SGP.26 Variant O fixture ZIP from `spec/SGP.26_v3.0.2-17-July-2025.zip` and signs the eUICC-side authentication/download/install responses with that test eUICC key. Override the path with `OPENIOTRSP_SGP26_FIXTURE_ZIP` and the demo IMEI with `OPENIOTRSP_MOCKIPA_IMEI`.

The software eUICC is intentionally limited: it proves the signed ES9+ authentication, BPP receipt, and installation-result notification path through the SM-DP+, but it does not decrypt or provision the Bound Profile Package like real eUICC silicon. A successful mock IPA run records the demo profile as enabled in OpenIoTRSP profile state; it is not a physical profile install.

External mock IPA (`go run ./cmd/mockipa`) and the embedded eIM demo path differ in how they handle local mock SM-DP+ hosts such as `mock.smdp.local`. Enterprise eIM builds may generate activation codes like `1$mock.smdp.local$<hex-iccid>` for offline profile simulation. External mockipa auto-detects `.local` SM-DP+ hosts and uses the offline downloader without network access. You can also force offline mode with `OPENIOTRSP_MOCKIPA_DOWNLOAD_MODE=offline`.

For offline CI plumbing only:

```bash
OPENIOTRSP_MOCKIPA_DOWNLOAD_MODE=offline docker compose up
```

The offline mode is useful for deterministic ESipa, storage, and compose validation. It does not prove SM-DP+ signatures.

An optional labelled stub service is also available:

```bash
docker compose --profile offline up offline-smdp
```

## Tests

Run normal tests:

```bash
go test ./...
```

Run integration tests:

```bash
go test -tags=integration ./...
```

The live sysmocom test is gated by `OPENIOTRSP_LIVE_SMDP=1`. Use `OPENIOTRSP_LIVE_SMDP=skip` when intentionally running integration tests without the public SM-DP+ dependency. When sysmocom is unavailable, the live test should fail with the upstream HTTP/TLS error rather than falling back to the stub.

Postgres integration tests require `OPENIOTRSP_POSTGRES_TEST_DSN` in CI. Local ad hoc runs may skip when the DSN is absent, but CI must set the DSN or `OPENIOTRSP_REQUIRE_POSTGRES_TEST_DSN=1` so missing database coverage fails loudly.

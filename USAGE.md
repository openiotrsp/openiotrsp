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

### BF52 vs profile inventory

`ipadata.DefaultTagList` (BF52 `IpaEuiccDataRequest`) requests eUICCInfo, notifications, EUM/eUICC certificates, and IPA capabilities. Profile inventory on production IPA/silicon is delivered as a signed `euiccPackageRequest` with `listProfileInfo` PSMO (BF51), not BF52. Hosts must not treat BF52 as a substitute for `listProfileInfo`. Presented EUM/eUICC certificates in `storage.EUICCState` remain observational unless the host validates them against an explicit CI root store before using them as EPR trust material.

### GSMA JSON `provideEimPackageResult` without `eidValue`

SGP.32 allows omitting `eidValue` on `ProvideEimPackageResult` (BF50). When GSMA JSON posts only `eimPackageResult` (for example a bare BF52 `ipaEuiccDataResponse`), OpenIoTRSP recovers the device EID before wrapping/handling:

1. Application 26 (`5A`) EID inside `ipaEuiccData`, when present
2. eUICC certificate (`A6`) subject `serialNumber` (32-digit hex EID encoding)
3. `eimTransactionId`, matched against the outstanding operations for the tenant

Decode accepts AUTOMATIC TAGS CHOICE `[0]` under BF52 (same class as BF51 / BF2D) and both A6 Certificate shapes: one nested SEQUENCE, or IMPLICIT TBS / AlgorithmIdentifier / signature siblings. EID recovery walks those data objects after CHOICE unwrap and does not require every `IpaEuiccData` field to decode successfully.

The same recovery runs in `provideTLVFromGSMA` / `ServeGSMAJSON` (and the ASN.1 provide path), so a consumer does not need its own `eimTransactionId`-to-EID adapter in front of the handler. Step 3 covers a bare BF51 `euiccPackageResult` that carries neither an embedded EID nor an eUICC certificate, which is what Kigen's IPA sends. It resolves only while the correlated operation is still outstanding: an IPA that omits `eidValue` on a redelivery after the operation completed cannot be associated to a device, so IPAs should still send `eidValue` whenever they have it.

### eUICC Package Result signatures (`euiccSignEPR` / `euiccSignEPE`)

Strict verify accepts both ASN.1 DER ECDSA and BSI TR-03111 fixed-width `r||s` (64 octets on P-256) under tag `5F37`. DER is tried first; TR-03111 is the common encoding from production eUICC silicon.

Per SGP.32, the signed input is the wire `euiccPackageResultDataSigned` (or error) SEQUENCE concatenated with `associationToken` (`[4] INTEGER`). When no token is configured for the Associated eIM, the token value is zero (`84 01 00`). AUTOMATIC TAGS BF51 CHOICE `[0]`/`[1]` do not change the covered bytes: still the inner data SEQUENCE, not `BF51`/`A0`/`5F37`.

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

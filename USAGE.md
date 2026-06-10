# OpenIoTRSP Usage

## Local Demo

Run the default demo from the repository root:

```bash
docker compose up
```

The stack starts Postgres, `eim-server`, and `mockipa`. The eIM registers the demo EID, queues a direct profile download trigger for `1$smdpp.test.rsp.sysmocom.de$TS48V1-B-UNIQUE`, and serves ESipa on `http://localhost:8080/esipa`. The mock IPA polls ESipa, handles the trigger, and uploads a profile download result. Override the demo profile with `OPENIOTRSP_DEMO_SMDP_ADDRESS` and `OPENIOTRSP_DEMO_MATCHING_ID`.

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

The software eUICC is intentionally limited: it proves the signed ES9+ authentication, BPP receipt, and installation-result notification path through the SM-DP+, but it does not decrypt or provision the Bound Profile Package like real eUICC silicon. A successful mock IPA run records the demo profile as enabled in OpenIoTRSP state; it is not a physical profile install.

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

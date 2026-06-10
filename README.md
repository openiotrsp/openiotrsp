# OpenIoTRSP

An open source eSIM IoT Manager (eIM) for SGP.32.

OpenIoTRSP lets you remotely manage the connectivity profiles on a fleet of IoT devices. It implements the GSMA SGP.32 standard, the specification that defines how eSIMs in IoT devices download, switch, enable, and disable mobile network profiles without anyone physically touching the device.

## What problem this solves

IoT devices ship to the field and stay there for years. The cellular connectivity inside them is delivered by an eSIM (an eUICC), and at some point you will need to change it: activate a profile when the device is first deployed, switch to a different operator for better coverage or cost, or retire a profile at end of life. Doing this at the scale of thousands or millions of devices, many of them on low-power networks like NB-IoT and LTE-M, is the job SGP.32 was created for.

SGP.32 introduces the eIM as the component that orchestrates this. The eIM is the server that tells each device's eSIM what to do. OpenIoTRSP is an implementation of that server, free to run for your own fleet.

## What it does

- Triggers profile downloads to devices in the field
- Enables, disables, and deletes profiles remotely
- Manages eSIM configuration across a fleet
- Speaks the SGP.32 ESipa interface to the IoT Profile Assistant (IPA) in the device
- Works over both standard HTTPS and CoAP/DTLS, so it functions on constrained NB-IoT and LTE-M networks where ordinary connections are too heavy
- Tracks the state of every device's profiles in one place

## Who it is for

- OEMs and device makers who ship cellular IoT products and need to manage their eSIMs after deployment
- System integrators and solution providers running connected fleets for their customers
- Connectivity teams who want to operate eSIM profile management themselves rather than depend on a single vendor
- Anyone who wants to learn, test, or build on a working SGP.32 eIM

## How it fits in the SGP.32 picture

A quick map of the moving parts:

- **eUICC**: the eSIM chip inside the device that holds the profiles
- **IPA** (IoT Profile Assistant): the agent in the device that carries out instructions on the eUICC
- **SM-DP+**: the operator's server that prepares and delivers a profile
- **eIM**: the manager that decides and orchestrates what happens, and when. This is OpenIoTRSP.

The device's IPA checks in with the eIM, the eIM tells it what to do, and profiles get downloaded from the SM-DP+ and activated. OpenIoTRSP is the eIM in that chain.

## Status

OpenIoTRSP implements the core SGP.32 eIM surface:

- Profile lifecycle: enable, disable, delete
- The remaining profile state operations, including fallback management
- Direct profile download triggering
- Indirect profile download relay (ES9+ via the eIM to the SM-DP+)
- eIM configuration operations: add, update, delete, list eIM
- IPA and eUICC data reads
- Notification handling
- Bootstrap configuration emission

The implementation is validated against the GSMA SGP.26 test certificates: the protocol cryptography and result verification are tested against real test key material. Several less-common ASN.1 structures are currently retained as raw TLV where structured decoding is not yet required; [ROADMAP.md](ROADMAP.md) tracks the exact status.

The boundary, stated plainly: full interoperability with a physical eUICC and a live SM-DP+ download is the remaining milestone, pending test hardware.

Only the mandatory NIST P-256 curve is supported; brainpool is deliberately not included.

## Quickstart

```bash
docker compose up
```

This starts the eIM, Postgres, and a mock IPA. The eIM queues a direct-download trigger for the public sysmocom test SM-DP+ (`smdpp.test.rsp.sysmocom.de`), and the mock IPA polls ESipa and reports the demo profile as enabled in OpenIoTRSP state. The software eUICC signs the SGP.22 ES9+ authentication/download/install responses and captures the Bound Profile Package for verification, but it does not decrypt or provision the profile like real silicon. Watch the mock IPA logs for:

```text
trigger->download->enable complete
```

For offline CI plumbing, set `OPENIOTRSP_MOCKIPA_DOWNLOAD_MODE=offline`. That fallback is intentionally labelled as a stub and is not a GSMA signature proof. Full setup and validation instructions are in [USAGE.md](USAGE.md).

## Standards

OpenIoTRSP implements GSMA SGP.32 (eSIM IoT Technical Specification) and interoperates with the wider eSIM RSP ecosystem (SGP.22, SGP.26 test infrastructure). Conformance to the GSMA SGP.33 test specification guides the implementation so that it works with eUICCs, IPAs, and SM-DP+ servers from other vendors.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get started and how to run the tests.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): the high-level design
- [SECURITY.md](SECURITY.md): security policy and cryptographic posture
- [ROADMAP.md](ROADMAP.md): planned and deferred work
- [USAGE.md](USAGE.md): full setup and validation instructions
- [INTERPRETATION_LOG.md](INTERPRETATION_LOG.md): specification-interpretation decisions
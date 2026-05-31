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

OpenIoTRSP is under active development. The first release targets the core profile lifecycle (download, enable, disable, delete) and Direct Profile Download, where the device retrieves its profile from the SM-DP+ directly. See the roadmap for what is planned next.

## Quickstart

```bash
docker compose up
```

This starts the eIM, its database, and a simulated device, and runs an end-to-end profile download and activation locally so you can see the full flow in one command. Full setup and usage instructions are in [USAGE.md](USAGE.md).

## Standards

OpenIoTRSP implements GSMA SGP.32 (eSIM IoT Technical Specification) and interoperates with the wider eSIM RSP ecosystem (SGP.22, SGP.26 test infrastructure). Conformance to the GSMA SGP.33 test specification guides the implementation so that it works with eUICCs, IPAs, and SM-DP+ servers from other vendors.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get started, the project structure, and how to run the tests.
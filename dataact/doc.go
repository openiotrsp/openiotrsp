// Package dataact implements EU Data Act tenant export bundle validation and
// import for self-hosted OpenIoTRSP deployments.
//
// Bundles are signed ZIP archives produced by a hosting eIM. Each archive
// contains NDJSON entity files and a manifest.json with per-file SHA-256
// digests and an ECDSA P-256 signature over the canonical digest list. The
// wire format is documented in the SymbIoT eIM export schema; OpenIoTRSP
// imports the subset of entities present in its storage.Store schema.
package dataact

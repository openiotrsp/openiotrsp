// Package asn1 contains BER-TLV encoders and decoders for the SGP.32 v1.3
// message structures that OpenIoTRSP sends or receives on wire-facing
// interfaces.
//
// The package follows the SGP.32 v1.3 ASN.1 module in spec/SGP.32 v1.3.asn1.
// Objects imported from SGP.22 are kept as euicc-go TLVs and are not rebuilt
// here. All encoders emit definite-length DER-compatible TLVs so signed
// structures re-encode canonically.
package asn1

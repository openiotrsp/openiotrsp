package esipa

import (
	"encoding/hex"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/pki"
)

// recoverEIDFromPackageResultTLV extracts a 16-byte EID from a Provide (BF50)
// or nested eimPackageResult payload when GSMA JSON omits eidValue.
//
// Preference order for IpaEuiccData (BF52):
//  1. Application 26 (5A) EID inside ipaEuiccData, when present
//  2. eUICC certificate (A6) subject serialNumber (32-digit hex EID)
//
// Returns nil when the payload does not carry a recoverable EID. Callers that
// cannot recover should require eidValue from the IPA.
func recoverEIDFromPackageResultTLV(tlv *bertlv.TLV) []byte {
	if tlv == nil {
		return nil
	}
	if tlv.Tag.Equal(tagProvideResult) {
		if child := tlv.First(tagEID); child != nil && len(child.Value) == 16 {
			return cloneBytes(child.Value)
		}
		for _, child := range tlv.Children {
			if child.Tag.Equal(tagEID) {
				continue
			}
			if eid := recoverEIDFromPackageResultTLV(child); len(eid) == 16 {
				return eid
			}
		}
		return nil
	}
	if tlv.Tag.Equal(tagIpaEuiccData) {
		return recoverEIDFromIpaEuiccDataTLV(tlv)
	}
	return nil
}

func recoverEIDFromIpaEuiccDataTLV(tlv *bertlv.TLV) []byte {
	if child := tlv.First(tagEID); child != nil && len(child.Value) == 16 {
		return cloneBytes(child.Value)
	}
	var response protocolasn1.IpaEuiccDataResponse
	if err := response.UnmarshalBERTLV(tlv); err != nil || response.Data == nil {
		return nil
	}
	if len(response.Data.EID) == 16 {
		return cloneBytes(response.Data.EID)
	}
	return eidFromEUICCCertificateTLV(response.Data.EUICCCertificateRaw)
}

func eidFromEUICCCertificateTLV(wrapper *bertlv.TLV) []byte {
	if wrapper == nil || len(wrapper.Children) == 0 {
		return nil
	}
	der, err := wrapper.Children[0].MarshalBinary()
	if err != nil || len(der) == 0 {
		return nil
	}
	eidHex, err := pki.EIDHexFromCertificate(der)
	if err != nil {
		return nil
	}
	eid, err := hex.DecodeString(eidHex)
	if err != nil || len(eid) != 16 {
		return nil
	}
	return eid
}

package mockipa

import (
	"github.com/damonto/euicc-go/bertlv"
)

// sgp26EUICCInfo builds EUICCInfo1/EUICCInfo2 for the SGP.26 Variant O NIST test
// chain. Field values follow SGP.22 Annex H / RSP test encodings used by public
// SM-DP+ implementations such as sysmocom's test server.
func sgp26EUICCInfo1(ciSubjectKeyID []byte) *bertlv.TLV {
	return bertlv.NewChildren(bertlv.ContextSpecific.Constructed(32),
		versionTypeTLV(bertlv.ContextSpecific.Primitive(2), 0x02, 0x07, 0x00),
		ciPKIDListTLV(bertlv.ContextSpecific.Constructed(9), ciSubjectKeyID),
		ciPKIDListTLV(bertlv.ContextSpecific.Constructed(10), ciSubjectKeyID),
	)
}

func sgp26EUICCInfo2(ciSubjectKeyID []byte) *bertlv.TLV {
	return bertlv.NewChildren(bertlv.ContextSpecific.Constructed(34),
		versionTypeTLV(bertlv.ContextSpecific.Primitive(1), 0x02, 0x01, 0x00),
		versionTypeTLV(bertlv.ContextSpecific.Primitive(2), 0x02, 0x07, 0x00),
		versionTypeTLV(bertlv.ContextSpecific.Primitive(3), 0x01, 0x00, 0x00),
		extCardResourceTLV(),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(5), []byte{0x06, 0x7F, 0x16, 0xC0}),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(8), []byte{0x04, 0x90}),
		ciPKIDListTLV(bertlv.ContextSpecific.Constructed(9), ciSubjectKeyID),
		ciPKIDListTLV(bertlv.ContextSpecific.Constructed(10), ciSubjectKeyID),
		// ppVersion and sasAcreditationNumber use universal tags inside EUICCInfo2.
		versionTypeTLV(bertlv.Universal.Primitive(4), 0xFF, 0xFF, 0xFF),
		bertlv.NewValue(bertlv.Universal.Primitive(12), nil),
	)
}

func versionTypeTLV(tag bertlv.Tag, major, minor, revision byte) *bertlv.TLV {
	return bertlv.NewValue(tag, []byte{major, minor, revision})
}

func ciPKIDListTLV(tag bertlv.Tag, subjectKeyID []byte) *bertlv.TLV {
	return bertlv.NewChildren(tag,
		bertlv.NewValue(bertlv.Universal.Primitive(4), cloneBytes(subjectKeyID)),
	)
}

func extCardResourceTLV() *bertlv.TLV {
	// Extended Card Resource per ETSI TS 102 226, carried as a single OCTET STRING.
	return bertlv.NewValue(bertlv.ContextSpecific.Primitive(4), []byte{
		0x81, 0x01, 0x00,
		0x82, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x83, 0x04, 0x00, 0x00, 0x00, 0x00,
	})
}

func certificateTLV(der []byte) *bertlv.TLV {
	return mustParseTLV(der)
}

func ipaEuiccDataCertificateTLV(tagNumber uint64, der []byte) *bertlv.TLV {
	if len(der) == 0 {
		return nil
	}
	return bertlv.NewChildren(bertlv.ContextSpecific.Constructed(tagNumber), mustParseTLV(der))
}

func authenticateResponseOkTLV(euiccSigned1 *bertlv.TLV, signature, euiccCertDER, eumCertDER []byte) *bertlv.TLV {
	return bertlv.NewChildren(bertlv.ContextSpecific.Constructed(56),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0),
			euiccSigned1,
			bertlv.NewValue(bertlv.Application.Primitive(55), signature),
			certificateTLV(euiccCertDER),
			certificateTLV(eumCertDER),
		),
	)
}

func prepareDownloadResponseOkTLV(euiccSigned2 *bertlv.TLV, signature []byte) *bertlv.TLV {
	return bertlv.NewChildren(bertlv.ContextSpecific.Constructed(33),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0),
			euiccSigned2,
			bertlv.NewValue(bertlv.Application.Primitive(55), signature),
		),
	)
}

package mockipa

import (
	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
)

// SuccessfulProfileDownloadResult builds the SGP.32 result shape accepted by ESipa.
func SuccessfulProfileDownloadResult(transactionID []byte) *protocolasn1.ProfileDownloadTriggerResult {
	return &protocolasn1.ProfileDownloadTriggerResult{
		EimTransactionID: transactionID,
		ProfileInstallationRaw: bertlv.NewChildren(bertlv.ContextSpecific.Constructed(55),
			bertlv.NewChildren(bertlv.ContextSpecific.Constructed(39),
				bertlv.NewChildren(bertlv.ContextSpecific.Constructed(2),
					bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0)),
				),
			),
		),
	}
}

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

// Notification builds a compact pending notification for the mock eUICC.
func Notification(eid []byte, sequenceNumber int64, kind string) *bertlv.TLV {
	return bertlv.NewChildren(bertlv.ContextSpecific.Constructed(1),
		bertlv.NewValue(bertlv.Application.Primitive(26), cloneBytes(eid)),
		notificationMetadata(sequenceNumber, kind),
		bertlv.NewValue(bertlv.Application.Primitive(55), []byte{0x30, 0x00}),
	)
}

func notificationMetadata(sequenceNumber int64, kind string) *bertlv.TLV {
	return bertlv.NewChildren(bertlv.ContextSpecific.Constructed(47),
		mustIntegerTLV(bertlv.ContextSpecific.Primitive(0), sequenceNumber),
		mustBitStringTLV(bertlv.ContextSpecific.Primitive(1), notificationEventBits(kind)),
		bertlv.NewValue(bertlv.Universal.Primitive(12), []byte("notification.openiotrsp.local")),
	)
}

func notificationEventBits(kind string) []bool {
	bits := make([]bool, 4)
	switch kind {
	case "install":
		bits[0] = true
	case "enable":
		bits[1] = true
	case "disable":
		bits[2] = true
	case "delete":
		bits[3] = true
	}
	return bits
}

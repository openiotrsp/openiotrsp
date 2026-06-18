package mockipa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
)

// ProfileDownloadResult builds the profile-download result reported to the eIM.
func ProfileDownloadResult(transactionID []byte, installationResult *bertlv.TLV) *protocolasn1.ProfileDownloadTriggerResult {
	result := &protocolasn1.ProfileDownloadTriggerResult{
		EimTransactionID: transactionID,
	}
	if installationResult != nil {
		result.ProfileInstallationRaw = installationResult.Clone()
		succeeded := true
		result.ProfileInstallationSucceeded = &succeeded
		return result
	}
	result.ProfileInstallationRaw = bertlv.NewChildren(bertlv.ContextSpecific.Constructed(55),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(39),
			bertlv.NewChildren(bertlv.ContextSpecific.Constructed(2),
				bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0)),
			),
		),
	)
	return result
}

// SuccessfulProfileDownloadResult is kept for callers that do not have a PIR yet.
func SuccessfulProfileDownloadResult(transactionID []byte) *protocolasn1.ProfileDownloadTriggerResult {
	return ProfileDownloadResult(transactionID, nil)
}

// SignedNotification builds a pending notification signed by the test eUICC key.
func SignedNotification(fixture *SGP26Fixture, eid []byte, sequenceNumber int64, kind string) (*bertlv.TLV, error) {
	if fixture == nil || fixture.EUICCKey == nil {
		return nil, fmt.Errorf("mockipa: missing SGP.26 eUICC signing key")
	}
	unsignedBody := bertlv.NewChildren(bertlv.ContextSpecific.Constructed(1),
		bertlv.NewValue(bertlv.Application.Primitive(26), cloneBytes(eid)),
		notificationMetadata(sequenceNumber, kind),
	)
	signature, err := signNotification(fixture.EUICCKey, unsignedBody)
	if err != nil {
		return nil, err
	}
	return bertlv.NewChildren(bertlv.ContextSpecific.Constructed(1),
		bertlv.NewValue(bertlv.Application.Primitive(26), cloneBytes(eid)),
		notificationMetadata(sequenceNumber, kind),
		bertlv.NewValue(bertlv.Application.Primitive(55), signature),
	), nil
}

func signNotification(key *ecdsa.PrivateKey, notification *bertlv.TLV) ([]byte, error) {
	payload, err := notification.MarshalBinary()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	return ecdsa.SignASN1(rand.Reader, key, digest[:])
}

// Notification builds an unsigned compact pending notification.
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

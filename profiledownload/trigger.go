// Package profiledownload builds and queues SGP.32 direct profile download
// triggers. In direct mode the eIM only sends the trigger; the IPA performs the
// ES9+ download with the SM-DP+.
package profiledownload

import (
	"context"
	"errors"
	"fmt"
	"strings"

	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/storage"
)

const activationCodeMaxLen = 255

// NewActivationCodeTrigger builds a ProfileDownloadTriggerRequest containing an
// SGP.22 activation code.
//
// The code is validated against the SGP.22 section 4.1 structure here, where the
// trigger is built, because a malformed code is otherwise signed, persisted, and
// delivered over the air only to be rejected by the eUICC. A QR "LPA:" prefix is
// accepted and stripped: the activationCode field carries the activation code
// itself, not the QR payload.
func NewActivationCodeTrigger(activationCode string, transactionID []byte) (*protocolasn1.ProfileDownloadTriggerRequest, error) {
	parsed, err := ParseActivationCode(activationCode)
	if err != nil {
		return nil, err
	}
	code := parsed.String()
	if len(code) > activationCodeMaxLen {
		return nil, fmt.Errorf("profiledownload: activation code is %d bytes, maximum is %d", len(code), activationCodeMaxLen)
	}
	return trigger(&protocolasn1.ProfileDownloadData{
		Kind:           protocolasn1.ProfileDownloadActivationCode,
		ActivationCode: code,
	}, transactionID), nil
}

// NewSMDPAddressTrigger builds the activation-code form used when the eIM has a
// concrete SM-DP+ address plus matching ID or EventID.
func NewSMDPAddressTrigger(smdpAddress string, matchingID string, transactionID []byte) (*protocolasn1.ProfileDownloadTriggerRequest, error) {
	if strings.TrimSpace(smdpAddress) == "" {
		return nil, errors.New("profiledownload: missing SM-DP+ address")
	}
	if strings.TrimSpace(matchingID) == "" {
		return nil, errors.New("profiledownload: missing matching ID")
	}
	return NewActivationCodeTrigger("1$"+smdpAddress+"$"+matchingID, transactionID)
}

// NewDefaultSMDPTrigger instructs the IPA to contact the default SM-DP+ address
// already available in the IoT Device.
func NewDefaultSMDPTrigger(transactionID []byte) *protocolasn1.ProfileDownloadTriggerRequest {
	return trigger(&protocolasn1.ProfileDownloadData{
		Kind: protocolasn1.ProfileDownloadContactDefaultSMDP,
	}, transactionID)
}

// NewSMDSAddressTrigger instructs the IPA to retrieve the SM-DP+ address and
// EventID from an SM-DS. An empty address means the IPA uses its configured SM-DS.
func NewSMDSAddressTrigger(smdsAddress string, transactionID []byte) *protocolasn1.ProfileDownloadTriggerRequest {
	var address *string
	if smdsAddress != "" {
		address = &smdsAddress
	}
	return trigger(&protocolasn1.ProfileDownloadData{
		Kind:        protocolasn1.ProfileDownloadContactSMDS,
		SMDSAddress: address,
	}, transactionID)
}

// EnqueueTrigger encodes and appends the trigger as pending work for the target EID.
func EnqueueTrigger(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	eid string,
	request *protocolasn1.ProfileDownloadTriggerRequest,
) (storage.Operation, error) {
	if store == nil {
		return storage.Operation{}, errors.New("profiledownload: nil Store")
	}
	if request == nil {
		return storage.Operation{}, errors.New("profiledownload: nil ProfileDownloadTriggerRequest")
	}
	payload, err := protocolasn1.Encode(request)
	if err != nil {
		return storage.Operation{}, err
	}
	return store.EnqueueOperation(ctx, tenantID, storage.OperationRequest{
		EID:     eid,
		Kind:    storage.OperationProfileDownloadTrigger,
		Payload: payload,
	})
}

func trigger(data *protocolasn1.ProfileDownloadData, transactionID []byte) *protocolasn1.ProfileDownloadTriggerRequest {
	return &protocolasn1.ProfileDownloadTriggerRequest{
		ProfileDownloadData: data,
		EimTransactionID:    cloneBytes(transactionID),
	}
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out
}

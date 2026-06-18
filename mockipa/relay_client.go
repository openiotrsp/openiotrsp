package mockipa

import (
	"context"
	"fmt"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
)

var (
	tagRelayInitiateAuth    = bertlv.ContextSpecific.Constructed(57)
	tagRelayGetBoundPackage = bertlv.ContextSpecific.Constructed(58)
	tagRelayAuthenticate    = bertlv.ContextSpecific.Constructed(59)
	tagRelayHandleNotify    = bertlv.ContextSpecific.Constructed(61)
	tagRelayCancelSession   = bertlv.ContextSpecific.Constructed(65)
)

// Relay sends an indirect ES9+ relay TLV to the eIM and returns the relay response TLV.
func (c Client) Relay(ctx context.Context, relayTLV *bertlv.TLV) (*bertlv.TLV, error) {
	if relayTLV == nil {
		return nil, fmt.Errorf("mockipa: missing relay TLV")
	}
	raw, err := marshalRawIPAEnvelope(relayTLV)
	if err != nil {
		return nil, err
	}
	response, err := c.exchange(ctx, raw)
	if err != nil {
		return nil, err
	}
	if response.Raw == nil {
		return nil, fmt.Errorf("mockipa: empty relay response")
	}
	return response.Raw, nil
}

func buildInitiateAuthenticationRelay(smdpAddress string, euiccInfo1 *bertlv.TLV) (*bertlv.TLV, error) {
	info1, err := euiccInfo1.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return bertlv.NewChildren(tagRelayInitiateAuth,
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(3), []byte(smdpAddress)),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(1), info1),
	), nil
}

func buildAuthenticateClientRelay(authenticateServerResponse *bertlv.TLV) *bertlv.TLV {
	return bertlv.NewChildren(tagRelayAuthenticate, authenticateServerResponse)
}

func buildGetBoundProfilePackageRelay(prepareDownloadResponse *bertlv.TLV) *bertlv.TLV {
	return bertlv.NewChildren(tagRelayGetBoundPackage, prepareDownloadResponse)
}

func buildHandleNotificationRelay(notification *bertlv.TLV) *bertlv.TLV {
	return bertlv.NewChildren(tagRelayHandleNotify, notification)
}

func buildCancelSessionRelay(cancelSessionResponse *bertlv.TLV) *bertlv.TLV {
	return bertlv.NewChildren(tagRelayCancelSession, cancelSessionResponse)
}

func relayResponseOK(relayResponse *bertlv.TLV) (*bertlv.TLV, error) {
	if relayResponse == nil {
		return nil, fmt.Errorf("mockipa: missing relay response")
	}
	if child := relayResponse.First(bertlv.ContextSpecific.Constructed(0)); child != nil {
		return child, nil
	}
	return relayResponse, nil
}

func parseES9InitiateAuthenticationResponse(relayResponse *bertlv.TLV) (transactionID []byte, signed1, signature1, usedIssuer, certificate *bertlv.TLV, err error) {
	ok, err := relayResponseOK(relayResponse)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	transactionID = cloneTLVValue(ok.First(bertlv.ContextSpecific.Primitive(0)))
	signed1 = ok.First(bertlv.Universal.Constructed(16))
	signature1 = ok.First(bertlv.Application.Primitive(55))
	usedIssuer = ok.First(bertlv.ContextSpecific.Constructed(9))
	certificate = ok.First(bertlv.ContextSpecific.Constructed(10))
	if len(transactionID) == 0 || signed1 == nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("mockipa: invalid initiateAuthentication relay response")
	}
	return transactionID, signed1, signature1, usedIssuer, certificate, nil
}

func parseES9AuthenticateClientResponse(relayResponse *bertlv.TLV) (transactionID []byte, profileMetadata, signed2, signature2, certificate *bertlv.TLV, err error) {
	ok, err := relayResponseOK(relayResponse)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	transactionID = cloneTLVValue(ok.First(bertlv.ContextSpecific.Primitive(0)))
	profileMetadata = ok.First(bertlv.ContextSpecific.Constructed(1))
	signed2 = ok.First(bertlv.Universal.Constructed(16))
	signature2 = ok.First(bertlv.Application.Primitive(55))
	certificate = ok.First(bertlv.ContextSpecific.Constructed(10))
	if len(transactionID) == 0 || signed2 == nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("mockipa: invalid authenticateClient relay response")
	}
	return transactionID, profileMetadata, signed2, signature2, certificate, nil
}

func parseES9BoundProfilePackageResponse(relayResponse *bertlv.TLV) (*bertlv.TLV, error) {
	ok, err := relayResponseOK(relayResponse)
	if err != nil {
		return nil, err
	}
	bpp := ok.First(bertlv.ContextSpecific.Constructed(1))
	if bpp == nil {
		return nil, fmt.Errorf("mockipa: missing boundProfilePackage in relay response")
	}
	return bpp, nil
}

// decodeProvideResultAck is shared with client upload path.
func decodeProvideResultAck(raw *bertlv.TLV) (*protocolasn1.EimAcknowledgements, error) {
	if raw == nil {
		return &protocolasn1.EimAcknowledgements{}, nil
	}
	var ack protocolasn1.EimAcknowledgements
	if err := ack.UnmarshalBERTLV(raw); err != nil {
		return &protocolasn1.EimAcknowledgements{}, nil
	}
	return &ack, nil
}

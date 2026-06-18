// Package mockipa implements a demo IoT Profile Assistant that polls an eIM over
// ESipa and drives the software eUICC for local interoperability testing.
package mockipa

import (
	"context"
	"fmt"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
)

// Client exchanges BER-TLV ESipa messages with an eIM.
type Client struct {
	Transport Transport
}

// NewHTTPClient creates a Client that uses HTTPS ESipa.
func NewHTTPClient(endpoint string, transport HTTPTransport) Client {
	if transport.Endpoint == "" {
		transport.Endpoint = endpoint
	}
	return Client{Transport: transport}
}

// NewCoAPClient creates a Client that uses CoAP/DTLS ESipa.
func NewCoAPClient(transport *CoAPTransport) Client {
	return Client{Transport: transport}
}

// Poll fetches one pending eIM package for eid.
func (c Client) Poll(ctx context.Context, eid []byte) (*protocolasn1.GetEimPackageResponse, error) {
	raw, err := marshalIPAEnvelope(&protocolasn1.GetEimPackageRequest{EID: eid})
	if err != nil {
		return nil, err
	}
	response, err := c.exchange(ctx, raw)
	if err != nil {
		return nil, err
	}
	var decoded protocolasn1.GetEimPackageResponse
	if err := decoded.UnmarshalBERTLV(response.Raw); err != nil {
		return nil, err
	}
	return &decoded, nil
}

// UploadProfileDownloadResult sends the profile-download result back to the eIM.
func (c Client) UploadProfileDownloadResult(ctx context.Context, eid []byte, result *protocolasn1.ProfileDownloadTriggerResult) error {
	tlv, err := result.MarshalBERTLV()
	if err != nil {
		return err
	}
	_, err = c.uploadEimPackageResultTLV(ctx, eid, tlv)
	return err
}

// UploadEUICCPackageResult sends an eUICC package result back to the eIM.
func (c Client) UploadEUICCPackageResult(ctx context.Context, eid []byte, result *protocolasn1.EuiccPackageResult) error {
	_, err := c.UploadEUICCPackageResultWithNotifications(ctx, eid, result, nil)
	return err
}

// UploadEUICCPackageResultWithNotifications sends an eUICC package result with
// pending notifications and returns the eIM acknowledgement sequence numbers.
func (c Client) UploadEUICCPackageResultWithNotifications(ctx context.Context, eid []byte, result *protocolasn1.EuiccPackageResult, notifications []*bertlv.TLV) (*protocolasn1.EimAcknowledgements, error) {
	tlv, err := result.MarshalBERTLV()
	if err != nil {
		return nil, err
	}
	if len(notifications) > 0 {
		children := make([]*bertlv.TLV, 0, 2)
		children = append(children, tlv)
		children = append(children, bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0), notifications...))
		tlv = bertlv.NewChildren(bertlv.Universal.Constructed(16), children...)
	}
	return c.uploadEimPackageResultTLV(ctx, eid, tlv)
}

// UploadIpaEuiccDataResponse sends an IPA eUICC data response back to the eIM.
func (c Client) UploadIpaEuiccDataResponse(ctx context.Context, eid []byte, result *protocolasn1.IpaEuiccDataResponse) error {
	tlv, err := result.MarshalBERTLV()
	if err != nil {
		return err
	}
	_, err = c.uploadEimPackageResultTLV(ctx, eid, tlv)
	return err
}

// SendNotification delivers one HandleNotificationEsipa pending notification.
func (c Client) SendNotification(ctx context.Context, notification *bertlv.TLV) error {
	raw, err := marshalRawIPAEnvelope(bertlv.NewChildren(bertlv.ContextSpecific.Constructed(61),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0), notification),
	))
	if err != nil {
		return err
	}
	return c.exchangeNoContent(ctx, raw)
}

func (c Client) uploadEimPackageResultTLV(ctx context.Context, eid []byte, tlv *bertlv.TLV) (*protocolasn1.EimAcknowledgements, error) {
	raw, err := marshalIPAEnvelope(&protocolasn1.ProvideEimPackageResult{
		EID: eid,
		EimPackageResult: protocolasn1.EimPackageResult{
			Raw: tlv,
		},
	})
	if err != nil {
		return nil, err
	}
	response, err := c.exchange(ctx, raw)
	if err != nil {
		return nil, err
	}
	var decoded protocolasn1.ProvideEimPackageResultResponse
	if err := decoded.UnmarshalBERTLV(response.Raw); err != nil {
		return nil, err
	}
	return decodeProvideResultAck(decoded.Raw)
}

func (c Client) exchange(ctx context.Context, payload []byte) (*protocolasn1.ESipaMessageFromEimToIpa, error) {
	if c.Transport == nil {
		return nil, fmt.Errorf("mockipa: missing ESipa transport")
	}
	body, noContent, err := c.Transport.Exchange(ctx, payload)
	if err != nil {
		return nil, err
	}
	if noContent {
		return &protocolasn1.ESipaMessageFromEimToIpa{}, nil
	}
	return decodeEimEnvelope(body)
}

func (c Client) exchangeNoContent(ctx context.Context, payload []byte) error {
	if c.Transport == nil {
		return fmt.Errorf("mockipa: missing ESipa transport")
	}
	_, noContent, err := c.Transport.Exchange(ctx, payload)
	if err != nil {
		return err
	}
	if !noContent {
		return fmt.Errorf("mockipa: ESipa notification expected no-content response")
	}
	return nil
}

func marshalIPAEnvelope(value protocolasn1.Marshaler) ([]byte, error) {
	tlv, err := value.MarshalBERTLV()
	if err != nil {
		return nil, err
	}
	return marshalRawIPAEnvelope(tlv)
}

func marshalRawIPAEnvelope(tlv *bertlv.TLV) ([]byte, error) {
	return protocolasn1.Encode(&protocolasn1.ESipaMessageFromIpaToEim{Raw: tlv})
}

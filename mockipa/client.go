// Package mockipa implements a small IPA used by the local demo and tests.
package mockipa

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/esipa"
)

// Client exchanges BER-TLV ESipa messages with an eIM.
type Client struct {
	Endpoint   string
	HTTPClient *http.Client
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
	var ack protocolasn1.EimAcknowledgements
	if err := ack.UnmarshalBERTLV(decoded.Raw); err != nil {
		return &protocolasn1.EimAcknowledgements{}, nil
	}
	return &ack, nil
}

func (c Client) exchange(ctx context.Context, payload []byte) (*protocolasn1.ESipaMessageFromEimToIpa, error) {
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", esipa.MediaType)
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mockipa: ESipa returned %s: %s", response.Status, string(body))
	}
	var envelope protocolasn1.ESipaMessageFromEimToIpa
	if err := protocolasn1.Decode(body, &envelope); err != nil {
		return nil, err
	}
	return &envelope, nil
}

func (c Client) exchangeNoContent(ctx context.Context, payload []byte) error {
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", esipa.MediaType)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusNoContent || len(body) != 0 {
		return fmt.Errorf("mockipa: ESipa notification returned %s: %s", response.Status, string(body))
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

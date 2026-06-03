// Package mockipa implements a small IPA used by the local demo and tests.
package mockipa

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

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
	raw, err := marshalIPAEnvelope(&protocolasn1.ProvideEimPackageResult{
		EID: eid,
		EimPackageResult: protocolasn1.EimPackageResult{
			Raw: tlv,
		},
	})
	if err != nil {
		return err
	}
	response, err := c.exchange(ctx, raw)
	if err != nil {
		return err
	}
	var decoded protocolasn1.ProvideEimPackageResultResponse
	return decoded.UnmarshalBERTLV(response.Raw)
}

// UploadEUICCPackageResult sends an eUICC package result back to the eIM.
func (c Client) UploadEUICCPackageResult(ctx context.Context, eid []byte, result *protocolasn1.EuiccPackageResult) error {
	tlv, err := result.MarshalBERTLV()
	if err != nil {
		return err
	}
	raw, err := marshalIPAEnvelope(&protocolasn1.ProvideEimPackageResult{
		EID: eid,
		EimPackageResult: protocolasn1.EimPackageResult{
			Raw: tlv,
		},
	})
	if err != nil {
		return err
	}
	response, err := c.exchange(ctx, raw)
	if err != nil {
		return err
	}
	var decoded protocolasn1.ProvideEimPackageResultResponse
	return decoded.UnmarshalBERTLV(response.Raw)
}

// UploadIpaEuiccDataResponse sends an IPA eUICC data response back to the eIM.
func (c Client) UploadIpaEuiccDataResponse(ctx context.Context, eid []byte, result *protocolasn1.IpaEuiccDataResponse) error {
	tlv, err := result.MarshalBERTLV()
	if err != nil {
		return err
	}
	raw, err := marshalIPAEnvelope(&protocolasn1.ProvideEimPackageResult{
		EID: eid,
		EimPackageResult: protocolasn1.EimPackageResult{
			Raw: tlv,
		},
	})
	if err != nil {
		return err
	}
	response, err := c.exchange(ctx, raw)
	if err != nil {
		return err
	}
	var decoded protocolasn1.ProvideEimPackageResultResponse
	return decoded.UnmarshalBERTLV(response.Raw)
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

func marshalIPAEnvelope(value protocolasn1.Marshaler) ([]byte, error) {
	tlv, err := value.MarshalBERTLV()
	if err != nil {
		return nil, err
	}
	return protocolasn1.Encode(&protocolasn1.ESipaMessageFromIpaToEim{Raw: tlv})
}

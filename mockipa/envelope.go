package mockipa

import (
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
)

func decodeEimEnvelope(body []byte) (*protocolasn1.ESipaMessageFromEimToIpa, error) {
	var envelope protocolasn1.ESipaMessageFromEimToIpa
	if err := protocolasn1.Decode(body, &envelope); err != nil {
		return nil, err
	}
	return &envelope, nil
}

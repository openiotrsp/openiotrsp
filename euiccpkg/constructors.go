// Package euiccpkg constructs, signs, verifies, and applies SGP.32 eUICC
// Packages.
package euiccpkg

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
)

// Enable builds a EuiccPackage containing one PSMO enable operation.
func Enable(iccid []byte, rollback bool) protocolasn1.EuiccPackage {
	return psmoPackage(protocolasn1.Psmo{
		Operation:    protocolasn1.PsmoEnable,
		ICCID:        cloneBytes(iccid),
		RollbackFlag: rollback,
	})
}

// Disable builds a EuiccPackage containing one PSMO disable operation.
func Disable(iccid []byte) protocolasn1.EuiccPackage {
	return psmoPackage(protocolasn1.Psmo{
		Operation: protocolasn1.PsmoDisable,
		ICCID:     cloneBytes(iccid),
	})
}

// Delete builds a EuiccPackage containing one PSMO delete operation.
func Delete(iccid []byte) protocolasn1.EuiccPackage {
	return psmoPackage(protocolasn1.Psmo{
		Operation: protocolasn1.PsmoDelete,
		ICCID:     cloneBytes(iccid),
	})
}

// NewEIMConfigurationData builds the common add/update ECO payload using a raw
// X.509 SubjectPublicKeyInfo DER public key.
func NewEIMConfigurationData(eimID, eimFQDN string, counterValue int64, publicKeyDER []byte) (*protocolasn1.EimConfigurationData, error) {
	return newEIMConfigurationData(eimID, eimFQDN, counterValue, protocolasn1.X509SubjectPublicKeyInfo, publicKeyDER)
}

// NewEIMConfigurationDataFromPublicKey builds the common add/update ECO payload
// from a crypto public key by DER-encoding it as SubjectPublicKeyInfo.
func NewEIMConfigurationDataFromPublicKey(eimID, eimFQDN string, counterValue int64, publicKey crypto.PublicKey) (*protocolasn1.EimConfigurationData, error) {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal eIM public key: %w", err)
	}
	return NewEIMConfigurationData(eimID, eimFQDN, counterValue, publicKeyDER)
}

// NewEIMConfigurationDataFromCertificate builds the common add/update ECO
// payload using a raw X.509 certificate DER.
func NewEIMConfigurationDataFromCertificate(eimID, eimFQDN string, counterValue int64, certificateDER []byte) (*protocolasn1.EimConfigurationData, error) {
	return newEIMConfigurationData(eimID, eimFQDN, counterValue, protocolasn1.X509Certificate, certificateDER)
}

func newEIMConfigurationData(eimID, eimFQDN string, counterValue int64, kind protocolasn1.X509ChoiceKind, x509DER []byte) (*protocolasn1.EimConfigurationData, error) {
	if eimID == "" {
		return nil, errors.New("euiccpkg: missing eIM ID")
	}
	if len(x509DER) == 0 {
		return nil, errors.New("euiccpkg: missing eIM public key data")
	}
	x509TLV, err := parseSingleTLV(x509DER)
	if err != nil {
		return nil, fmt.Errorf("parse eIM public key data: %w", err)
	}
	config := &protocolasn1.EimConfigurationData{
		EimID:            eimID,
		CounterValue:     &counterValue,
		EimPublicKeyData: &protocolasn1.X509Choice{Kind: kind, Data: x509TLV},
	}
	if eimFQDN != "" {
		config.EimFQDN = &eimFQDN
	}
	return config, nil
}

// AddEIM builds a EuiccPackage containing one ECO addEim operation.
func AddEIM(config *protocolasn1.EimConfigurationData) protocolasn1.EuiccPackage {
	return ecoPackage(protocolasn1.Eco{
		Operation: protocolasn1.EcoAddEIM,
		Config:    config,
	})
}

// AddEim builds a EuiccPackage containing one ECO addEim operation.
func AddEim(config *protocolasn1.EimConfigurationData) protocolasn1.EuiccPackage {
	return AddEIM(config)
}

// DeleteEIM builds a EuiccPackage containing one ECO deleteEim operation.
func DeleteEIM(eimID string) protocolasn1.EuiccPackage {
	return ecoPackage(protocolasn1.Eco{
		Operation: protocolasn1.EcoDeleteEIM,
		EimID:     eimID,
	})
}

// DeleteEim builds a EuiccPackage containing one ECO deleteEim operation.
func DeleteEim(eimID string) protocolasn1.EuiccPackage {
	return DeleteEIM(eimID)
}

// UpdateEIM builds a EuiccPackage containing one ECO updateEim operation.
func UpdateEIM(config *protocolasn1.EimConfigurationData) protocolasn1.EuiccPackage {
	return ecoPackage(protocolasn1.Eco{
		Operation: protocolasn1.EcoUpdateEIM,
		Config:    config,
	})
}

// UpdateEim builds a EuiccPackage containing one ECO updateEim operation.
func UpdateEim(config *protocolasn1.EimConfigurationData) protocolasn1.EuiccPackage {
	return UpdateEIM(config)
}

// ListEIM builds a EuiccPackage containing one ECO listEim operation.
func ListEIM() protocolasn1.EuiccPackage {
	return ecoPackage(protocolasn1.Eco{
		Operation: protocolasn1.EcoListEIM,
	})
}

// ListEim builds a EuiccPackage containing one ECO listEim operation.
func ListEim() protocolasn1.EuiccPackage {
	return ListEIM()
}

func psmoPackage(psmo protocolasn1.Psmo) protocolasn1.EuiccPackage {
	return protocolasn1.EuiccPackage{
		Kind:  protocolasn1.EuiccPackagePSMO,
		PSMOs: []protocolasn1.Psmo{psmo},
	}
}

func ecoPackage(eco protocolasn1.Eco) protocolasn1.EuiccPackage {
	return protocolasn1.EuiccPackage{
		Kind: protocolasn1.EuiccPackageECO,
		ECOs: []protocolasn1.Eco{eco},
	}
}

func parseSingleTLV(data []byte) (*bertlv.TLV, error) {
	reader := bytes.NewReader(data)
	tlv := new(bertlv.TLV)
	n, err := tlv.ReadFrom(reader)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("truncated BER-TLV input: %w", err)
		}
		return nil, err
	}
	if n != int64(len(data)) || reader.Len() != 0 {
		return nil, errors.New("trailing data after BER-TLV object")
	}
	return tlv, nil
}

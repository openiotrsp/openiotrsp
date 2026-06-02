package asn1

import (
	stdasn1 "encoding/asn1"
	"errors"
	"fmt"

	"github.com/damonto/euicc-go/bertlv"
)

// TLV is the BER-TLV representation used by euicc-go for SGP.22 imported
// structures.
type TLV = bertlv.TLV

// EimIDType identifies the namespace used by an eIM identifier.
type EimIDType int64

const (
	// EimIDTypeOID means the eIM ID is an object identifier.
	EimIDTypeOID EimIDType = 1
	// EimIDTypeFQDN means the eIM ID is a fully qualified domain name.
	EimIDTypeFQDN EimIDType = 2
	// EimIDTypeProprietary means the eIM ID uses a proprietary namespace.
	EimIDTypeProprietary EimIDType = 3
)

// EimSupportedProtocol is the SGP.32 eimSupportedProtocol BIT STRING.
type EimSupportedProtocol []bool

// X509ChoiceKind identifies the selected X.509 object in SGP.32 public-key
// choice fields.
type X509ChoiceKind int

const (
	// X509SubjectPublicKeyInfo selects SubjectPublicKeyInfo.
	X509SubjectPublicKeyInfo X509ChoiceKind = iota + 1
	// X509Certificate selects Certificate.
	X509Certificate
)

// X509Choice carries a raw X.509 SubjectPublicKeyInfo or Certificate TLV.
type X509Choice struct {
	Kind X509ChoiceKind
	Data *bertlv.TLV
}

// EimConfigurationData is SGP.32 EimConfigurationData.
type EimConfigurationData struct {
	EimID                               string
	EimFQDN                             *string
	EimIDType                           *EimIDType
	CounterValue                        *int64
	AssociationToken                    *int64
	EimPublicKeyData                    *X509Choice
	TrustedPublicKeyDataTLS             *X509Choice
	EimSupportedProtocol                *EimSupportedProtocol
	EUICCCIPKID                         []byte
	IndirectProfileDownload             bool
	ESipaProprietaryProtocolInformation *bertlv.TLV
}

// MarshalBERTLV encodes EimConfigurationData as a universal SEQUENCE.
func (e *EimConfigurationData) MarshalBERTLV() (*bertlv.TLV, error) {
	if e == nil {
		return nil, errors.New("asn1: nil EimConfigurationData")
	}
	children := []*bertlv.TLV{utf8TLV(bertlv.ContextSpecific.Primitive(0), e.EimID)}
	if e.EimFQDN != nil {
		children = append(children, utf8TLV(bertlv.ContextSpecific.Primitive(1), *e.EimFQDN))
	}
	if e.EimIDType != nil {
		child, err := integerTLV(bertlv.ContextSpecific.Primitive(2), *e.EimIDType)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	if e.CounterValue != nil {
		child, err := integerTLV(bertlv.ContextSpecific.Primitive(3), *e.CounterValue)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	if e.AssociationToken != nil {
		child, err := integerTLV(bertlv.ContextSpecific.Primitive(4), *e.AssociationToken)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	if e.EimPublicKeyData != nil {
		child, err := marshalX509Choice(bertlv.ContextSpecific.Constructed(5), e.EimPublicKeyData)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	if e.TrustedPublicKeyDataTLS != nil {
		child, err := marshalX509Choice(bertlv.ContextSpecific.Constructed(6), e.TrustedPublicKeyDataTLS)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	if e.EimSupportedProtocol != nil {
		children = append(children, bitStringTLV(bertlv.ContextSpecific.Primitive(7), []bool(*e.EimSupportedProtocol)))
	}
	if e.EUICCCIPKID != nil {
		children = append(children, octetTLV(bertlv.ContextSpecific.Primitive(8), e.EUICCCIPKID))
	}
	if e.IndirectProfileDownload {
		children = append(children, nullTLV(bertlv.ContextSpecific.Primitive(9)))
	}
	if e.ESipaProprietaryProtocolInformation != nil {
		children = append(children, rawChild(e.ESipaProprietaryProtocolInformation))
	}
	return constructed(tagSequence, children...), nil
}

// UnmarshalBERTLV decodes EimConfigurationData from a universal SEQUENCE.
func (e *EimConfigurationData) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagSequence); err != nil {
		return err
	}
	var out EimConfigurationData
	var err error
	if out.EimID, err = utf8Value(tlv.First(bertlv.ContextSpecific.Primitive(0))); err != nil {
		return err
	}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(1)); child != nil {
		value, err := utf8Value(child)
		if err != nil {
			return err
		}
		out.EimFQDN = &value
	}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(2)); child != nil {
		value, err := integerValue[EimIDType](child)
		if err != nil {
			return err
		}
		out.EimIDType = &value
	}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(3)); child != nil {
		value, err := integerValue[int64](child)
		if err != nil {
			return err
		}
		out.CounterValue = &value
	}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(4)); child != nil {
		value, err := integerValue[int64](child)
		if err != nil {
			return err
		}
		out.AssociationToken = &value
	}
	if child := tlv.First(bertlv.ContextSpecific.Constructed(5)); child != nil {
		out.EimPublicKeyData, err = unmarshalX509Choice(child, X509SubjectPublicKeyInfo)
		if err != nil {
			return err
		}
	}
	if child := tlv.First(bertlv.ContextSpecific.Constructed(6)); child != nil {
		out.TrustedPublicKeyDataTLS, err = unmarshalX509Choice(child, X509SubjectPublicKeyInfo)
		if err != nil {
			return err
		}
	}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(7)); child != nil {
		bits, err := bitStringValue(child)
		if err != nil {
			return err
		}
		value := EimSupportedProtocol(bits)
		out.EimSupportedProtocol = &value
	}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(8)); child != nil {
		out.EUICCCIPKID, err = octetValue(child)
		if err != nil {
			return err
		}
	}
	out.IndirectProfileDownload = tlv.First(bertlv.ContextSpecific.Primitive(9)) != nil
	if child := tlv.First(bertlv.ContextSpecific.Constructed(10)); child != nil {
		out.ESipaProprietaryProtocolInformation = cloneTLV(child)
	}
	*e = out
	return nil
}

func marshalX509Choice(tag bertlv.Tag, choice *X509Choice) (*bertlv.TLV, error) {
	if choice == nil || choice.Data == nil {
		return nil, errors.New("asn1: missing X.509 choice data")
	}
	if choice.Kind != X509SubjectPublicKeyInfo && choice.Kind != X509Certificate {
		return nil, fmt.Errorf("asn1: unknown X.509 choice kind %d", choice.Kind)
	}
	return constructed(tag, rawChild(choice.Data)), nil
}

func unmarshalX509Choice(tlv *bertlv.TLV, fallback X509ChoiceKind) (*X509Choice, error) {
	if len(tlv.Children) != 1 {
		return nil, errors.New("asn1: X.509 choice must contain exactly one child")
	}
	return &X509Choice{Kind: fallback, Data: cloneTLV(tlv.Children[0])}, nil
}

// EcoOperation identifies the selected SGP.32 ECO command.
type EcoOperation int

const (
	// EcoAddEIM selects addEim.
	EcoAddEIM EcoOperation = iota + 1
	// EcoDeleteEIM selects deleteEim.
	EcoDeleteEIM
	// EcoUpdateEIM selects updateEim.
	EcoUpdateEIM
	// EcoListEIM selects listEim.
	EcoListEIM
)

// Eco is SGP.32 Eco, an eIM Configuration Operation CHOICE.
type Eco struct {
	Operation EcoOperation
	Config    *EimConfigurationData
	EimID     string
}

// MarshalBERTLV encodes an ECO CHOICE.
func (e *Eco) MarshalBERTLV() (*bertlv.TLV, error) {
	if e == nil {
		return nil, errors.New("asn1: nil Eco")
	}
	switch e.Operation {
	case EcoAddEIM:
		return marshalTaggedEimConfig(bertlv.ContextSpecific.Constructed(8), e.Config)
	case EcoDeleteEIM:
		return constructed(bertlv.ContextSpecific.Constructed(9), utf8TLV(bertlv.ContextSpecific.Primitive(0), e.EimID)), nil
	case EcoUpdateEIM:
		return marshalTaggedEimConfig(bertlv.ContextSpecific.Constructed(10), e.Config)
	case EcoListEIM:
		return constructed(bertlv.ContextSpecific.Constructed(11)), nil
	default:
		return nil, fmt.Errorf("asn1: unknown ECO operation %d", e.Operation)
	}
}

// UnmarshalBERTLV decodes an ECO CHOICE.
func (e *Eco) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if tlv == nil {
		return errors.New("asn1: missing Eco")
	}
	var out Eco
	switch {
	case hasTag(tlv, bertlv.ContextSpecific.Constructed(8)):
		out.Operation = EcoAddEIM
		config, err := unmarshalTaggedEimConfig(tlv)
		if err != nil {
			return err
		}
		out.Config = config
	case hasTag(tlv, bertlv.ContextSpecific.Constructed(9)):
		out.Operation = EcoDeleteEIM
		value, err := utf8Value(tlv.First(bertlv.ContextSpecific.Primitive(0)))
		if err != nil {
			return err
		}
		out.EimID = value
	case hasTag(tlv, bertlv.ContextSpecific.Constructed(10)):
		out.Operation = EcoUpdateEIM
		config, err := unmarshalTaggedEimConfig(tlv)
		if err != nil {
			return err
		}
		out.Config = config
	case hasTag(tlv, bertlv.ContextSpecific.Constructed(11)):
		out.Operation = EcoListEIM
	default:
		return fmt.Errorf("%w: unknown ECO tag %s", errUnexpectedTag, tlv.Tag.String())
	}
	*e = out
	return nil
}

func marshalTaggedEimConfig(tag bertlv.Tag, config *EimConfigurationData) (*bertlv.TLV, error) {
	if config == nil {
		return nil, errors.New("asn1: missing EimConfigurationData")
	}
	encoded, err := config.MarshalBERTLV()
	if err != nil {
		return nil, err
	}
	return constructed(tag, encoded.Children...), nil
}

func unmarshalTaggedEimConfig(tlv *bertlv.TLV) (*EimConfigurationData, error) {
	config := new(EimConfigurationData)
	if err := config.UnmarshalBERTLV(constructed(tagSequence, tlv.Children...)); err != nil {
		return nil, err
	}
	return config, nil
}

// PsmoOperation identifies the selected Profile State Management Operation.
type PsmoOperation int

const (
	// PsmoEnable selects enable.
	PsmoEnable PsmoOperation = iota + 1
	// PsmoDisable selects disable.
	PsmoDisable
	// PsmoDelete selects delete.
	PsmoDelete
	// PsmoListProfileInfo selects listProfileInfo.
	PsmoListProfileInfo
	// PsmoGetRAT selects getRAT.
	PsmoGetRAT
	// PsmoConfigureImmediateEnable selects configureImmediateEnable.
	PsmoConfigureImmediateEnable
	// PsmoSetFallbackAttribute selects setFallbackAttribute.
	PsmoSetFallbackAttribute
	// PsmoUnsetFallbackAttribute selects unsetFallbackAttribute.
	PsmoUnsetFallbackAttribute
	// PsmoSetDefaultDPAddress selects setDefaultDpAddress.
	PsmoSetDefaultDPAddress
)

// ConfigureImmediateEnable carries the configureImmediateEnable PSMO payload.
type ConfigureImmediateEnable struct {
	ImmediateEnableFlag bool
	DefaultSMDPOID      stdasn1.ObjectIdentifier
	DefaultSMDPAddress  *string
}

// Psmo is SGP.32 Psmo, a Profile State Management Operation CHOICE.
type Psmo struct {
	Operation              PsmoOperation
	ICCID                  []byte
	RollbackFlag           bool
	ProfileInfoListRequest *bertlv.TLV
	ImmediateEnable        *ConfigureImmediateEnable
	SetDefaultDPAddress    *SetDefaultDPAddressRequest
}

// MarshalBERTLV encodes a PSMO CHOICE.
func (p *Psmo) MarshalBERTLV() (*bertlv.TLV, error) {
	if p == nil {
		return nil, errors.New("asn1: nil Psmo")
	}
	switch p.Operation {
	case PsmoEnable:
		children := []*bertlv.TLV{octetTLV(tagEID, p.ICCID)}
		if p.RollbackFlag {
			children = append(children, nullTLV(tagNull))
		}
		return constructed(bertlv.ContextSpecific.Constructed(3), children...), nil
	case PsmoDisable:
		return constructed(bertlv.ContextSpecific.Constructed(4), octetTLV(tagEID, p.ICCID)), nil
	case PsmoDelete:
		return constructed(bertlv.ContextSpecific.Constructed(5), octetTLV(tagEID, p.ICCID)), nil
	case PsmoListProfileInfo:
		if p.ProfileInfoListRequest == nil {
			return nil, errors.New("asn1: missing ProfileInfoListRequest TLV")
		}
		return rawChild(p.ProfileInfoListRequest), nil
	case PsmoGetRAT:
		return constructed(bertlv.ContextSpecific.Constructed(6)), nil
	case PsmoConfigureImmediateEnable:
		return marshalConfigureImmediateEnable(p.ImmediateEnable)
	case PsmoSetFallbackAttribute:
		return constructed(bertlv.ContextSpecific.Constructed(8), octetTLV(tagEID, p.ICCID)), nil
	case PsmoUnsetFallbackAttribute:
		return constructed(bertlv.ContextSpecific.Constructed(9)), nil
	case PsmoSetDefaultDPAddress:
		if p.SetDefaultDPAddress == nil {
			return nil, errors.New("asn1: missing SetDefaultDPAddressRequest")
		}
		return p.SetDefaultDPAddress.MarshalBERTLV()
	default:
		return nil, fmt.Errorf("asn1: unknown PSMO operation %d", p.Operation)
	}
}

// UnmarshalBERTLV decodes a PSMO CHOICE.
func (p *Psmo) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if tlv == nil {
		return errors.New("asn1: missing Psmo")
	}
	var out Psmo
	var err error
	switch {
	case hasTag(tlv, bertlv.ContextSpecific.Constructed(3)):
		out.Operation = PsmoEnable
		out.ICCID, err = octetValue(tlv.First(tagEID))
		if err != nil {
			return err
		}
		out.RollbackFlag = tlv.First(tagNull) != nil
	case hasTag(tlv, bertlv.ContextSpecific.Constructed(4)):
		out.Operation = PsmoDisable
		out.ICCID, err = octetValue(tlv.First(tagEID))
	case hasTag(tlv, bertlv.ContextSpecific.Constructed(5)):
		out.Operation = PsmoDelete
		out.ICCID, err = octetValue(tlv.First(tagEID))
	case hasTag(tlv, tagProfileInfoList):
		out.Operation = PsmoListProfileInfo
		out.ProfileInfoListRequest = cloneTLV(tlv)
	case hasTag(tlv, bertlv.ContextSpecific.Constructed(6)):
		out.Operation = PsmoGetRAT
	case hasTag(tlv, bertlv.ContextSpecific.Constructed(7)):
		out.Operation = PsmoConfigureImmediateEnable
		out.ImmediateEnable, err = unmarshalConfigureImmediateEnable(tlv)
	case hasTag(tlv, bertlv.ContextSpecific.Constructed(8)):
		out.Operation = PsmoSetFallbackAttribute
		out.ICCID, err = octetValue(tlv.First(tagEID))
	case hasTag(tlv, bertlv.ContextSpecific.Constructed(9)):
		out.Operation = PsmoUnsetFallbackAttribute
	case hasTag(tlv, tagSetDefaultDPAddress):
		out.Operation = PsmoSetDefaultDPAddress
		out.SetDefaultDPAddress = new(SetDefaultDPAddressRequest)
		err = out.SetDefaultDPAddress.UnmarshalBERTLV(tlv)
	default:
		return fmt.Errorf("%w: unknown PSMO tag %s", errUnexpectedTag, tlv.Tag.String())
	}
	if err != nil {
		return err
	}
	*p = out
	return nil
}

func marshalConfigureImmediateEnable(value *ConfigureImmediateEnable) (*bertlv.TLV, error) {
	if value == nil {
		return constructed(bertlv.ContextSpecific.Constructed(7)), nil
	}
	var children []*bertlv.TLV
	if value.ImmediateEnableFlag {
		children = append(children, nullTLV(bertlv.ContextSpecific.Primitive(0)))
	}
	if len(value.DefaultSMDPOID) > 0 {
		child, err := oidTLV(bertlv.ContextSpecific.Primitive(1), value.DefaultSMDPOID)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	if value.DefaultSMDPAddress != nil {
		children = append(children, utf8TLV(bertlv.ContextSpecific.Primitive(2), *value.DefaultSMDPAddress))
	}
	return constructed(bertlv.ContextSpecific.Constructed(7), children...), nil
}

func unmarshalConfigureImmediateEnable(tlv *bertlv.TLV) (*ConfigureImmediateEnable, error) {
	out := &ConfigureImmediateEnable{
		ImmediateEnableFlag: tlv.First(bertlv.ContextSpecific.Primitive(0)) != nil,
	}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(1)); child != nil {
		oid, err := oidValue(child)
		if err != nil {
			return nil, err
		}
		out.DefaultSMDPOID = oid
	}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(2)); child != nil {
		value, err := utf8Value(child)
		if err != nil {
			return nil, err
		}
		out.DefaultSMDPAddress = &value
	}
	return out, nil
}

func oidTLV(tag bertlv.Tag, oid stdasn1.ObjectIdentifier) (*bertlv.TLV, error) {
	encoded, err := stdasn1.Marshal(oid)
	if err != nil {
		return nil, err
	}
	tlv, err := parseTLV(encoded)
	if err != nil {
		return nil, err
	}
	if err := expectTag(tlv, bertlv.Universal.Primitive(6)); err != nil {
		return nil, err
	}
	return bertlv.NewValue(tag, copyBytes(tlv.Value)), nil
}

func oidValue(tlv *bertlv.TLV) (stdasn1.ObjectIdentifier, error) {
	if tlv == nil {
		return nil, errors.New("asn1: missing OBJECT IDENTIFIER")
	}
	encoded := make([]byte, 0, 2+len(tlv.Value))
	encoded = append(encoded, 0x06)
	encoded = append(encoded, lengthBytes(len(tlv.Value))...)
	encoded = append(encoded, tlv.Value...)
	var oid stdasn1.ObjectIdentifier
	if rest, err := stdasn1.Unmarshal(encoded, &oid); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("asn1: trailing OBJECT IDENTIFIER data")
	}
	return oid, nil
}

func lengthBytes(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	if length <= 0xff {
		return []byte{0x81, byte(length)}
	}
	return []byte{0x82, byte(length >> 8), byte(length)}
}

// EuiccPackageKind identifies the selected EuiccPackage list.
type EuiccPackageKind int

const (
	// EuiccPackagePSMO selects psmoList.
	EuiccPackagePSMO EuiccPackageKind = iota + 1
	// EuiccPackageECO selects ecoList.
	EuiccPackageECO
)

// EuiccPackage is SGP.32 EuiccPackage, a CHOICE of psmoList or ecoList.
type EuiccPackage struct {
	Kind  EuiccPackageKind
	PSMOs []Psmo
	ECOs  []Eco
}

// MarshalBERTLV encodes EuiccPackage.
func (p *EuiccPackage) MarshalBERTLV() (*bertlv.TLV, error) {
	if p == nil {
		return nil, errors.New("asn1: nil EuiccPackage")
	}
	switch p.Kind {
	case EuiccPackagePSMO:
		children := make([]*bertlv.TLV, 0, len(p.PSMOs))
		for index := range p.PSMOs {
			child, err := p.PSMOs[index].MarshalBERTLV()
			if err != nil {
				return nil, err
			}
			children = append(children, child)
		}
		return constructed(bertlv.ContextSpecific.Constructed(0), children...), nil
	case EuiccPackageECO:
		children := make([]*bertlv.TLV, 0, len(p.ECOs))
		for index := range p.ECOs {
			child, err := p.ECOs[index].MarshalBERTLV()
			if err != nil {
				return nil, err
			}
			children = append(children, child)
		}
		return constructed(bertlv.ContextSpecific.Constructed(1), children...), nil
	default:
		return nil, fmt.Errorf("asn1: unknown EuiccPackage kind %d", p.Kind)
	}
}

// UnmarshalBERTLV decodes EuiccPackage.
func (p *EuiccPackage) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if tlv == nil {
		return errors.New("asn1: missing EuiccPackage")
	}
	var out EuiccPackage
	switch {
	case hasTag(tlv, bertlv.ContextSpecific.Constructed(0)):
		out.Kind = EuiccPackagePSMO
		out.PSMOs = make([]Psmo, 0, len(tlv.Children))
		for _, child := range tlv.Children {
			var psmo Psmo
			if err := psmo.UnmarshalBERTLV(child); err != nil {
				return err
			}
			out.PSMOs = append(out.PSMOs, psmo)
		}
	case hasTag(tlv, bertlv.ContextSpecific.Constructed(1)):
		out.Kind = EuiccPackageECO
		out.ECOs = make([]Eco, 0, len(tlv.Children))
		for _, child := range tlv.Children {
			var eco Eco
			if err := eco.UnmarshalBERTLV(child); err != nil {
				return err
			}
			out.ECOs = append(out.ECOs, eco)
		}
	default:
		return fmt.Errorf("%w: unknown EuiccPackage tag %s", errUnexpectedTag, tlv.Tag.String())
	}
	*p = out
	return nil
}

// EuiccPackageSigned is the to-be-signed SGP.32 eUICC package data.
type EuiccPackageSigned struct {
	EimID            string
	EID              []byte
	CounterValue     int64
	EimTransactionID []byte
	EuiccPackage     EuiccPackage
}

// MarshalBERTLV encodes EuiccPackageSigned as a universal SEQUENCE.
func (s *EuiccPackageSigned) MarshalBERTLV() (*bertlv.TLV, error) {
	if s == nil {
		return nil, errors.New("asn1: nil EuiccPackageSigned")
	}
	counter, err := integerTLV(bertlv.ContextSpecific.Primitive(1), s.CounterValue)
	if err != nil {
		return nil, err
	}
	pkg, err := s.EuiccPackage.MarshalBERTLV()
	if err != nil {
		return nil, err
	}
	children := []*bertlv.TLV{
		utf8TLV(bertlv.ContextSpecific.Primitive(0), s.EimID),
		octetTLV(tagEID, s.EID),
		counter,
	}
	if s.EimTransactionID != nil {
		children = append(children, octetTLV(bertlv.ContextSpecific.Primitive(2), s.EimTransactionID))
	}
	children = append(children, pkg)
	return constructed(tagSequence, children...), nil
}

// UnmarshalBERTLV decodes EuiccPackageSigned.
func (s *EuiccPackageSigned) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagSequence); err != nil {
		return err
	}
	var out EuiccPackageSigned
	var err error
	if out.EimID, err = utf8Value(tlv.First(bertlv.ContextSpecific.Primitive(0))); err != nil {
		return err
	}
	if out.EID, err = octetValue(tlv.First(tagEID)); err != nil {
		return err
	}
	if out.CounterValue, err = integerValue[int64](tlv.First(bertlv.ContextSpecific.Primitive(1))); err != nil {
		return err
	}
	if child := tlv.First(bertlv.ContextSpecific.Primitive(2)); child != nil {
		out.EimTransactionID = copyBytes(child.Value)
	}
	pkgTLV := tlv.First(bertlv.ContextSpecific.Constructed(0))
	if pkgTLV == nil {
		pkgTLV = tlv.First(bertlv.ContextSpecific.Constructed(1))
	}
	if err := out.EuiccPackage.UnmarshalBERTLV(pkgTLV); err != nil {
		return err
	}
	*s = out
	return nil
}

// EuiccPackageRequest is SGP.32 EuiccPackageRequest, tag BF51.
type EuiccPackageRequest struct {
	EuiccPackageSigned EuiccPackageSigned
	EimSignature       []byte
}

// MarshalBERTLV encodes EuiccPackageRequest.
func (r *EuiccPackageRequest) MarshalBERTLV() (*bertlv.TLV, error) {
	if r == nil {
		return nil, errors.New("asn1: nil EuiccPackageRequest")
	}
	signed, err := r.EuiccPackageSigned.MarshalBERTLV()
	if err != nil {
		return nil, err
	}
	return constructed(tagEuiccPkg, signed, octetTLV(tagSignature, r.EimSignature)), nil
}

// UnmarshalBERTLV decodes EuiccPackageRequest.
func (r *EuiccPackageRequest) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagEuiccPkg); err != nil {
		return err
	}
	if len(tlv.Children) < 2 {
		return errors.New("asn1: EuiccPackageRequest requires signed data and signature")
	}
	var out EuiccPackageRequest
	if err := out.EuiccPackageSigned.UnmarshalBERTLV(tlv.Children[0]); err != nil {
		return err
	}
	signature := tlv.First(tagSignature)
	var err error
	if out.EimSignature, err = octetValue(signature); err != nil {
		return err
	}
	*r = out
	return nil
}

// SetDefaultDPAddressRequest is SGP.32 SetDefaultDpAddressRequest, tag BF65.
type SetDefaultDPAddressRequest struct {
	DefaultDPAddress string
}

// MarshalBERTLV encodes SetDefaultDPAddressRequest.
func (r *SetDefaultDPAddressRequest) MarshalBERTLV() (*bertlv.TLV, error) {
	if r == nil {
		return nil, errors.New("asn1: nil SetDefaultDPAddressRequest")
	}
	return constructed(tagSetDefaultDPAddress, utf8TLV(tagUTF8, r.DefaultDPAddress)), nil
}

// UnmarshalBERTLV decodes SetDefaultDPAddressRequest.
func (r *SetDefaultDPAddressRequest) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagSetDefaultDPAddress); err != nil {
		return err
	}
	if len(tlv.Children) != 1 {
		return errors.New("asn1: SetDefaultDPAddressRequest requires one child")
	}
	value, err := utf8Value(tlv.Children[0])
	if err != nil {
		return err
	}
	*r = SetDefaultDPAddressRequest{DefaultDPAddress: value}
	return nil
}

// SetDefaultDPAddressResponse is SGP.32 SetDefaultDpAddressResponse, tag BF65.
type SetDefaultDPAddressResponse struct {
	Result int64
}

// MarshalBERTLV encodes SetDefaultDPAddressResponse.
func (r *SetDefaultDPAddressResponse) MarshalBERTLV() (*bertlv.TLV, error) {
	if r == nil {
		return nil, errors.New("asn1: nil SetDefaultDPAddressResponse")
	}
	result, err := integerTLV(tagInteger, r.Result)
	if err != nil {
		return nil, err
	}
	return constructed(tagSetDefaultDPAddress, result), nil
}

// UnmarshalBERTLV decodes SetDefaultDPAddressResponse.
func (r *SetDefaultDPAddressResponse) UnmarshalBERTLV(tlv *bertlv.TLV) error {
	if err := expectTag(tlv, tagSetDefaultDPAddress); err != nil {
		return err
	}
	if len(tlv.Children) != 1 {
		return errors.New("asn1: SetDefaultDPAddressResponse requires one child")
	}
	value, err := integerValue[int64](tlv.Children[0])
	if err != nil {
		return err
	}
	*r = SetDefaultDPAddressResponse{Result: value}
	return nil
}

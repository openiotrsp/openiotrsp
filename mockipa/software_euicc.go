package mockipa

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	stdasn1 "encoding/asn1"
	"errors"
	"fmt"

	"github.com/damonto/euicc-go/bertlv"
	"github.com/damonto/euicc-go/bertlv/primitive"
	sgp22 "github.com/damonto/euicc-go/v2"
)

// SoftwareEUICC is the minimal SGP.26-backed APDU surface needed by euicc-go's
// direct-download flow. It signs the ES10b authentication/download/install
// responses but does not decrypt or provision a Bound Profile Package like real
// eUICC silicon.
type SoftwareEUICC struct {
	fixture     *SGP26Fixture
	ciSubjectID []byte
	challenge   []byte
	euiccInfo1  *bertlv.TLV
	euiccInfo2  *bertlv.TLV
	euiccOtpk   []byte
	euiccOtpkSK *ecdh.PrivateKey
	transaction []byte
	bpp         *bertlv.TLV
	pir         *bertlv.TLV
}

// NewSoftwareEUICC creates a software eUICC from SGP.26 test material.
func NewSoftwareEUICC(fixture *SGP26Fixture) (*SoftwareEUICC, error) {
	if fixture == nil || fixture.EUICCKey == nil {
		return nil, errors.New("mockipa: missing SGP.26 fixture")
	}
	ci, err := x509.ParseCertificate(fixture.CICertificate)
	if err != nil {
		return nil, fmt.Errorf("mockipa: parse SGP.26 CI certificate: %w", err)
	}
	subjectID := ci.SubjectKeyId
	if len(subjectID) == 0 {
		sum := sha256.Sum256(ci.RawSubjectPublicKeyInfo)
		subjectID = sum[:]
	}
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	info1 := euiccInfo1(subjectID)
	info2 := euiccInfo2(subjectID)
	return &SoftwareEUICC{
		fixture:     fixture,
		ciSubjectID: cloneBytes(subjectID),
		challenge:   challenge,
		euiccInfo1:  info1,
		euiccInfo2:  info2,
	}, nil
}

// Transmit handles structured ES10 requests from euicc-go.
func (s *SoftwareEUICC) Transmit(request bertlv.Marshaler, response bertlv.Unmarshaler) error {
	switch request.(type) {
	case *sgp22.GetEuiccChallengeRequest:
		return response.UnmarshalBERTLV(bertlv.NewChildren(bertlv.ContextSpecific.Constructed(46),
			bertlv.NewValue(bertlv.ContextSpecific.Primitive(1), cloneBytes(s.challenge)),
		))
	case *sgp22.GetEuiccInfoRequest:
		tlv, err := request.MarshalBERTLV()
		if err != nil {
			return err
		}
		if tlv.Tag.Equal(bertlv.ContextSpecific.Constructed(32)) {
			return response.UnmarshalBERTLV(s.euiccInfo1.Clone())
		}
		return response.UnmarshalBERTLV(s.euiccInfo2.Clone())
	case *sgp22.AuthenticateServerRequest:
		return s.authenticateServer(request, response)
	case *sgp22.PrepareDownloadRequest:
		return s.prepareDownload(request, response)
	case *sgp22.CancelSessionRequest:
		return response.UnmarshalBERTLV(bertlv.NewChildren(bertlv.ContextSpecific.Constructed(65),
			bertlv.NewChildren(bertlv.Universal.Constructed(16)),
		))
	default:
		return fmt.Errorf("mockipa: unsupported software eUICC request %T", request)
	}
}

// TransmitRaw simulates ES10b.LoadBoundProfilePackage completion for callers
// that still route the BPP through euicc-go's APDU segment helper.
func (s *SoftwareEUICC) TransmitRaw(_ []byte) ([]byte, error) {
	_, _, err := s.LoadBoundProfilePackage(nil, nil, "openiotrsp.local", nil)
	if err != nil {
		return nil, err
	}
	return s.profileInstallationResultBytes()
}

// LoadBoundProfilePackage captures the BPP and returns a signed success PIR.
//
// The software eUICC deliberately does not provision the profile into a secure
// element. It records the BPP for verification work and emits the same signed
// installation result shape a real eUICC sends after a successful load.
func (s *SoftwareEUICC) LoadBoundProfilePackage(
	bpp *bertlv.TLV,
	metadata *sgp22.ProfileInfo,
	notificationAddress string,
	smdpOID stdasn1.ObjectIdentifier,
) (*sgp22.LoadBoundProfilePackageResponse, *sgp22.PendingNotification, error) {
	if bpp != nil {
		s.bpp = bpp.Clone()
	}
	transaction := s.transaction
	if len(transaction) == 0 {
		transaction = []byte{0x00}
	}
	if notificationAddress == "" {
		notificationAddress = "openiotrsp.local"
	}
	iccid := []byte{0x89, 0x10, 0x10, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0xf1}
	isdPAID := []byte{0xa0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10}
	if metadata != nil {
		if len(metadata.ICCID) > 0 {
			iccid = cloneBytes(metadata.ICCID)
		}
		if len(metadata.ISDPAID) > 0 {
			isdPAID = cloneBytes(metadata.ISDPAID)
		}
	}
	dataChildren := []*bertlv.TLV{
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), cloneBytes(transaction)),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(47),
			mustIntegerTLV(bertlv.ContextSpecific.Primitive(0), int64(1)),
			mustBitStringTLV(bertlv.ContextSpecific.Primitive(1), []bool{true}),
			bertlv.NewValue(bertlv.Universal.Primitive(12), []byte(notificationAddress)),
			bertlv.NewValue(bertlv.Application.Primitive(26), iccid),
		),
	}
	if len(smdpOID) > 0 {
		dataChildren = append(dataChildren, mustOIDTLV(bertlv.Universal.Primitive(6), smdpOID))
	}
	dataChildren = append(dataChildren,
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(2),
			bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0),
				bertlv.NewValue(bertlv.Application.Primitive(15), isdPAID),
				bertlv.NewValue(bertlv.Universal.Primitive(4), nil),
			),
		),
	)
	data := bertlv.NewChildren(bertlv.ContextSpecific.Constructed(39), dataChildren...)
	signature, err := s.sign(data)
	if err != nil {
		return nil, nil, err
	}
	result := bertlv.NewChildren(bertlv.ContextSpecific.Constructed(55),
		data,
		bertlv.NewValue(bertlv.Application.Primitive(55), signature),
	)
	s.pir = result.Clone()
	var response sgp22.LoadBoundProfilePackageResponse
	if err := response.UnmarshalBERTLV(result); err != nil {
		return nil, nil, err
	}
	if err := response.Valid(); err != nil {
		return nil, nil, err
	}
	return &response, &sgp22.PendingNotification{
		PendingNotification: result.Clone(),
		Notification:        response.Notification,
	}, nil
}

func (s *SoftwareEUICC) authenticateServer(request bertlv.Marshaler, response bertlv.Unmarshaler) error {
	tlv, err := request.MarshalBERTLV()
	if err != nil {
		return err
	}
	serverSigned1 := tlv.First(bertlv.Universal.Constructed(16))
	if serverSigned1 == nil {
		return errors.New("mockipa: AuthenticateServerRequest missing serverSigned1")
	}
	ctxParams1 := tlv.First(bertlv.ContextSpecific.Constructed(0))
	if ctxParams1 == nil {
		return errors.New("mockipa: AuthenticateServerRequest missing ctxParams1")
	}
	transaction := cloneTLVValue(serverSigned1.First(bertlv.ContextSpecific.Primitive(0)))
	serverAddress := cloneTLVValue(serverSigned1.First(bertlv.ContextSpecific.Primitive(3)))
	serverChallenge := cloneTLVValue(serverSigned1.First(bertlv.ContextSpecific.Primitive(4)))
	s.transaction = cloneBytes(transaction)

	euiccSigned1 := bertlv.NewChildren(bertlv.Universal.Constructed(16),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), transaction),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(3), serverAddress),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(4), serverChallenge),
		s.euiccInfo2.Clone(),
		ctxParams1.Clone(),
	)
	signature, err := s.sign(euiccSigned1)
	if err != nil {
		return err
	}
	return response.UnmarshalBERTLV(bertlv.NewChildren(bertlv.ContextSpecific.Constructed(56),
		bertlv.NewChildren(bertlv.Universal.Constructed(16),
			euiccSigned1,
			bertlv.NewValue(bertlv.Application.Primitive(55), signature),
			mustParseTLV(s.fixture.EUICCCertificate),
			mustParseTLV(s.fixture.EUMCertificate),
		),
	))
}

func (s *SoftwareEUICC) prepareDownload(request bertlv.Marshaler, response bertlv.Unmarshaler) error {
	tlv, err := request.MarshalBERTLV()
	if err != nil {
		return err
	}
	smdpSigned2 := tlv.First(bertlv.Universal.Constructed(16))
	if smdpSigned2 == nil {
		return errors.New("mockipa: PrepareDownloadRequest missing smdpSigned2")
	}
	transaction := cloneTLVValue(smdpSigned2.First(bertlv.ContextSpecific.Primitive(0)))
	s.transaction = cloneBytes(transaction)
	otpkSK, otpk, err := generateOTPK()
	if err != nil {
		return err
	}
	s.euiccOtpk = otpk
	s.euiccOtpkSK = otpkSK

	children := []*bertlv.TLV{
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), transaction),
		bertlv.NewValue(bertlv.Application.Primitive(73), otpk),
	}
	if hashCC := tlv.First(bertlv.Universal.Primitive(4)); hashCC != nil {
		children = append(children, hashCC.Clone())
	}
	euiccSigned2 := bertlv.NewChildren(bertlv.Universal.Constructed(16), children...)
	signature, err := s.sign(euiccSigned2)
	if err != nil {
		return err
	}
	return response.UnmarshalBERTLV(bertlv.NewChildren(bertlv.ContextSpecific.Constructed(33),
		bertlv.NewChildren(bertlv.Universal.Constructed(16),
			euiccSigned2,
			bertlv.NewValue(bertlv.Application.Primitive(55), signature),
		),
	))
}

func (s *SoftwareEUICC) sign(tlv *bertlv.TLV) ([]byte, error) {
	encoded, err := tlv.MarshalBinary()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	return ecdsa.SignASN1(rand.Reader, s.fixture.EUICCKey, digest[:])
}

func euiccInfo1(subjectKeyID []byte) *bertlv.TLV {
	return bertlv.NewChildren(bertlv.ContextSpecific.Constructed(32),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(2), []byte{0x02, 0x07, 0x00}),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(9), bertlv.NewValue(bertlv.Universal.Primitive(4), cloneBytes(subjectKeyID))),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(10), bertlv.NewValue(bertlv.Universal.Primitive(4), cloneBytes(subjectKeyID))),
	)
}

func euiccInfo2(subjectKeyID []byte) *bertlv.TLV {
	return bertlv.NewChildren(bertlv.ContextSpecific.Constructed(34),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(1), []byte{0x03, 0x03, 0x00}),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(2), []byte{0x02, 0x07, 0x00}),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(3), []byte{0x01, 0x00, 0x00}),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(4), []byte{0x82, 0x00, 0x00}),
		mustBitStringTLV(bertlv.ContextSpecific.Primitive(5), []bool{true}),
		mustBitStringTLV(bertlv.ContextSpecific.Primitive(8), []bool{true, true, false, true}),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(9), bertlv.NewValue(bertlv.Universal.Primitive(4), cloneBytes(subjectKeyID))),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(10), bertlv.NewValue(bertlv.Universal.Primitive(4), cloneBytes(subjectKeyID))),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(22), []byte{0x01, 0x00, 0x00}),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(23), []byte("OPENIOTRSP-DEMO")),
	)
}

func (s *SoftwareEUICC) BoundProfilePackage() *bertlv.TLV {
	if s == nil || s.bpp == nil {
		return nil
	}
	return s.bpp.Clone()
}

func (s *SoftwareEUICC) ProfileInstallationResult() *bertlv.TLV {
	if s == nil || s.pir == nil {
		return nil
	}
	return s.pir.Clone()
}

func (s *SoftwareEUICC) profileInstallationResultBytes() ([]byte, error) {
	if s.pir == nil {
		return nil, errors.New("mockipa: missing ProfileInstallationResult")
	}
	return s.pir.MarshalBinary()
}

func generateOTPK() (*ecdh.PrivateKey, []byte, error) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return key, key.PublicKey().Bytes(), nil
}

func mustParseTLV(data []byte) *bertlv.TLV {
	tlv := new(bertlv.TLV)
	if err := tlv.UnmarshalBinary(data); err != nil {
		panic(err)
	}
	return tlv
}

func mustIntegerTLV(tag bertlv.Tag, value int64) *bertlv.TLV {
	tlv, err := bertlv.MarshalValue(tag, primitive.MarshalInt(value))
	if err != nil {
		panic(err)
	}
	return tlv
}

func mustBitStringTLV(tag bertlv.Tag, bits []bool) *bertlv.TLV {
	tlv, err := bertlv.MarshalValue(tag, primitive.MarshalBitString(bits))
	if err != nil {
		panic(err)
	}
	return tlv
}

func mustOIDTLV(tag bertlv.Tag, oid stdasn1.ObjectIdentifier) *bertlv.TLV {
	encoded, err := stdasn1.Marshal(oid)
	if err != nil {
		panic(err)
	}
	tlv := new(bertlv.TLV)
	if err := tlv.UnmarshalBinary(encoded); err != nil {
		panic(err)
	}
	if !tlv.Tag.Equal(bertlv.Universal.Primitive(6)) {
		panic("mockipa: OBJECT IDENTIFIER encoded with unexpected tag")
	}
	return bertlv.NewValue(tag, cloneBytes(tlv.Value))
}

func cloneTLVValue(tlv *bertlv.TLV) []byte {
	if tlv == nil {
		return nil
	}
	return cloneBytes(tlv.Value)
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out
}

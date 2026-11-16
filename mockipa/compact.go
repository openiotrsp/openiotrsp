package mockipa

import (
	"errors"

	"github.com/damonto/euicc-go/bertlv"
)

// defaultCompactSimaResponse is the success EUICCResponse omitted from
// CompactSuccessResult. SGP.32 names the nine bytes 30 07 A0 05 30 03 80 01 00.
var defaultCompactSimaResponse = []byte{0x30, 0x07, 0xa0, 0x05, 0x30, 0x03, 0x80, 0x01, 0x00}

// CompactAuthenticateServerResponse signs EuiccSigned1 and returns the BF38 a
// minimizeEsipaBytes IPA sends when the eIM generated ctxParams1.
// ctxParams1 is the CtxParams1 CHOICE (context [0]). extCardResource replaces
// EUICCInfo2.extCardResource in the signed bytes and is what compactEuiccSigned1
// carries. omitCtxParams leaves ctxParams1 out of the compact form.
func (s *SoftwareEUICC) CompactAuthenticateServerResponse(serverSigned1, ctxParams1 *bertlv.TLV, extCardResource []byte, omitCtxParams bool) (compact, signedEuiccSigned1 *bertlv.TLV, err error) {
	if s == nil {
		return nil, nil, errors.New("mockipa: nil software eUICC")
	}
	if serverSigned1 == nil || ctxParams1 == nil {
		return nil, nil, errors.New("mockipa: compact authenticateServer requires serverSigned1 and ctxParams1")
	}
	info2 := s.euiccInfo2.Clone()
	if len(extCardResource) > 0 {
		ext := bertlv.NewValue(bertlv.ContextSpecific.Primitive(4), cloneBytes(extCardResource))
		replaced, err := replaceChild(info2, ext)
		if err != nil {
			return nil, nil, err
		}
		info2 = replaced
	}
	transaction := cloneTLVValue(serverSigned1.First(bertlv.ContextSpecific.Primitive(0)))
	serverAddress := cloneTLVValue(serverSigned1.First(bertlv.ContextSpecific.Primitive(3)))
	serverChallenge := cloneTLVValue(serverSigned1.First(bertlv.ContextSpecific.Primitive(4)))
	s.transaction = cloneBytes(transaction)
	signed := bertlv.NewChildren(bertlv.Universal.Constructed(16),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), transaction),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(3), serverAddress),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(4), serverChallenge),
		info2,
		ctxParams1.Clone(),
	)
	if info2.First(bertlv.ContextSpecific.Primitive(4)) == nil {
		return nil, nil, errors.New("mockipa: EUICCInfo2 missing extCardResource")
	}
	signature, err := s.sign(signed)
	if err != nil {
		return nil, nil, err
	}
	compact = bertlv.NewChildren(bertlv.ContextSpecific.Constructed(56),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(2),
			bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0), compactDataChildren(info2, ctxParams1, omitCtxParams)...),
			bertlv.NewValue(bertlv.Application.Primitive(55), signature),
		),
	)
	return compact, signed, nil
}

func compactDataChildren(info2, ctxParams1 *bertlv.TLV, omitCtxParams bool) []*bertlv.TLV {
	children := []*bertlv.TLV{info2.First(bertlv.ContextSpecific.Primitive(4)).Clone()}
	if !omitCtxParams && ctxParams1 != nil {
		children = append(children, bertlv.NewChildren(bertlv.ContextSpecific.Constructed(2), ctxParams1.Clone()))
	}
	return children
}

// CompactPrepareDownloadResponse signs EuiccSigned2 and returns the compact
// BF21 a minimizeEsipaBytes IPA sends. hashCC is included in both forms when
// non-empty.
func (s *SoftwareEUICC) CompactPrepareDownloadResponse(transactionID, hashCC []byte) (compact, signedEuiccSigned2 *bertlv.TLV, err error) {
	if s == nil {
		return nil, nil, errors.New("mockipa: nil software eUICC")
	}
	if len(transactionID) == 0 {
		return nil, nil, errors.New("mockipa: compact prepareDownload missing transactionId")
	}
	_, otpk, err := generateOTPK()
	if err != nil {
		return nil, nil, err
	}
	s.euiccOtpk = otpk
	s.transaction = cloneBytes(transactionID)
	children := []*bertlv.TLV{
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), cloneBytes(transactionID)),
		bertlv.NewValue(bertlv.Application.Primitive(73), otpk),
	}
	compactChildren := []*bertlv.TLV{
		bertlv.NewValue(bertlv.Application.Primitive(73), cloneBytes(otpk)),
	}
	if len(hashCC) > 0 {
		hash := bertlv.NewValue(bertlv.Universal.Primitive(4), cloneBytes(hashCC))
		children = append(children, hash)
		compactChildren = append(compactChildren, hash.Clone())
	}
	signed := bertlv.NewChildren(bertlv.Universal.Constructed(16), children...)
	signature, err := s.sign(signed)
	if err != nil {
		return nil, nil, err
	}
	compact = bertlv.NewChildren(bertlv.ContextSpecific.Constructed(33),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(2),
			bertlv.NewChildren(bertlv.Universal.Constructed(16), compactChildren...),
			bertlv.NewValue(bertlv.Application.Primitive(55), signature),
		),
	)
	return compact, signed, nil
}

// CompactProfileInstallationResult signs ProfileInstallationResultData and
// returns the compactProfileInstallationResult choice arm. The compact form
// carries bytes 14 and 15 of the ISD-P AID and omits simaResponse, seqNumber
// metadata, and the notification address.
func (s *SoftwareEUICC) CompactProfileInstallationResult(transaction []byte, address string, iccid, aid []byte, seq int64) (compact, signedData *bertlv.TLV, err error) {
	if s == nil {
		return nil, nil, errors.New("mockipa: nil software eUICC")
	}
	if len(aid) < 15 {
		return nil, nil, errors.New("mockipa: ISD-P AID has no bytes 14 and 15")
	}
	data := bertlv.NewChildren(bertlv.ContextSpecific.Constructed(39),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), cloneBytes(transaction)),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(47),
			mustIntegerTLV(bertlv.ContextSpecific.Primitive(0), seq),
			mustBitStringTLV(bertlv.ContextSpecific.Primitive(1), []bool{true}),
			bertlv.NewValue(bertlv.Universal.Primitive(12), []byte(address)),
			bertlv.NewValue(bertlv.Application.Primitive(26), cloneBytes(iccid)),
		),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(2),
			bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0),
				bertlv.NewValue(bertlv.Application.Primitive(15), cloneBytes(aid)),
				bertlv.NewValue(bertlv.Universal.Primitive(4), cloneBytes(defaultCompactSimaResponse)),
			),
		),
	)
	signature, err := s.sign(data)
	if err != nil {
		return nil, nil, err
	}
	compact = bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0),
			bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), cloneBytes(transaction)),
			mustIntegerTLV(bertlv.Universal.Primitive(2), seq),
			bertlv.NewChildren(bertlv.ContextSpecific.Constructed(2),
				bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0),
					bertlv.NewValue(bertlv.Application.Primitive(15), cloneBytes(aid[13:15])),
				),
			),
		),
		bertlv.NewValue(bertlv.Application.Primitive(55), signature),
	)
	return compact, data, nil
}

func replaceChild(parent, replacement *bertlv.TLV) (*bertlv.TLV, error) {
	if parent == nil || replacement == nil {
		return nil, errors.New("mockipa: missing TLV")
	}
	children := make([]*bertlv.TLV, 0, len(parent.Children))
	found := false
	for _, child := range parent.Children {
		if child.Tag.Equal(replacement.Tag) {
			children = append(children, replacement.Clone())
			found = true
			continue
		}
		children = append(children, child.Clone())
	}
	if !found {
		return nil, errors.New("mockipa: TLV child not found")
	}
	return bertlv.NewChildren(parent.Tag, children...), nil
}

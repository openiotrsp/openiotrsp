package asn1

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/damonto/euicc-go/bertlv"
	"github.com/damonto/euicc-go/bertlv/primitive"
)

func TestEimPackageResultBareInteger(t *testing.T) {
	t.Parallel()

	codeTLV, err := integerTLV(tagInteger, EimPackageResultErrorCode(127))
	if err != nil {
		t.Fatalf("integerTLV() error = %v", err)
	}
	var decoded EimPackageResult
	if err := decoded.UnmarshalBERTLV(codeTLV); err != nil {
		t.Fatalf("UnmarshalBERTLV() error = %v", err)
	}
	if decoded.Kind != EimPackageResultError {
		t.Fatalf("kind = %v, want error", decoded.Kind)
	}
	if decoded.Error == nil || decoded.Error.Code != 127 {
		t.Fatalf("error = %#v, want code 127", decoded.Error)
	}
	if decoded.Raw == nil {
		t.Fatal("Raw not preserved")
	}
}

func TestEimPackageResultA0IntegerRegression(t *testing.T) {
	t.Parallel()

	codeTLV, err := integerTLV(tagInteger, EimPackageResultErrorCode(2))
	if err != nil {
		t.Fatalf("integerTLV() error = %v", err)
	}
	wrapper := constructed(bertlv.ContextSpecific.Constructed(0), codeTLV)
	var decoded EimPackageResult
	if err := decoded.UnmarshalBERTLV(wrapper); err != nil {
		t.Fatalf("UnmarshalBERTLV() error = %v", err)
	}
	if decoded.Kind != EimPackageResultError || decoded.Error == nil || decoded.Error.Code != 2 {
		t.Fatalf("decoded = %#v, want A0-wrapped error code 2", decoded)
	}
}

func TestEuiccPackageResultBareInteger(t *testing.T) {
	t.Parallel()

	codeTLV, err := integerTLV(tagInteger, EuiccPackageUnsignedErrorCode(127))
	if err != nil {
		t.Fatalf("integerTLV() error = %v", err)
	}
	tlv := constructed(tagEuiccPkg, codeTLV)
	var decoded EuiccPackageResult
	if err := decoded.UnmarshalBERTLV(tlv); err != nil {
		t.Fatalf("UnmarshalBERTLV() error = %v", err)
	}
	if decoded.Kind != EuiccPackageResultErrorUnsigned {
		t.Fatalf("kind = %v, want unsigned error", decoded.Kind)
	}
	if decoded.ErrorUnsigned == nil || decoded.ErrorUnsigned.ErrorCode == nil || *decoded.ErrorUnsigned.ErrorCode != 127 {
		t.Fatalf("error unsigned = %#v, want code 127", decoded.ErrorUnsigned)
	}
}

func TestEuiccPackageResultDataSignedIntegerResult(t *testing.T) {
	t.Parallel()

	result, err := IntegerEuiccResult(3, 0)
	if err != nil {
		t.Fatalf("IntegerEuiccResult() error = %v", err)
	}
	counter, err := integerTLV(bertlv.ContextSpecific.Primitive(1), int64(1))
	if err != nil {
		t.Fatalf("integerTLV(counter) error = %v", err)
	}
	seq, err := integerTLV(bertlv.ContextSpecific.Primitive(3), int64(1))
	if err != nil {
		t.Fatalf("integerTLV(seq) error = %v", err)
	}
	data := constructed(tagSequence,
		utf8TLV(bertlv.ContextSpecific.Primitive(0), "testeim1"),
		counter,
		seq,
		result.Raw,
	)
	var decoded EuiccPackageResultDataSigned
	if err := decoded.UnmarshalBERTLV(data); err != nil {
		t.Fatalf("UnmarshalBERTLV() error = %v", err)
	}
	if len(decoded.Results) != 1 || decoded.Results[0].Raw == nil {
		t.Fatalf("results = %#v, want one raw result", decoded.Results)
	}
	if !decoded.Results[0].Raw.Tag.Equal(bertlv.ContextSpecific.Primitive(3)) {
		t.Fatalf("result tag = %s, want context [3]", decoded.Results[0].Raw.Tag.String())
	}
}

func TestProvideEimPackageResultVariantPayloads(t *testing.T) {
	t.Parallel()

	eid := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	bf51Integer, err := integerTLV(tagInteger, EuiccPackageUnsignedErrorCode(127))
	if err != nil {
		t.Fatalf("integerTLV() error = %v", err)
	}
	cases := []struct {
		name string
		tlv  *bertlv.TLV
	}{
		{
			name: "BF51BareInteger",
			tlv: constructed(tagProvideEimResult,
				octetTLV(tagEID, eid),
				constructed(tagEuiccPkg, bf51Integer),
			),
		},
		{
			name: "TopLevelInteger",
			tlv: constructed(tagProvideEimResult,
				octetTLV(tagEID, eid),
				mustIntegerTLV(t, tagInteger, int64(EimPackageResultErrorCode(127))),
			),
		},
		{
			name: "A0Integer",
			tlv: constructed(tagProvideEimResult,
				octetTLV(tagEID, eid),
				constructed(bertlv.ContextSpecific.Constructed(0),
					mustIntegerTLV(t, tagInteger, int64(EimPackageResultErrorCode(2))),
				),
			),
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var decoded ProvideEimPackageResult
			if err := decoded.UnmarshalBERTLV(tc.tlv); err != nil {
				t.Fatalf("UnmarshalBERTLV() error = %v", err)
			}
			if decoded.EimPackageResult.Raw == nil {
				t.Fatal("missing EimPackageResult raw TLV")
			}
		})
	}
}

func TestEuiccPackageResultChoiceA0Signed_ProductionSample(t *testing.T) {
	t.Parallel()

	// Live production IPA handleNotification / provideEimPackageResult body (seq 14):
	// BF50 { 5A EID, BF51 { A0 { data SEQUENCE, 5F37 } } }
	const sample = "v1CCAblaEIkEQEWTAAAAAAAAIVOJMhC/UYIBoqCCAZ4wggFXgBBlaW0uc3ltYi1pb3QuY29tgQENghCEx2BkV1bZwxvxpFIRwcW/gwEOMIIBKb8tggEkoIIBIONNWgqYABAyVHaYEDIUTxCgAAAFWRAQ/////4kAABEAn3ABAJEFS2lnZW6SH0dTTUEgR2VuZXJpYyBlVUlDQyBUZXN0IFByb2ZpbGWVAQDjRVoKmEQFMWCBA2NAYU8QoAAABVkQEP////+JAAASAJ9wAQCRBUtpZ2VukhNLaWdlbi1UQ0EtSlQtU0dQLjMylQECn2cB/+NDWgqYU3YHYhKURBD1TxCgAAAFWRAQ/////4kAABMAn3ABAJEGTWVsaXRhkhQ4OTM1Njc3MDI2MjE0OTQ0MDE1RpUBAuNDWgqYU3YHYhKURCDzTxCgAAAFWRAQ/////4kAABQAn3ABAZEGTWVsaXRhkhQ4OTM1Njc3MDI2MjE0OTQ0MDIzRpUBAl83QMSTo0mj78gm7izrMLgSzjPYehfXipNGGFPevuMs1Z8Tx3s5PrHRfv6v3OPqqCj5f4FSmE32tcr0B+gjjPGdOQQ="
	der, err := decodeTestBase64(t, sample)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	var provide ProvideEimPackageResult
	if err := Decode(der, &provide); err != nil {
		t.Fatalf("Decode(ProvideEimPackageResult) error = %v", err)
	}
	if len(provide.EID) != 16 {
		t.Fatalf("EID len = %d, want 16", len(provide.EID))
	}
	var result EuiccPackageResult
	if err := result.UnmarshalBERTLV(provide.EimPackageResult.Raw); err != nil {
		t.Fatalf("UnmarshalBERTLV(EuiccPackageResult CHOICE A0) error = %v", err)
	}
	if result.Kind != EuiccPackageResultOK || result.Signed == nil {
		t.Fatalf("result = %#v, want signed OK", result)
	}
	if result.Signed.Data.EimID != "eim.symb-iot.com" {
		t.Fatalf("eimId = %q", result.Signed.Data.EimID)
	}
	if result.Signed.Data.SeqNumber != 14 {
		t.Fatalf("seqNumber = %d, want 14", result.Signed.Data.SeqNumber)
	}
	wantTxn := mustDecodeHex(t, "84c760645756d9c31bf1a45211c1c5bf")
	if !bytes.Equal(result.Signed.Data.EimTransactionID, wantTxn) {
		t.Fatalf("eimTransactionId = %x, want %x", result.Signed.Data.EimTransactionID, wantTxn)
	}
}

func TestEuiccPackageResultChoiceArmsDecodeAndSequenceRoundTrip(t *testing.T) {
	t.Parallel()

	signed := &EuiccPackageResult{
		Kind: EuiccPackageResultOK,
		Signed: &EuiccPackageResultSigned{
			Data: EuiccPackageResultDataSigned{
				EimID:            "testeim1",
				CounterValue:     1,
				EimTransactionID: []byte{0x01, 0x02},
				SeqNumber:        7,
				Results: []EuiccResultData{{
					Raw: mustIntegerTLV(t, bertlv.ContextSpecific.Primitive(3), 0),
				}},
			},
			EuiccSignEPR: []byte{0x30, 0x03, 0x02, 0x01, 0x02},
		},
	}
	sequenceTLV, err := signed.MarshalBERTLV()
	if err != nil {
		t.Fatalf("MarshalBERTLV(SEQUENCE form) error = %v", err)
	}
	var fromSequence EuiccPackageResult
	if err := fromSequence.UnmarshalBERTLV(sequenceTLV); err != nil {
		t.Fatalf("UnmarshalBERTLV(SEQUENCE form) error = %v", err)
	}
	if fromSequence.Kind != EuiccPackageResultOK || fromSequence.Signed == nil || fromSequence.Signed.Data.SeqNumber != 7 {
		t.Fatalf("SEQUENCE decode = %#v", fromSequence)
	}

	cases := []struct {
		name string
		arm  uint64
		wrap func(*bertlv.TLV) *bertlv.TLV
	}{
		{
			name: "A0SignedOK",
			arm:  0,
			wrap: func(child *bertlv.TLV) *bertlv.TLV {
				return constructed(tagEuiccPkg, constructed(bertlv.ContextSpecific.Constructed(0), child.Children...))
			},
		},
		{
			name: "A1SignedError",
			arm:  1,
			wrap: func(_ *bertlv.TLV) *bertlv.TLV {
				errorSigned := &EuiccPackageResult{
					Kind: EuiccPackageResultErrorSigned,
					ErrorSigned: &EuiccPackageErrorSigned{
						Data: EuiccPackageErrorDataSigned{
							EimID:        "testeim1",
							CounterValue: 1,
							ErrorCode:    3,
						},
						EuiccSignEPE: []byte{0x30, 0x03, 0x02, 0x01, 0x02},
					},
				}
				tlv, err := errorSigned.ErrorSigned.MarshalBERTLV()
				if err != nil {
					t.Fatalf("MarshalBERTLV(error signed) error = %v", err)
				}
				return constructed(tagEuiccPkg, constructed(bertlv.ContextSpecific.Constructed(1), tlv.Children...))
			},
		},
		{
			name: "A2UnsignedError",
			arm:  2,
			wrap: func(_ *bertlv.TLV) *bertlv.TLV {
				return constructed(tagEuiccPkg, constructed(bertlv.ContextSpecific.Constructed(2),
					utf8TLV(bertlv.ContextSpecific.Primitive(0), "testeim1"),
					octetTLV(bertlv.ContextSpecific.Primitive(2), []byte{0xaa}),
				))
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var decoded EuiccPackageResult
			if err := decoded.UnmarshalBERTLV(tc.wrap(sequenceTLV.Children[0])); err != nil {
				t.Fatalf("UnmarshalBERTLV([%d]) error = %v", tc.arm, err)
			}
			switch tc.arm {
			case 0:
				if decoded.Kind != EuiccPackageResultOK || decoded.Signed == nil || decoded.Signed.Data.SeqNumber != 7 {
					t.Fatalf("decoded = %#v", decoded)
				}
			case 1:
				if decoded.Kind != EuiccPackageResultErrorSigned || decoded.ErrorSigned == nil || decoded.ErrorSigned.Data.ErrorCode != 3 {
					t.Fatalf("decoded = %#v", decoded)
				}
			case 2:
				if decoded.Kind != EuiccPackageResultErrorUnsigned || decoded.ErrorUnsigned == nil || decoded.ErrorUnsigned.EimID != "testeim1" {
					t.Fatalf("decoded = %#v", decoded)
				}
			}
		})
	}
}

func TestProfileInfoListResponseChoiceA0_SequenceRoundTrip(t *testing.T) {
	t.Parallel()

	state := ProfileStateEnabled
	original := &ProfileInfoListResponse{
		Profiles: []ProfileInfo{
			{ICCID: []byte{0x89, 0x10}, ProfileState: &state, FallbackAttribute: true},
			{ICCID: []byte{0x89, 0x20}},
		},
	}
	sequenceTLV, err := original.MarshalBERTLV()
	if err != nil {
		t.Fatalf("MarshalBERTLV(SEQUENCE form) error = %v", err)
	}
	if len(sequenceTLV.Children) != 1 || !hasTag(sequenceTLV.Children[0], tagSequence) {
		t.Fatalf("marshal child = %v, want UNIVERSAL 16 SEQUENCE", sequenceTLV.Children)
	}
	var fromSequence ProfileInfoListResponse
	if err := fromSequence.UnmarshalBERTLV(sequenceTLV); err != nil {
		t.Fatalf("UnmarshalBERTLV(SEQUENCE form) error = %v", err)
	}
	if len(fromSequence.Profiles) != 2 {
		t.Fatalf("SEQUENCE profiles = %d, want 2", len(fromSequence.Profiles))
	}

	a0TLV := constructed(tagProfileInfoList, constructed(bertlv.ContextSpecific.Constructed(0), sequenceTLV.Children[0].Children...))
	var fromA0 ProfileInfoListResponse
	if err := fromA0.UnmarshalBERTLV(a0TLV); err != nil {
		t.Fatalf("UnmarshalBERTLV(A0 form) error = %v", err)
	}
	if len(fromA0.Profiles) != 2 {
		t.Fatalf("A0 profiles = %d, want 2", len(fromA0.Profiles))
	}
	if !bytes.Equal(fromA0.Profiles[0].ICCID, original.Profiles[0].ICCID) {
		t.Fatalf("A0 ICCID[0] = %x, want %x", fromA0.Profiles[0].ICCID, original.Profiles[0].ICCID)
	}
	if fromA0.Profiles[0].ProfileState == nil || *fromA0.Profiles[0].ProfileState != ProfileStateEnabled {
		t.Fatalf("A0 ProfileState[0] = %#v, want enabled", fromA0.Profiles[0].ProfileState)
	}
	if !fromA0.Profiles[0].FallbackAttribute {
		t.Fatal("A0 FallbackAttribute[0] = false, want true")
	}
}

func TestProfileInfoListResponseErrorArms(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		tlv  *bertlv.TLV
		want ProfileInfoListError
	}{
		{
			name: "BareInteger",
			tlv:  constructed(tagProfileInfoList, mustIntegerTLV(t, tagInteger, 127)),
			want: 127,
		},
		{
			name: "ContextPrimitive1",
			tlv:  constructed(tagProfileInfoList, mustIntegerTLV(t, bertlv.ContextSpecific.Primitive(1), 1)),
			want: 1,
		},
		{
			name: "ContextConstructed1",
			tlv: constructed(tagProfileInfoList, constructed(bertlv.ContextSpecific.Constructed(1),
				mustIntegerTLV(t, tagInteger, 11),
			)),
			want: 11,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var decoded ProfileInfoListResponse
			if err := decoded.UnmarshalBERTLV(tc.tlv); err != nil {
				t.Fatalf("UnmarshalBERTLV() error = %v", err)
			}
			if decoded.Error == nil || *decoded.Error != tc.want {
				t.Fatalf("error = %#v, want %d", decoded.Error, tc.want)
			}
			if len(decoded.Profiles) != 0 {
				t.Fatalf("profiles = %d, want 0", len(decoded.Profiles))
			}
		})
	}
}

func TestProfileInfoListResponseChoiceA0_ProductionSample(t *testing.T) {
	t.Parallel()

	// Same live production IPA provide/handleNotification body as EuiccPackageResult A0
	// sample: nested BF2D success is A0 → E3 ProfileInfo ×4 (not SEQUENCE).
	const sample = "v1CCAblaEIkEQEWTAAAAAAAAIVOJMhC/UYIBoqCCAZ4wggFXgBBlaW0uc3ltYi1pb3QuY29tgQENghCEx2BkV1bZwxvxpFIRwcW/gwEOMIIBKb8tggEkoIIBIONNWgqYABAyVHaYEDIUTxCgAAAFWRAQ/////4kAABEAn3ABAJEFS2lnZW6SH0dTTUEgR2VuZXJpYyBlVUlDQyBUZXN0IFByb2ZpbGWVAQDjRVoKmEQFMWCBA2NAYU8QoAAABVkQEP////+JAAASAJ9wAQCRBUtpZ2VukhNLaWdlbi1UQ0EtSlQtU0dQLjMylQECn2cB/+NDWgqYU3YHYhKURBD1TxCgAAAFWRAQ/////4kAABMAn3ABAJEGTWVsaXRhkhQ4OTM1Njc3MDI2MjE0OTQ0MDE1RpUBAuNDWgqYU3YHYhKURCDzTxCgAAAFWRAQ/////4kAABQAn3ABAZEGTWVsaXRhkhQ4OTM1Njc3MDI2MjE0OTQ0MDIzRpUBAl83QMSTo0mj78gm7izrMLgSzjPYehfXipNGGFPevuMs1Z8Tx3s5PrHRfv6v3OPqqCj5f4FSmE32tcr0B+gjjPGdOQQ="
	der, err := decodeTestBase64(t, sample)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	var provide ProvideEimPackageResult
	if err := Decode(der, &provide); err != nil {
		t.Fatalf("Decode(ProvideEimPackageResult) error = %v", err)
	}
	var epr EuiccPackageResult
	if err := epr.UnmarshalBERTLV(provide.EimPackageResult.Raw); err != nil {
		t.Fatalf("UnmarshalBERTLV(EuiccPackageResult) error = %v", err)
	}
	if epr.Kind != EuiccPackageResultOK || epr.Signed == nil || len(epr.Signed.Data.Results) != 1 {
		t.Fatalf("EPR = %#v, want one signed result", epr)
	}
	bf2d := epr.Signed.Data.Results[0].Raw
	if bf2d == nil || !hasTag(bf2d, tagProfileInfoList) {
		t.Fatalf("result Raw = %#v, want BF2D", bf2d)
	}
	if len(bf2d.Children) != 1 || !hasTag(bf2d.Children[0], bertlv.ContextSpecific.Constructed(0)) {
		t.Fatalf("BF2D child = %v, want A0 CHOICE arm", bf2d.Children)
	}

	var list ProfileInfoListResponse
	if err := list.UnmarshalBERTLV(bf2d); err != nil {
		t.Fatalf("UnmarshalBERTLV(ProfileInfoListResponse A0) error = %v", err)
	}
	if list.Error != nil {
		t.Fatalf("Error = %#v, want nil", list.Error)
	}
	if len(list.Profiles) != 4 {
		t.Fatalf("profiles = %d, want 4", len(list.Profiles))
	}
	for i, profile := range list.Profiles {
		if len(profile.ICCID) == 0 {
			t.Fatalf("profiles[%d].ICCID empty", i)
		}
	}
}

func decodeTestBase64(t *testing.T, value string) ([]byte, error) {
	t.Helper()
	return base64.StdEncoding.DecodeString(value)
}

func TestEuiccPackageErrorUnsigned_A2Structured(t *testing.T) {
	t.Parallel()

	tlv := constructed(bertlv.ContextSpecific.Constructed(2),
		utf8TLV(bertlv.ContextSpecific.Primitive(0), "eim.symb-iot.com"),
		octetTLV(bertlv.ContextSpecific.Primitive(2), mustDecodeHex(t, "a7438f4401a3dbd873f28404ce8758a1")),
	)
	var decoded EuiccPackageErrorUnsigned
	if err := decoded.UnmarshalBERTLV(tlv); err != nil {
		t.Fatalf("UnmarshalBERTLV() error = %v", err)
	}
	if decoded.EimID != "eim.symb-iot.com" {
		t.Fatalf("eimId = %q, want eim.symb-iot.com", decoded.EimID)
	}
	wantTxn := mustDecodeHex(t, "a7438f4401a3dbd873f28404ce8758a1")
	if !bytes.Equal(decoded.EimTransactionID, wantTxn) {
		t.Fatalf("transactionId = %x, want %x", decoded.EimTransactionID, wantTxn)
	}
}

func TestProvideEimPackageResult_VendorUnsignedErrorA2(t *testing.T) {
	t.Parallel()

	eid := mustDecodeHex(t, "89041030081106202526200000027839")
	unsigned := constructed(bertlv.ContextSpecific.Constructed(2),
		utf8TLV(bertlv.ContextSpecific.Primitive(0), "eim.symb-iot.com"),
		octetTLV(bertlv.ContextSpecific.Primitive(2), mustDecodeHex(t, "a7438f4401a3dbd873f28404ce8758a1")),
	)
	provide := constructed(tagProvideEimResult,
		octetTLV(tagEID, eid),
		constructed(tagEuiccPkg, unsigned),
	)
	var decoded ProvideEimPackageResult
	if err := decoded.UnmarshalBERTLV(provide); err != nil {
		t.Fatalf("UnmarshalBERTLV(ProvideEimPackageResult) error = %v", err)
	}
	resultTLV := decoded.EimPackageResult.Raw
	var result EuiccPackageResult
	if err := result.UnmarshalBERTLV(resultTLV); err != nil {
		t.Fatalf("UnmarshalBERTLV(EuiccPackageResult) error = %v", err)
	}
	if result.Kind != EuiccPackageResultErrorUnsigned || result.ErrorUnsigned == nil {
		t.Fatalf("result = %#v, want unsigned error", result)
	}
	if result.ErrorUnsigned.EimID != "eim.symb-iot.com" {
		t.Fatalf("eimId = %q, want eim.symb-iot.com", result.ErrorUnsigned.EimID)
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) error = %v", value, err)
	}
	return out
}

func mustIntegerTLV(t *testing.T, tag bertlv.Tag, value int64) *bertlv.TLV {
	t.Helper()
	tlv, err := bertlv.MarshalValue(tag, primitive.MarshalInt(value))
	if err != nil {
		t.Fatalf("MarshalValue(INTEGER) error = %v", err)
	}
	return tlv
}

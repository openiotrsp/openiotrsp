package asn1

import (
	"bytes"
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

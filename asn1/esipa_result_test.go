package asn1

import (
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

func mustIntegerTLV(t *testing.T, tag bertlv.Tag, value int64) *bertlv.TLV {
	t.Helper()
	tlv, err := bertlv.MarshalValue(tag, primitive.MarshalInt(value))
	if err != nil {
		t.Fatalf("MarshalValue(INTEGER) error = %v", err)
	}
	return tlv
}

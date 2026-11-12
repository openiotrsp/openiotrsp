package euiccpkg

import (
	"bytes"
	"testing"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
)

func TestDefaultProfileInfoListTagList(t *testing.T) {
	t.Parallel()

	if !bytes.Equal(DefaultProfileInfoListTagList, SGP32ProfileInfoListTagList) {
		t.Fatalf("DefaultProfileInfoListTagList = %x, want %x", DefaultProfileInfoListTagList, SGP32ProfileInfoListTagList)
	}
}

func TestListProfileInfoWithAlternativeTagList(t *testing.T) {
	t.Parallel()

	pkg := ListProfileInfoWithTagList(AlternativeProfileInfoListTagList)
	tagListTLV := pkg.PSMOs[0].ProfileInfoListRequest.First(bertlv.Application.Primitive(28))
	if tagListTLV == nil {
		t.Fatal("ProfileInfoListRequest missing tagList")
	}
	if !bytes.Equal(tagListTLV.Value, AlternativeProfileInfoListTagList) {
		t.Fatalf("tagList = %x, want %x", tagListTLV.Value, AlternativeProfileInfoListTagList)
	}
}

func TestListProfileInfoWithTagList(t *testing.T) {
	t.Parallel()

	custom := []byte{0x5a, 0x9f, 0x70, 0x9f, 0x26}
	pkg := ListProfileInfoWithTagList(custom)
	request := pkg.PSMOs[0].ProfileInfoListRequest
	tagListTLV := request.First(bertlv.Application.Primitive(28))
	if tagListTLV == nil {
		t.Fatal("ProfileInfoListRequest missing tagList (5C)")
	}
	if !bytes.Equal(tagListTLV.Value, custom) {
		t.Fatalf("tagList = %x, want %x", tagListTLV.Value, custom)
	}
}

func TestListProfileInfoUsesDefaultTagList(t *testing.T) {
	t.Parallel()

	pkg := ListProfileInfo()
	if len(pkg.PSMOs) != 1 || pkg.PSMOs[0].Operation != protocolasn1.PsmoListProfileInfo {
		t.Fatalf("ListProfileInfo() = %#v, want single listProfileInfo PSMO", pkg.PSMOs)
	}
	request := pkg.PSMOs[0].ProfileInfoListRequest
	if request == nil {
		t.Fatal("ProfileInfoListRequest = nil, want BF2D with tagList")
	}
	tagListTLV := request.First(bertlv.Application.Primitive(28))
	if tagListTLV == nil {
		t.Fatalf("ProfileInfoListRequest = %x, missing tagList (5C)", mustMarshalTLV(t, request))
	}
	if !bytes.Equal(tagListTLV.Value, DefaultProfileInfoListTagList) {
		t.Fatalf("tagList = %x, want %x", tagListTLV.Value, DefaultProfileInfoListTagList)
	}
}

func mustMarshalTLV(t *testing.T, tlv *bertlv.TLV) []byte {
	t.Helper()
	encoded, err := tlv.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	return encoded
}

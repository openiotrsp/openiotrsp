package euiccpkg

import (
	"bytes"
	"testing"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
)

func TestDefaultProfileInfoListTagList(t *testing.T) {
	t.Parallel()

	want := []byte{
		0x5a, 0x4f, 0x9f, 0x70, 0x91, 0x92, 0x95, 0x9f, 0x7b, 0x9f, 0x26, 0x9f, 0x67,
	}
	if !bytes.Equal(DefaultProfileInfoListTagList, want) {
		t.Fatalf("DefaultProfileInfoListTagList = %x, want %x", DefaultProfileInfoListTagList, want)
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

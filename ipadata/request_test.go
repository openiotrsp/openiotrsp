package ipadata

import (
	"bytes"
	"context"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

func TestDefaultTagListExcludesEID(t *testing.T) {
	t.Parallel()

	if slices.Contains(DefaultTagList, byte(0x5a)) {
		t.Fatalf("DefaultTagList = %x, must not contain EID tag 5A", DefaultTagList)
	}
	want := []byte{0xbf, 0x20, 0xbf, 0x22, 0xa0, 0xa5, 0xa6, 0xa8, 0xa9}
	if !bytes.Equal(DefaultTagList, want) {
		t.Fatalf("DefaultTagList = %x, want %x", DefaultTagList, want)
	}
}

func TestDefaultTagListExcludesBF2D(t *testing.T) {
	t.Parallel()

	if bytes.Contains(DefaultTagList, []byte{0xbf, 0x2d}) {
		t.Fatalf("DefaultTagList = %x, must not contain BF2D", DefaultTagList)
	}
	if !slices.ContainsFunc(parseTagEntries(DefaultTagList), func(tag []byte) bool {
		return len(tag) == 1 && tag[0] == 0xa0
	}) {
		t.Fatalf("DefaultTagList = %x, must contain notifications tag A0", DefaultTagList)
	}
}

func TestNewRequestEncodesDefaultTagList(t *testing.T) {
	t.Parallel()

	request, err := NewRequest(RequestInput{})
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	encoded, err := request.MarshalBERTLV()
	if err != nil {
		t.Fatalf("MarshalBERTLV() error = %v", err)
	}
	var decoded protocolasn1.IpaEuiccDataRequest
	if err := decoded.UnmarshalBERTLV(encoded); err != nil {
		t.Fatalf("UnmarshalBERTLV() error = %v", err)
	}
	if !bytes.Equal(decoded.TagList, DefaultTagList) {
		t.Fatalf("decoded tagList = %x, want %x", decoded.TagList, DefaultTagList)
	}
}

func TestEnqueueRequestDefaultTagListExcludesEID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := hex.EncodeToString(bytes.Repeat([]byte{0x01}, 16))
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	operation, err := EnqueueRequest(ctx, store, storage.DefaultTenantID, eid, RequestInput{})
	if err != nil {
		t.Fatalf("EnqueueRequest() error = %v", err)
	}
	request, err := NewRequest(RequestInput{})
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if slices.Contains(request.TagList, byte(0x5a)) {
		t.Fatalf("tagList = %x, must not contain EID tag 5A", request.TagList)
	}
	if operation.Kind != storage.OperationIpaEuiccData {
		t.Fatalf("operation kind = %q, want ipa-euicc-data", operation.Kind)
	}
}

func TestStateFromResponseStoresDeviceInfo(t *testing.T) {
	t.Parallel()

	device := bertlv.NewChildren(bertlv.ContextSpecific.Constructed(9),
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), []byte{0x35, 0x32, 0x30, 0x31}),
		bertlv.NewChildren(bertlv.ContextSpecific.Constructed(1)),
	)
	deviceBytes, err := device.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(deviceInfo) error = %v", err)
	}
	responseTLV := bertlv.NewChildren(bertlv.ContextSpecific.Constructed(82), device)
	var response protocolasn1.IpaEuiccDataResponse
	if err := response.UnmarshalBERTLV(responseTLV); err != nil {
		t.Fatalf("UnmarshalBERTLV() error = %v", err)
	}
	state, err := StateFromResponse("89044045930000000000002153893210", &response, nil)
	if err != nil {
		t.Fatalf("StateFromResponse() error = %v", err)
	}
	if !bytes.Equal(state.DeviceInfo, deviceBytes) {
		t.Fatalf("DeviceInfo = %x, want %x", state.DeviceInfo, deviceBytes)
	}
}

func parseTagEntries(tagList []byte) [][]byte {
	var out [][]byte
	for i := 0; i < len(tagList); {
		n := 1
		if tagList[i]&0x1f == 0x1f {
			for n < len(tagList)-i && tagList[i+n]&0x80 != 0 {
				n++
			}
			n++
		}
		if i+n > len(tagList) {
			break
		}
		out = append(out, tagList[i:i+n])
		i += n
	}
	return out
}

package ipadata

import (
	"bytes"
	"context"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

func TestDefaultTagListExcludesEID(t *testing.T) {
	t.Parallel()

	if slices.Contains(DefaultTagList, byte(0x5a)) {
		t.Fatalf("DefaultTagList = %x, must not contain EID tag 5A", DefaultTagList)
	}
	want := []byte{0xbf, 0x20, 0xbf, 0x22, 0xbf, 0x2d, 0xa5, 0xa6, 0xa8}
	if !bytes.Equal(DefaultTagList, want) {
		t.Fatalf("DefaultTagList = %x, want %x", DefaultTagList, want)
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

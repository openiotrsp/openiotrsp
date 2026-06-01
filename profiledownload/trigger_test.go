package profiledownload

import (
	"context"
	"testing"

	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

func TestTriggerConstructionRoundTrips(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		build    func() (*protocolasn1.ProfileDownloadTriggerRequest, error)
		wantKind protocolasn1.ProfileDownloadDataKind
		wantAC   string
	}{
		{
			name: "activation code",
			build: func() (*protocolasn1.ProfileDownloadTriggerRequest, error) {
				return NewActivationCodeTrigger("1$smdp.example$MATCH", []byte{0x01})
			},
			wantKind: protocolasn1.ProfileDownloadActivationCode,
			wantAC:   "1$smdp.example$MATCH",
		},
		{
			name: "SM-DP+ address as activation code",
			build: func() (*protocolasn1.ProfileDownloadTriggerRequest, error) {
				return NewSMDPAddressTrigger("smdp.example", "MATCH", []byte{0x02})
			},
			wantKind: protocolasn1.ProfileDownloadActivationCode,
			wantAC:   "1$smdp.example$MATCH",
		},
		{
			name: "default SM-DP+ address",
			build: func() (*protocolasn1.ProfileDownloadTriggerRequest, error) {
				return NewDefaultSMDPTrigger([]byte{0x03}), nil
			},
			wantKind: protocolasn1.ProfileDownloadContactDefaultSMDP,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			request, err := tc.build()
			if err != nil {
				t.Fatalf("build() error = %v", err)
			}
			encoded, err := protocolasn1.Encode(request)
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}

			var decoded protocolasn1.ProfileDownloadTriggerRequest
			if err := protocolasn1.Decode(encoded, &decoded); err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			if decoded.ProfileDownloadData == nil || decoded.ProfileDownloadData.Kind != tc.wantKind {
				t.Fatalf("decoded data = %#v, want kind %v", decoded.ProfileDownloadData, tc.wantKind)
			}
			if decoded.ProfileDownloadData.ActivationCode != tc.wantAC {
				t.Fatalf("activation code = %q, want %q", decoded.ProfileDownloadData.ActivationCode, tc.wantAC)
			}
		})
	}
}

func TestEnqueueTrigger(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := "00112233445566778899aabbccddeeff"
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	trigger, err := NewActivationCodeTrigger("1$smdp.example$MATCH", []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("NewActivationCodeTrigger() error = %v", err)
	}

	operation, err := EnqueueTrigger(ctx, store, storage.DefaultTenantID, eid, trigger)
	if err != nil {
		t.Fatalf("EnqueueTrigger() error = %v", err)
	}
	if operation.Kind != storage.OperationProfileDownloadTrigger || operation.SequenceNumber != 1 {
		t.Fatalf("operation = %#v, want profile download trigger sequence 1", operation)
	}

	pending, err := store.FetchPendingOperations(ctx, storage.DefaultTenantID, eid, 1)
	if err != nil {
		t.Fatalf("FetchPendingOperations() error = %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending count = %d, want 1", len(pending))
	}
	var decoded protocolasn1.ProfileDownloadTriggerRequest
	if err := protocolasn1.Decode(pending[0].Payload, &decoded); err != nil {
		t.Fatalf("Decode(pending payload) error = %v", err)
	}
	if decoded.ProfileDownloadData == nil || decoded.ProfileDownloadData.ActivationCode != "1$smdp.example$MATCH" {
		t.Fatalf("decoded pending trigger = %#v", decoded)
	}
}

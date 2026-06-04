package ipadata

import (
	"context"
	"errors"
	"testing"

	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
)

func TestApplyResponseReconcilesProfileInventory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := "000102030405060708090a0b0c0d0e0f"
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	if err := store.SetProfileState(ctx, storage.DefaultTenantID, storage.ProfileState{
		EID:         eid,
		ICCID:       "89101122334455",
		IsEnabled:   false,
		IsFallback:  false,
		SMDPAddress: "smdp.example",
	}); err != nil {
		t.Fatalf("SetProfileState(existing) error = %v", err)
	}
	if err := store.SetProfileState(ctx, storage.DefaultTenantID, storage.ProfileState{
		EID:       eid,
		ICCID:     "9999",
		IsEnabled: true,
	}); err != nil {
		t.Fatalf("SetProfileState(stale) error = %v", err)
	}

	enabled := protocolasn1.ProfileStateEnabled
	response := &protocolasn1.IpaEuiccDataResponse{Data: &protocolasn1.IpaEuiccData{
		ProfileInfoListPresent: true,
		Profiles: []protocolasn1.ProfileInfo{{
			ICCID:             []byte{0x89, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55},
			ProfileState:      &enabled,
			FallbackAttribute: true,
		}},
	}}
	if err := ApplyResponse(ctx, store, storage.DefaultTenantID, eid, response, []byte{0xbf, 0x52, 0x00}); err != nil {
		t.Fatalf("ApplyResponse() error = %v", err)
	}

	profile, err := store.GetProfileState(ctx, storage.DefaultTenantID, eid, "89101122334455")
	if err != nil {
		t.Fatalf("GetProfileState(updated) error = %v", err)
	}
	if !profile.IsEnabled || !profile.IsFallback || profile.SMDPAddress != "smdp.example" {
		t.Fatalf("profile = %#v, want enabled fallback preserving SMDP address", profile)
	}
	if _, err := store.GetProfileState(ctx, storage.DefaultTenantID, eid, "9999"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("GetProfileState(stale) error = %v, want %v", err, storage.ErrNotFound)
	}
}

func TestApplyResponseWithoutProfileInventoryPreservesProfiles(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := memory.New()
	eid := "101112131415161718191a1b1c1d1e1f"
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: eid}); err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}
	if err := store.SetProfileState(ctx, storage.DefaultTenantID, storage.ProfileState{
		EID:         eid,
		ICCID:       "891011",
		IsEnabled:   true,
		SMDPAddress: "smdp.example",
	}); err != nil {
		t.Fatalf("SetProfileState() error = %v", err)
	}

	response := &protocolasn1.IpaEuiccDataResponse{Data: &protocolasn1.IpaEuiccData{
		EID: []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
	}}
	if err := ApplyResponse(ctx, store, storage.DefaultTenantID, eid, response, []byte{0xbf, 0x52, 0x00}); err != nil {
		t.Fatalf("ApplyResponse() error = %v", err)
	}

	profile, err := store.GetProfileState(ctx, storage.DefaultTenantID, eid, "891011")
	if err != nil {
		t.Fatalf("GetProfileState() error = %v", err)
	}
	if !profile.IsEnabled || profile.SMDPAddress != "smdp.example" {
		t.Fatalf("profile = %#v, want unchanged profile", profile)
	}
}

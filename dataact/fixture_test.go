package dataact

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateMinimalFixture(t *testing.T) {
	if os.Getenv("OPENIOTRSP_GENERATE_DATAACT_FIXTURE") == "" {
		t.Skip("set OPENIOTRSP_GENERATE_DATAACT_FIXTURE=1 to regenerate testdata/minimal-bundle.zip")
	}

	tenantID := "fixture-tenant"
	prev := make([]byte, 32)
	ts := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	journal := []JournalRecord{
		BuildJournalRecord(tenantID, 1, ts, prev, "user", "fixture", "fixture_seed", "accepted"),
	}
	devices := []DeviceRecord{{
		EID:                     "89049032000000000000000000000001",
		NextSequenceNumber:      2,
		NextEUICCPackageCounter: 2,
		CreatedAt:               ts,
		UpdatedAt:               ts,
	}}
	profileStates := []ProfileStateRecord{{
		EID:         devices[0].EID,
		ICCID:       "8900000000000000001",
		IsEnabled:   true,
		IsFallback:  false,
		SMDPAddress: "smdpp.test.rsp.sysmocom.de",
		CreatedAt:   ts,
		UpdatedAt:   ts,
	}}
	anchor := JournalChainAnchor{
		FirstSeq:       1,
		LastSeq:        1,
		PrevHashBefore: hex.EncodeToString(prev),
	}
	path := filepath.Join("testdata", "minimal-bundle.zip")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := BuildTestBundle(path, tenantID, devices, profileStates, journal, anchor); err != nil {
		t.Fatalf("BuildTestBundle() error = %v", err)
	}
	manifest, err := ValidateBundle(path, nil)
	if err != nil {
		t.Fatalf("ValidateBundle() error = %v", err)
	}
	entries, err := ReadJournalRecords(path)
	if err != nil {
		t.Fatalf("ReadJournalRecords() error = %v", err)
	}
	if err := VerifyJournalSlice(manifest.TenantID, entries, manifest.JournalChain); err != nil {
		t.Fatalf("VerifyJournalSlice() error = %v", err)
	}
}

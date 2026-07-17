package dataact

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"testing"
	"time"
)

func TestValidateBundleRejectsTamperedDigest(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/bundle.zip"
	devices := []DeviceRecord{{
		EID:                     "89049032000000000000000000000001",
		NextSequenceNumber:      2,
		NextEUICCPackageCounter: 3,
		CreatedAt:               time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		UpdatedAt:               time.Date(2026, 1, 2, 3, 4, 6, 0, time.UTC),
	}}
	if err := BuildTestBundle(path, "tenant-a", devices, nil, nil, JournalChainAnchor{}); err != nil {
		t.Fatalf("BuildTestBundle() error = %v", err)
	}
	if _, err := ValidateBundle(path, nil); err != nil {
		t.Fatalf("ValidateBundle() error = %v", err)
	}

	tampered, err := tamperZipEntry(path, FileTenant, []byte(`{"id":"tenant-a","name":"tampered"}`))
	if err != nil {
		t.Fatalf("tamperZipEntry() error = %v", err)
	}
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := ValidateBundle(path, nil); err == nil {
		t.Fatal("ValidateBundle() expected digest mismatch")
	}
}

func tamperZipEntry(path, name string, payload []byte) ([]byte, error) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	buf := new(bytes.Buffer)
	writer := zip.NewWriter(buf)
	for _, file := range reader.File {
		rc, err := file.Open()
		if err != nil {
			return nil, err
		}
		content, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return nil, err
		}
		if file.Name == name {
			content = payload
		}
		fw, err := writer.Create(file.Name)
		if err != nil {
			return nil, err
		}
		if _, err := fw.Write(content); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func TestVerifyJournalSlice(t *testing.T) {
	tenantID := "tenant-a"
	prev := make([]byte, hashSize)
	ts := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	record := BuildJournalRecord(tenantID, 1, ts, prev, "user", "operator", "import_seed", "accepted")
	anchor := JournalChainAnchor{
		FirstSeq:       1,
		LastSeq:        1,
		PrevHashBefore: record.PrevHash,
	}
	if err := VerifyJournalSlice(tenantID, []JournalRecord{record}, anchor); err != nil {
		t.Fatalf("VerifyJournalSlice() error = %v", err)
	}
}

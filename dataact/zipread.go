package dataact

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

func readNDJSON[T any](bundlePath, name string) ([]T, error) {
	reader, err := zip.OpenReader(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("dataact: open bundle: %w", err)
	}
	defer func() { _ = reader.Close() }()

	for _, file := range reader.File {
		if file.Name != name {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return nil, err
		}
		payload, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return nil, err
		}
		return decodeNDJSONLines[T](payload)
	}
	return nil, nil
}

func decodeNDJSONLines[T any](payload []byte) ([]T, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	lines := strings.Split(string(payload), "\n")
	out := make([]T, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var record T
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return nil, fmt.Errorf("dataact: decode ndjson line: %w", err)
		}
		out = append(out, record)
	}
	return out, nil
}

// ReadJournalRecords loads command journal rows from an export bundle.
func ReadJournalRecords(bundlePath string) ([]JournalRecord, error) {
	return readNDJSON[JournalRecord](bundlePath, FileCommandJournal)
}

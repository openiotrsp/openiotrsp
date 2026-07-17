package dataact

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const hashSize = sha256.Size

// journalInput is the domain data hashed into one command journal entry.
type journalInput struct {
	TenantID          string
	ActorType         string
	ActorID           string
	EID               string
	Command           string
	PSMOPayloadSHA256 []byte
	CounterValue      *int64
	SigningKeyID      string
	SignatureSHA256   []byte
	OperationID       *int64
	Outcome           string
	ErrorCode         string
}

// entryHash computes entry_hash for a journal row.
func entryHash(prevHash []byte, seq int64, ts time.Time, input journalInput) []byte {
	payload := journalCanonical(seq, ts.UTC(), input)
	sum := sha256.Sum256(append(append([]byte(nil), prevHash...), payload...))
	return sum[:]
}

func journalCanonical(seq int64, ts time.Time, input journalInput) []byte {
	buf := make([]byte, 0, 256)
	buf = appendUint64(buf, uint64(seq))
	buf = appendString(buf, ts.Format(time.RFC3339Nano))
	buf = appendString(buf, input.TenantID)
	buf = appendString(buf, input.ActorType)
	buf = appendString(buf, input.ActorID)
	buf = appendString(buf, input.EID)
	buf = appendOptionalBytes32(buf, input.PSMOPayloadSHA256)
	buf = appendOptionalInt64(buf, input.CounterValue)
	buf = appendString(buf, input.SigningKeyID)
	buf = appendOptionalBytes32(buf, input.SignatureSHA256)
	buf = appendOptionalInt64(buf, input.OperationID)
	buf = appendString(buf, input.Outcome)
	buf = appendString(buf, input.ErrorCode)
	return buf
}

func appendUint64(buf []byte, value uint64) []byte {
	var scratch [8]byte
	binary.BigEndian.PutUint64(scratch[:], value)
	return append(buf, scratch[:]...)
}

func appendString(buf []byte, value string) []byte {
	buf = appendUint32(buf, uint32(len(value)))
	return append(buf, value...)
}

func appendUint32(buf []byte, value uint32) []byte {
	var scratch [4]byte
	binary.BigEndian.PutUint32(scratch[:], value)
	return append(buf, scratch[:]...)
}

func appendOptionalBytes32(buf []byte, value []byte) []byte {
	if len(value) == 0 {
		return append(buf, 0)
	}
	buf = append(buf, 1)
	return append(buf, value...)
}

func appendOptionalInt64(buf []byte, value *int64) []byte {
	if value == nil {
		return append(buf, 0)
	}
	buf = append(buf, 1)
	return appendUint64(buf, uint64(*value))
}

// VerifyJournalSlice checks internal continuity and chain anchors for the
// exported command_journal.ndjson slice.
func VerifyJournalSlice(tenantID string, entries []JournalRecord, anchor JournalChainAnchor) error {
	if len(entries) == 0 {
		return nil
	}
	for i, entry := range entries {
		if i == 0 && anchor.PrevHashBefore != "" && entry.PrevHash != anchor.PrevHashBefore {
			return fmt.Errorf("dataact: journal slice head mismatch at seq %d", entry.Seq)
		}
		if i > 0 && entry.PrevHash != entries[i-1].EntryHash {
			return fmt.Errorf("dataact: journal slice chain break at seq %d", entry.Seq)
		}
		prev, err := hex.DecodeString(entry.PrevHash)
		if err != nil {
			return fmt.Errorf("dataact: decode prev_hash at seq %d: %w", entry.Seq, err)
		}
		if len(prev) != hashSize {
			return fmt.Errorf("dataact: prev_hash at seq %d must be %d bytes", entry.Seq, hashSize)
		}
		stored, err := hex.DecodeString(entry.EntryHash)
		if err != nil {
			return fmt.Errorf("dataact: decode entry_hash at seq %d: %w", entry.Seq, err)
		}
		want := entryHash(prev, entry.Seq, entry.Timestamp.UTC().Truncate(time.Microsecond), journalInput{
			TenantID:          tenantID,
			ActorType:         entry.ActorType,
			ActorID:           entry.ActorID,
			EID:               entry.EID,
			Command:           entry.Command,
			PSMOPayloadSHA256: decodeOptionalHex(entry.PSMOPayloadSHA256),
			CounterValue:      entry.CounterValue,
			SigningKeyID:      entry.SigningKeyID,
			SignatureSHA256:   decodeOptionalHex(entry.SignatureSHA256),
			OperationID:       entry.OperationID,
			Outcome:           entry.Outcome,
			ErrorCode:         entry.ErrorCode,
		})
		if string(want) != string(stored) {
			return fmt.Errorf("dataact: journal entry_hash mismatch at seq %d", entry.Seq)
		}
	}
	last := entries[len(entries)-1]
	if anchor.EntryHashAfter != "" && last.EntryHash != anchor.EntryHashAfter {
		return fmt.Errorf("dataact: journal slice tail mismatch at seq %d", last.Seq)
	}
	return nil
}

// BuildJournalRecord constructs a journal row with a valid entry_hash.
func BuildJournalRecord(tenantID string, seq int64, ts time.Time, prevHash []byte, actorType, actorID, command, outcome string) JournalRecord {
	hash := entryHash(prevHash, seq, ts.UTC().Truncate(time.Microsecond), journalInput{
		TenantID:  tenantID,
		ActorType: actorType,
		ActorID:   actorID,
		Command:   command,
		Outcome:   outcome,
	})
	return JournalRecord{
		Seq:       seq,
		Timestamp: ts,
		ActorType: actorType,
		ActorID:   actorID,
		Command:   command,
		Outcome:   outcome,
		PrevHash:  hex.EncodeToString(prevHash),
		EntryHash: hex.EncodeToString(hash),
	}
}

func decodeOptionalHex(value string) []byte {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	out, err := hex.DecodeString(value)
	if err != nil {
		return nil
	}
	return out
}

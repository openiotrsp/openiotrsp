package dataact

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openiotrsp/openiotrsp/storage"
)

// ImportOptions configures bundle import.
type ImportOptions struct {
	// TrustCert pins the hosting eIM certificate used to sign the bundle.
	TrustCert *x509.Certificate
}

// BundleImporter applies validated bundle rows to persistent storage.
type BundleImporter interface {
	ImportBundle(ctx context.Context, tenantID storage.TenantID, bundle *BundlePayload) error
}

// BundlePayload is the decoded, validated entity set from one export bundle.
type BundlePayload struct {
	Manifest      Manifest
	Devices       []DeviceRecord
	ProfileStates []ProfileStateRecord
	AssociatedEIM []AssociatedEIMRecord
	EUICCStates   []EUICCStateRecord
	Operations    []OperationRecord
	Notifications []NotificationRecord
	Journal       []JournalRecord
}

// ImportBundle validates bundlePath and imports its entities into store.
func ImportBundle(ctx context.Context, importer BundleImporter, tenantID storage.TenantID, bundlePath string, opts ImportOptions) error {
	manifest, err := ValidateBundle(bundlePath, opts.TrustCert)
	if err != nil {
		return err
	}

	journal, err := ReadJournalRecords(bundlePath)
	if err != nil {
		return err
	}
	if err := VerifyJournalSlice(manifest.TenantID, journal, manifest.JournalChain); err != nil {
		return err
	}

	devices, err := readNDJSON[DeviceRecord](bundlePath, FileDevices)
	if err != nil {
		return err
	}
	profileStates, err := readNDJSON[ProfileStateRecord](bundlePath, FileProfileState)
	if err != nil {
		return err
	}
	associatedEIM, err := readNDJSON[AssociatedEIMRecord](bundlePath, FileAssociatedEIM)
	if err != nil {
		return err
	}
	euiccStates, err := readNDJSON[EUICCStateRecord](bundlePath, FileEUICCState)
	if err != nil {
		return err
	}
	operations, err := readNDJSON[OperationRecord](bundlePath, FileOperations)
	if err != nil {
		return err
	}
	notifications, err := readNDJSON[NotificationRecord](bundlePath, FileNotifications)
	if err != nil {
		return err
	}

	payload := &BundlePayload{
		Manifest:      manifest,
		Devices:       devices,
		ProfileStates: profileStates,
		AssociatedEIM: associatedEIM,
		EUICCStates:   euiccStates,
		Operations:    operations,
		Notifications: notifications,
		Journal:       journal,
	}
	return importer.ImportBundle(ctx, tenantID, payload)
}

// DecodeOptionalBase64 decodes a standard base64 field from an export row.
func DecodeOptionalBase64(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	out, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("dataact: decode base64: %w", err)
	}
	return out, nil
}

// DecodeCertificateIdentifiers unmarshals the certificate identifier JSON field.
func DecodeCertificateIdentifiers(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var identifiers []string
	if err := json.Unmarshal(raw, &identifiers); err != nil {
		return nil, fmt.Errorf("dataact: decode certificate identifiers: %w", err)
	}
	return identifiers, nil
}

// NotificationSequence returns the sequence number for an imported notification.
func NotificationSequence(record NotificationRecord) (int64, error) {
	if record.SequenceNumber != nil {
		return *record.SequenceNumber, nil
	}
	return 0, fmt.Errorf("dataact: notification %d missing sequenceNumber", record.ID)
}

// ImportTimestamps returns created and updated timestamps, defaulting updated to created.
func ImportTimestamps(createdAt, updatedAt time.Time) (time.Time, time.Time) {
	if updatedAt.IsZero() {
		return createdAt, createdAt
	}
	return createdAt, updatedAt
}

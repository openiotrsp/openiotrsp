// Package storage defines the persistence boundary used by protocol and API
// packages.
package storage

import (
	"context"
	"errors"
	"time"
)

// TenantID scopes all fleet and device data. The open source build uses
// DefaultTenantID, while enterprise builds can route calls to tenant-specific
// stores.
type TenantID string

// DefaultTenantID is the single tenant used by the open source build.
const DefaultTenantID TenantID = "openiotrsp"

// ErrNotFound is returned when a tenant-scoped record does not exist.
var ErrNotFound = errors.New("storage: not found")

// Device is the tenant-scoped eUICC device record.
type Device struct {
	EID string
}

// ProfileState is the eIM's persisted view of one device's profile state.
type ProfileState struct {
	EID  string
	Data []byte
}

// OperationStatus is the lifecycle state of an operation queued for an IPA poll.
type OperationStatus string

const (
	// OperationPending is ready to be returned to the IPA.
	OperationPending OperationStatus = "pending"
	// OperationInFlight has been returned to the IPA and awaits acknowledgement
	// or package result handling.
	OperationInFlight OperationStatus = "in-flight"
	// OperationDone completed successfully.
	OperationDone OperationStatus = "done"
	// OperationFailed completed with an error.
	OperationFailed OperationStatus = "failed"
)

// OperationKind identifies the encoded operation payload.
type OperationKind string

const (
	// OperationEuiccPackage carries an encoded eUICC Package request.
	OperationEuiccPackage OperationKind = "euicc-package"
	// OperationProfileDownloadTrigger carries an encoded ProfileDownloadTriggerRequest.
	OperationProfileDownloadTrigger OperationKind = "profile-download-trigger"
	// OperationIpaEuiccData carries an encoded IPA eUICC data request.
	OperationIpaEuiccData OperationKind = "ipa-euicc-data"
)

// OperationRequest is the input for enqueueing work for a device.
type OperationRequest struct {
	EID     string
	Kind    OperationKind
	Payload []byte
}

// Operation is queued work for one device. SequenceNumber is the SGP.32
// EimAcknowledgements sequence value for this tenant and EID.
type Operation struct {
	ID             int64
	EID            string
	SequenceNumber int64
	Kind           OperationKind
	Payload        []byte
	Status         OperationStatus
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// EUICCPackageResult records the IPA-provided eUICC Package Result for a queued
// operation.
type EUICCPackageResult struct {
	EID            string
	OperationID    int64
	SequenceNumber int64
	Status         OperationStatus
	Payload        []byte
}

// EIMConfig is an encoded eIM configuration record.
type EIMConfig struct {
	EIMID string
	Data  []byte
}

// Notification is an encoded notification emitted by an IPA/eUICC.
type Notification struct {
	EID     string
	Kind    string
	Payload []byte
}

// Store is the tenant-scoped persistence contract used by protocol logic. Every
// I/O method takes context.Context first.
type Store interface {
	RegisterDevice(ctx context.Context, tenantID TenantID, device Device) error
	GetProfileState(ctx context.Context, tenantID TenantID, eid string) (ProfileState, error)
	SetProfileState(ctx context.Context, tenantID TenantID, state ProfileState) error
	EnqueueOperation(ctx context.Context, tenantID TenantID, operation OperationRequest) (Operation, error)
	FetchPendingOperations(ctx context.Context, tenantID TenantID, eid string, limit int) ([]Operation, error)
	RecordEUICCPackageResult(ctx context.Context, tenantID TenantID, result EUICCPackageResult) error
	StoreEIMConfig(ctx context.Context, tenantID TenantID, config EIMConfig) error
	ReadEIMConfig(ctx context.Context, tenantID TenantID, eimID string) (EIMConfig, error)
	StoreNotification(ctx context.Context, tenantID TenantID, notification Notification) error
}

// NormalizeTenantID maps the open source empty tenant path to DefaultTenantID.
func NormalizeTenantID(tenantID TenantID) TenantID {
	if tenantID == "" {
		return DefaultTenantID
	}
	return tenantID
}

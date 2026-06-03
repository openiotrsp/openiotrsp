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

// ProfileState is the eIM's persisted observability view of one profile on one
// eUICC. It may be refreshed from BF52 IPA eUICC data responses, which are not
// signed eUICC Package Results, so callers must not treat it as authorization
// evidence for trust decisions without independent verification.
type ProfileState struct {
	EID         string
	ICCID       string
	IsEnabled   bool
	IsFallback  bool
	SMDPAddress string
}

// EUICCState is the eIM's current IPA-reported observability view of one eUICC.
// BF52 IpaEuiccDataResponse messages do not carry EuiccSignEPR signatures, so
// this state is suitable for reporting/reconciliation but not for authorization
// or security decisions unless a future caller adds a separate trust mechanism.
type EUICCState struct {
	EID                    string
	EIDValue               []byte
	DefaultSMDPAddress     string
	RootSMDSAddress        string
	EUICCInfo1             []byte
	EUICCInfo2             []byte
	IPACapabilities        []byte
	DeviceInfo             []byte
	EUMCertificate         []byte
	EUICCCertificate       []byte
	CertificateIdentifiers []string
	RawPayload             []byte
	UpdatedAt              time.Time
}

// OperationStatus is the lifecycle state of an operation queued for an IPA poll.
type OperationStatus string

const (
	// OperationPending is ready to be returned to the IPA. ESipa package delivery
	// does not clear this state; the result upload does.
	OperationPending OperationStatus = "pending"
	// OperationInFlight is reserved for transports that use explicit leases. ESipa
	// keeps operations pending until a result is recorded.
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

// OperationResult is the persisted completion payload for a queued operation.
type OperationResult struct {
	OperationID    int64
	EID            string
	SequenceNumber int64
	Status         OperationStatus
	Payload        []byte
	CreatedAt      time.Time
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

// AssociatedEIM is the eIM's persisted view of one Associated eIM configured on
// one eUICC.
type AssociatedEIM struct {
	EID           string
	EIMID         string
	EIMIDType     *int64
	ConfigPayload []byte
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
	GetProfileState(ctx context.Context, tenantID TenantID, eid string, iccid string) (ProfileState, error)
	ListProfileStates(ctx context.Context, tenantID TenantID, eid string) ([]ProfileState, error)
	SetProfileState(ctx context.Context, tenantID TenantID, state ProfileState) error
	DeleteProfileState(ctx context.Context, tenantID TenantID, eid string, iccid string) error
	GetEUICCState(ctx context.Context, tenantID TenantID, eid string) (EUICCState, error)
	SetEUICCState(ctx context.Context, tenantID TenantID, state EUICCState) error
	NextEUICCPackageCounter(ctx context.Context, tenantID TenantID, eid string) (int64, error)
	EnqueueOperation(ctx context.Context, tenantID TenantID, operation OperationRequest) (Operation, error)
	GetOperation(ctx context.Context, tenantID TenantID, operationID int64) (Operation, error)
	GetOperationBySequence(ctx context.Context, tenantID TenantID, eid string, sequenceNumber int64) (Operation, error)
	FetchPendingOperations(ctx context.Context, tenantID TenantID, eid string, limit int) ([]Operation, error)
	RecordEUICCPackageResult(ctx context.Context, tenantID TenantID, result EUICCPackageResult) error
	GetOperationResult(ctx context.Context, tenantID TenantID, operationID int64) (OperationResult, error)
	StoreEIMConfig(ctx context.Context, tenantID TenantID, config EIMConfig) error
	ReadEIMConfig(ctx context.Context, tenantID TenantID, eimID string) (EIMConfig, error)
	SetAssociatedEIM(ctx context.Context, tenantID TenantID, associated AssociatedEIM) error
	DeleteAssociatedEIM(ctx context.Context, tenantID TenantID, eid string, eimID string) error
	GetAssociatedEIM(ctx context.Context, tenantID TenantID, eid string, eimID string) (AssociatedEIM, error)
	ListAssociatedEIMs(ctx context.Context, tenantID TenantID, eid string) ([]AssociatedEIM, error)
	StoreNotification(ctx context.Context, tenantID TenantID, notification Notification) error
}

// NormalizeTenantID maps the open source empty tenant path to DefaultTenantID.
func NormalizeTenantID(tenantID TenantID) TenantID {
	if tenantID == "" {
		return DefaultTenantID
	}
	return tenantID
}

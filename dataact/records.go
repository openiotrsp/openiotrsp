package dataact

import (
	"encoding/json"
	"time"
)

// DeviceRecord is one exported device row.
type DeviceRecord struct {
	EID                     string    `json:"eid"`
	NextSequenceNumber      int64     `json:"nextSequenceNumber"`
	NextEUICCPackageCounter int64     `json:"nextEuiccPackageCounter"`
	CreatedAt               time.Time `json:"createdAt"`
	UpdatedAt               time.Time `json:"updatedAt"`
}

// ProfileStateRecord is one exported profile state row.
type ProfileStateRecord struct {
	EID         string    `json:"eid"`
	ICCID       string    `json:"iccid"`
	IsEnabled   bool      `json:"isEnabled"`
	IsFallback  bool      `json:"isFallback"`
	SMDPAddress string    `json:"smdpAddress"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// AssociatedEIMRecord is one exported associated eIM row.
type AssociatedEIMRecord struct {
	EID           string    `json:"eid"`
	EIMID         string    `json:"eimId"`
	EIMIDType     *int64    `json:"eimIdType,omitempty"`
	ConfigPayload string    `json:"configPayloadBase64"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

// EUICCStateRecord is one exported eUICC state row.
type EUICCStateRecord struct {
	EID                    string          `json:"eid"`
	EIDValue               string          `json:"eidValueBase64,omitempty"`
	DefaultSMDPAddress     string          `json:"defaultSmdpAddress"`
	RootSMDSAddress        string          `json:"rootSmdsAddress"`
	EUICCInfo1             string          `json:"euiccInfo1Base64,omitempty"`
	EUICCInfo2             string          `json:"euiccInfo2Base64,omitempty"`
	IPACapabilities        string          `json:"ipaCapabilitiesBase64,omitempty"`
	DeviceInfo             string          `json:"deviceInfoBase64,omitempty"`
	EUMCertificate         string          `json:"eumCertificateBase64,omitempty"`
	EUICCCertificate       string          `json:"euiccCertificateBase64,omitempty"`
	CertificateIdentifiers json.RawMessage `json:"certificateIdentifiers"`
	RawPayload             string          `json:"rawPayloadBase64,omitempty"`
	CreatedAt              time.Time       `json:"createdAt"`
	UpdatedAt              time.Time       `json:"updatedAt"`
}

// OperationRecord is one exported operation row.
type OperationRecord struct {
	ID             int64     `json:"id"`
	EID            string    `json:"eid"`
	SequenceNumber int64     `json:"sequenceNumber"`
	Kind           string    `json:"kind"`
	Payload        string    `json:"payloadBase64"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// NotificationRecord is one exported notification row.
type NotificationRecord struct {
	ID             int64     `json:"id"`
	EID            string    `json:"eid"`
	Kind           string    `json:"kind"`
	Payload        string    `json:"payloadBase64"`
	SequenceNumber *int64    `json:"sequenceNumber,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
}

// JournalRecord is one exported command journal row.
type JournalRecord struct {
	Seq               int64     `json:"seq"`
	Timestamp         time.Time `json:"ts"`
	ActorType         string    `json:"actorType"`
	ActorID           string    `json:"actorId"`
	RemoteAddr        string    `json:"remoteAddr,omitempty"`
	RequestID         string    `json:"requestId,omitempty"`
	EID               string    `json:"eid,omitempty"`
	Command           string    `json:"command"`
	PSMOPayloadSHA256 string    `json:"psmoPayloadSha256,omitempty"`
	CounterValue      *int64    `json:"counterValue,omitempty"`
	SigningKeyID      string    `json:"signingKeyId,omitempty"`
	SignatureSHA256   string    `json:"signatureSha256,omitempty"`
	OperationID       *int64    `json:"operationId,omitempty"`
	Outcome           string    `json:"outcome"`
	ErrorCode         string    `json:"errorCode,omitempty"`
	PrevHash          string    `json:"prevHash"`
	EntryHash         string    `json:"entryHash"`
}

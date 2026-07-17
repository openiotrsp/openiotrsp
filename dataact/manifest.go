package dataact

import "time"

// ManifestFile describes one file in the export bundle.
type ManifestFile struct {
	Name   string `json:"name"`
	Rows   int    `json:"rows"`
	SHA256 string `json:"sha256"`
}

// Manifest is the signed export manifest.
type Manifest struct {
	SchemaVersion  string             `json:"schemaVersion"`
	ExportID       string             `json:"exportId"`
	TenantID       string             `json:"tenantId"`
	ExportedAt     time.Time          `json:"exportedAt"`
	EIMID          string             `json:"eimId"`
	Files          []ManifestFile     `json:"files"`
	JournalChain   JournalChainAnchor `json:"journalChain"`
	BundleSHA256   string             `json:"bundleSha256"`
	SigningKeyID   string             `json:"signingKeyId"`
	Signature      string             `json:"signatureBase64"`
	CertificateDER string             `json:"certificateDerBase64,omitempty"`
}

// JournalChainAnchor holds neighbouring hashes for chain verification.
type JournalChainAnchor struct {
	FirstSeq       int64  `json:"firstSeq,omitempty"`
	LastSeq        int64  `json:"lastSeq,omitempty"`
	PrevHashBefore string `json:"prevHashBefore,omitempty"`
	EntryHashAfter string `json:"entryHashAfter,omitempty"`
}

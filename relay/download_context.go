package relay

import "encoding/hex"

// DownloadContext is the indirect-download memory for one SM-DP+ transactionId.
// Compact ESipa forms omit fields the eUICC already signed; esipa rebuilds those
// fields from this record before the ES9+ hop. The record lives on the Relay
// because that object already tracks the transaction for the whole download.
type DownloadContext struct {
	EID             string
	TransactionID   []byte
	ServerAddress   []byte
	ServerChallenge []byte
	// CtxParams1 is the CtxParams1 CHOICE encoding (context [0]), not the
	// explicit [2] wrapper used on InitiateAuthenticationOkEsipa.
	CtxParams1 []byte
	ICCID      []byte
	ISDPAID    []byte
	HashCC     []byte
	EUICCOTPK  []byte
	// SMDPOID is the content of the activation-code SM-DP+ OBJECT IDENTIFIER,
	// without the universal tag.
	SMDPOID []byte
	// CIPKID is the full euiccCiPKIdentifierToBeUsed from the SM-DP+.
	// The ESipa response may carry only a truncated prefix.
	CIPKID []byte
	// ProfileMetadata is the StoreMetadataRequest TLV from AuthenticateClient,
	// kept so GetBoundProfilePackage can compare the bound package copy.
	ProfileMetadata []byte
	// EimTransactionID is the eimTransactionId of the pending
	// profile-download-trigger that InitiateAuthentication resolved for this
	// download. It is empty when the download was not started by a trigger.
	// The value lives only in this in-memory record.
	EimTransactionID []byte
}

// RememberDownload stores context for transactionId, replacing any previous
// record for that id.
func (r *Relay) RememberDownload(ctx DownloadContext) {
	if r == nil || len(ctx.TransactionID) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.downloads == nil {
		r.downloads = make(map[string]DownloadContext)
	}
	r.downloads[hex.EncodeToString(ctx.TransactionID)] = cloneDownloadContext(ctx)
}

// DownloadContext returns the remembered record for transactionID.
func (r *Relay) DownloadContext(transactionID []byte) (DownloadContext, bool) {
	if r == nil || len(transactionID) == 0 {
		return DownloadContext{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx, ok := r.downloads[hex.EncodeToString(transactionID)]
	if !ok {
		return DownloadContext{}, false
	}
	return cloneDownloadContext(ctx), true
}

// UpdateDownload applies update to the record for transactionID.
func (r *Relay) UpdateDownload(transactionID []byte, update func(*DownloadContext)) {
	if r == nil || len(transactionID) == 0 || update == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.downloads == nil {
		return
	}
	key := hex.EncodeToString(transactionID)
	ctx, ok := r.downloads[key]
	if !ok {
		return
	}
	update(&ctx)
	r.downloads[key] = ctx
}

func cloneDownloadContext(ctx DownloadContext) DownloadContext {
	ctx.TransactionID = cloneBytes(ctx.TransactionID)
	ctx.ServerAddress = cloneBytes(ctx.ServerAddress)
	ctx.ServerChallenge = cloneBytes(ctx.ServerChallenge)
	ctx.CtxParams1 = cloneBytes(ctx.CtxParams1)
	ctx.ICCID = cloneBytes(ctx.ICCID)
	ctx.ISDPAID = cloneBytes(ctx.ISDPAID)
	ctx.HashCC = cloneBytes(ctx.HashCC)
	ctx.EUICCOTPK = cloneBytes(ctx.EUICCOTPK)
	ctx.SMDPOID = cloneBytes(ctx.SMDPOID)
	ctx.CIPKID = cloneBytes(ctx.CIPKID)
	ctx.ProfileMetadata = cloneBytes(ctx.ProfileMetadata)
	ctx.EimTransactionID = cloneBytes(ctx.EimTransactionID)
	return ctx
}

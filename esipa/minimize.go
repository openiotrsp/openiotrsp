package esipa

import (
	"bytes"
	"context"
	"errors"
	"log/slog"

	"github.com/damonto/euicc-go/bertlv"
	"github.com/openiotrsp/openiotrsp/relay"
	"github.com/openiotrsp/openiotrsp/storage"
)

// SGP.32 status codes that map onto ESipa INTEGER errors.
const (
	// authenticateClientErrorPPRNotAllowed is "8.2.8 PPR – 1.2 Not Allowed".
	authenticateClientErrorPPRNotAllowed int64 = 50
	// getBoundPackageErrorMetadataMismatch is "8.2.9 Profile Metadata – 3.11 Value has Changed".
	getBoundPackageErrorMetadataMismatch int64 = 50
)

const scp03tMACLen = 8

var (
	errCIPKNotUnique   = errors.New("esipa: CI public key identifier is not unique in euiccCiPKIdListForSigning")
	errMetadataChanged = errors.New("esipa: profile metadata in the bound profile package has changed")
	tagBoundPackage    = bertlv.ContextSpecific.Constructed(54)
	tagSegment88       = bertlv.ContextSpecific.Primitive(8)
	tagSigningCIPKList = bertlv.ContextSpecific.Constructed(10)
	tagProfileOwner    = bertlv.ContextSpecific.Constructed(23)
	tagProfilePolicy   = bertlv.ContextSpecific.Primitive(25)
)

// minimizeInitiateAuthentication applies SGP.32 §5.14.1 when minimizeEsipaBytes
// is set: drop transactionId [0], and replace euiccCiPKIdentifierToBeUsed with
// the shortest unique prefix of EUICCInfo1.euiccCiPKIdListForSigning. A list of
// one entry becomes a zero-length OCTET STRING. full is the SM-DP+ identifier
// before truncation.
func minimizeInitiateAuthentication(payload, info1 []byte) (minimized, full []byte, err error) {
	root, err := parseRelayTLV(payload)
	if err != nil {
		return nil, nil, err
	}
	container, ok := esipaSuccessContainer(root)
	if !ok {
		return payload, nil, nil
	}
	full = directOctetString(container)
	if full == nil {
		return nil, nil, errCIPKNotUnique
	}
	list, err := signingCIPKIDs(info1)
	if err != nil {
		return nil, nil, err
	}
	prefix, err := truncateCIPKIdentifier(full, list)
	if err != nil {
		return nil, nil, err
	}
	replaceDirectChildren(container, true, prefix)
	raw, err := root.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return raw, full, nil
}

func ciPKIdentifier(payload []byte) []byte {
	root, err := parseRelayTLV(payload)
	if err != nil {
		return nil
	}
	container, ok := esipaSuccessContainer(root)
	if !ok {
		return nil
	}
	return directOctetString(container)
}

func signingCIPKIDs(info1 []byte) ([][]byte, error) {
	if len(info1) == 0 {
		return nil, errCIPKNotUnique
	}
	tlv, err := parseRelayTLV(info1)
	if err != nil || !tlv.Tag.Equal(tagInitAuthInfo1) {
		return nil, errCIPKNotUnique
	}
	list := tlv.First(tagSigningCIPKList)
	if list == nil {
		return nil, errCIPKNotUnique
	}
	var out [][]byte
	for _, child := range list.Children {
		if child.Tag.Equal(tagOctetString) {
			out = append(out, cloneBytes(child.Value))
		}
	}
	if len(out) == 0 {
		return nil, errCIPKNotUnique
	}
	return out, nil
}

// truncateCIPKIdentifier returns the leading bytes of id that select exactly
// one entry of list, and that entry must be id. One entry selects the empty
// prefix, which SGP.32 encodes as a zero-length OCTET STRING.
func truncateCIPKIdentifier(id []byte, list [][]byte) ([]byte, error) {
	if len(list) == 0 {
		return nil, errCIPKNotUnique
	}
	if len(list) == 1 {
		return []byte{}, nil
	}
	if len(id) == 0 || !cipkInList(id, list) {
		return nil, errCIPKNotUnique
	}
	for n := 1; n <= len(id); n++ {
		prefix := id[:n]
		var matched []byte
		matches := 0
		for _, entry := range list {
			if bytes.HasPrefix(entry, prefix) {
				matches++
				matched = entry
			}
		}
		if matches == 1 && bytes.Equal(matched, id) {
			return append([]byte(nil), prefix...), nil
		}
	}
	return nil, errCIPKNotUnique
}

func cipkInList(id []byte, list [][]byte) bool {
	for _, entry := range list {
		if bytes.Equal(entry, id) {
			return true
		}
	}
	return false
}

func directOctetString(container *bertlv.TLV) []byte {
	if container == nil {
		return nil
	}
	for _, child := range container.Children {
		if child.Tag.Equal(tagOctetString) {
			return cloneBytes(child.Value)
		}
	}
	return nil
}

func replaceDirectChildren(container *bertlv.TLV, dropTransaction bool, ciPrefix []byte) {
	children := make([]*bertlv.TLV, 0, len(container.Children))
	replaced := false
	for _, child := range container.Children {
		if dropTransaction && child.Tag.Equal(bertlv.ContextSpecific.Primitive(0)) {
			continue
		}
		if ciPrefix != nil && !replaced && child.Tag.Equal(tagOctetString) {
			children = append(children, bertlv.NewValue(tagOctetString, ciPrefix))
			replaced = true
			continue
		}
		children = append(children, child)
	}
	container.Children = children
}

func esipaSuccessContainer(root *bertlv.TLV) (*bertlv.TLV, bool) {
	if root == nil {
		return nil, false
	}
	if len(root.Children) == 1 && root.Children[0].Tag.Equal(tagInteger) {
		return nil, false
	}
	if root.First(bertlv.ContextSpecific.Primitive(1)) != nil || root.First(bertlv.ContextSpecific.Constructed(1)) != nil {
		return nil, false
	}
	if child := root.First(bertlv.ContextSpecific.Constructed(0)); child != nil {
		return child, true
	}
	return root, true
}

func finishAuthenticateClient(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	relayService *relay.Relay,
	logger *slog.Logger,
	request, payload []byte,
) (Response, error) {
	root, err := parseRelayTLV(payload)
	if err != nil {
		return Response{}, err
	}
	container, ok := esipaSuccessContainer(root)
	if !ok {
		return relayResponse(payload)
	}
	state, session, haveState := sessionEUICCState(ctx, store, tenantID, relayService, relayTransactionID(request))
	minimize := haveState && ipaFeatureSet(state.IPACapabilities, ipaFeatureMinimizeEsipaBytes)
	verify := haveState && ipaFeatureSet(state.IPACapabilities, ipaFeatureEimProfileMetadataVerification)
	changed := false
	if verify {
		if meta := container.First(tagProfileMetadata); meta != nil {
			profiles, err := store.ListProfileStates(ctx, tenantID, session.EID)
			if err != nil {
				return Response{}, err
			}
			if err := verifyProfileMetadata(meta, state.RulesAuthorisationTable, profiles); err != nil {
				logProfileMetadataRejected(logger, session.EID, err)
				return functionErrorResponse(tagAuthenticate, authenticateClientErrorPPRNotAllowed)
			}
			dropChild(container, tagProfileMetadata)
			changed = true
		}
	}
	if minimize && container.First(tagSignature) != nil {
		dropChild(container, bertlv.ContextSpecific.Primitive(0))
		changed = true
	}
	if !changed {
		return relayResponse(payload)
	}
	raw, err := root.MarshalBinary()
	if err != nil {
		return Response{}, err
	}
	return relayResponse(raw)
}

func finishGetBoundProfilePackage(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	relayService *relay.Relay,
	logger *slog.Logger,
	request, payload []byte,
) (Response, error) {
	root, err := parseRelayTLV(payload)
	if err != nil {
		return Response{}, err
	}
	container, ok := esipaSuccessContainer(root)
	if !ok {
		return relayResponse(payload)
	}
	state, session, haveState := sessionEUICCState(ctx, store, tenantID, relayService, relayTransactionID(request))
	if !haveState {
		return relayResponse(payload)
	}
	if ipaFeatureSet(state.IPACapabilities, ipaFeatureEimProfileMetadataVerification) && len(session.ProfileMetadata) > 0 {
		got, err := storeMetadataFromBoundPackage(container)
		if err != nil || !bytes.Equal(got, session.ProfileMetadata) {
			if err == nil {
				err = errMetadataChanged
			}
			logProfileMetadataRejected(logger, session.EID, err)
			return functionErrorResponse(tagGetBoundPackage, getBoundPackageErrorMetadataMismatch)
		}
	}
	if ipaFeatureSet(state.IPACapabilities, ipaFeatureMinimizeEsipaBytes) {
		dropChild(container, bertlv.ContextSpecific.Primitive(0))
		raw, err := root.MarshalBinary()
		if err != nil {
			return Response{}, err
		}
		return relayResponse(raw)
	}
	return relayResponse(payload)
}

func sessionEUICCState(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	relayService *relay.Relay,
	transactionID []byte,
) (storage.EUICCState, relay.DownloadContext, bool) {
	if relayService == nil || store == nil || len(transactionID) == 0 {
		return storage.EUICCState{}, relay.DownloadContext{}, false
	}
	session, ok := relayService.DownloadContext(transactionID)
	if !ok || session.EID == "" {
		return storage.EUICCState{}, session, false
	}
	state, err := store.GetEUICCState(ctx, tenantID, session.EID)
	if err != nil {
		return storage.EUICCState{}, session, false
	}
	return state, session, true
}

func relayTransactionID(payload []byte) []byte {
	root, err := parseRelayTLV(payload)
	if err != nil {
		return nil
	}
	if child := root.First(bertlv.ContextSpecific.Primitive(0)); child != nil && len(child.Value) > 0 {
		return cloneBytes(child.Value)
	}
	return nil
}

func dropChild(container *bertlv.TLV, tag bertlv.Tag) {
	if container == nil {
		return
	}
	children := make([]*bertlv.TLV, 0, len(container.Children))
	for _, child := range container.Children {
		if child.Tag.Equal(tag) {
			continue
		}
		children = append(children, child)
	}
	container.Children = children
}

func storeMetadataFromBoundPackage(container *bertlv.TLV) ([]byte, error) {
	bpp := container.First(tagBoundPackage)
	if bpp == nil {
		return nil, errMetadataChanged
	}
	var payload []byte
	var walk func(*bertlv.TLV)
	walk = func(tlv *bertlv.TLV) {
		if tlv == nil {
			return
		}
		if tlv.Tag.Equal(tagSegment88) {
			if len(tlv.Value) > scp03tMACLen {
				payload = append(payload, tlv.Value[:len(tlv.Value)-scp03tMACLen]...)
			}
			return
		}
		for _, child := range tlv.Children {
			walk(child)
		}
	}
	walk(bpp)
	if len(payload) == 0 {
		return nil, errMetadataChanged
	}
	meta, err := parseRelayTLV(payload)
	if err != nil || !meta.Tag.Equal(tagProfileMetadata) {
		return nil, errMetadataChanged
	}
	return payload, nil
}

func logProfileMetadataRejected(logger *slog.Logger, eid string, err error) {
	if logger == nil {
		logger = slog.Default()
	}
	if err == nil {
		err = errMetadataChanged
	}
	logger.Warn("profile metadata rejected", "eid", eid, "reason", err.Error())
}

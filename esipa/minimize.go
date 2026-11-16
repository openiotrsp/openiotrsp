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
//
// serverSigned1, serverSignature1, and serverCertificate are copied from
// payload. BF39 and its A0 success SEQUENCE are the only lengths rewritten.
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
	raw, err := editSuccessPayload(payload, successEdit{
		dropTransaction: true,
		replaceCIPK:     true,
		cipk:            prefix,
	})
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
	dropMetadata := false
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
			dropMetadata = true
		}
	}
	dropTransaction := minimize && container.First(tagSignature) != nil
	if !dropMetadata && !dropTransaction {
		return relayResponse(payload)
	}
	raw, err := editSuccessPayload(payload, successEdit{
		dropTransaction: dropTransaction,
		dropMetadata:    dropMetadata,
	})
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
		raw, err := editSuccessPayload(payload, successEdit{dropTransaction: true})
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

// successEdit is a byte-level change to the direct children of an ESipa
// success SEQUENCE. Fields that are not listed are copied unchanged.
type successEdit struct {
	dropTransaction bool
	dropMetadata    bool
	// replaceCIPK replaces the first universal OCTET STRING. An empty cipk
	// is the SGP.32 zero-length identifier, so the flag is separate from the
	// value.
	replaceCIPK bool
	cipk        []byte
}

// rawTLV is one definite BER element. raw is the original tag, length, and
// content; value is the content only.
type rawTLV struct {
	tag   bertlv.Tag
	raw   []byte
	value []byte
}

// editSuccessPayload applies edit to the original SM-DP+ bytes.
//
// SGP.22 signs and MACs serverSigned1, smdpSigned2, and BoundProfilePackage
// over the encoding the SM-DP+ sent. BER length octets are not unique, so
// rebuilding those elements with shortest lengths produces a different value.
// The function tag (BF39, BF3B, or BF3A) and, when present, its A0 success
// SEQUENCE are the only elements that receive new length octets, and only
// when a direct field was removed or replaced. An unchanged payload is returned
// as the caller passed it.
func editSuccessPayload(payload []byte, edit successEdit) ([]byte, error) {
	root, n, err := readRawTLV(payload)
	if err != nil {
		return nil, err
	}
	if n != len(payload) {
		return nil, errors.New("esipa: trailing data after BER-TLV payload")
	}
	children, err := readRawTLVs(root.value)
	if err != nil {
		return nil, err
	}
	container := -1
	for i, child := range children {
		if child.tag.Equal(bertlv.ContextSpecific.Constructed(0)) {
			container = i
			break
		}
	}
	if container >= 0 {
		inner, err := readRawTLVs(children[container].value)
		if err != nil {
			return nil, err
		}
		rewritten, changed, err := rewriteSuccessChildren(inner, edit)
		if err != nil || !changed {
			return payload, err
		}
		encoded, err := encodeTLV(children[container].tag, concatRaw(rewritten))
		if err != nil {
			return nil, err
		}
		children[container].raw = encoded
		return encodeTLV(root.tag, concatRaw(children))
	}
	rewritten, changed, err := rewriteSuccessChildren(children, edit)
	if err != nil || !changed {
		return payload, err
	}
	return encodeTLV(root.tag, concatRaw(rewritten))
}

func rewriteSuccessChildren(children []rawTLV, edit successEdit) ([]rawTLV, bool, error) {
	out := make([]rawTLV, 0, len(children))
	changed := false
	replaced := false
	transaction := bertlv.ContextSpecific.Primitive(0)
	for _, child := range children {
		if edit.dropTransaction && child.tag.Equal(transaction) {
			changed = true
			continue
		}
		if edit.dropMetadata && child.tag.Equal(tagProfileMetadata) {
			changed = true
			continue
		}
		if edit.replaceCIPK && !replaced && child.tag.Equal(tagOctetString) {
			encoded, err := encodeTLV(tagOctetString, edit.cipk)
			if err != nil {
				return nil, false, err
			}
			if !bytes.Equal(encoded, child.raw) {
				changed = true
			}
			out = append(out, rawTLV{tag: tagOctetString, raw: encoded, value: edit.cipk})
			replaced = true
			continue
		}
		out = append(out, child)
	}
	if edit.replaceCIPK && !replaced {
		return nil, false, errCIPKNotUnique
	}
	return out, changed, nil
}

func readRawTLVs(data []byte) ([]rawTLV, error) {
	var out []rawTLV
	for len(data) > 0 {
		element, n, err := readRawTLV(data)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, errors.New("esipa: empty BER-TLV")
		}
		out = append(out, element)
		data = data[n:]
	}
	return out, nil
}

func readRawTLV(data []byte) (rawTLV, int, error) {
	if len(data) == 0 {
		return rawTLV{}, 0, errors.New("esipa: empty BER-TLV")
	}
	var tag bertlv.Tag
	tagN, err := tag.ReadFrom(bytes.NewReader(data))
	if err != nil {
		return rawTLV{}, 0, err
	}
	length, lenN, err := readBERLength(data[tagN:])
	if err != nil {
		return rawTLV{}, 0, err
	}
	header := int(tagN) + lenN
	total := header + length
	if length < 0 || total < header || total > len(data) {
		return rawTLV{}, 0, errors.New("esipa: BER-TLV length exceeds input")
	}
	tagCopy := make(bertlv.Tag, len(tag))
	copy(tagCopy, tag)
	return rawTLV{
		tag:   tagCopy,
		raw:   data[:total:total],
		value: data[header:total:total],
	}, total, nil
}

func readBERLength(data []byte) (length, n int, err error) {
	if len(data) == 0 {
		return 0, 0, errors.New("esipa: missing BER length")
	}
	switch data[0] {
	case 0x81:
		if len(data) < 2 {
			return 0, 0, errors.New("esipa: truncated BER length")
		}
		return int(data[1]), 2, nil
	case 0x82:
		if len(data) < 3 {
			return 0, 0, errors.New("esipa: truncated BER length")
		}
		return int(data[1])<<8 | int(data[2]), 3, nil
	case 0x83:
		if len(data) < 4 {
			return 0, 0, errors.New("esipa: truncated BER length")
		}
		return int(data[1])<<16 | int(data[2])<<8 | int(data[3]), 4, nil
	default:
		if data[0] >= 0x80 {
			return 0, 0, errors.New("esipa: unsupported BER length")
		}
		return int(data[0]), 1, nil
	}
}

func encodeTLV(tag bertlv.Tag, content []byte) ([]byte, error) {
	if len(content) > 0xffffff {
		return nil, errors.New("esipa: BER-TLV length exceeds 3-byte limit")
	}
	length := definiteLength(len(content))
	out := make([]byte, 0, len(tag)+len(length)+len(content))
	out = append(out, tag...)
	out = append(out, length...)
	return append(out, content...), nil
}

func definiteLength(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	case n < 0x10000:
		return []byte{0x82, byte(n >> 8), byte(n)}
	default:
		return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func concatRaw(children []rawTLV) []byte {
	n := 0
	for _, child := range children {
		n += len(child.raw)
	}
	out := make([]byte, 0, n)
	for _, child := range children {
		out = append(out, child.raw...)
	}
	return out
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

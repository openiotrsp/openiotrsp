package esipa

import (
	"encoding/asn1"
	"errors"
	"log/slog"

	"github.com/damonto/euicc-go/bertlv"
	"github.com/openiotrsp/openiotrsp/profiledownload"
	"github.com/openiotrsp/openiotrsp/relay"
	"github.com/openiotrsp/openiotrsp/storage"
)

// SGP.32 IpaCapabilities.ipaFeatures bit positions.
const (
	ipaFeatureEimDownloadDataHandling = 2
	ipaFeatureEimCtxParams1Generation = 3
)

var (
	tagUTF8String       = bertlv.Universal.Primitive(12)
	tagCtxParams1Field  = bertlv.ContextSpecific.Constructed(2)
	tagCtxParams1Choice = bertlv.ContextSpecific.Constructed(0)
	tagDeviceInfoField  = bertlv.ContextSpecific.Constructed(9)
	tagDeviceInfoInCtx  = bertlv.ContextSpecific.Constructed(1)
	tagServerChallenge  = bertlv.ContextSpecific.Primitive(4)

	errCtxParams1NeedsDeviceInfo = errors.New("esipa: ctxParams1 required but deviceInfo is missing")
)

// augmentInitiateAuthentication appends matchingId and ctxParams1 to a
// successful SM-DP+ BF39 when the IPA asked the eIM to supply them.
// The returned payload is the original bytes when nothing is appended.
func augmentInitiateAuthentication(
	payload []byte,
	state storage.EUICCState,
	activation profiledownload.ActivationCode,
	logger *slog.Logger,
) ([]byte, relay.DownloadContext, error) {
	download, err := downloadContextFromInitiateAuth(payload, state.EID, activation)
	if err != nil {
		return nil, relay.DownloadContext{}, err
	}
	if isInitiateAuthErrorPayload(payload) {
		return payload, download, nil
	}
	downloadData := ipaFeatureSet(state.IPACapabilities, ipaFeatureEimDownloadDataHandling)
	ctxParams := ipaFeatureSet(state.IPACapabilities, ipaFeatureEimCtxParams1Generation)
	if !downloadData && !ctxParams {
		return payload, download, nil
	}

	var extra []*bertlv.TLV
	if downloadData && activation.MatchingID != "" {
		extra = append(extra, bertlv.NewValue(tagUTF8String, []byte(activation.MatchingID)))
	}
	if ctxParams {
		field, choice, err := buildCtxParams1(activation.MatchingID, state.DeviceInfo)
		if err != nil {
			logCtxParamsRejected(logger, state.EID, err)
			return nil, relay.DownloadContext{}, err
		}
		extra = append(extra, field)
		download.CtxParams1 = choice
	}
	if len(extra) == 0 {
		return payload, download, nil
	}
	augmented, err := appendInitiateAuthOK(payload, extra)
	if err != nil {
		return nil, relay.DownloadContext{}, err
	}
	return augmented, download, nil
}

func downloadContextFromInitiateAuth(payload []byte, eid string, activation profiledownload.ActivationCode) (relay.DownloadContext, error) {
	out := relay.DownloadContext{EID: eid}
	if isInitiateAuthErrorPayload(payload) {
		return out, nil
	}
	ok, err := parseInitiateAuthOK(payload)
	if err != nil {
		return relay.DownloadContext{}, err
	}
	signed1 := ok.First(tagInitAuthOKSeq)
	if signed1 == nil {
		return out, nil
	}
	if child := signed1.First(bertlv.ContextSpecific.Primitive(0)); child != nil {
		out.TransactionID = cloneBytes(child.Value)
	}
	if child := signed1.First(tagServerAddress); child != nil {
		out.ServerAddress = cloneBytes(child.Value)
	}
	if child := signed1.First(tagServerChallenge); child != nil {
		out.ServerChallenge = cloneBytes(child.Value)
	}
	out.SMDPOID = oidContent(activation.OID)
	return out, nil
}

func buildCtxParams1(matchingID string, deviceInfo []byte) (field *bertlv.TLV, choice []byte, err error) {
	device, err := deviceInfoForCtx(deviceInfo)
	if err != nil {
		return nil, nil, err
	}
	var children []*bertlv.TLV
	if matchingID != "" {
		children = append(children, bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), []byte(matchingID)))
	}
	children = append(children, device)
	inner := bertlv.NewChildren(tagCtxParams1Choice, children...)
	raw, err := inner.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return bertlv.NewChildren(tagCtxParams1Field, inner), raw, nil
}

// deviceInfoForCtx retags IpaEuiccData deviceInfo [9] as CtxParams1 deviceInfo [1].
// Both tags are IMPLICIT on the DeviceInfo SEQUENCE, so the contents stay put.
func deviceInfoForCtx(raw []byte) (*bertlv.TLV, error) {
	if len(raw) == 0 {
		return nil, errCtxParams1NeedsDeviceInfo
	}
	tlv, err := parseRelayTLV(raw)
	if err != nil {
		return nil, errCtxParams1NeedsDeviceInfo
	}
	if !tlv.Tag.Equal(tagDeviceInfoField) {
		return nil, errCtxParams1NeedsDeviceInfo
	}
	children := make([]*bertlv.TLV, 0, len(tlv.Children))
	for _, child := range tlv.Children {
		if child != nil {
			children = append(children, child.Clone())
		}
	}
	return bertlv.NewChildren(tagDeviceInfoInCtx, children...), nil
}

func appendInitiateAuthOK(payload []byte, extra []*bertlv.TLV) ([]byte, error) {
	root, err := parseRelayTLV(payload)
	if err != nil {
		return nil, err
	}
	container := root
	if child := root.First(bertlv.ContextSpecific.Constructed(0)); child != nil {
		container = child
	}
	container.Children = append(container.Children, extra...)
	return root.MarshalBinary()
}

func ipaFeatureSet(raw []byte, bit int) bool {
	if len(raw) == 0 || bit < 0 {
		return false
	}
	tlv, err := parseRelayTLV(raw)
	if err != nil {
		return false
	}
	features := tlv.First(bertlv.ContextSpecific.Primitive(0))
	if features == nil || len(features.Value) < 2 {
		return false
	}
	unused := int(features.Value[0])
	if unused > 7 {
		return false
	}
	width := (len(features.Value)-1)*8 - unused
	if bit >= width {
		return false
	}
	return features.Value[1+bit/8]&(1<<uint(7-bit%8)) != 0
}

func oidContent(dotted string) []byte {
	oid, err := parseDottedOID(dotted)
	if err != nil || len(oid) == 0 {
		return nil
	}
	encoded, err := asn1.Marshal(oid)
	if err != nil {
		return nil
	}
	tlv, err := parseRelayTLV(encoded)
	if err != nil || len(tlv.Value) == 0 {
		return nil
	}
	return cloneBytes(tlv.Value)
}

func logCtxParamsRejected(logger *slog.Logger, eid string, err error) {
	if logger == nil {
		logger = slog.Default()
	}
	logger.Warn("initiateAuthentication rejected", "eid", eid, "reason", err.Error())
}

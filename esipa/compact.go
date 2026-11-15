package esipa

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/damonto/euicc-go/bertlv"
	"github.com/damonto/euicc-go/bertlv/primitive"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/relay"
	"github.com/openiotrsp/openiotrsp/storage"
)

// errCompactUnavailable means a compact ESipa payload cannot be rebuilt into
// the SGP.22 structure the SM-DP+ verifies. Callers answer with undefinedError.
var errCompactUnavailable = errors.New("esipa: compact ESipa data unavailable")

var (
	tagAuthenticateServer = bertlv.ContextSpecific.Constructed(56)
	tagPrepareDownload    = bertlv.ContextSpecific.Constructed(33)
	tagProfileInstall     = bertlv.ContextSpecific.Constructed(55)
	tagInstallData        = bertlv.ContextSpecific.Constructed(39)
	tagEUICCInfo2         = bertlv.ContextSpecific.Constructed(34)
	tagExtCardResource    = bertlv.ContextSpecific.Primitive(4)
	tagProfileMetadata    = bertlv.ContextSpecific.Constructed(37)
	tagEUICCOTPK          = bertlv.Application.Primitive(73)
	tagISDPAID            = bertlv.Application.Primitive(15)
	tagSignature          = bertlv.Application.Primitive(55)
	tagOctetString        = bertlv.Universal.Primitive(4)
	tagObjectID           = bertlv.Universal.Primitive(6)
	tagBoolean            = bertlv.Universal.Primitive(1)
	tagCompactOK          = bertlv.ContextSpecific.Constructed(2)
	tagCompactSigned1     = bertlv.ContextSpecific.Constructed(0)

	// defaultSimaResponse is the success EUICCResponse compact form omits.
	// SGP.32 CompactSuccessResult: 30 07 A0 05 30 03 80 01 00.
	defaultSimaResponse = []byte{0x30, 0x07, 0xa0, 0x05, 0x30, 0x03, 0x80, 0x01, 0x00}
)

func compactError(reason string) error {
	return fmt.Errorf("%w: %s", errCompactUnavailable, reason)
}

func logCompactRejected(logger *slog.Logger, tlv *bertlv.TLV, err error) {
	if logger == nil {
		logger = slog.Default()
	}
	tag := ""
	if tlv != nil {
		tag = tlv.Tag.String()
	}
	logger.Warn("compact ESipa expansion rejected", "tag", tag, "reason", err.Error())
}

func functionErrorResponse(tag bertlv.Tag, code int64) (Response, error) {
	child, err := bertlv.MarshalValue(tagInteger, primitive.MarshalInt(code))
	if err != nil {
		return Response{}, err
	}
	tlv := bertlv.NewChildren(tag, child)
	raw, err := tlv.MarshalBinary()
	if err != nil {
		return Response{}, err
	}
	return Response{
		Message: protocolasn1.ESipaMessageFromEimToIpa{Raw: tlv},
		Raw:     raw,
	}, nil
}

func expandCompactAuthenticateClient(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	relayService *relay.Relay,
	payload []byte,
) ([]byte, error) {
	root, err := parseRelayTLV(payload)
	if err != nil || !root.Tag.Equal(tagAuthenticate) {
		return payload, err
	}
	server := root.First(tagAuthenticateServer)
	if server == nil {
		return payload, nil
	}
	compact := server.First(tagCompactOK)
	if compact == nil {
		return payload, nil
	}
	rebuilt, err := rebuildAuthenticateServer(ctx, store, tenantID, relayService, root, compact)
	if err != nil {
		return nil, err
	}
	return rebuilt, nil
}

func rebuildAuthenticateServer(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	relayService *relay.Relay,
	root *bertlv.TLV,
	compact *bertlv.TLV,
) ([]byte, error) {
	txNode := root.First(bertlv.ContextSpecific.Primitive(0))
	if txNode == nil || len(txNode.Value) == 0 {
		return nil, compactError("authenticateClient missing transactionId")
	}
	if relayService == nil {
		return nil, compactError("no download session")
	}
	session, ok := relayService.DownloadContext(txNode.Value)
	if !ok {
		return nil, compactError("no download session for transactionId")
	}
	if len(session.ServerAddress) == 0 || len(session.ServerChallenge) == 0 || len(session.TransactionID) == 0 {
		return nil, compactError("download session missing serverSigned1 fields")
	}
	signature := compact.First(tagSignature)
	if signature == nil {
		return nil, compactError("compact authenticate response missing euiccSignature1")
	}

	var state storage.EUICCState
	if store != nil && session.EID != "" {
		loaded, err := store.GetEUICCState(ctx, tenantID, session.EID)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			return nil, err
		}
		if err == nil {
			state = loaded
		}
	}

	signed1, err := euiccSigned1FromCompact(compact, session, state.EUICCInfo2)
	if err != nil {
		return nil, err
	}
	euiccCert, err := certificateTLV(compact.First(bertlv.ContextSpecific.Constructed(1)), state.EUICCCertificate)
	if err != nil {
		return nil, err
	}
	eumCert, err := certificateTLV(compact.First(tagCompactOK), state.EUMCertificate)
	if err != nil {
		return nil, err
	}
	bf38 := bertlv.NewChildren(tagAuthenticateServer,
		bertlv.NewChildren(tagCompactSigned1,
			signed1,
			bertlv.NewValue(tagSignature, cloneBytes(signature.Value)),
			euiccCert,
			eumCert,
		),
	)
	children := make([]*bertlv.TLV, 0, len(root.Children))
	replaced := false
	for _, child := range root.Children {
		if child.Tag.Equal(tagAuthenticateServer) {
			children = append(children, bf38)
			replaced = true
			continue
		}
		children = append(children, child.Clone())
	}
	if !replaced {
		return nil, compactError("authenticateClient missing authenticateServerResponse")
	}
	return bertlv.NewChildren(tagAuthenticate, children...).MarshalBinary()
}

func euiccSigned1FromCompact(compact *bertlv.TLV, session relay.DownloadContext, storedInfo2 []byte) (*bertlv.TLV, error) {
	if full := compact.First(tagSequence); full != nil && compact.First(tagCompactSigned1) == nil {
		return full.Clone(), nil
	}
	compactSigned := compact.First(tagCompactSigned1)
	if compactSigned == nil {
		return nil, compactError("compact authenticate response missing signedData")
	}
	ext := compactSigned.First(tagExtCardResource)
	if ext == nil {
		return nil, compactError("compactEuiccSigned1 missing extCardResource")
	}
	if len(storedInfo2) == 0 {
		return nil, compactError("stored EUICCInfo2 is missing")
	}
	info2, err := parseRelayTLV(storedInfo2)
	if err != nil {
		return nil, err
	}
	if !info2.Tag.Equal(tagEUICCInfo2) {
		return nil, compactError("stored EUICCInfo2 tag is not BF22")
	}
	replaced, err := replaceExtCardResource(info2, ext)
	if err != nil {
		return nil, err
	}
	ctxBytes := session.CtxParams1
	if field := compactSigned.First(tagCompactOK); field != nil {
		choice := field
		if inner := field.First(tagCompactSigned1); inner != nil {
			choice = inner
		}
		raw, err := choice.MarshalBinary()
		if err != nil {
			return nil, err
		}
		ctxBytes = raw
	}
	if len(ctxBytes) == 0 {
		return nil, compactError("ctxParams1 missing from IPA and eIM")
	}
	ctxParams, err := parseRelayTLV(ctxBytes)
	if err != nil {
		return nil, err
	}
	return bertlv.NewChildren(tagSequence,
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), cloneBytes(session.TransactionID)),
		bertlv.NewValue(tagServerAddress, cloneBytes(session.ServerAddress)),
		bertlv.NewValue(tagServerChallenge, cloneBytes(session.ServerChallenge)),
		replaced,
		ctxParams,
	), nil
}

func replaceExtCardResource(info2, ext *bertlv.TLV) (*bertlv.TLV, error) {
	children := make([]*bertlv.TLV, 0, len(info2.Children))
	found := false
	for _, child := range info2.Children {
		if child.Tag.Equal(tagExtCardResource) {
			children = append(children, ext.Clone())
			found = true
			continue
		}
		children = append(children, child.Clone())
	}
	if !found {
		return nil, compactError("stored EUICCInfo2 missing extCardResource")
	}
	return bertlv.NewChildren(info2.Tag, children...), nil
}

func certificateTLV(fromCompact *bertlv.TLV, stored []byte) (*bertlv.TLV, error) {
	if fromCompact != nil {
		return certificateFromWrapper(fromCompact)
	}
	if len(stored) == 0 {
		return nil, compactError("eUICC or EUM certificate is missing")
	}
	wrapper, err := parseRelayTLV(stored)
	if err != nil {
		return nil, err
	}
	return certificateFromWrapper(wrapper)
}

func certificateFromWrapper(wrapper *bertlv.TLV) (*bertlv.TLV, error) {
	der, err := protocolasn1.CertificateDERFromTagged(wrapper)
	if err != nil {
		return nil, compactError("certificate encoding")
	}
	cert, err := parseRelayTLV(der)
	if err != nil {
		return nil, err
	}
	if !cert.Tag.Equal(tagSequence) {
		return nil, compactError("certificate is not a SEQUENCE")
	}
	return cert, nil
}

func expandCompactPrepareDownload(relayService *relay.Relay, payload []byte) ([]byte, error) {
	root, err := parseRelayTLV(payload)
	if err != nil || !root.Tag.Equal(tagGetBoundPackage) {
		return payload, err
	}
	prepare := root.First(tagPrepareDownload)
	if prepare == nil {
		return payload, nil
	}
	compact := prepare.First(tagCompactOK)
	if compact == nil {
		return payload, nil
	}
	txNode := root.First(bertlv.ContextSpecific.Primitive(0))
	if txNode == nil || len(txNode.Value) == 0 {
		return nil, compactError("getBoundProfilePackage missing transactionId")
	}
	signature := compact.First(tagSignature)
	if signature == nil {
		return nil, compactError("compact prepareDownload missing euiccSignature2")
	}
	body := compact.First(tagSequence)
	if body == nil {
		body = compact
	}
	var otpk, hashCC []byte
	if child := body.First(tagEUICCOTPK); child != nil {
		otpk = cloneBytes(child.Value)
	}
	if child := body.First(tagOctetString); child != nil {
		hashCC = cloneBytes(child.Value)
	}
	if relayService != nil {
		if session, ok := relayService.DownloadContext(txNode.Value); ok {
			if len(otpk) == 0 {
				otpk = session.EUICCOTPK
			}
			if len(hashCC) == 0 {
				hashCC = session.HashCC
			}
		}
	}
	if len(otpk) == 0 {
		return nil, compactError("compact prepareDownload missing euiccOtpk")
	}
	children := []*bertlv.TLV{
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), cloneBytes(txNode.Value)),
		bertlv.NewValue(tagEUICCOTPK, otpk),
	}
	if len(hashCC) > 0 {
		children = append(children, bertlv.NewValue(tagOctetString, hashCC))
	}
	signed2 := bertlv.NewChildren(tagSequence, children...)
	bf21 := bertlv.NewChildren(tagPrepareDownload,
		bertlv.NewChildren(tagCompactSigned1,
			signed2,
			bertlv.NewValue(tagSignature, cloneBytes(signature.Value)),
		),
	)
	out := make([]*bertlv.TLV, 0, len(root.Children))
	for _, child := range root.Children {
		if child.Tag.Equal(tagPrepareDownload) {
			out = append(out, bf21)
			continue
		}
		out = append(out, child.Clone())
	}
	return bertlv.NewChildren(tagGetBoundPackage, out...).MarshalBinary()
}

func expandCompactNotification(relayService *relay.Relay, payload []byte) ([]byte, error) {
	root, err := parseRelayTLV(payload)
	if err != nil || !root.Tag.Equal(tagHandleNotify) {
		return payload, err
	}
	compact := findCompactProfileInstallation(root)
	if compact == nil {
		return payload, nil
	}
	rebuilt, err := rebuildProfileInstallationResult(relayService, compact)
	if err != nil {
		return nil, err
	}
	return bertlv.NewChildren(tagHandleNotify, rebuilt).MarshalBinary()
}

func findCompactProfileInstallation(tlv *bertlv.TLV) *bertlv.TLV {
	if tlv == nil {
		return nil
	}
	if isCompactProfileInstallation(tlv) {
		return tlv
	}
	for _, child := range tlv.Children {
		if found := findCompactProfileInstallation(child); found != nil {
			return found
		}
	}
	return nil
}

func isCompactProfileInstallation(tlv *bertlv.TLV) bool {
	if tlv == nil || !tlv.Tag.Equal(tagCompactSigned1) {
		return false
	}
	data := tlv.First(tagCompactSigned1)
	signature := tlv.First(tagSignature)
	if data == nil || signature == nil {
		return false
	}
	return data.First(bertlv.ContextSpecific.Primitive(0)) != nil &&
		data.First(tagInteger) != nil &&
		data.First(tagCompactOK) != nil
}

func rebuildProfileInstallationResult(relayService *relay.Relay, compact *bertlv.TLV) (*bertlv.TLV, error) {
	data := compact.First(tagCompactSigned1)
	signature := compact.First(tagSignature)
	if data == nil || signature == nil {
		return nil, compactError("compact profile installation result is incomplete")
	}
	txNode := data.First(bertlv.ContextSpecific.Primitive(0))
	if txNode == nil || len(txNode.Value) == 0 {
		return nil, compactError("compact profile installation result missing transactionId")
	}
	if relayService == nil {
		return nil, compactError("no download session")
	}
	session, ok := relayService.DownloadContext(txNode.Value)
	if !ok {
		return nil, compactError("no download session for profile installation result")
	}
	if len(session.ServerAddress) == 0 {
		return nil, compactError("download session missing notification address")
	}
	seqNode := data.First(tagInteger)
	var seq int64
	if err := seqNode.UnmarshalValue(primitive.UnmarshalInt(&seq)); err != nil {
		return nil, compactError("compact profile installation result has a bad seqNumber")
	}
	iccidPresent := true
	if flag := data.First(tagBoolean); flag != nil {
		if err := flag.UnmarshalValue(primitive.UnmarshalBool(&iccidPresent)); err != nil {
			return nil, compactError("compact profile installation result has a bad iccidPresent")
		}
	}
	final, err := expandCompactFinalResult(data.First(tagCompactOK), session)
	if err != nil {
		return nil, err
	}
	seqTLV, err := bertlv.MarshalValue(bertlv.ContextSpecific.Primitive(0), primitive.MarshalInt(seq))
	if err != nil {
		return nil, err
	}
	opTLV, err := bertlv.MarshalValue(bertlv.ContextSpecific.Primitive(1), primitive.MarshalBitString([]bool{true}))
	if err != nil {
		return nil, err
	}
	metaChildren := []*bertlv.TLV{
		seqTLV,
		opTLV,
		bertlv.NewValue(tagUTF8String, cloneBytes(session.ServerAddress)),
	}
	if iccidPresent {
		if len(session.ICCID) == 0 {
			return nil, compactError("compact profile installation result missing iccid")
		}
		metaChildren = append(metaChildren, bertlv.NewValue(tagEID, cloneBytes(session.ICCID)))
	}
	installChildren := []*bertlv.TLV{
		bertlv.NewValue(bertlv.ContextSpecific.Primitive(0), cloneBytes(txNode.Value)),
		bertlv.NewChildren(tagNotificationMeta, metaChildren...),
	}
	if len(session.SMDPOID) > 0 {
		installChildren = append(installChildren, bertlv.NewValue(tagObjectID, cloneBytes(session.SMDPOID)))
	}
	installChildren = append(installChildren, final)
	return bertlv.NewChildren(tagProfileInstall,
		bertlv.NewChildren(tagInstallData, installChildren...),
		bertlv.NewValue(tagSignature, cloneBytes(signature.Value)),
	), nil
}

func expandCompactFinalResult(final *bertlv.TLV, session relay.DownloadContext) (*bertlv.TLV, error) {
	if final == nil {
		return nil, compactError("compact profile installation result missing finalResult")
	}
	if final.First(bertlv.ContextSpecific.Constructed(1)) != nil && final.First(tagCompactSigned1) == nil {
		return final.Clone(), nil
	}
	success := final.First(tagCompactSigned1)
	if success == nil {
		return nil, compactError("compact profile installation result missing success result")
	}
	aidNode := success.First(tagISDPAID)
	if aidNode == nil || len(aidNode.Value) == 0 {
		return nil, compactError("compact success result missing aid")
	}
	aid := session.ISDPAID
	if len(aid) == 0 {
		return nil, compactError("download session missing ISD-P AID")
	}
	if len(aidNode.Value) == 2 {
		if len(aid) < 2 || !bytes.Equal(aid[len(aid)-2:], aidNode.Value) {
			return nil, compactError("compactAid does not match the stored ISD-P AID")
		}
	} else if !bytes.Equal(aid, aidNode.Value) {
		aid = cloneBytes(aidNode.Value)
	}
	sima := defaultSimaResponse
	if child := success.First(tagOctetString); child != nil && len(child.Value) > 0 {
		sima = cloneBytes(child.Value)
	}
	return bertlv.NewChildren(tagCompactOK,
		bertlv.NewChildren(tagCompactSigned1,
			bertlv.NewValue(tagISDPAID, cloneBytes(aid)),
			bertlv.NewValue(tagOctetString, sima),
		),
	), nil
}

func noteAuthenticateClientResponse(relayService *relay.Relay, payload []byte) {
	if relayService == nil || len(payload) == 0 {
		return
	}
	root, err := parseRelayTLV(payload)
	if err != nil || !root.Tag.Equal(tagAuthenticate) {
		return
	}
	ok := root.First(tagCompactSigned1)
	if ok == nil {
		ok = root
	}
	txNode := ok.First(bertlv.ContextSpecific.Primitive(0))
	if txNode == nil {
		txNode = root.First(bertlv.ContextSpecific.Primitive(0))
	}
	if txNode == nil || len(txNode.Value) == 0 {
		return
	}
	relayService.UpdateDownload(txNode.Value, func(ctx *relay.DownloadContext) {
		if meta := ok.First(tagProfileMetadata); meta != nil {
			if iccid := meta.First(tagEID); iccid != nil && len(iccid.Value) == 10 {
				ctx.ICCID = cloneBytes(iccid.Value)
			}
			if aid := meta.First(tagISDPAID); aid != nil && len(aid.Value) > 0 {
				ctx.ISDPAID = cloneBytes(aid.Value)
			}
		}
		for _, child := range ok.Children {
			if child.Tag.Equal(tagSequence) && child.First(bertlv.ContextSpecific.Primitive(0)) != nil {
				if otpk := child.First(tagEUICCOTPK); otpk != nil && len(otpk.Value) > 0 {
					ctx.EUICCOTPK = cloneBytes(otpk.Value)
				}
			}
		}
		if hash := ok.First(tagOctetString); hash != nil && len(hash.Value) == 32 {
			ctx.HashCC = cloneBytes(hash.Value)
		}
	})
}

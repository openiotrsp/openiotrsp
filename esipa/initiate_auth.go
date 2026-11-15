package esipa

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/damonto/euicc-go/bertlv"
	"github.com/damonto/euicc-go/bertlv/primitive"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/profiledownload"
	"github.com/openiotrsp/openiotrsp/relay"
	"github.com/openiotrsp/openiotrsp/storage"
)

// SGP.32 InitiateAuthenticationResponseEsipa error integers (tag BF39).
const (
	initiateAuthErrorSMDPAddressMismatch     int64 = 50
	initiateAuthErrorSMDPOIDMismatch         int64 = 51
	initiateAuthErrorInvalidEimTransactionID int64 = 52
	initiateAuthErrorUndefined               int64 = 127
)

var (
	tagInitAuthChallenge = bertlv.ContextSpecific.Primitive(1)
	tagInitAuthTxn       = bertlv.ContextSpecific.Primitive(2)
	tagInitAuthAddress   = bertlv.ContextSpecific.Primitive(3)
	tagInitAuthInfo1     = bertlv.ContextSpecific.Constructed(32)
	tagInitAuthOKSeq     = bertlv.Universal.Constructed(16)
	tagServerAddress     = bertlv.ContextSpecific.Primitive(3)
	tagInteger           = bertlv.Universal.Primitive(2)

	oidOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}
)

type initiateAuthFields struct {
	challenge      []byte
	smdpAddress    string
	euiccInfo1     *bertlv.TLV
	transactionID  []byte
	hasAddress     bool
	hasInfo1       bool
	hasTransaction bool
}

type initiateAuthSession struct {
	activation   profiledownload.ActivationCode
	checkAddress bool
	checkOID     bool
	eid          string
}

func handleInitiateAuthentication(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	payload []byte,
	relayService *relay.Relay,
	logger *slog.Logger,
) (Response, error) {
	fields, err := parseInitiateAuthRequest(payload)
	if err != nil {
		return Response{}, err
	}
	hadAddress := fields.hasAddress
	hadInfo1 := fields.hasInfo1
	session, errResp, err := resolveInitiateAuthSession(ctx, store, tenantID, &fields)
	if err != nil {
		return Response{}, err
	}
	if errResp != nil {
		return *errResp, nil
	}
	request := payload
	if !hadAddress || !hadInfo1 {
		request, err = buildInitiateAuthRequest(&fields)
		if err != nil {
			return Response{}, err
		}
	}
	relayed, err := relayService.InitiateAuthentication(ctx, request)
	if err != nil {
		return Response{}, err
	}
	if relayed.NoContent {
		return Response{}, nil
	}
	if errResp, err := checkInitiateAuthResponse(relayed.Payload, session); err != nil {
		return Response{}, err
	} else if errResp != nil {
		return *errResp, nil
	}
	return finishInitiateAuthentication(ctx, store, tenantID, relayService, logger, session, relayed.Payload)
}

func finishInitiateAuthentication(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	relayService *relay.Relay,
	logger *slog.Logger,
	session initiateAuthSession,
	payload []byte,
) (Response, error) {
	var state storage.EUICCState
	if session.eid != "" && store != nil {
		loaded, err := store.GetEUICCState(ctx, tenantID, session.eid)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			return Response{}, err
		}
		if err == nil {
			state = loaded
		}
	}
	state.EID = session.eid
	augmented, download, err := augmentInitiateAuthentication(payload, state, session.activation, logger)
	if errors.Is(err, errCtxParams1NeedsDeviceInfo) {
		return initiateAuthErrorResponse(initiateAuthErrorUndefined)
	}
	if err != nil {
		return Response{}, err
	}
	if relayService != nil && len(download.TransactionID) > 0 && session.eid != "" && !isInitiateAuthErrorPayload(payload) {
		relayService.RememberDownload(download)
	}
	return relayResponse(augmented)
}

func parseInitiateAuthRequest(payload []byte) (initiateAuthFields, error) {
	tlv, err := parseRelayTLV(payload)
	if err != nil {
		return initiateAuthFields{}, err
	}
	if !tlv.Tag.Equal(tagInitiateAuth) {
		return initiateAuthFields{}, fmt.Errorf("esipa: initiateAuthentication tag %s, want bf39", tlv.Tag)
	}
	var out initiateAuthFields
	if child := tlv.First(tagInitAuthChallenge); child != nil {
		out.challenge = cloneBytes(child.Value)
	}
	if child := tlv.First(tagInitAuthAddress); child != nil && len(child.Value) > 0 {
		out.smdpAddress = string(child.Value)
		out.hasAddress = true
	}
	if child := tlv.First(tagInitAuthInfo1); child != nil {
		out.euiccInfo1 = child.Clone()
		out.hasInfo1 = true
	}
	if child := tlv.First(tagInitAuthTxn); child != nil && len(child.Value) > 0 {
		out.transactionID = cloneBytes(child.Value)
		out.hasTransaction = true
	}
	if len(out.challenge) == 0 {
		return initiateAuthFields{}, errors.New("esipa: initiateAuthentication missing euiccChallenge")
	}
	return out, nil
}

func resolveInitiateAuthSession(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	fields *initiateAuthFields,
) (initiateAuthSession, *Response, error) {
	needsRestore := !fields.hasAddress || !fields.hasInfo1
	if !fields.hasTransaction {
		if needsRestore {
			resp, err := initiateAuthErrorResponse(initiateAuthErrorInvalidEimTransactionID)
			return initiateAuthSession{}, &resp, err
		}
		return initiateAuthSession{}, nil, nil
	}
	if store == nil {
		resp, err := initiateAuthErrorResponse(initiateAuthErrorInvalidEimTransactionID)
		return initiateAuthSession{}, &resp, err
	}
	operation, trigger, ok, err := pendingProfileDownloadTriggerByTransaction(ctx, store, tenantID, fields.transactionID)
	if err != nil {
		return initiateAuthSession{}, nil, err
	}
	if !ok {
		resp, err := initiateAuthErrorResponse(initiateAuthErrorInvalidEimTransactionID)
		return initiateAuthSession{}, &resp, err
	}
	session := initiateAuthSession{eid: operation.EID}
	if trigger.ProfileDownloadData != nil &&
		trigger.ProfileDownloadData.Kind == protocolasn1.ProfileDownloadActivationCode {
		activation, err := profiledownload.ParseActivationCode(trigger.ProfileDownloadData.ActivationCode)
		if err != nil {
			return initiateAuthSession{}, nil, err
		}
		session.activation = activation
		if activation.OID != "" {
			session.checkOID = true
		}
	}
	if !fields.hasAddress {
		if session.activation.SMDPAddress == "" {
			resp, err := initiateAuthErrorResponse(initiateAuthErrorUndefined)
			return initiateAuthSession{}, &resp, err
		}
		fields.smdpAddress = session.activation.SMDPAddress
		fields.hasAddress = true
		session.checkAddress = true
	}
	if !fields.hasInfo1 {
		state, err := store.GetEUICCState(ctx, tenantID, operation.EID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				resp, errResp := initiateAuthErrorResponse(initiateAuthErrorUndefined)
				return initiateAuthSession{}, &resp, errResp
			}
			return initiateAuthSession{}, nil, err
		}
		info1, err := euiccInfo1FromState(state.EUICCInfo1)
		if err != nil || info1 == nil {
			resp, errResp := initiateAuthErrorResponse(initiateAuthErrorUndefined)
			return initiateAuthSession{}, &resp, errResp
		}
		fields.euiccInfo1 = info1
		fields.hasInfo1 = true
	}
	return session, nil, nil
}

func pendingProfileDownloadTriggerByTransaction(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	transactionID []byte,
) (storage.Operation, protocolasn1.ProfileDownloadTriggerRequest, bool, error) {
	operations, err := store.ListPendingOperations(ctx, tenantID, 1000)
	if err != nil {
		return storage.Operation{}, protocolasn1.ProfileDownloadTriggerRequest{}, false, err
	}
	for _, operation := range operations {
		if operation.Kind != storage.OperationProfileDownloadTrigger {
			continue
		}
		match, err := OperationMatchesEimTransactionID(operation, transactionID)
		if err != nil {
			return storage.Operation{}, protocolasn1.ProfileDownloadTriggerRequest{}, false, err
		}
		if !match {
			continue
		}
		var request protocolasn1.ProfileDownloadTriggerRequest
		if err := protocolasn1.Decode(operation.Payload, &request); err != nil {
			return storage.Operation{}, protocolasn1.ProfileDownloadTriggerRequest{}, false, err
		}
		return operation, request, true, nil
	}
	return storage.Operation{}, protocolasn1.ProfileDownloadTriggerRequest{}, false, nil
}

func euiccInfo1FromState(raw []byte) (*bertlv.TLV, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	tlv, err := parseRelayTLV(raw)
	if err != nil {
		return nil, err
	}
	if !tlv.Tag.Equal(tagInitAuthInfo1) {
		return nil, fmt.Errorf("esipa: stored EUICCInfo1 tag %s, want bf20", tlv.Tag)
	}
	return tlv, nil
}

func buildInitiateAuthRequest(fields *initiateAuthFields) ([]byte, error) {
	children := []*bertlv.TLV{
		bertlv.NewValue(tagInitAuthChallenge, cloneBytes(fields.challenge)),
	}
	if fields.hasAddress {
		children = append(children, bertlv.NewValue(tagInitAuthAddress, []byte(fields.smdpAddress)))
	}
	if fields.hasInfo1 && fields.euiccInfo1 != nil {
		children = append(children, fields.euiccInfo1.Clone())
	}
	if fields.hasTransaction {
		children = append(children, bertlv.NewValue(tagInitAuthTxn, cloneBytes(fields.transactionID)))
	}
	tlv := bertlv.NewChildren(tagInitiateAuth, children...)
	return tlv.MarshalBinary()
}

func checkInitiateAuthResponse(payload []byte, session initiateAuthSession) (*Response, error) {
	if !session.checkAddress && !session.checkOID {
		return nil, nil
	}
	if isInitiateAuthErrorPayload(payload) {
		return nil, nil
	}
	ok, err := parseInitiateAuthOK(payload)
	if err != nil {
		return nil, err
	}
	if session.checkAddress {
		got := serverAddressFromSigned1(ok)
		if !strings.EqualFold(strings.TrimSpace(got), strings.TrimSpace(session.activation.SMDPAddress)) {
			resp, err := initiateAuthErrorResponse(initiateAuthErrorSMDPAddressMismatch)
			return &resp, err
		}
	}
	if session.checkOID {
		certOID, err := smdpOIDFromInitiateAuthOK(ok)
		if err != nil || !oidStringsEqual(certOID, session.activation.OID) {
			resp, errResp := initiateAuthErrorResponse(initiateAuthErrorSMDPOIDMismatch)
			return &resp, errResp
		}
	}
	return nil, nil
}

func isInitiateAuthErrorPayload(payload []byte) bool {
	tlv, err := parseRelayTLV(payload)
	if err != nil || !tlv.Tag.Equal(tagInitiateAuth) {
		return false
	}
	return len(tlv.Children) == 1 && tlv.Children[0].Tag.Equal(tagInteger)
}

func parseInitiateAuthOK(payload []byte) (*bertlv.TLV, error) {
	tlv, err := parseRelayTLV(payload)
	if err != nil {
		return nil, err
	}
	if !tlv.Tag.Equal(tagInitiateAuth) {
		return nil, fmt.Errorf("esipa: initiateAuthentication response tag %s, want bf39", tlv.Tag)
	}
	if child := tlv.First(bertlv.ContextSpecific.Constructed(0)); child != nil {
		return child, nil
	}
	return tlv, nil
}

func serverAddressFromSigned1(ok *bertlv.TLV) string {
	if ok == nil {
		return ""
	}
	signed1 := ok.First(tagInitAuthOKSeq)
	if signed1 == nil {
		signed1 = ok.First(bertlv.ContextSpecific.Constructed(1))
	}
	if signed1 == nil {
		return ""
	}
	child := signed1.First(tagServerAddress)
	if child == nil {
		return ""
	}
	return string(child.Value)
}

func smdpOIDFromInitiateAuthOK(ok *bertlv.TLV) (string, error) {
	if ok == nil {
		return "", errors.New("esipa: missing initiateAuthentication OK")
	}
	for _, child := range ok.Children {
		if der, err := protocolasn1.CertificateDERFromTagged(child); err == nil {
			return smdpOIDFromCertificateDER(der)
		}
		if child.Tag.Equal(tagInitAuthOKSeq) {
			if der, err := child.MarshalBinary(); err == nil {
				if oid, err := smdpOIDFromCertificateDER(der); err == nil {
					return oid, nil
				}
			}
		}
	}
	return "", errors.New("esipa: initiateAuthentication response missing serverCertificate")
}

func smdpOIDFromCertificateDER(der []byte) (string, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	names := make([]pkix.AttributeTypeAndValue, 0, len(cert.Subject.Names)+len(cert.Subject.ExtraNames))
	names = append(names, cert.Subject.Names...)
	names = append(names, cert.Subject.ExtraNames...)
	for _, atv := range names {
		if atv.Type.Equal(oidOrganizationIdentifier) {
			switch value := atv.Value.(type) {
			case string:
				if oid := strings.TrimSpace(value); oid != "" {
					return oid, nil
				}
			case []byte:
				var oid asn1.ObjectIdentifier
				if _, err := asn1.Unmarshal(value, &oid); err == nil && len(oid) > 0 {
					return oid.String(), nil
				}
			}
		}
		if oid, ok := atv.Value.(asn1.ObjectIdentifier); ok && len(oid) > 0 {
			return oid.String(), nil
		}
	}
	return "", errors.New("esipa: SM-DP+ certificate subject has no OID")
}

func oidStringsEqual(a, b string) bool {
	left, err := parseDottedOID(a)
	if err != nil {
		return strings.TrimSpace(a) == strings.TrimSpace(b)
	}
	right, err := parseDottedOID(b)
	if err != nil {
		return strings.TrimSpace(a) == strings.TrimSpace(b)
	}
	return left.Equal(right)
}

func parseDottedOID(value string) (asn1.ObjectIdentifier, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("empty OID")
	}
	parts := strings.Split(value, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, part := range parts {
		var arc int
		for _, c := range part {
			if c < '0' || c > '9' {
				return nil, fmt.Errorf("invalid OID arc %q", part)
			}
			arc = arc*10 + int(c-'0')
		}
		oid[i] = arc
	}
	return oid, nil
}

func initiateAuthErrorResponse(code int64) (Response, error) {
	child, err := bertlv.MarshalValue(tagInteger, primitive.MarshalInt(code))
	if err != nil {
		return Response{}, err
	}
	tlv := bertlv.NewChildren(tagInitiateAuth, child)
	raw, err := tlv.MarshalBinary()
	if err != nil {
		return Response{}, err
	}
	return Response{
		Message: protocolasn1.ESipaMessageFromEimToIpa{Raw: tlv},
		Raw:     raw,
	}, nil
}

func parseRelayTLV(data []byte) (*bertlv.TLV, error) {
	if len(data) == 0 {
		return nil, errors.New("esipa: empty BER-TLV payload")
	}
	reader := bytes.NewReader(data)
	tlv := new(bertlv.TLV)
	n, err := tlv.ReadFrom(reader)
	if err != nil {
		return nil, err
	}
	if n != int64(len(data)) || reader.Len() != 0 {
		return nil, errors.New("esipa: trailing data after BER-TLV payload")
	}
	return tlv, nil
}

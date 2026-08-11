package esipa

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
)

const (
	// GSMAPathGetEimPackage is the SGP.32 HTTP JSON path used by GSMA IPA
	// implementations that speak HTTP JSON ESipa.
	GSMAPathGetEimPackage = "/gsma/rsp2/esipa/getEimPackage"
	// GSMAPathProvideEimPackageResult is the JSON provideResult path.
	GSMAPathProvideEimPackageResult = "/gsma/rsp2/esipa/provideEimPackageResult"
	// GSMAPathHandleNotification is the JSON handleNotification path. Some IPAs
	// also deliver ProvideEimPackageResult payloads on this path.
	GSMAPathHandleNotification = "/gsma/rsp2/esipa/handleNotification"

	// GSMAJSONMediaType is the Content-Type used by GSMA HTTP JSON ESipa.
	GSMAJSONMediaType = "application/json"

	// DefaultAdminProtocol is echoed on GSMA JSON responses when the request
	// does not negotiate a different gsma/rsp version.
	DefaultAdminProtocol = "gsma/rsp/v2.4.0"

	adminProtocolHeader = "X-Admin-Protocol"
)

// DefaultGSMAPaths are the first-class GSMA HTTP JSON ESipa endpoints.
var DefaultGSMAPaths = []string{
	GSMAPathGetEimPackage,
	GSMAPathProvideEimPackageResult,
	GSMAPathHandleNotification,
}

type gsmaFunctionExecutionStatus struct {
	Status string `json:"status"`
}

type gsmaResponseHeader struct {
	FunctionExecutionStatus gsmaFunctionExecutionStatus `json:"functionExecutionStatus"`
}

type gsmaGetEimPackageRequest struct {
	EIDValue string `json:"eidValue"`
}

type gsmaGetEimPackageResponse struct {
	Header                          gsmaResponseHeader `json:"header"`
	EimPackageError                 int                `json:"eimPackageError"`
	EuiccPackageRequest             string             `json:"euiccPackageRequest,omitempty"`
	IpaEuiccDataRequest             string             `json:"ipaEuiccDataRequest,omitempty"`
	ProfileDownloadTriggerRequest   string             `json:"profileDownloadTriggerRequest,omitempty"`
}

type gsmaProvideEimPackageResultRequest struct {
	EIDValue         string `json:"eidValue"`
	EimPackageResult string `json:"eimPackageResult"`
}

type gsmaHandleNotificationRequest struct {
	ProvideEimPackageResult string `json:"provideEimPackageResult"`
}

type gsmaProvideResponse struct {
	Header              gsmaResponseHeader `json:"header"`
	EimAcknowledgements string             `json:"eimAcknowledgements,omitempty"`
	EimPackageError     *int               `json:"eimPackageError,omitempty"`
}

// ServeGSMAJSON handles one GSMA HTTP JSON ESipa request on the DefaultGSMAPaths.
func (h *Handler) ServeGSMAJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	setAdminProtocolResponse(w, r.Header.Get(adminProtocolHeader))

	maxSize := h.maxMessageSize()
	body := http.MaxBytesReader(w, r.Body, maxSize)
	defer func() {
		_ = r.Body.Close()
	}()
	payload, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, fmt.Sprintf("read GSMA ESipa request: %v", err), http.StatusBadRequest)
		return
	}

	switch r.URL.Path {
	case GSMAPathGetEimPackage:
		h.serveGSMAGetEimPackage(w, r, payload)
	case GSMAPathProvideEimPackageResult:
		h.serveGSMAProvideEimPackageResult(w, r, payload)
	case GSMAPathHandleNotification:
		h.serveGSMAHandleNotification(w, r, payload)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) serveGSMAGetEimPackage(w http.ResponseWriter, r *http.Request, payload []byte) {
	var request gsmaGetEimPackageRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		http.Error(w, fmt.Sprintf("decode getEimPackage JSON: %v", err), http.StatusBadRequest)
		return
	}
	eid, err := parseGSMAEIDValue(request.EIDValue)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	berRequest, err := protocolasn1.Encode(&protocolasn1.GetEimPackageRequest{EID: eid})
	if err != nil {
		http.Error(w, fmt.Sprintf("encode getEimPackage: %v", err), http.StatusInternalServerError)
		return
	}
	encoded, err := h.handleEncodedResponse(r.Context(), berRequest)
	if err != nil {
		http.Error(w, fmt.Sprintf("handle getEimPackage: %v", err), http.StatusBadRequest)
		return
	}
	response, err := gsmaGetResponseFromBER(encoded.Payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeGSMAJSON(w, http.StatusOK, response)
}

func (h *Handler) serveGSMAProvideEimPackageResult(w http.ResponseWriter, r *http.Request, payload []byte) {
	var request gsmaProvideEimPackageResultRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		http.Error(w, fmt.Sprintf("decode provideEimPackageResult JSON: %v", err), http.StatusBadRequest)
		return
	}
	provideTLV, err := provideTLVFromGSMA(request.EIDValue, request.EimPackageResult)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	berRequest, err := protocolasn1.Encode(&protocolasn1.ESipaMessageFromIpaToEim{Raw: provideTLV})
	if err != nil {
		http.Error(w, fmt.Sprintf("encode provideEimPackageResult: %v", err), http.StatusInternalServerError)
		return
	}
	encoded, err := h.handleEncodedResponse(r.Context(), berRequest)
	if err != nil {
		http.Error(w, fmt.Sprintf("handle provideEimPackageResult: %v", err), http.StatusBadRequest)
		return
	}
	if encoded.NoContent {
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	response, err := gsmaProvideResponseFromBER(encoded.Payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeGSMAJSON(w, http.StatusOK, response)
}

func (h *Handler) serveGSMAHandleNotification(w http.ResponseWriter, r *http.Request, payload []byte) {
	var request gsmaHandleNotificationRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		http.Error(w, fmt.Sprintf("decode handleNotification JSON: %v", err), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(request.ProvideEimPackageResult) == "" {
		http.Error(w, "handleNotification requires provideEimPackageResult", http.StatusBadRequest)
		return
	}
	provideDER, err := decodeGSMABase64(request.ProvideEimPackageResult)
	if err != nil {
		http.Error(w, fmt.Sprintf("decode provideEimPackageResult: %v", err), http.StatusBadRequest)
		return
	}
	provideTLV, err := parseGSMAProvideOrResultTLV(nil, provideDER)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	notifyTLV := constructed(tagHandleNotify, provideTLV)
	berRequest, err := protocolasn1.Encode(&protocolasn1.ESipaMessageFromIpaToEim{Raw: notifyTLV})
	if err != nil {
		http.Error(w, fmt.Sprintf("encode handleNotification: %v", err), http.StatusInternalServerError)
		return
	}
	encoded, err := h.handleEncodedResponse(r.Context(), berRequest)
	if err != nil {
		http.Error(w, fmt.Sprintf("handle handleNotification: %v", err), http.StatusBadRequest)
		return
	}
	if encoded.NoContent || len(encoded.Payload) == 0 {
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	response, err := gsmaProvideResponseFromBER(encoded.Payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeGSMAJSON(w, http.StatusOK, response)
}

func provideTLVFromGSMA(eidValue string, resultBase64 string) (*bertlv.TLV, error) {
	resultDER, err := decodeGSMABase64(resultBase64)
	if err != nil {
		return nil, fmt.Errorf("decode eimPackageResult: %w", err)
	}
	var eid []byte
	if strings.TrimSpace(eidValue) != "" {
		eid, err = parseGSMAEIDValue(eidValue)
		if err != nil {
			return nil, err
		}
	}
	return parseGSMAProvideOrResultTLV(eid, resultDER)
}

func parseGSMAProvideOrResultTLV(eid []byte, der []byte) (*bertlv.TLV, error) {
	tlv, err := parseRawTLV(der)
	if err != nil {
		return nil, err
	}
	if len(eid) == 0 {
		eid = recoverEIDFromPackageResultTLV(tlv)
	}
	if tlv.Tag.Equal(tagProvideResult) {
		if len(eid) == 0 || tlv.First(tagEID) != nil {
			return tlv, nil
		}
		children := make([]*bertlv.TLV, 0, len(tlv.Children)+1)
		children = append(children, octetTLV(tagEID, eid))
		children = append(children, tlv.Children...)
		return constructed(tagProvideResult, children...), nil
	}
	children := make([]*bertlv.TLV, 0, 2)
	if len(eid) != 0 {
		children = append(children, octetTLV(tagEID, eid))
	}
	children = append(children, tlv)
	return constructed(tagProvideResult, children...), nil
}

func gsmaGetResponseFromBER(payload []byte) (gsmaGetEimPackageResponse, error) {
	var message protocolasn1.ESipaMessageFromEimToIpa
	if err := protocolasn1.Decode(payload, &message); err != nil {
		return gsmaGetEimPackageResponse{}, err
	}
	var response protocolasn1.GetEimPackageResponse
	if err := response.UnmarshalBERTLV(message.Raw); err != nil {
		return gsmaGetEimPackageResponse{}, err
	}
	out := gsmaGetEimPackageResponse{
		Header: gsmaSuccessHeader(),
	}
	switch response.Kind {
	case protocolasn1.GetEimPackageEuiccPackageRequest:
		if response.EuiccPackageRequest == nil {
			return gsmaGetEimPackageResponse{}, fmt.Errorf("esipa: missing euiccPackageRequest")
		}
		encoded, err := protocolasn1.Encode(response.EuiccPackageRequest)
		if err != nil {
			return gsmaGetEimPackageResponse{}, err
		}
		out.EuiccPackageRequest = base64.StdEncoding.EncodeToString(encoded)
	case protocolasn1.GetEimPackageIpaEuiccDataRequest:
		if response.IpaEuiccDataRequest == nil {
			return gsmaGetEimPackageResponse{}, fmt.Errorf("esipa: missing ipaEuiccDataRequest")
		}
		encoded, err := response.IpaEuiccDataRequest.MarshalBinary()
		if err != nil {
			return gsmaGetEimPackageResponse{}, err
		}
		out.IpaEuiccDataRequest = base64.StdEncoding.EncodeToString(encoded)
	case protocolasn1.GetEimPackageProfileDownloadTriggerRequest:
		if response.ProfileDownloadTriggerRequest == nil {
			return gsmaGetEimPackageResponse{}, fmt.Errorf("esipa: missing profileDownloadTriggerRequest")
		}
		encoded, err := protocolasn1.Encode(response.ProfileDownloadTriggerRequest)
		if err != nil {
			return gsmaGetEimPackageResponse{}, err
		}
		out.ProfileDownloadTriggerRequest = base64.StdEncoding.EncodeToString(encoded)
	case protocolasn1.GetEimPackageError:
		if response.Error == nil {
			return gsmaGetEimPackageResponse{}, fmt.Errorf("esipa: missing eimPackageError")
		}
		out.EimPackageError = int(*response.Error)
	default:
		return gsmaGetEimPackageResponse{}, fmt.Errorf("esipa: unsupported getEimPackage response kind %d", response.Kind)
	}
	return out, nil
}

func gsmaProvideResponseFromBER(payload []byte) (gsmaProvideResponse, error) {
	var message protocolasn1.ESipaMessageFromEimToIpa
	if err := protocolasn1.Decode(payload, &message); err != nil {
		return gsmaProvideResponse{}, err
	}
	var response protocolasn1.ProvideEimPackageResultResponse
	if err := response.UnmarshalBERTLV(message.Raw); err != nil {
		return gsmaProvideResponse{}, err
	}
	out := gsmaProvideResponse{Header: gsmaSuccessHeader()}
	switch response.Kind {
	case protocolasn1.ProvideResultResponseEmpty:
		return out, nil
	case protocolasn1.ProvideResultResponseAcknowledgements:
		if response.Acknowledgements == nil {
			return out, nil
		}
		encoded, err := protocolasn1.Encode(response.Acknowledgements)
		if err != nil {
			return gsmaProvideResponse{}, err
		}
		out.EimAcknowledgements = base64.StdEncoding.EncodeToString(encoded)
	case protocolasn1.ProvideResultResponseError:
		if response.Error == nil {
			return gsmaProvideResponse{}, fmt.Errorf("esipa: missing provide eimPackageError")
		}
		code := int(*response.Error)
		out.EimPackageError = &code
	default:
		return gsmaProvideResponse{}, fmt.Errorf("esipa: unsupported provideResult response kind %d", response.Kind)
	}
	return out, nil
}

func gsmaSuccessHeader() gsmaResponseHeader {
	return gsmaResponseHeader{
		FunctionExecutionStatus: gsmaFunctionExecutionStatus{Status: "Executed-Success"},
	}
}

func parseGSMAEIDValue(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, fmt.Errorf("esipa: missing eidValue")
	}
	decoded, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("esipa: invalid eidValue hex: %w", err)
	}
	if len(decoded) != 16 {
		return nil, fmt.Errorf("esipa: eidValue must be 16 bytes, got %d", len(decoded))
	}
	return decoded, nil
}

func decodeGSMABase64(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, fmt.Errorf("esipa: empty base64 payload")
	}
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(trimmed)
	}
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func parseRawTLV(data []byte) (*bertlv.TLV, error) {
	tlv := new(bertlv.TLV)
	if err := tlv.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("esipa: parse BER-TLV: %w", err)
	}
	return tlv, nil
}

func setAdminProtocolResponse(w http.ResponseWriter, requestValue string) {
	value := DefaultAdminProtocol
	if trimmed := strings.TrimSpace(requestValue); strings.HasPrefix(trimmed, "gsma/rsp/") {
		value = trimmed
	}
	w.Header().Set(adminProtocolHeader, value)
}

func writeGSMAJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", GSMAJSONMediaType+";charset=UTF-8")
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func constructed(tag bertlv.Tag, children ...*bertlv.TLV) *bertlv.TLV {
	return bertlv.NewChildren(tag, children...)
}

func octetTLV(tag bertlv.Tag, value []byte) *bertlv.TLV {
	return bertlv.NewValue(tag, append([]byte(nil), value...))
}

package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/euiccpkg"
	"github.com/openiotrsp/openiotrsp/profiledownload"
	"github.com/openiotrsp/openiotrsp/storage"
)

const (
	defaultMaxBodyBytes = 1 << 20
)

var errPackageServiceUnavailable = errors.New("api: eUICC package service unavailable")

// Handler serves the northbound API.
type Handler struct {
	Store          storage.Store
	TenantResolver TenantResolver
	PackageService *euiccpkg.Service
	MaxBodyBytes   int64
}

// NewHandler creates a northbound API handler.
func NewHandler(store storage.Store, resolver TenantResolver, packageService *euiccpkg.Service) *Handler {
	return &Handler{
		Store:          store,
		TenantResolver: resolver,
		PackageService: packageService,
	}
}

// HTTPHandler returns a stdlib HTTP handler for all northbound routes.
func (h *Handler) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/profile-downloads", h.triggerProfileDownload)
	mux.HandleFunc("POST /v1/devices/{eid}/profiles/{iccid}/enable", h.enableProfile)
	mux.HandleFunc("POST /v1/devices/{eid}/profiles/{iccid}/disable", h.disableProfile)
	mux.HandleFunc("DELETE /v1/devices/{eid}/profiles/{iccid}", h.deleteProfile)
	mux.HandleFunc("GET /v1/devices/{eid}/status", h.deviceStatus)
	mux.HandleFunc("GET /v1/operations/{id}", h.operationResult)
	return mux
}

// NewHTTPHandler creates a northbound API HTTP handler.
func NewHTTPHandler(store storage.Store, resolver TenantResolver, packageService *euiccpkg.Service) http.Handler {
	return NewHandler(store, resolver, packageService).HTTPHandler()
}

type profileDownloadRequest struct {
	EID            string   `json:"eid,omitempty"`
	EIDs           []string `json:"eids,omitempty"`
	ActivationCode string   `json:"activationCode,omitempty"`
	SMDPAddress    string   `json:"smdpAddress,omitempty"`
	MatchingID     string   `json:"matchingId,omitempty"`
	DefaultSMDP    bool     `json:"defaultSmdp,omitempty"`
	SMDSAddress    *string  `json:"smdsAddress,omitempty"`
}

type operationResponse struct {
	ID             int64     `json:"id"`
	EID            string    `json:"eid"`
	SequenceNumber int64     `json:"sequenceNumber"`
	Kind           string    `json:"kind"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type enqueueResponse struct {
	Operations []operationResponse `json:"operations"`
}

type profileResponse struct {
	ICCID       string `json:"iccid"`
	IsEnabled   bool   `json:"isEnabled"`
	SMDPAddress string `json:"smdpAddress"`
}

type statusResponse struct {
	EID      string            `json:"eid"`
	Profiles []profileResponse `json:"profiles"`
}

type resultResponse struct {
	Status        string    `json:"status"`
	PayloadBase64 string    `json:"payloadBase64"`
	CreatedAt     time.Time `json:"createdAt"`
}

type operationResultResponse struct {
	Operation operationResponse `json:"operation"`
	Result    *resultResponse   `json:"result,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func (h *Handler) triggerProfileDownload(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.resolveTenant(w, r)
	if !ok {
		return
	}
	var request profileDownloadRequest
	if !decodeJSON(w, r, h.maxBodyBytes(), &request) {
		return
	}
	targets, err := request.targetEIDs()
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	operations := make([]operationResponse, 0, len(targets))
	for _, target := range targets {
		eid, _, err := parseEID(target)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := h.Store.RegisterDevice(r.Context(), tenantID, storage.Device{EID: eid}); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		trigger, err := request.trigger()
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		operation, err := profiledownload.EnqueueTrigger(r.Context(), h.Store, tenantID, eid, trigger)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		operations = append(operations, newOperationResponse(operation))
	}
	writeJSON(w, http.StatusAccepted, enqueueResponse{Operations: operations})
}

func (h *Handler) enableProfile(w http.ResponseWriter, r *http.Request) {
	h.enqueueProfileOperation(w, r, func(iccid []byte) protocolasn1.EuiccPackage {
		return euiccpkg.Enable(iccid, false)
	})
}

func (h *Handler) disableProfile(w http.ResponseWriter, r *http.Request) {
	h.enqueueProfileOperation(w, r, func(iccid []byte) protocolasn1.EuiccPackage {
		return euiccpkg.Disable(iccid)
	})
}

func (h *Handler) deleteProfile(w http.ResponseWriter, r *http.Request) {
	h.enqueueProfileOperation(w, r, func(iccid []byte) protocolasn1.EuiccPackage {
		return euiccpkg.Delete(iccid)
	})
}

func (h *Handler) enqueueProfileOperation(w http.ResponseWriter, r *http.Request, build func([]byte) protocolasn1.EuiccPackage) {
	tenantID, ok := h.resolveTenant(w, r)
	if !ok {
		return
	}
	service, err := h.packageService()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	eid, eidValue, err := parseEID(r.PathValue("eid"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	iccid, err := parseICCID(r.PathValue("iccid"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.Store.RegisterDevice(r.Context(), tenantID, storage.Device{EID: eid}); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	transactionID, err := randomTransactionID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	pkg := build(iccid)
	signed, err := service.Sign(r.Context(), euiccpkg.SignInput{
		TenantID:         tenantID,
		EID:              eid,
		EIDValue:         eidValue,
		EimTransactionID: transactionID,
		Package:          pkg,
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	operation, err := h.Store.EnqueueOperation(r.Context(), tenantID, storage.OperationRequest{
		EID:     eid,
		Kind:    storage.OperationEuiccPackage,
		Payload: signed.DER,
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, enqueueResponse{Operations: []operationResponse{newOperationResponse(operation)}})
}

func (h *Handler) deviceStatus(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.resolveTenant(w, r)
	if !ok {
		return
	}
	eid, _, err := parseEID(r.PathValue("eid"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	states, err := h.Store.ListProfileStates(r.Context(), tenantID, eid)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	profiles := make([]profileResponse, 0, len(states))
	for _, state := range states {
		profiles = append(profiles, profileResponse{
			ICCID:       state.ICCID,
			IsEnabled:   state.IsEnabled,
			SMDPAddress: state.SMDPAddress,
		})
	}
	writeJSON(w, http.StatusOK, statusResponse{EID: eid, Profiles: profiles})
}

func (h *Handler) operationResult(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.resolveTenant(w, r)
	if !ok {
		return
	}
	operationID, err := parseOperationID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	operation, err := h.Store.GetOperation(r.Context(), tenantID, operationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	response := operationResultResponse{Operation: newOperationResponse(operation)}
	result, err := h.Store.GetOperationResult(r.Context(), tenantID, operationID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		writeStoreError(w, err)
		return
	}
	if err == nil {
		response.Result = &resultResponse{
			Status:        string(result.Status),
			PayloadBase64: base64.StdEncoding.EncodeToString(result.Payload),
			CreatedAt:     result.CreatedAt,
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) resolveTenant(w http.ResponseWriter, r *http.Request) (storage.TenantID, bool) {
	if h == nil || h.Store == nil {
		writeError(w, http.StatusInternalServerError, errors.New("api: nil Store"))
		return "", false
	}
	resolver := h.TenantResolver
	if resolver == nil {
		resolver = DefaultTenantResolver{}
	}
	tenantID, err := resolver.ResolveTenant(r.Context(), r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return "", false
	}
	return storage.NormalizeTenantID(tenantID), true
}

func (h *Handler) packageService() (*euiccpkg.Service, error) {
	if h == nil || h.PackageService == nil || h.PackageService.Signer == nil || h.PackageService.EimID == "" {
		return nil, errPackageServiceUnavailable
	}
	service := *h.PackageService
	if service.Store == nil {
		service.Store = h.Store
	}
	return &service, nil
}

func (h *Handler) maxBodyBytes() int64 {
	if h == nil || h.MaxBodyBytes <= 0 {
		return defaultMaxBodyBytes
	}
	return h.MaxBodyBytes
}

func (r profileDownloadRequest) targetEIDs() ([]string, error) {
	eid := strings.TrimSpace(r.EID)
	if eid != "" && len(r.EIDs) > 0 {
		return nil, errors.New("api: provide either eid or eids, not both")
	}
	if eid != "" {
		return []string{eid}, nil
	}
	if len(r.EIDs) == 0 {
		return nil, errors.New("api: missing eid or eids")
	}
	targets := make([]string, len(r.EIDs))
	for index, value := range r.EIDs {
		targets[index] = strings.TrimSpace(value)
		if targets[index] == "" {
			return nil, errors.New("api: eids contains an empty value")
		}
	}
	return targets, nil
}

func (r profileDownloadRequest) trigger() (*protocolasn1.ProfileDownloadTriggerRequest, error) {
	transactionID, err := randomTransactionID()
	if err != nil {
		return nil, err
	}
	choices := 0
	if strings.TrimSpace(r.ActivationCode) != "" {
		choices++
	}
	if strings.TrimSpace(r.SMDPAddress) != "" || strings.TrimSpace(r.MatchingID) != "" {
		choices++
	}
	if r.DefaultSMDP {
		choices++
	}
	if r.SMDSAddress != nil {
		choices++
	}
	if choices != 1 {
		return nil, errors.New("api: provide exactly one download source")
	}
	switch {
	case strings.TrimSpace(r.ActivationCode) != "":
		return profiledownload.NewActivationCodeTrigger(strings.TrimSpace(r.ActivationCode), transactionID)
	case strings.TrimSpace(r.SMDPAddress) != "" || strings.TrimSpace(r.MatchingID) != "":
		return profiledownload.NewSMDPAddressTrigger(strings.TrimSpace(r.SMDPAddress), strings.TrimSpace(r.MatchingID), transactionID)
	case r.DefaultSMDP:
		return profiledownload.NewDefaultSMDPTrigger(transactionID), nil
	default:
		return profiledownload.NewSMDSAddressTrigger(strings.TrimSpace(*r.SMDSAddress), transactionID), nil
	}
}

func parseEID(value string) (string, []byte, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	bytes, err := hex.DecodeString(normalized)
	if err != nil || len(bytes) != 16 {
		return "", nil, fmt.Errorf("api: EID must be 32 hex characters")
	}
	return normalized, bytes, nil
}

func parseICCID(value string) ([]byte, error) {
	normalized := strings.TrimSpace(value)
	bytes, err := hex.DecodeString(normalized)
	if err != nil || len(bytes) == 0 {
		return nil, fmt.Errorf("api: ICCID must be non-empty hex")
	}
	return bytes, nil
}

func parseOperationID(value string) (int64, error) {
	operationID, err := strconv.ParseInt(value, 10, 64)
	if err != nil || operationID <= 0 {
		return 0, errors.New("api: operation id must be a positive integer")
	}
	return operationID, nil
}

func randomTransactionID() ([]byte, error) {
	transactionID := make([]byte, 16)
	if _, err := rand.Read(transactionID); err != nil {
		return nil, err
	}
	return transactionID, nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) bool {
	body := http.MaxBytesReader(w, r.Body, maxBytes)
	defer func() {
		_ = r.Body.Close()
	}()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return false
	}
	if err := decoder.Decode(new(struct{})); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, errors.New("api: request body must contain one JSON object"))
		return false
	}
	return true
}

func newOperationResponse(operation storage.Operation) operationResponse {
	return operationResponse{
		ID:             operation.ID,
		EID:            operation.EID,
		SequenceNumber: operation.SequenceNumber,
		Kind:           string(operation.Kind),
		Status:         string(operation.Status),
		CreatedAt:      operation.CreatedAt,
		UpdatedAt:      operation.UpdatedAt,
	}
}

func writeStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, storage.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeError(w, http.StatusInternalServerError, err)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, errorResponse{Error: err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

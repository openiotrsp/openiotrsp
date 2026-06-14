package api

import (
	"bytes"
	"context"
	"crypto/rand"
	stdasn1 "encoding/asn1"
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
	"github.com/openiotrsp/openiotrsp/ipadata"
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
	mux.HandleFunc("POST /v1/devices/{eid}/profiles/{iccid}/fallback", h.setFallbackAttribute)
	mux.HandleFunc("DELETE /v1/devices/{eid}/profiles/fallback", h.unsetFallbackAttribute)
	mux.HandleFunc("DELETE /v1/devices/{eid}/profiles/{iccid}", h.deleteProfile)
	mux.HandleFunc("POST /v1/devices/{eid}/profiles/list", h.listProfileInfo)
	mux.HandleFunc("POST /v1/devices/{eid}/profiles/get-rat", h.getRAT)
	mux.HandleFunc("POST /v1/devices/{eid}/profiles/immediate-enable", h.configureImmediateEnable)
	mux.HandleFunc("POST /v1/devices/{eid}/profiles/default-dp-address", h.setDefaultDPAddress)
	mux.HandleFunc("POST /v1/eims/initial-configuration", h.initialEIMConfiguration)
	mux.HandleFunc("POST /v1/devices/{eid}/eims", h.addEIM)
	mux.HandleFunc("GET /v1/devices/{eid}/eims", h.eimStatus)
	mux.HandleFunc("POST /v1/devices/{eid}/eims/initial-association", h.recordInitialEIMAssociation)
	mux.HandleFunc("PUT /v1/devices/{eid}/eims/{eimId}", h.updateEIM)
	mux.HandleFunc("DELETE /v1/devices/{eid}/eims/{eimId}", h.deleteEIM)
	mux.HandleFunc("POST /v1/devices/{eid}/eims/list", h.listEIM)
	mux.HandleFunc("POST /v1/devices/{eid}/euicc-data/fetch", h.fetchEUICCData)
	mux.HandleFunc("GET /v1/devices/{eid}/euicc-data", h.euiccData)
	mux.HandleFunc("GET /v1/devices/{eid}/status", h.deviceStatus)
	mux.HandleFunc("GET /v1/devices/{eid}/notifications", h.deviceNotifications)
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

type enableProfileRequest struct {
	Rollback bool `json:"rollback,omitempty"`
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
	IsFallback  bool   `json:"isFallback"`
	SMDPAddress string `json:"smdpAddress"`
}

type statusResponse struct {
	EID      string            `json:"eid"`
	Profiles []profileResponse `json:"profiles"`
}

type eimConfigRequest struct {
	EIMID                  string `json:"eimId,omitempty"`
	EIMFQDN                string `json:"eimFqdn,omitempty"`
	EIMIDType              *int64 `json:"eimIdType,omitempty"`
	CounterValue           *int64 `json:"counterValue,omitempty"`
	AssociationToken       *int64 `json:"associationToken,omitempty"`
	EIMPublicKeyDataBase64 string `json:"eimPublicKeyDataBase64,omitempty"`
	EIMCertificateBase64   string `json:"eimCertificateBase64,omitempty"`
	EUICCCIPKIDBase64      string `json:"euiccCiPKIdBase64,omitempty"`
}

type configureImmediateEnableRequest struct {
	ImmediateEnableFlag bool   `json:"immediateEnableFlag,omitempty"`
	DefaultSMDPOID      string `json:"defaultSmdpOid,omitempty"`
	DefaultSMDPAddress  string `json:"defaultSmdpAddress,omitempty"`
}

type setDefaultDPAddressRequest struct {
	DefaultDPAddress string `json:"defaultDpAddress"`
}

type euiccDataFetchRequest struct {
	TagListHex                  string `json:"tagListHex,omitempty"`
	TagListBase64               string `json:"tagListBase64,omitempty"`
	EUICCCIPKIdentifierBase64   string `json:"euiccCiPKIdentifierBase64,omitempty"`
	NotificationSeqNumber       *int64 `json:"notificationSeqNumber,omitempty"`
	EuiccPackageResultSeqNumber *int64 `json:"euiccPackageResultSeqNumber,omitempty"`
	EimTransactionIDBase64      string `json:"eimTransactionIdBase64,omitempty"`
}

type associatedEIMResponse struct {
	EIMID            string `json:"eimId"`
	EIMFQDN          string `json:"eimFqdn,omitempty"`
	EIMIDType        *int64 `json:"eimIdType,omitempty"`
	CounterValue     *int64 `json:"counterValue,omitempty"`
	AssociationToken *int64 `json:"associationToken,omitempty"`
}

type eimConfigurationResponse struct {
	EIMID         string                `json:"eimId"`
	PayloadBase64 string                `json:"payloadBase64"`
	Config        associatedEIMResponse `json:"config"`
}

type initialEIMAssociationResponse struct {
	EID              string                `json:"eid"`
	BootstrapAllowed bool                  `json:"bootstrapAllowed"`
	EIM              associatedEIMResponse `json:"eim"`
}

type eimStatusResponse struct {
	EID              string                  `json:"eid"`
	BootstrapAllowed bool                    `json:"bootstrapAllowed"`
	EIMs             []associatedEIMResponse `json:"eims"`
}

type euiccDataResponse struct {
	EID                    string            `json:"eid"`
	EIDValueBase64         string            `json:"eidValueBase64,omitempty"`
	DefaultSMDPAddress     string            `json:"defaultSmdpAddress,omitempty"`
	RootSMDSAddress        string            `json:"rootSmdsAddress,omitempty"`
	EUICCInfo1Base64       string            `json:"euiccInfo1Base64,omitempty"`
	EUICCInfo2Base64       string            `json:"euiccInfo2Base64,omitempty"`
	IPACapabilitiesBase64  string            `json:"ipaCapabilitiesBase64,omitempty"`
	DeviceInfoBase64       string            `json:"deviceInfoBase64,omitempty"`
	EUMCertificateBase64   string            `json:"eumCertificateBase64,omitempty"`
	EUICCCertificateBase64 string            `json:"euiccCertificateBase64,omitempty"`
	CertificateIdentifiers []string          `json:"certificateIdentifiers,omitempty"`
	Profiles               []profileResponse `json:"profiles"`
	RawPayloadBase64       string            `json:"rawPayloadBase64,omitempty"`
	UpdatedAt              time.Time         `json:"updatedAt"`
}

type resultResponse struct {
	Status        string    `json:"status"`
	PayloadBase64 string    `json:"payloadBase64"`
	CreatedAt     time.Time `json:"createdAt"`
}

type notificationResponse struct {
	SequenceNumber int64     `json:"sequenceNumber"`
	Kind           string    `json:"kind"`
	PayloadBase64  string    `json:"payloadBase64"`
	CreatedAt      time.Time `json:"createdAt"`
}

type notificationsResponse struct {
	EID           string                 `json:"eid"`
	Notifications []notificationResponse `json:"notifications"`
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
	var request enableProfileRequest
	if !decodeOptionalJSON(w, r, h.maxBodyBytes(), &request) {
		return
	}
	h.enqueueProfileOperation(w, r, func(iccid []byte) protocolasn1.EuiccPackage {
		return euiccpkg.Enable(iccid, request.Rollback)
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

func (h *Handler) listProfileInfo(w http.ResponseWriter, r *http.Request) {
	h.enqueueDeviceOperation(w, r, func(*euiccpkg.Service) (protocolasn1.EuiccPackage, error) {
		return euiccpkg.ListProfileInfo(), nil
	})
}

func (h *Handler) getRAT(w http.ResponseWriter, r *http.Request) {
	h.enqueueDeviceOperation(w, r, func(*euiccpkg.Service) (protocolasn1.EuiccPackage, error) {
		return euiccpkg.GetRAT(), nil
	})
}

func (h *Handler) configureImmediateEnable(w http.ResponseWriter, r *http.Request) {
	var request configureImmediateEnableRequest
	if !decodeJSON(w, r, h.maxBodyBytes(), &request) {
		return
	}
	h.enqueueDeviceOperation(w, r, func(*euiccpkg.Service) (protocolasn1.EuiccPackage, error) {
		oid, err := parseOID(request.DefaultSMDPOID)
		if err != nil {
			return protocolasn1.EuiccPackage{}, err
		}
		return euiccpkg.ConfigureImmediateEnable(request.ImmediateEnableFlag, oid, strings.TrimSpace(request.DefaultSMDPAddress)), nil
	})
}

func (h *Handler) setFallbackAttribute(w http.ResponseWriter, r *http.Request) {
	h.enqueueProfileOperation(w, r, func(iccid []byte) protocolasn1.EuiccPackage {
		return euiccpkg.SetFallbackAttribute(iccid)
	})
}

func (h *Handler) unsetFallbackAttribute(w http.ResponseWriter, r *http.Request) {
	h.enqueueDeviceOperation(w, r, func(*euiccpkg.Service) (protocolasn1.EuiccPackage, error) {
		return euiccpkg.UnsetFallbackAttribute(), nil
	})
}

func (h *Handler) setDefaultDPAddress(w http.ResponseWriter, r *http.Request) {
	var request setDefaultDPAddressRequest
	if !decodeJSON(w, r, h.maxBodyBytes(), &request) {
		return
	}
	h.enqueueDeviceOperation(w, r, func(*euiccpkg.Service) (protocolasn1.EuiccPackage, error) {
		address := strings.TrimSpace(request.DefaultDPAddress)
		if address == "" {
			return protocolasn1.EuiccPackage{}, errors.New("api: defaultDpAddress is required")
		}
		return euiccpkg.SetDefaultDPAddress(address), nil
	})
}

func (h *Handler) initialEIMConfiguration(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.resolveTenant(w, r)
	if !ok {
		return
	}
	service, err := h.packageService()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	var request eimConfigRequest
	if !decodeJSON(w, r, h.maxBodyBytes(), &request) {
		return
	}
	config, err := request.config(service, "")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := euiccpkg.ValidateInitialEIMConfigurationData(config); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	payload, err := protocolasn1.Encode(config)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := h.Store.StoreEIMConfig(r.Context(), tenantID, storage.EIMConfig{
		EIMID: config.EimID,
		Data:  payload,
	}); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, eimConfigurationResponse{
		EIMID:         config.EimID,
		PayloadBase64: base64.StdEncoding.EncodeToString(payload),
		Config:        associatedResponseFromConfig(config),
	})
}

func (h *Handler) addEIM(w http.ResponseWriter, r *http.Request) {
	var request eimConfigRequest
	if !decodeJSON(w, r, h.maxBodyBytes(), &request) {
		return
	}
	h.enqueueEIMOperation(w, r, func(service *euiccpkg.Service) (protocolasn1.EuiccPackage, error) {
		config, err := request.config(service, "")
		if err != nil {
			return protocolasn1.EuiccPackage{}, err
		}
		return euiccpkg.AddEim(config), nil
	})
}

func (h *Handler) updateEIM(w http.ResponseWriter, r *http.Request) {
	var request eimConfigRequest
	if !decodeJSON(w, r, h.maxBodyBytes(), &request) {
		return
	}
	eimID, err := parseEIMID(r.PathValue("eimId"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	h.enqueueEIMOperation(w, r, func(service *euiccpkg.Service) (protocolasn1.EuiccPackage, error) {
		config, err := request.config(service, eimID)
		if err != nil {
			return protocolasn1.EuiccPackage{}, err
		}
		return euiccpkg.UpdateEim(config), nil
	})
}

func (h *Handler) deleteEIM(w http.ResponseWriter, r *http.Request) {
	eimID, err := parseEIMID(r.PathValue("eimId"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	h.enqueueEIMOperation(w, r, func(*euiccpkg.Service) (protocolasn1.EuiccPackage, error) {
		return euiccpkg.DeleteEim(eimID), nil
	})
}

func (h *Handler) listEIM(w http.ResponseWriter, r *http.Request) {
	h.enqueueEIMOperation(w, r, func(*euiccpkg.Service) (protocolasn1.EuiccPackage, error) {
		return euiccpkg.ListEim(), nil
	})
}

func (h *Handler) fetchEUICCData(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.resolveTenant(w, r)
	if !ok {
		return
	}
	eid, _, err := parseEID(r.PathValue("eid"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var request euiccDataFetchRequest
	if !decodeOptionalJSON(w, r, h.maxBodyBytes(), &request) {
		return
	}
	input, err := request.input()
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.Store.RegisterDevice(r.Context(), tenantID, storage.Device{EID: eid}); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	operation, err := ipadata.EnqueueRequest(r.Context(), h.Store, tenantID, eid, input)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, enqueueResponse{Operations: []operationResponse{newOperationResponse(operation)}})
}

func (h *Handler) recordInitialEIMAssociation(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.resolveTenant(w, r)
	if !ok {
		return
	}
	service, err := h.packageService()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	eid, _, err := parseEID(r.PathValue("eid"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var request eimConfigRequest
	if !decodeJSON(w, r, h.maxBodyBytes(), &request) {
		return
	}
	config, err := h.initialAssociationConfig(r.Context(), tenantID, service, request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if config.AssociationToken == nil {
		writeError(w, http.StatusBadRequest, errors.New("api: associationToken is required"))
		return
	}
	if err := euiccpkg.ValidateInitialEIMConfigurationData(config); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.Store.RegisterDevice(r.Context(), tenantID, storage.Device{EID: eid}); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := euiccpkg.RecordInitialEIMAssociation(r.Context(), h.Store, tenantID, eid, config); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, initialEIMAssociationResponse{
		EID:              eid,
		BootstrapAllowed: false,
		EIM:              associatedResponseFromConfig(config),
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

func (h *Handler) enqueueEIMOperation(w http.ResponseWriter, r *http.Request, build func(*euiccpkg.Service) (protocolasn1.EuiccPackage, error)) {
	h.enqueueDeviceOperation(w, r, build)
}

func (h *Handler) enqueueDeviceOperation(w http.ResponseWriter, r *http.Request, build func(*euiccpkg.Service) (protocolasn1.EuiccPackage, error)) {
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
	if err := h.Store.RegisterDevice(r.Context(), tenantID, storage.Device{EID: eid}); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	transactionID, err := randomTransactionID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	pkg, err := build(service)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
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
			IsFallback:  state.IsFallback,
			SMDPAddress: state.SMDPAddress,
		})
	}
	writeJSON(w, http.StatusOK, statusResponse{EID: eid, Profiles: profiles})
}

func (h *Handler) deviceNotifications(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.resolveTenant(w, r)
	if !ok {
		return
	}
	eid, _, err := parseEID(r.PathValue("eid"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	notifications, err := h.Store.ListNotifications(r.Context(), tenantID, eid)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	response := notificationsResponse{
		EID:           eid,
		Notifications: make([]notificationResponse, 0, len(notifications)),
	}
	for _, notification := range notifications {
		response.Notifications = append(response.Notifications, notificationResponse{
			SequenceNumber: notification.SequenceNumber,
			Kind:           notification.Kind,
			PayloadBase64:  base64.StdEncoding.EncodeToString(notification.Payload),
			CreatedAt:      notification.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) eimStatus(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.resolveTenant(w, r)
	if !ok {
		return
	}
	eid, _, err := parseEID(r.PathValue("eid"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	items, err := h.Store.ListAssociatedEIMs(r.Context(), tenantID, eid)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	eims := make([]associatedEIMResponse, 0, len(items))
	for _, item := range items {
		var config protocolasn1.EimConfigurationData
		if err := protocolasn1.Decode(item.ConfigPayload, &config); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		eims = append(eims, associatedResponseFromConfig(&config))
	}
	writeJSON(w, http.StatusOK, eimStatusResponse{EID: eid, BootstrapAllowed: len(eims) == 0, EIMs: eims})
}

func (h *Handler) euiccData(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.resolveTenant(w, r)
	if !ok {
		return
	}
	eid, _, err := parseEID(r.PathValue("eid"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	state, err := h.Store.GetEUICCState(r.Context(), tenantID, eid)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	profileStates, err := h.Store.ListProfileStates(r.Context(), tenantID, eid)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newEUICCDataResponse(state, profileStates))
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

func (r eimConfigRequest) config(service *euiccpkg.Service, pathEIMID string) (*protocolasn1.EimConfigurationData, error) {
	eimID := strings.TrimSpace(r.EIMID)
	if pathEIMID != "" {
		if eimID != "" && eimID != pathEIMID {
			return nil, errors.New("api: body eimId must match path eimId")
		}
		eimID = pathEIMID
	}
	if eimID == "" && service != nil {
		eimID = service.EimID
	}
	if _, err := parseEIMID(eimID); err != nil {
		return nil, err
	}

	counter := int64(1)
	if r.CounterValue != nil {
		counter = *r.CounterValue
	}
	if counter < 0 {
		return nil, errors.New("api: counterValue must be non-negative")
	}

	if strings.TrimSpace(r.EIMPublicKeyDataBase64) != "" && strings.TrimSpace(r.EIMCertificateBase64) != "" {
		return nil, errors.New("api: provide either eimPublicKeyDataBase64 or eimCertificateBase64, not both")
	}

	var config *protocolasn1.EimConfigurationData
	switch {
	case strings.TrimSpace(r.EIMPublicKeyDataBase64) != "":
		publicKeyDER, err := decodeBase64Field("eimPublicKeyDataBase64", r.EIMPublicKeyDataBase64)
		if err != nil {
			return nil, err
		}
		config, err = euiccpkg.NewEIMConfigurationData(eimID, strings.TrimSpace(r.EIMFQDN), counter, publicKeyDER)
		if err != nil {
			return nil, err
		}
	case strings.TrimSpace(r.EIMCertificateBase64) != "":
		certificateDER, err := decodeBase64Field("eimCertificateBase64", r.EIMCertificateBase64)
		if err != nil {
			return nil, err
		}
		config, err = euiccpkg.NewEIMConfigurationDataFromCertificate(eimID, strings.TrimSpace(r.EIMFQDN), counter, certificateDER)
		if err != nil {
			return nil, err
		}
	case service != nil && service.Signer != nil && eimID == service.EimID && len(service.Signer.CertificateDER()) > 0:
		var err error
		config, err = euiccpkg.NewEIMConfigurationDataFromCertificate(eimID, strings.TrimSpace(r.EIMFQDN), counter, service.Signer.CertificateDER())
		if err != nil {
			return nil, err
		}
	case service != nil && service.Signer != nil && eimID == service.EimID:
		var err error
		config, err = euiccpkg.NewEIMConfigurationDataFromPublicKey(eimID, strings.TrimSpace(r.EIMFQDN), counter, service.Signer.PublicKey())
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("api: missing eIM public key data")
	}
	if r.EIMIDType != nil {
		if *r.EIMIDType < int64(protocolasn1.EimIDTypeOID) || *r.EIMIDType > int64(protocolasn1.EimIDTypeProprietary) {
			return nil, errors.New("api: eimIdType must be 1, 2, or 3")
		}
		value := protocolasn1.EimIDType(*r.EIMIDType)
		config.EimIDType = &value
	}
	if r.AssociationToken != nil {
		value := *r.AssociationToken
		config.AssociationToken = &value
	}
	if strings.TrimSpace(r.EUICCCIPKIDBase64) != "" {
		var err error
		config.EUICCCIPKID, err = decodeBase64Field("euiccCiPKIdBase64", r.EUICCCIPKIDBase64)
		if err != nil {
			return nil, err
		}
	}
	return config, nil
}

func (r euiccDataFetchRequest) input() (ipadata.RequestInput, error) {
	if strings.TrimSpace(r.TagListHex) != "" && strings.TrimSpace(r.TagListBase64) != "" {
		return ipadata.RequestInput{}, errors.New("api: provide either tagListHex or tagListBase64, not both")
	}
	var tagList []byte
	var err error
	if strings.TrimSpace(r.TagListHex) != "" {
		tagList, err = hex.DecodeString(strings.TrimSpace(r.TagListHex))
		if err != nil || len(tagList) == 0 {
			return ipadata.RequestInput{}, errors.New("api: tagListHex must be non-empty hex")
		}
	}
	if strings.TrimSpace(r.TagListBase64) != "" {
		tagList, err = decodeBase64Field("tagListBase64", r.TagListBase64)
		if err != nil {
			return ipadata.RequestInput{}, err
		}
	}
	var cipk []byte
	if strings.TrimSpace(r.EUICCCIPKIdentifierBase64) != "" {
		cipk, err = decodeBase64Field("euiccCiPKIdentifierBase64", r.EUICCCIPKIdentifierBase64)
		if err != nil {
			return ipadata.RequestInput{}, err
		}
	}
	var transactionID []byte
	if strings.TrimSpace(r.EimTransactionIDBase64) != "" {
		transactionID, err = decodeBase64Field("eimTransactionIdBase64", r.EimTransactionIDBase64)
		if err != nil {
			return ipadata.RequestInput{}, err
		}
	}
	return ipadata.RequestInput{
		TagList:                     tagList,
		EUICCCIPKIdentifierToBeUsed: cipk,
		NotificationSeqNumber:       r.NotificationSeqNumber,
		EuiccPackageResultSeqNumber: r.EuiccPackageResultSeqNumber,
		EimTransactionID:            transactionID,
	}, nil
}

func (h *Handler) initialAssociationConfig(ctx context.Context, tenantID storage.TenantID, service *euiccpkg.Service, request eimConfigRequest) (*protocolasn1.EimConfigurationData, error) {
	eimID := strings.TrimSpace(request.EIMID)
	if eimID == "" && service != nil {
		eimID = service.EimID
	}
	if _, err := parseEIMID(eimID); err != nil {
		return nil, err
	}
	stored, err := h.Store.ReadEIMConfig(ctx, tenantID, eimID)
	if err == nil {
		var config protocolasn1.EimConfigurationData
		if err := protocolasn1.Decode(stored.Data, &config); err != nil {
			return nil, err
		}
		overlayInitialAssociationToken(&config, request.AssociationToken)
		return &config, nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return nil, err
	}
	config, err := request.config(service, eimID)
	if err != nil {
		return nil, err
	}
	overlayInitialAssociationToken(config, request.AssociationToken)
	return config, nil
}

func newEUICCDataResponse(state storage.EUICCState, profiles []storage.ProfileState) euiccDataResponse {
	out := euiccDataResponse{
		EID:                    state.EID,
		EIDValueBase64:         encodeOptionalBase64(state.EIDValue),
		DefaultSMDPAddress:     state.DefaultSMDPAddress,
		RootSMDSAddress:        state.RootSMDSAddress,
		EUICCInfo1Base64:       encodeOptionalBase64(state.EUICCInfo1),
		EUICCInfo2Base64:       encodeOptionalBase64(state.EUICCInfo2),
		IPACapabilitiesBase64:  encodeOptionalBase64(state.IPACapabilities),
		DeviceInfoBase64:       encodeOptionalBase64(state.DeviceInfo),
		EUMCertificateBase64:   encodeOptionalBase64(state.EUMCertificate),
		EUICCCertificateBase64: encodeOptionalBase64(state.EUICCCertificate),
		CertificateIdentifiers: append([]string(nil), state.CertificateIdentifiers...),
		RawPayloadBase64:       encodeOptionalBase64(state.RawPayload),
		UpdatedAt:              state.UpdatedAt,
		Profiles:               make([]profileResponse, 0, len(profiles)),
	}
	for _, profile := range profiles {
		out.Profiles = append(out.Profiles, profileResponse{
			ICCID:       profile.ICCID,
			IsEnabled:   profile.IsEnabled,
			IsFallback:  profile.IsFallback,
			SMDPAddress: profile.SMDPAddress,
		})
	}
	return out
}

func overlayInitialAssociationToken(config *protocolasn1.EimConfigurationData, token *int64) {
	if config == nil || token == nil {
		return
	}
	value := *token
	config.AssociationToken = &value
}

func associatedResponseFromConfig(config *protocolasn1.EimConfigurationData) associatedEIMResponse {
	response := associatedEIMResponse{
		EIMID:            config.EimID,
		CounterValue:     cloneInt64(config.CounterValue),
		AssociationToken: cloneInt64(config.AssociationToken),
	}
	if config.EimFQDN != nil {
		response.EIMFQDN = *config.EimFQDN
	}
	if config.EimIDType != nil {
		value := int64(*config.EimIDType)
		response.EIMIDType = &value
	}
	return response
}

func parseEID(value string) (string, []byte, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	bytes, err := hex.DecodeString(normalized)
	if err != nil || len(bytes) != 16 {
		return "", nil, fmt.Errorf("api: EID must be 32 hex characters")
	}
	return normalized, bytes, nil
}

func parseEIMID(value string) (string, error) {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return "", errors.New("api: eimId must be non-empty")
	}
	if len(normalized) > 128 {
		return "", errors.New("api: eimId must be at most 128 characters")
	}
	return normalized, nil
}

func parseOID(value string) (stdasn1.ObjectIdentifier, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return nil, errors.New("api: defaultSmdpOid must have at least two arcs")
	}
	oid := make(stdasn1.ObjectIdentifier, len(parts))
	for index, part := range parts {
		if part == "" {
			return nil, errors.New("api: defaultSmdpOid contains an empty arc")
		}
		arc, err := strconv.Atoi(part)
		if err != nil || arc < 0 {
			return nil, errors.New("api: defaultSmdpOid arcs must be non-negative integers")
		}
		oid[index] = arc
	}
	if oid[0] > 2 {
		return nil, errors.New("api: defaultSmdpOid first arc must be 0, 1, or 2")
	}
	if oid[0] < 2 && oid[1] > 39 {
		return nil, errors.New("api: defaultSmdpOid second arc must be <= 39 when first arc is 0 or 1")
	}
	return oid, nil
}

func parseICCID(value string) ([]byte, error) {
	normalized := strings.TrimSpace(value)
	bytes, err := hex.DecodeString(normalized)
	if err != nil || len(bytes) == 0 {
		return nil, fmt.Errorf("api: ICCID must be non-empty hex")
	}
	return bytes, nil
}

func decodeBase64Field(name string, value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, fmt.Errorf("api: %s must be base64", name)
	}
	if len(decoded) == 0 {
		return nil, fmt.Errorf("api: %s must not be empty", name)
	}
	return decoded, nil
}

func encodeOptionalBase64(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(value)
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	out := *value
	return &out
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

func decodeOptionalJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) bool {
	body := http.MaxBytesReader(w, r.Body, maxBytes)
	defer func() {
		_ = r.Body.Close()
	}()
	payload, err := io.ReadAll(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return false
	}
	if strings.TrimSpace(string(payload)) == "" {
		return true
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
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

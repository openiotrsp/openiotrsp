package asn1

import (
	"os"
	"regexp"
	"sort"
	"testing"
)

type implementationStatus string

const (
	implementationStructured     implementationStatus = "structured"
	implementationPartial        implementationStatus = "partial"
	implementationRawTLV         implementationStatus = "raw-tlv"
	implementationIntegerAlias   implementationStatus = "integer-alias"
	implementationNotImplemented implementationStatus = "not-implemented"
)

type moduleStructureInventoryEntry struct {
	name   string
	status implementationStatus
	note   string
}

// sgp32ModuleInventory is the explicit implementation inventory for every
// local type definition in spec/SGP.32 v1.3.asn1. It is intentionally separate
// from requiredRoundTripStructures: this list documents the full ASN.1 module,
// while requiredRoundTripStructures gates the narrower Part 3 Stage 2 scope
// that is currently implemented and round-trip tested.
var sgp32ModuleInventory = []moduleStructureInventoryEntry{
	{"EuiccPackageRequest", implementationStructured, "Part 3 eUICC Package request, tag BF51."},
	{"EuiccPackageSigned", implementationStructured, "Part 3 signed request payload."},
	{"EuiccPackage", implementationStructured, "Part 3 CHOICE of PSMO or ECO list."},
	{"EimConfigurationData", implementationStructured, "Part 3 ECO configuration data; X.509 choices are raw TLVs."},
	{"EimIdType", implementationIntegerAlias, "Part 3 INTEGER enumeration."},
	{"EimSupportedProtocol", implementationStructured, "Part 3 BIT STRING."},
	{"Eco", implementationStructured, "Part 3 eIM Configuration Operation CHOICE."},
	{"Psmo", implementationStructured, "Part 3 Profile State Management Operation CHOICE."},
	{"IpaEuiccDataRequest", implementationStructured, "Stage 12 BF52 IPA-directed data request with tagList and sequence search criteria."},
	{"ProfileDownloadTriggerRequest", implementationStructured, "Part 3 profile download trigger, tag BF54."},
	{"ProfileDownloadData", implementationStructured, "Part 3 profile download data CHOICE."},
	{"EimAcknowledgements", implementationStructured, "Part 3 acknowledgements, tag BF53."},
	{"SequenceNumber", implementationIntegerAlias, "Part 3 INTEGER wrapped by EimAcknowledgements."},
	{"EuiccPackageResult", implementationStructured, "Part 3 result wrapper, tag BF51."},
	{"EuiccPackageResultSigned", implementationStructured, "Part 3 signed result."},
	{"EuiccPackageResultDataSigned", implementationStructured, "Part 3 signed result payload."},
	{"EuiccResultData", implementationRawTLV, "Part 3 tag-validated CHOICE; specific result alternatives are raw or integer aliases."},
	{"EuiccPackageErrorSigned", implementationStructured, "Part 3 signed package error."},
	{"EuiccPackageErrorDataSigned", implementationStructured, "Part 3 signed package error payload."},
	{"EuiccPackageErrorCode", implementationIntegerAlias, "Part 3 INTEGER enumeration."},
	{"EuiccPackageUnsignedErrorCode", implementationIntegerAlias, "Part 3 INTEGER enumeration."},
	{"EuiccPackageErrorUnsigned", implementationStructured, "Part 3 unsigned package error."},
	{"ConfigureImmediateEnableResult", implementationIntegerAlias, "Part 3 EuiccResultData INTEGER alternative."},
	{"EnableProfileResult", implementationIntegerAlias, "Part 3 EuiccResultData INTEGER alternative."},
	{"DisableProfileResult", implementationIntegerAlias, "Part 3 EuiccResultData INTEGER alternative."},
	{"DeleteProfileResult", implementationIntegerAlias, "Part 3 EuiccResultData INTEGER alternative."},
	{"ProfileInfoListResponse", implementationStructured, "Part 3 response; decodes profile ICCID, state, and fallback attribute."},
	{"ProfileInfoListError", implementationIntegerAlias, "Part 3 INTEGER enumeration."},
	{"RollbackProfileResult", implementationIntegerAlias, "Part 3 EuiccResultData INTEGER alternative."},
	{"SetFallbackAttributeResult", implementationIntegerAlias, "Part 3 EuiccResultData INTEGER alternative."},
	{"UnsetFallbackAttributeResult", implementationIntegerAlias, "Part 3 EuiccResultData INTEGER alternative."},
	{"AddEimResult", implementationStructured, "Part 3 CHOICE of associationToken or result code."},
	{"DeleteEimResult", implementationIntegerAlias, "Part 3 EuiccResultData INTEGER alternative."},
	{"UpdateEimResult", implementationIntegerAlias, "Part 3 EuiccResultData INTEGER alternative."},
	{"ListEimResult", implementationStructured, "Part 3 CHOICE of EimIdInfo list or error; decodes AUTOMATIC TAGS [0]/[1] and bare SEQUENCE/INTEGER."},
	{"EimIdInfo", implementationStructured, "Part 3 ListEimResult entry."},
	{"IpaEuiccDataErrorCode", implementationIntegerAlias, "Stage 12 IPA eUICC data response error enumeration."},
	{"IpaEuiccDataResponseError", implementationStructured, "Stage 12 IPA eUICC data response error."},
	{"IpaEuiccDataResponse", implementationStructured, "Stage 12 BF52 response; decodes data or error."},
	{"PendingNotificationList", implementationStructured, "Non-compact pending notification list used by IPA data and ESipa result acknowledgements."},
	{"EuiccPackageResultList", implementationStructured, "Stage 12 package-result list inside IpaEuiccData."},
	{"IpaEuiccData", implementationPartial, "Stage 12 decodes eUICC info, IPA capabilities, profiles, certificates as raw TLV, and unknown objects as raw TLV."},
	{"ProfileDownloadTriggerResult", implementationPartial, "Part 3 direct download result; decodes typed ProfileInstallationResult success/failure while preserving imported result detail TLVs."},
	{"ISDRProprietaryApplicationTemplateIoT", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"IpaeActivationRequest", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"IpaeActivationResponse", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"IpaCapabilities", implementationStructured, "Stage 12 decodes IPA feature and protocol bit strings."},
	{"ProfileInfo", implementationPartial, "Profile list model decodes the eIM-persisted ICCID, state, and fallback attribute fields."},
	{"UpdateMetadataRequest", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"StoreMetadataRequest", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"AuthenticateClientRequest", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"EUICCInfo2", implementationNotImplemented, "Deferred; SGP.22 EUICCInfo1 reuse is smoke-tested separately."},
	{"IoTSpecificInfo", implementationNotImplemented, "Deferred EUICCInfo2 substructure."},
	{"IpaMode", implementationNotImplemented, "Deferred EUICCInfo2 substructure."},
	{"AddInitialEimRequest", implementationNotImplemented, "ES10b IPA-to-eUICC bootstrap deferred; eIM emits EimConfigurationData only."},
	{"AddInitialEimResponse", implementationNotImplemented, "ES10b IPA-to-eUICC bootstrap deferred; eIM consumes the returned association token as state."},
	{"EuiccMemoryResetRequest", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"EuiccMemoryResetResponse", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"GetCertsRequest", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"GetCertsResponse", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"RetrieveNotificationsListRequest", implementationNotImplemented, "Deferred notification model."},
	{"RetrieveNotificationsListResponse", implementationNotImplemented, "Deferred notification model."},
	{"ImmediateEnableRequest", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"ImmediateEnableResponse", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"ProfileRollbackRequest", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"ProfileRollbackResponse", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"ConfigureImmediateProfileEnablingRequest", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"ConfigureImmediateProfileEnablingResponse", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"GetEimConfigurationDataRequest", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"GetEimConfigurationDataResponse", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"ExecuteFallbackMechanismRequest", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"ExecuteFallbackMechanismResponse", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"ReturnFromFallbackRequest", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"ReturnFromFallbackResponse", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"EnableEmergencyProfileRequest", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"EnableEmergencyProfileResponse", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"DisableEmergencyProfileRequest", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"DisableEmergencyProfileResponse", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"GetConnectivityParametersRequest", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"GetConnectivityParametersResponse", implementationNotImplemented, "Out of Part 3 Stage 2 package/message scope."},
	{"ConnectivityParameters", implementationNotImplemented, "Deferred connectivity parameters substructure."},
	{"ConnectivityParametersError", implementationNotImplemented, "Deferred connectivity parameters substructure."},
	{"SetDefaultDpAddressRequest", implementationStructured, "Part 3 PSMO request, tag BF65."},
	{"SetDefaultDpAddressResponse", implementationStructured, "Part 3 EuiccResultData response, tag BF65."},
	{"PrepareDownloadResponse", implementationRawTLV, "esipa expands compactDownloadResponseOk into SGP.22 PrepareDownloadResponseOk before the ES9+ relay; the asn1 package keeps the TLV raw."},
	{"CompactPrepareDownloadResponseOk", implementationRawTLV, "esipa rebuilds euiccSigned2 from the compact form plus the SM-DP+ transactionId before ES9+."},
	{"CompactEuiccSigned2", implementationRawTLV, "esipa reads euiccOtpk and optional hashCc from the compact SEQUENCE when rebuilding euiccSigned2."},
	{"EuiccSigned1", implementationRawTLV, "esipa rebuilds EuiccSigned1 from stored EUICCInfo2, serverSigned1, and ctxParams1 when the IPA sends compactEuiccSigned1."},
	{"AuthenticateResponseOk", implementationRawTLV, "esipa emits SGP.22 AuthenticateResponseOk from a compact ESipa authenticate response before the ES9+ relay."},
	{"AuthenticateServerResponse", implementationRawTLV, "esipa unwraps compactAuthenticateResponseOk (CHOICE [2]) and forwards SGP.22 authenticateResponseOk."},
	{"CompactAuthenticateResponseOk", implementationRawTLV, "esipa expands this arm into AuthenticateResponseOk using stored EUICCInfo2, certificates, and remembered ctxParams1."},
	{"CompactEuiccSigned1", implementationRawTLV, "esipa replaces EUICCInfo2.extCardResource with this value when rebuilding the signed EuiccSigned1."},
	{"PendingNotification", implementationPartial, "Non-compact profile-install and other-signed notifications are decoded enough for EID, sequence, kind, and payload persistence."},
	{"ProfileInstallationResult", implementationPartial, "Decodes ProfileInstallationResultData metadata and finalResult success/failure; detailed SGP.22 success/error payloads remain raw TLV."},
	{"CompactProfileInstallationResult", implementationRawTLV, "esipa expands this into ProfileInstallationResult before ES9+.HandleNotification."},
	{"CompactProfileInstallationResultData", implementationRawTLV, "esipa reads transactionId, seqNumber, iccidPresent, and compactFinalResult when rebuilding the signed PIR."},
	{"CompactSuccessResult", implementationRawTLV, "esipa restores the full ISD-P AID and the default success simaResponse when the compact form omits them."},
	{"CompactOtherSignedNotification", implementationNotImplemented, "Deferred compact notification model."},
	{"CancelSessionResponse", implementationRawTLV, "Stage 14 indirect-download relay preserves cancel-session response bytes; structured decoding remains deferred."},
	{"CompactCancelSessionResponseOk", implementationNotImplemented, "Deferred compact cancellation flow."},
	{"CompactEuiccCancelSessionSigned", implementationNotImplemented, "Deferred compact cancellation flow."},
	{"EsipaMessageFromIpaToEim", implementationRawTLV, "Top-level ESipa envelope validates allowed IPA-to-eIM tags and preserves payload TLV."},
	{"EsipaMessageFromEimToIpa", implementationRawTLV, "Top-level ESipa envelope validates allowed eIM-to-IPA tags and preserves payload TLV."},
	{"InitiateAuthenticationRequestEsipa", implementationRawTLV, "Stage 14 indirect-download: esipa restores omitted smdpAddress/euiccInfo1 from the pending trigger and stored EUICCInfo1 before relay; relay adapts ESipa BF39 to ES9+ by stripping eimTransactionId [2]."},
	{"InitiateAuthenticationResponseEsipa", implementationRawTLV, "esipa returns the SM-DP+ BF39 plus matchingId and ctxParams1 when IPA capability bits 2 and 3 require them, or BF39 INTEGER errors (50/51/52/127)."},
	{"InitiateAuthenticationOkEsipa", implementationRawTLV, "esipa appends universal UTF8String matchingId and explicit ctxParams1 [2] after serverCertificate when the IPA capabilities require them."},
	{"AuthenticateClientRequestEsipa", implementationRawTLV, "esipa expands compact BF38 into SGP.22 AuthenticateResponseOk before the ES9+ relay and forwards a full BF38 unchanged."},
	{"AuthenticateClientResponseEsipa", implementationRawTLV, "Stage 14 indirect-download relay returns the raw SM-DP+ BF3B response unchanged."},
	{"AuthenticateClientOkDPEsipa", implementationRawTLV, "Stage 14 relay preserves DP response contents; structured OK decoding remains deferred."},
	{"AuthenticateClientOkDSEsipa", implementationRawTLV, "Stage 14 relay preserves DS response contents; structured OK decoding remains deferred."},
	{"GetBoundProfilePackageRequestEsipa", implementationRawTLV, "esipa expands compact BF21 into SGP.22 PrepareDownloadResponseOk before the ES9+ relay and forwards a full BF21 unchanged."},
	{"GetBoundProfilePackageResponseEsipa", implementationRawTLV, "Stage 14 indirect-download relay returns the raw SM-DP+ BF3A response unchanged."},
	{"GetBoundProfilePackageOkEsipa", implementationRawTLV, "Stage 14 relay preserves BPP response contents; structured decoding remains deferred."},
	{"HandleNotificationEsipa", implementationRawTLV, "esipa expands compactProfileInstallationResult into ProfileInstallationResult before ES9+.HandleNotification and returns empty 204 on success."},
	{"CancelSessionRequestEsipa", implementationRawTLV, "Stage 14 indirect-download relay routes by BF41 and forwards the raw cancel-session TLV unchanged."},
	{"CancelSessionResponseEsipa", implementationRawTLV, "Stage 14 indirect-download relay returns the raw SM-DP+ BF41 response unchanged."},
	{"CancelSessionOk", implementationRawTLV, "Stage 14 relay preserves cancel-session OK contents; structured decoding remains deferred."},
	{"StateChangeCause", implementationIntegerAlias, "Part 3 GetEimPackageRequest INTEGER enumeration."},
	{"GetEimPackageRequest", implementationStructured, "Part 3 ESipa request, tag BF4F."},
	{"GetEimPackageResponse", implementationPartial, "Part 3 ESipa response; IpaEuiccDataRequest branch is raw TLV."},
	{"EimPackageResultErrorCode", implementationIntegerAlias, "Part 3 ESipa package/result error enumeration."},
	{"EimPackageResultResponseError", implementationStructured, "Part 3 ESipa result error with optional transaction ID."},
	{"EimPackageResult", implementationStructured, "Part 3 result CHOICE with typed package, notification, IPA data, download, and error branches while preserving raw payload bytes."},
	{"ProvideEimPackageResult", implementationStructured, "Part 3 ESipa result carrier with typed nested EimPackageResult."},
	{"ProvideEimPackageResultResponse", implementationStructured, "Part 3 ESipa result response CHOICE with acknowledgements, empty, and error branches."},
	{"TransferEimPackageRequest", implementationPartial, "Part 3 ESipa transfer request; IpaEuiccDataRequest branch is raw TLV."},
	{"TransferEimPackageResponse", implementationStructured, "Part 3 ESipa transfer response CHOICE with typed local result, ack/error, IPA data, and CID branches while preserving raw child TLV."},
	{"EimPackageReceivedWithCid", implementationStructured, "Part 3 transfer acknowledgement with optional transaction-ID/EID correlation."},
	{"EimPackageErrorWithCid", implementationStructured, "Part 3 transfer error with optional transaction-ID/EID correlation."},
}

func TestSGP32ModuleInventoryMatchesASN1Module(t *testing.T) {
	t.Parallel()

	if _, err := os.Stat("../spec/SGP.32 v1.3.asn1"); os.IsNotExist(err) {
		t.Skip("spec module not present (local-only); skipping inventory cross-check")
	}

	moduleTypes := parseSGP32ModuleTypes(t)
	inventory := map[string]moduleStructureInventoryEntry{}
	for _, entry := range sgp32ModuleInventory {
		if entry.note == "" {
			t.Errorf("%s inventory entry must document implementation scope", entry.name)
		}
		if !validImplementationStatus(entry.status) {
			t.Errorf("%s inventory entry has unknown status %q", entry.name, entry.status)
		}
		if _, ok := inventory[entry.name]; ok {
			t.Errorf("duplicate inventory entry for %s", entry.name)
		}
		inventory[entry.name] = entry
	}

	for _, name := range moduleTypes {
		if _, ok := inventory[name]; !ok {
			t.Errorf("SGP.32 module type %s is missing from sgp32ModuleInventory", name)
		}
	}
	moduleSet := make(map[string]bool, len(moduleTypes))
	for _, name := range moduleTypes {
		moduleSet[name] = true
	}
	for name := range inventory {
		if !moduleSet[name] {
			t.Errorf("inventory entry %s is not a local type in spec/SGP.32 v1.3.asn1", name)
		}
	}
}

func parseSGP32ModuleTypes(t *testing.T) []string {
	t.Helper()

	module, err := os.ReadFile("../spec/SGP.32 v1.3.asn1")
	if err != nil {
		t.Fatalf("read SGP.32 ASN.1 module: %v", err)
	}
	// ASN.1 type references may contain hyphens, and the assignment marker can
	// legally wrap to the following line. The current SGP.32 module uses
	// alphanumeric CamelCase names with same-line ::= assignments, but the wider
	// pattern keeps the inventory gate honest if a future module revision adds a
	// hyphenated or wrapped type assignment.
	matches := regexp.MustCompile(`(?m)^([A-Za-z][A-Za-z0-9-]*)\s*(?:\r?\n\s*)?::=`).FindAllSubmatch(module, -1)
	names := make([]string, 0, len(matches))
	for _, match := range matches {
		names = append(names, string(match[1]))
	}
	sort.Strings(names)
	return names
}

func validImplementationStatus(status implementationStatus) bool {
	switch status {
	case implementationStructured,
		implementationPartial,
		implementationRawTLV,
		implementationIntegerAlias,
		implementationNotImplemented:
		return true
	default:
		return false
	}
}

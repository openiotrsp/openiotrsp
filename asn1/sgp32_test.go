package asn1

import (
	"encoding/hex"
	"testing"

	"github.com/damonto/euicc-go/bertlv"
	sgp22 "github.com/damonto/euicc-go/v2"
)

type roundTripCase struct {
	name    string
	covers  []string
	value   Marshaler
	newFunc func() Unmarshaler
	tagHex  string
}

type knownAnswerDERCase struct {
	name    string
	source  string
	value   Marshaler
	wantHex string
}

func TestSGP22ReuseSmoke(t *testing.T) {
	t.Parallel()

	request := &sgp22.ProfileInfoListRequest{
		Tags: []bertlv.Tag{tagEID},
	}
	tlv, err := request.MarshalBERTLV()
	if err != nil {
		t.Fatalf("MarshalBERTLV() error = %v", err)
	}
	encoded, err := tlv.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	assertHex(t, encoded, "bf2d035c015a")
}

func TestRoundTripAndCanonicalReencode(t *testing.T) {
	t.Parallel()

	cases := roundTripCases()
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			encoded, err := Encode(tc.value)
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			assertTagPrefix(t, encoded, tc.tagHex)

			decoded := tc.newFunc()
			if err := Decode(encoded, decoded); err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			reencoded, err := Encode(decoded.(Marshaler))
			if err != nil {
				t.Fatalf("re-Encode() error = %v", err)
			}
			if string(reencoded) != string(encoded) {
				t.Fatalf("re-encode mismatch\n got %x\nwant %x", reencoded, encoded)
			}
		})
	}
}

func TestRoundTripCoverageGate(t *testing.T) {
	t.Parallel()

	// This gate enforces the Part 3 Stage 2 implementation scope, not the full
	// SGP.32 ASN.1 module. The full module inventory is documented and checked
	// separately in TestSGP32ModuleInventoryMatchesASN1Module.
	covered := map[string]bool{}
	for _, tc := range roundTripCases() {
		for _, name := range tc.covers {
			covered[name] = true
		}
	}
	for _, required := range requiredRoundTripStructures {
		if !covered[required] {
			t.Errorf("missing round-trip coverage for %s", required)
		}
	}
}

func TestKnownAnswerDER(t *testing.T) {
	t.Parallel()

	request := sampleEuiccPackageRequest()
	request.EuiccPackageSigned.EimID = "eim"
	request.EuiccPackageSigned.EID = []byte{0x01, 0x02}
	request.EuiccPackageSigned.EimTransactionID = nil
	request.EuiccPackageSigned.EuiccPackage = EuiccPackage{
		Kind: EuiccPackagePSMO,
		PSMOs: []Psmo{{
			Operation: PsmoEnable,
			ICCID:     []byte{0x98, 0x10},
		}},
	}
	request.EimSignature = []byte{0xaa, 0xbb}

	for _, tc := range knownAnswerDERCases(request) {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.source == "" {
				t.Fatalf("%s known-answer vector must document its independent source", tc.name)
			}
			encoded, err := Encode(tc.value)
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			assertHex(t, encoded, tc.wantHex)
		})
	}
}

func TestMalformedInputReturnsError(t *testing.T) {
	t.Parallel()

	for _, tc := range roundTripCases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			encoded, err := Encode(tc.value)
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			inputs := [][]byte{
				nil,
				encoded[:len(encoded)-1],
				{0x00, 0x00},
				{0xff, 0x01, 0x00},
			}
			for _, input := range inputs {
				assertDecodeErrorNoPanic(t, input, tc.newFunc())
			}
		})
	}
}

// requiredRoundTripStructures is the exact set enforced by
// TestRoundTripCoverageGate. A structure is covered only when at least one
// roundTripCase lists its ASN.1 type name in covers, then encode -> decode ->
// re-encode produces byte-identical DER. This list follows the user's Part 3.1
// Stage 2 scope: new eUICC Package, ECO/PSMO, profile download trigger,
// eUICC Package Result, acknowledgement, and ESipa package-envelope structures.
// It deliberately does not claim that every local definition in the SGP.32
// module is fully modeled; see sgp32ModuleInventory for that explicit status.
var requiredRoundTripStructures = []string{
	"EuiccPackageRequest",
	"EuiccPackageSigned",
	"EuiccPackage",
	"Psmo",
	"Eco",
	"EimConfigurationData",
	"EimIdType",
	"EimSupportedProtocol",
	"ProfileDownloadTriggerRequest",
	"ProfileDownloadData",
	"EuiccPackageResult",
	"EuiccPackageResultSigned",
	"EuiccPackageResultDataSigned",
	"EuiccResultData",
	"EuiccPackageErrorSigned",
	"EuiccPackageErrorDataSigned",
	"EuiccPackageErrorCode",
	"EuiccPackageUnsignedErrorCode",
	"EuiccPackageErrorUnsigned",
	"EimAcknowledgements",
	"SequenceNumber",
	"ProfileInfoListResponse",
	"AddEimResult",
	"ListEimResult",
	"EimIdInfo",
	"SetDefaultDpAddressRequest",
	"SetDefaultDpAddressResponse",
	"TransferEimPackageRequest",
	"TransferEimPackageResponse",
	"GetEimPackageRequest",
	"GetEimPackageResponse",
	"EimPackageResult",
	"ProvideEimPackageResult",
	"ProvideEimPackageResultResponse",
	"ESipaMessageFromIpaToEim",
	"ESipaMessageFromEimToIpa",
}

func knownAnswerDERCases(request *EuiccPackageRequest) []knownAnswerDERCase {
	return []knownAnswerDERCase{
		{
			name: "EimAcknowledgements",
			source: "Independent OpenSSL DER fixture. Generated with: " +
				"`openssl asn1parse -genconf` using `asn1=IMPLICIT:83,SEQUENCE:seq`, " +
				"`n1=IMPLICIT:0,INTEGER:1`, and `n2=IMPLICIT:0,INTEGER:2`. " +
				"No SGP.33-1/spec byte example was found for this minimal fixture.",
			value:   &EimAcknowledgements{SequenceNumbers: []SequenceNumber{1, 2}},
			wantHex: "bf5306800101800102",
		},
		{
			name: "ProfileDownloadTriggerRequest",
			source: "Independent OpenSSL DER fixture. Generated with: " +
				"`openssl asn1parse -genconf` using `asn1=IMPLICIT:84,SEQUENCE:trigger`, " +
				"`profileDownloadData=IMPLICIT:0,SEQUENCE:pdd`, " +
				"`activationCode=IMPLICIT:0,UTF8:ACT`, and " +
				"`eimTransactionId=IMPLICIT:2,FORMAT:HEX,OCTETSTRING:0102`. " +
				"No SGP.33-1/spec byte example was found for this minimal fixture.",
			value: &ProfileDownloadTriggerRequest{
				ProfileDownloadData: &ProfileDownloadData{
					Kind:           ProfileDownloadActivationCode,
					ActivationCode: "ACT",
				},
				EimTransactionID: []byte{0x01, 0x02},
			},
			wantHex: "bf540ba005800341435482020102",
		},
		{
			name: "ProfileDownloadTriggerRequest default SMDP",
			source: "Independent OpenSSL DER fixture. Generated with: " +
				"`openssl asn1parse -genconf` using `asn1=IMPLICIT:84,SEQUENCE:trigger`, " +
				"`profileDownloadData=IMPLICIT:0,SEQUENCE:pdd`, " +
				"`contactDefaultSmdp=IMPLICIT:1,NULL`, and " +
				"`eimTransactionId=IMPLICIT:2,FORMAT:HEX,OCTETSTRING:01`. " +
				"No SGP.33-1/spec byte example was found for this minimal fixture.",
			value: &ProfileDownloadTriggerRequest{
				ProfileDownloadData: &ProfileDownloadData{
					Kind: ProfileDownloadContactDefaultSMDP,
				},
				EimTransactionID: []byte{0x01},
			},
			wantHex: "bf5407a0028100820101",
		},
		{
			name: "EuiccPackageRequest",
			source: "Independent DER fixture regenerated outside the OpenIoTRSP encoder. " +
				"The context-specific and universal TLV skeleton was generated with " +
				"`openssl asn1parse -genconf`; the application-class 5A and 5F37 TLVs " +
				"were inserted from the explicit SGP.32 ASN.1 tag assignments because " +
				"OpenSSL ASN1_generate cannot emit these high application-class tags. " +
				"The final DER was validated with `openssl asn1parse -inform DER`. " +
				"No SGP.33-1/spec byte example was found for this minimal fixture.",
			value:   request,
			wantHex: "bf511b3014800365696d5a020102810101a006a3045a0298105f3702aabb",
		},
	}
}

func roundTripCases() []roundTripCase {
	result, err := IntegerEuiccResult(3, 0)
	if err != nil {
		panic(err)
	}
	errorCode := EuiccPackageUnsignedErrorCode(15)
	assoc := int64(77)
	profileErr := ProfileInfoListError(127)
	addCode := AddEimResultCode(0)
	listErr := ListEimError(127)
	stateCause := StateChangeCause(0)
	profileState := ProfileStateEnabled
	getError := EimPackageResultErrorCode(1)
	eimType := EimIDTypeFQDN

	epr := sampleEuiccPackageResult()
	eprTLV, err := epr.MarshalBERTLV()
	if err != nil {
		panic(err)
	}
	transferRequest := &TransferEimPackageRequest{
		Kind:                TransferEuiccPackageRequest,
		EuiccPackageRequest: sampleEuiccPackageRequest(),
	}
	transferTLV, err := transferRequest.MarshalBERTLV()
	if err != nil {
		panic(err)
	}

	return []roundTripCase{
		{
			name:    "EimConfigurationData",
			covers:  []string{"EimConfigurationData", "EimIdType", "EimSupportedProtocol"},
			value:   sampleEimConfigurationData(),
			newFunc: func() Unmarshaler { return new(EimConfigurationData) },
			tagHex:  "30",
		},
		{
			name:    "EcoAddEim",
			covers:  []string{"Eco"},
			value:   &Eco{Operation: EcoAddEIM, Config: sampleEimConfigurationData()},
			newFunc: func() Unmarshaler { return new(Eco) },
			tagHex:  "a8",
		},
		{
			name:    "PsmoEnable",
			covers:  []string{"Psmo"},
			value:   &Psmo{Operation: PsmoEnable, ICCID: []byte{0x98, 0x10}, RollbackFlag: true},
			newFunc: func() Unmarshaler { return new(Psmo) },
			tagHex:  "a3",
		},
		{
			name: "EuiccPackage",
			covers: []string{
				"EuiccPackage",
			},
			value:   &EuiccPackage{Kind: EuiccPackageECO, ECOs: []Eco{{Operation: EcoDeleteEIM, EimID: "eim"}}},
			newFunc: func() Unmarshaler { return new(EuiccPackage) },
			tagHex:  "a1",
		},
		{
			name:    "EuiccPackageSigned",
			covers:  []string{"EuiccPackageSigned"},
			value:   &sampleEuiccPackageRequest().EuiccPackageSigned,
			newFunc: func() Unmarshaler { return new(EuiccPackageSigned) },
			tagHex:  "30",
		},
		{
			name:    "EuiccPackageRequest",
			covers:  []string{"EuiccPackageRequest"},
			value:   sampleEuiccPackageRequest(),
			newFunc: func() Unmarshaler { return new(EuiccPackageRequest) },
			tagHex:  "bf51",
		},
		{
			name:    "ProfileDownloadData",
			covers:  []string{"ProfileDownloadData"},
			value:   &ProfileDownloadData{Kind: ProfileDownloadContactSMDS, SMDSAddress: stringPtr("smds.example")},
			newFunc: func() Unmarshaler { return new(ProfileDownloadData) },
			tagHex:  "a2",
		},
		{
			name:    "ProfileDownloadData default SMDP",
			covers:  []string{"ProfileDownloadData"},
			value:   &ProfileDownloadData{Kind: ProfileDownloadContactDefaultSMDP},
			newFunc: func() Unmarshaler { return new(ProfileDownloadData) },
			tagHex:  "81",
		},
		{
			name:    "ProfileDownloadTriggerRequest",
			covers:  []string{"ProfileDownloadTriggerRequest"},
			value:   &ProfileDownloadTriggerRequest{ProfileDownloadData: &ProfileDownloadData{Kind: ProfileDownloadActivationCode, ActivationCode: "ACT"}, EimTransactionID: []byte{1}},
			newFunc: func() Unmarshaler { return new(ProfileDownloadTriggerRequest) },
			tagHex:  "bf54",
		},
		{
			name: "ProfileDownloadTriggerResult",
			covers: []string{
				"ProfileDownloadTriggerResult",
			},
			value: &ProfileDownloadTriggerResult{
				EimTransactionID: []byte{1},
				ProfileInstallationRaw: bertlv.NewChildren(tagProfileInstall,
					bertlv.NewChildren(tagProfileInstallData,
						bertlv.NewChildren(tagProfileFinalResult,
							bertlv.NewChildren(bertlv.ContextSpecific.Constructed(0)),
						),
					),
				),
			},
			newFunc: func() Unmarshaler { return new(ProfileDownloadTriggerResult) },
			tagHex:  "bf54",
		},
		{
			name:    "EimAcknowledgements",
			covers:  []string{"EimAcknowledgements", "SequenceNumber"},
			value:   &EimAcknowledgements{SequenceNumbers: []SequenceNumber{1, 2}},
			newFunc: func() Unmarshaler { return new(EimAcknowledgements) },
			tagHex:  "bf53",
		},
		{
			name:    "EuiccResultData",
			covers:  []string{"EuiccResultData"},
			value:   &result,
			newFunc: func() Unmarshaler { return new(EuiccResultData) },
			tagHex:  "83",
		},
		{
			name:    "EuiccPackageResultDataSigned",
			covers:  []string{"EuiccPackageResultDataSigned"},
			value:   &sampleEuiccPackageResult().Signed.Data,
			newFunc: func() Unmarshaler { return new(EuiccPackageResultDataSigned) },
			tagHex:  "30",
		},
		{
			name:    "EuiccPackageResultSigned",
			covers:  []string{"EuiccPackageResultSigned"},
			value:   sampleEuiccPackageResult().Signed,
			newFunc: func() Unmarshaler { return new(EuiccPackageResultSigned) },
			tagHex:  "30",
		},
		{
			name:    "EuiccPackageErrorDataSigned",
			covers:  []string{"EuiccPackageErrorDataSigned", "EuiccPackageErrorCode"},
			value:   &EuiccPackageErrorDataSigned{EimID: "eim", CounterValue: 1, ErrorCode: EuiccPackageErrorCode(127)},
			newFunc: func() Unmarshaler { return new(EuiccPackageErrorDataSigned) },
			tagHex:  "30",
		},
		{
			name:    "EuiccPackageErrorSigned",
			covers:  []string{"EuiccPackageErrorSigned"},
			value:   &EuiccPackageErrorSigned{Data: EuiccPackageErrorDataSigned{EimID: "eim", CounterValue: 1, ErrorCode: 127}, EuiccSignEPE: []byte{9}},
			newFunc: func() Unmarshaler { return new(EuiccPackageErrorSigned) },
			tagHex:  "30",
		},
		{
			name:    "EuiccPackageErrorUnsigned",
			covers:  []string{"EuiccPackageErrorUnsigned", "EuiccPackageUnsignedErrorCode"},
			value:   &EuiccPackageErrorUnsigned{EimID: "eim", AssociationToken: &assoc, ErrorCode: &errorCode},
			newFunc: func() Unmarshaler { return new(EuiccPackageErrorUnsigned) },
			tagHex:  "30",
		},
		{
			name:    "EuiccPackageResult",
			covers:  []string{"EuiccPackageResult"},
			value:   sampleEuiccPackageResult(),
			newFunc: func() Unmarshaler { return new(EuiccPackageResult) },
			tagHex:  "bf51",
		},
		{
			name:    "ProfileInfoListResponse",
			covers:  []string{"ProfileInfoListResponse"},
			value:   &ProfileInfoListResponse{Error: &profileErr},
			newFunc: func() Unmarshaler { return new(ProfileInfoListResponse) },
			tagHex:  "bf2d",
		},
		{
			name:    "ProfileInfo",
			covers:  []string{"ProfileInfo"},
			value:   &ProfileInfo{ICCID: []byte{0x89, 0x10}, ProfileState: &profileState, FallbackAttribute: true},
			newFunc: func() Unmarshaler { return new(ProfileInfo) },
			tagHex:  "e3",
		},
		{
			name:    "AddEimResult",
			covers:  []string{"AddEimResult"},
			value:   &AddEimResult{Code: &addCode},
			newFunc: func() Unmarshaler { return new(AddEimResult) },
			tagHex:  "02",
		},
		{
			name:    "EimIDInfo",
			covers:  []string{"EimIdInfo"},
			value:   &EimIDInfo{EimID: "eim", EimIDType: &eimType},
			newFunc: func() Unmarshaler { return new(EimIDInfo) },
			tagHex:  "30",
		},
		{
			name:    "ListEimResult",
			covers:  []string{"ListEimResult"},
			value:   &ListEimResult{Error: &listErr},
			newFunc: func() Unmarshaler { return new(ListEimResult) },
			tagHex:  "02",
		},
		{
			name:    "SetDefaultDPAddressRequest",
			covers:  []string{"SetDefaultDpAddressRequest"},
			value:   &SetDefaultDPAddressRequest{DefaultDPAddress: "smdp.example"},
			newFunc: func() Unmarshaler { return new(SetDefaultDPAddressRequest) },
			tagHex:  "bf65",
		},
		{
			name:    "SetDefaultDPAddressResponse",
			covers:  []string{"SetDefaultDpAddressResponse"},
			value:   &SetDefaultDPAddressResponse{Result: 0},
			newFunc: func() Unmarshaler { return new(SetDefaultDPAddressResponse) },
			tagHex:  "bf65",
		},
		{
			name:    "TransferEimPackageRequest",
			covers:  []string{"TransferEimPackageRequest"},
			value:   transferRequest,
			newFunc: func() Unmarshaler { return new(TransferEimPackageRequest) },
			tagHex:  "bf4e",
		},
		{
			name:    "TransferEimPackageResponse",
			covers:  []string{"TransferEimPackageResponse"},
			value:   &TransferEimPackageResponse{Raw: eprTLV},
			newFunc: func() Unmarshaler { return new(TransferEimPackageResponse) },
			tagHex:  "bf4e",
		},
		{
			name:    "GetEimPackageRequest",
			covers:  []string{"GetEimPackageRequest"},
			value:   &GetEimPackageRequest{EID: []byte{1, 2}, NotifyStateChange: true, StateChangeCause: &stateCause, RPLMN: []byte{0x21, 0x43, 0x65}},
			newFunc: func() Unmarshaler { return new(GetEimPackageRequest) },
			tagHex:  "bf4f",
		},
		{
			name:    "GetEimPackageResponse",
			covers:  []string{"GetEimPackageResponse"},
			value:   &GetEimPackageResponse{Kind: GetEimPackageError, Error: &getError},
			newFunc: func() Unmarshaler { return new(GetEimPackageResponse) },
			tagHex:  "bf4f",
		},
		{
			name:    "EimPackageResult",
			covers:  []string{"EimPackageResult"},
			value:   &EimPackageResult{Raw: eprTLV},
			newFunc: func() Unmarshaler { return new(EimPackageResult) },
			tagHex:  "bf51",
		},
		{
			name:    "ProvideEimPackageResult",
			covers:  []string{"ProvideEimPackageResult"},
			value:   &ProvideEimPackageResult{EID: []byte{1, 2}, EimPackageResult: EimPackageResult{Raw: eprTLV}},
			newFunc: func() Unmarshaler { return new(ProvideEimPackageResult) },
			tagHex:  "bf50",
		},
		{
			name:    "ProvideEimPackageResultResponse",
			covers:  []string{"ProvideEimPackageResultResponse"},
			value:   &ProvideEimPackageResultResponse{Raw: (&EimAcknowledgements{SequenceNumbers: []SequenceNumber{1}}).mustTLV()},
			newFunc: func() Unmarshaler { return new(ProvideEimPackageResultResponse) },
			tagHex:  "bf50",
		},
		{
			name:    "ESipaMessageFromIpaToEim",
			covers:  []string{"ESipaMessageFromIpaToEim"},
			value:   &ESipaMessageFromIpaToEim{Raw: transferTLV},
			newFunc: func() Unmarshaler { return new(ESipaMessageFromIpaToEim) },
			tagHex:  "bf4e",
		},
		{
			name:    "ESipaMessageFromEimToIpa",
			covers:  []string{"ESipaMessageFromEimToIpa"},
			value:   &ESipaMessageFromEimToIpa{Raw: transferTLV},
			newFunc: func() Unmarshaler { return new(ESipaMessageFromEimToIpa) },
			tagHex:  "bf4e",
		},
	}
}

func sampleEimConfigurationData() *EimConfigurationData {
	counter := int64(1)
	association := int64(2)
	idType := EimIDTypeFQDN
	protocols := EimSupportedProtocol{true, false, true}
	return &EimConfigurationData{
		EimID:                   "eim.example",
		EimFQDN:                 stringPtr("eim.example"),
		EimIDType:               &idType,
		CounterValue:            &counter,
		AssociationToken:        &association,
		EimSupportedProtocol:    &protocols,
		EUICCCIPKID:             []byte{0x01, 0x02},
		IndirectProfileDownload: true,
	}
}

func sampleEuiccPackageRequest() *EuiccPackageRequest {
	return &EuiccPackageRequest{
		EuiccPackageSigned: EuiccPackageSigned{
			EimID:            "eim.example",
			EID:              []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			CounterValue:     1,
			EimTransactionID: []byte{0xaa},
			EuiccPackage: EuiccPackage{
				Kind: EuiccPackagePSMO,
				PSMOs: []Psmo{{
					Operation: PsmoEnable,
					ICCID:     []byte{0x98, 0x10},
				}},
			},
		},
		EimSignature: []byte{0x01, 0x02, 0x03},
	}
}

func sampleEuiccPackageResult() *EuiccPackageResult {
	result, err := IntegerEuiccResult(3, 0)
	if err != nil {
		panic(err)
	}
	return &EuiccPackageResult{
		Kind: EuiccPackageResultOK,
		Signed: &EuiccPackageResultSigned{
			Data: EuiccPackageResultDataSigned{
				EimID:            "eim.example",
				CounterValue:     1,
				EimTransactionID: []byte{0xaa},
				SeqNumber:        1,
				Results:          []EuiccResultData{result},
			},
			EuiccSignEPR: []byte{0x01},
		},
	}
}

func (a *EimAcknowledgements) mustTLV() *bertlv.TLV {
	tlv, err := a.MarshalBERTLV()
	if err != nil {
		panic(err)
	}
	return tlv
}

func stringPtr(value string) *string {
	return &value
}

func assertTagPrefix(t *testing.T, encoded []byte, prefixHex string) {
	t.Helper()
	prefix, err := hex.DecodeString(prefixHex)
	if err != nil {
		t.Fatalf("bad prefix hex %q: %v", prefixHex, err)
	}
	if len(encoded) < len(prefix) || string(encoded[:len(prefix)]) != string(prefix) {
		t.Fatalf("encoded tag = %x, want prefix %x", encoded, prefix)
	}
}

func assertHex(t *testing.T, got []byte, wantHex string) {
	t.Helper()
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("bad expected hex %q: %v", wantHex, err)
	}
	if string(got) != string(want) {
		t.Fatalf("hex mismatch\n got %x\nwant %x", got, want)
	}
}

func assertDecodeErrorNoPanic(t *testing.T, input []byte, target Unmarshaler) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("Decode(%x) panicked: %v", input, recovered)
		}
	}()
	if err := Decode(input, target); err == nil {
		t.Fatalf("Decode(%x) succeeded, want error", input)
	}
}

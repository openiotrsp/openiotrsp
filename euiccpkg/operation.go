package euiccpkg

import protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"

// OperationKind is the domain operation carried by a single-operation package.
type OperationKind string

const (
	OperationNone                     OperationKind = ""
	OperationEnable                   OperationKind = "enable"
	OperationDisable                  OperationKind = "disable"
	OperationDelete                   OperationKind = "delete"
	OperationListProfileInfo          OperationKind = "list-profile-info"
	OperationGetRAT                   OperationKind = "get-rat"
	OperationConfigureImmediateEnable OperationKind = "configure-immediate-enable"
	OperationSetFallbackAttribute     OperationKind = "set-fallback-attribute"
	OperationUnsetFallbackAttribute   OperationKind = "unset-fallback-attribute"
	OperationSetDefaultDPAddress      OperationKind = "set-default-dp-address"
	OperationAddEIM                   OperationKind = "add-eim"
	OperationDeleteEIM                OperationKind = "delete-eim"
	OperationUpdateEIM                OperationKind = "update-eim"
	OperationListEIM                  OperationKind = "list-eim"
)

func (o OperationKind) resultTag() uint64 {
	switch o {
	case OperationEnable:
		return 3
	case OperationDisable:
		return 4
	case OperationDelete:
		return 5
	case OperationListProfileInfo:
		return 45
	case OperationGetRAT:
		return 6
	case OperationConfigureImmediateEnable:
		return 7
	case OperationSetFallbackAttribute:
		return 13
	case OperationUnsetFallbackAttribute:
		return 14
	case OperationSetDefaultDPAddress:
		return 101
	case OperationAddEIM:
		return 8
	case OperationDeleteEIM:
		return 9
	case OperationUpdateEIM:
		return 10
	case OperationListEIM:
		return 11
	default:
		return 0
	}
}

func requestPSMO(request *SignedRequest) (OperationKind, []byte) {
	if request == nil {
		return OperationNone, nil
	}
	return packagePSMO(request.Package)
}

func packagePSMO(pkg protocolasn1.EuiccPackage) (OperationKind, []byte) {
	if pkg.Kind != protocolasn1.EuiccPackagePSMO || len(pkg.PSMOs) != 1 {
		return OperationNone, nil
	}
	psmo := pkg.PSMOs[0]
	switch psmo.Operation {
	case protocolasn1.PsmoEnable:
		return OperationEnable, cloneBytes(psmo.ICCID)
	case protocolasn1.PsmoDisable:
		return OperationDisable, cloneBytes(psmo.ICCID)
	case protocolasn1.PsmoDelete:
		return OperationDelete, cloneBytes(psmo.ICCID)
	case protocolasn1.PsmoListProfileInfo:
		return OperationListProfileInfo, nil
	case protocolasn1.PsmoGetRAT:
		return OperationGetRAT, nil
	case protocolasn1.PsmoConfigureImmediateEnable:
		return OperationConfigureImmediateEnable, nil
	case protocolasn1.PsmoSetFallbackAttribute:
		return OperationSetFallbackAttribute, cloneBytes(psmo.ICCID)
	case protocolasn1.PsmoUnsetFallbackAttribute:
		return OperationUnsetFallbackAttribute, nil
	case protocolasn1.PsmoSetDefaultDPAddress:
		return OperationSetDefaultDPAddress, nil
	default:
		return OperationNone, nil
	}
}

func requestECO(request *SignedRequest) (OperationKind, *protocolasn1.Eco) {
	if request == nil {
		return OperationNone, nil
	}
	return packageECO(request.Package)
}

func packageECO(pkg protocolasn1.EuiccPackage) (OperationKind, *protocolasn1.Eco) {
	if pkg.Kind != protocolasn1.EuiccPackageECO || len(pkg.ECOs) != 1 {
		return OperationNone, nil
	}
	eco := pkg.ECOs[0]
	switch eco.Operation {
	case protocolasn1.EcoAddEIM:
		return OperationAddEIM, &eco
	case protocolasn1.EcoDeleteEIM:
		return OperationDeleteEIM, &eco
	case protocolasn1.EcoUpdateEIM:
		return OperationUpdateEIM, &eco
	case protocolasn1.EcoListEIM:
		return OperationListEIM, &eco
	default:
		return OperationNone, nil
	}
}

func (o OperationKind) String() string {
	if o == OperationNone {
		return "none"
	}
	return string(o)
}

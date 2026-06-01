// Package euiccpkg constructs, signs, verifies, and applies SGP.32 eUICC
// Packages.
package euiccpkg

import protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"

// Enable builds a EuiccPackage containing one PSMO enable operation.
func Enable(iccid []byte, rollback bool) protocolasn1.EuiccPackage {
	return psmoPackage(protocolasn1.Psmo{
		Operation:    protocolasn1.PsmoEnable,
		ICCID:        cloneBytes(iccid),
		RollbackFlag: rollback,
	})
}

// Disable builds a EuiccPackage containing one PSMO disable operation.
func Disable(iccid []byte) protocolasn1.EuiccPackage {
	return psmoPackage(protocolasn1.Psmo{
		Operation: protocolasn1.PsmoDisable,
		ICCID:     cloneBytes(iccid),
	})
}

// Delete builds a EuiccPackage containing one PSMO delete operation.
func Delete(iccid []byte) protocolasn1.EuiccPackage {
	return psmoPackage(protocolasn1.Psmo{
		Operation: protocolasn1.PsmoDelete,
		ICCID:     cloneBytes(iccid),
	})
}

// AddEIM builds a EuiccPackage containing one ECO addEim operation.
func AddEIM(config *protocolasn1.EimConfigurationData) protocolasn1.EuiccPackage {
	return ecoPackage(protocolasn1.Eco{
		Operation: protocolasn1.EcoAddEIM,
		Config:    config,
	})
}

// DeleteEIM builds a EuiccPackage containing one ECO deleteEim operation.
func DeleteEIM(eimID string) protocolasn1.EuiccPackage {
	return ecoPackage(protocolasn1.Eco{
		Operation: protocolasn1.EcoDeleteEIM,
		EimID:     eimID,
	})
}

// UpdateEIM builds a EuiccPackage containing one ECO updateEim operation.
func UpdateEIM(config *protocolasn1.EimConfigurationData) protocolasn1.EuiccPackage {
	return ecoPackage(protocolasn1.Eco{
		Operation: protocolasn1.EcoUpdateEIM,
		Config:    config,
	})
}

// ListEIM builds a EuiccPackage containing one ECO listEim operation.
func ListEIM() protocolasn1.EuiccPackage {
	return ecoPackage(protocolasn1.Eco{
		Operation: protocolasn1.EcoListEIM,
	})
}

func psmoPackage(psmo protocolasn1.Psmo) protocolasn1.EuiccPackage {
	return protocolasn1.EuiccPackage{
		Kind:  protocolasn1.EuiccPackagePSMO,
		PSMOs: []protocolasn1.Psmo{psmo},
	}
}

func ecoPackage(eco protocolasn1.Eco) protocolasn1.EuiccPackage {
	return protocolasn1.EuiccPackage{
		Kind: protocolasn1.EuiccPackageECO,
		ECOs: []protocolasn1.Eco{eco},
	}
}

package euiccpkg

import (
	"context"
	"encoding/hex"
	"errors"

	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/storage"
)

// ApplyPackageState applies successful single-operation package effects to the
// persisted local state. ECO add results that return an association token should
// use ApplyPackageResultState so the returned token can be persisted.
func ApplyPackageState(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	eid string,
	pkg protocolasn1.EuiccPackage,
) error {
	operation, iccid := packagePSMO(pkg)
	if err := applyPSMOState(ctx, store, tenantID, eid, operation, iccid); err != nil {
		return err
	}
	return applyECOState(ctx, store, tenantID, eid, pkg, nil)
}

// ApplyPackageResultState applies successful single-operation package effects
// that depend on the parsed eUICC result, such as addEim association tokens.
func ApplyPackageResultState(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	eid string,
	pkg protocolasn1.EuiccPackage,
	result *Result,
) error {
	operation, iccid := packagePSMO(pkg)
	if err := applyPSMOState(ctx, store, tenantID, eid, operation, iccid); err != nil {
		return err
	}
	return applyECOState(ctx, store, tenantID, eid, pkg, result)
}

func applyPSMOState(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	eid string,
	operation OperationKind,
	iccid []byte,
) error {
	if operation == OperationNone {
		return nil
	}

	iccidHex := hex.EncodeToString(iccid)
	switch operation {
	case OperationEnable:
		return setProfileEnabled(ctx, store, tenantID, eid, iccidHex, true)
	case OperationDisable:
		return setProfileEnabled(ctx, store, tenantID, eid, iccidHex, false)
	case OperationDelete:
		err := store.DeleteProfileState(ctx, tenantID, eid, iccidHex)
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		return err
	default:
		return nil
	}
}

func setProfileEnabled(ctx context.Context, store storage.Store, tenantID storage.TenantID, eid string, iccid string, enabled bool) error {
	state, err := store.GetProfileState(ctx, tenantID, eid, iccid)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			return err
		}
		state = storage.ProfileState{EID: eid, ICCID: iccid}
	}
	state.EID = eid
	state.ICCID = iccid
	state.IsEnabled = enabled
	return store.SetProfileState(ctx, tenantID, state)
}

func applyECOState(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	eid string,
	pkg protocolasn1.EuiccPackage,
	result *Result,
) error {
	operation, eco := packageECO(pkg)
	if operation == OperationNone || eco == nil {
		return nil
	}
	switch operation {
	case OperationAddEIM, OperationUpdateEIM:
		config := eco.Config
		if config == nil {
			return nil
		}
		if operation == OperationAddEIM && result != nil && result.AddEIMAssociationToken != nil {
			copied := *config
			token := *result.AddEIMAssociationToken
			copied.AssociationToken = &token
			config = &copied
		} else if operation == OperationUpdateEIM && config.AssociationToken == nil {
			copied := *config
			if token, ok, err := existingAssociationToken(ctx, store, tenantID, eid, config.EimID); err != nil {
				return err
			} else if ok {
				copied.AssociationToken = &token
				config = &copied
			}
		}
		associated, err := associatedEIMFromConfig(eid, config)
		if err != nil {
			return err
		}
		return store.SetAssociatedEIM(ctx, tenantID, associated)
	case OperationDeleteEIM:
		err := store.DeleteAssociatedEIM(ctx, tenantID, eid, eco.EimID)
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		return err
	default:
		return nil
	}
}

func existingAssociationToken(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	eid string,
	eimID string,
) (int64, bool, error) {
	associated, err := store.GetAssociatedEIM(ctx, tenantID, eid, eimID)
	if errors.Is(err, storage.ErrNotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	var config protocolasn1.EimConfigurationData
	if err := protocolasn1.Decode(associated.ConfigPayload, &config); err != nil {
		return 0, false, err
	}
	if config.AssociationToken == nil {
		return 0, false, nil
	}
	return *config.AssociationToken, true, nil
}

func associatedEIMFromConfig(eid string, config *protocolasn1.EimConfigurationData) (storage.AssociatedEIM, error) {
	payload, err := protocolasn1.Encode(config)
	if err != nil {
		return storage.AssociatedEIM{}, err
	}
	var eimIDType *int64
	if config.EimIDType != nil {
		value := int64(*config.EimIDType)
		eimIDType = &value
	}
	return storage.AssociatedEIM{
		EID:           eid,
		EIMID:         config.EimID,
		EIMIDType:     eimIDType,
		ConfigPayload: payload,
	}, nil
}

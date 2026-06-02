package euiccpkg

import (
	"context"
	"encoding/hex"
	"errors"

	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/storage"
)

// ApplyPackageState applies successful single-operation PSMO package effects to
// the persisted profile state.
func ApplyPackageState(
	ctx context.Context,
	store storage.Store,
	tenantID storage.TenantID,
	eid string,
	pkg protocolasn1.EuiccPackage,
) error {
	operation, iccid := packagePSMO(pkg)
	return applyPSMOState(ctx, store, tenantID, eid, operation, iccid)
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

package euiccpkg

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/openiotrsp/openiotrsp/storage"
)

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
